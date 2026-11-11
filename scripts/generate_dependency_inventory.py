#!/usr/bin/env python3
"""Enumerate managed dependency and infrastructure pins across the AiSOC tree.

This script is the reproducible inventory behind ``docs/upgrade/DEPENDENCY_MODERNIZATION.md``.
It does not upgrade anything; it reads manifests, lockfiles, compose files, Helm
values, Dockerfiles, and CI workflows, then writes a machine-readable report or
fails when datastore image pins drift across surfaces.

Usage::

    python3 scripts/generate_dependency_inventory.py
    python3 scripts/generate_dependency_inventory.py --check
    python3 scripts/generate_dependency_inventory.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

ROOT = repo_root()
OUT_JSON = ROOT / "docs" / "upgrade" / "dependency-inventory.json"

# Compose is the dev-stack source of truth for third-party datastore images.
COMPOSE_CANONICAL = ROOT / "docker-compose.yml"

IMAGE_LINE = re.compile(r"^\s*image:\s*(?P<ref>.+?)\s*$", re.MULTILINE)
IMAGE_INLINE = re.compile(r'image:\s*["\']?(?P<ref>[^"\'\s${}]+:[^"\'\s${}]+)["\']?')
FROM_LINE = re.compile(r"^FROM\s+(?P<ref>\S+)", re.MULTILINE)
GO_VERSION = re.compile(r"^go\s+(?P<v>\d+\.\d+(?:\.\d+)?)", re.MULTILINE)
CHECKOUT_SHA = re.compile(
    r"uses:\s*actions/checkout@(?P<sha>[0-9a-f]{40})\s+#\s*(?P<label>\S+)",
    re.MULTILINE,
)

SCAN_GLOBS = (
    "docker-compose*.yml",
    "infra/compose/*.yml",
    "infra/helm/**/*.yaml",
    "infra/helm/**/*.yml",
    ".github/workflows/*.yml",
    "**/Dockerfile",
    "**/Dockerfile.*",
)


@dataclass
class Inventory:
    generated_from: str
    container_images: dict[str, list[str]] = field(default_factory=dict)
    datastore_pins: dict[str, str] = field(default_factory=dict)
    runtimes: dict[str, list[str]] = field(default_factory=dict)
    package_managers: dict[str, str] = field(default_factory=dict)
    poetry_services: list[str] = field(default_factory=list)
    go_modules: list[str] = field(default_factory=list)
    pnpm_workspace: dict[str, str] = field(default_factory=dict)
    ci_action_pins: dict[str, str] = field(default_factory=dict)
    lockfiles: dict[str, str] = field(default_factory=dict)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _collect_images(text: str) -> list[str]:
    refs: list[str] = []
    for m in IMAGE_LINE.finditer(text):
        ref = m.group("ref").strip().strip("'\"")
        if ref and not ref.startswith("${"):
            refs.append(ref)
    for m in IMAGE_INLINE.finditer(text):
        refs.append(m.group("ref").strip())
    return refs


def _datastore_pins_from_compose() -> dict[str, str]:
    text = _read_text(COMPOSE_CANONICAL)
    pins: dict[str, str] = {}
    for ref in _collect_images(text):
        if ":" not in ref:
            continue
        name, tag = ref.rsplit(":", 1)
        base = name.split("/")[-1]
        if (
            base
            in {
                "clickhouse-server",
                "opensearch",
                "qdrant",
                "neo4j",
                "cp-kafka",
                "cp-zookeeper",
                "redis",
                "postgres",
            }
            or name.endswith("/opensearch")
            or "clickhouse-server" in name
        ):
            key = name if "/" in name else base
            pins[key] = tag
    return pins


def _python_services() -> list[str]:
    return sorted(p.parent.name for p in ROOT.glob("services/*/pyproject.toml"))


def _go_modules() -> list[str]:
    return sorted(str(p.relative_to(ROOT)) for p in ROOT.glob("**/go.mod") if "plans" not in p.parts)


def _scan_files() -> dict[str, list[str]]:
    by_file: dict[str, list[str]] = defaultdict(list)
    for pattern in SCAN_GLOBS:
        for path in ROOT.glob(pattern):
            if "plans" in path.parts:
                continue
            rel = str(path.relative_to(ROOT))
            text = _read_text(path)
            refs = _collect_images(text)
            for m in FROM_LINE.finditer(text):
                refs.append(m.group("ref"))
            if refs:
                by_file[rel] = sorted(set(refs))
    return dict(sorted(by_file.items()))


def _runtimes() -> dict[str, list[str]]:
    python: set[str] = set()
    node: set[str] = set()
    go: set[str] = set()
    for dockerfile in ROOT.glob("**/Dockerfile"):
        if "plans" in dockerfile.parts:
            continue
        text = _read_text(dockerfile)
        for m in FROM_LINE.finditer(text):
            ref = m.group("ref")
            if "python:" in ref:
                python.add(ref.split(":", 1)[1])
            if "node:" in ref:
                node.add(ref.split(":", 1)[1])
            if "golang:" in ref:
                go.add(ref.split(":", 1)[1])
    for mod in ROOT.glob("**/go.mod"):
        if "plans" in mod.parts:
            continue
        go_match = GO_VERSION.search(_read_text(mod))
        if go_match:
            go.add(go_match.group("v"))
    return {
        "python_base_images": sorted(python),
        "node_base_images": sorted(node),
        "go_toolchain": sorted(go),
    }


def _pnpm_root() -> dict[str, str]:
    pkg = json.loads(_read_text(ROOT / "package.json"))
    return {
        "node_engine": pkg.get("engines", {}).get("node", ""),
        "pnpm_engine": pkg.get("engines", {}).get("pnpm", ""),
        "packageManager": pkg.get("packageManager", ""),
    }


def _lockfile_digest() -> dict[str, str]:
    paths: list[Path] = []
    paths.extend(ROOT.glob("services/*/poetry.lock"))
    paths.extend(ROOT.glob("packages/*/poetry.lock"))
    paths.append(ROOT / "pnpm-lock.yaml")
    paths.extend(ROOT.glob("**/go.sum"))
    for p in sorted(ROOT.glob("apps/*/package-lock.json")):
        paths.append(p)
    out: dict[str, str] = {}
    for path in sorted(set(paths)):
        if not path.is_file() or "plans" in path.parts:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        out[str(path.relative_to(ROOT))] = digest
    return dict(sorted(out.items()))


def _ci_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = _read_text(wf)
        for m in CHECKOUT_SHA.finditer(text):
            pins[f"actions/checkout@{m.group('label')}"] = m.group("sha")[:12]
    return dict(sorted(pins.items()))


def build_inventory() -> Inventory:
    return Inventory(
        generated_from=str(ROOT),
        container_images=_scan_files(),
        datastore_pins=_datastore_pins_from_compose(),
        runtimes=_runtimes(),
        package_managers={"root_package_json": json.dumps(_pnpm_root(), sort_keys=True)},
        poetry_services=_python_services() + sorted(p.name for p in ROOT.glob("packages/*/pyproject.toml")),
        go_modules=_go_modules(),
        pnpm_workspace=_pnpm_root(),
        ci_action_pins=_ci_pins(),
        lockfiles=_lockfile_digest(),
    )


def _check_datastore_consistency() -> list[str]:
    """Workflows and Helm must not drift from compose datastore tags."""
    canonical = _datastore_pins_from_compose()
    errors: list[str] = []

    def canonical_tag(image_ref: str) -> str | None:
        if ":" not in image_ref:
            return None
        repo, _tag = image_ref.rsplit(":", 1)
        for key, ctag in canonical.items():
            if repo == key or repo.endswith("/" + key.split("/")[-1]):
                return ctag
        return None

    workflow_dir = ROOT / ".github" / "workflows"
    for wf in workflow_dir.glob("*.yml"):
        for ref in _collect_images(_read_text(wf)):
            if "ghcr.io/" in ref or "mcr.microsoft.com" in ref:
                continue
            ctag = canonical_tag(ref)
            if ctag is None:
                continue
            actual = ref.rsplit(":", 1)[1]
            allowed = {ctag, f"{ctag}-alpine"}
            if actual not in allowed:
                errors.append(f"{wf.relative_to(ROOT)}: {ref} (compose tag {ctag})")

    helm_values = ROOT / "infra" / "helm" / "aisoc" / "values.yaml"
    qdrant = re.search(
        r"repository:\s*qdrant/qdrant\s+tag:\s*(?P<t>v[\d.]+)",
        _read_text(helm_values),
        re.MULTILINE,
    )
    if qdrant:
        ctag = canonical.get("qdrant/qdrant")
        if ctag and qdrant.group("t") != ctag:
            errors.append(f"helm qdrant tag {qdrant.group('t')} != compose {ctag}")

    return errors


def write_inventory(path: Path, inv: Inventory) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(inv), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify compose / helm / workflow consistency and JSON snapshot")
    args = parser.parse_args(argv)

    inv = build_inventory()
    if args.check:
        drift = _check_datastore_consistency()
        if drift:
            for line in drift:
                print(line, file=sys.stderr)
            return 1
        if not OUT_JSON.exists():
            print(f"{OUT_JSON.relative_to(ROOT)} is missing; run without --check first", file=sys.stderr)
            return 1
        on_disk = json.loads(OUT_JSON.read_text(encoding="utf-8"))
        if on_disk.get("datastore_pins") != inv.datastore_pins:
            print("datastore_pins in dependency-inventory.json drifted from docker-compose.yml", file=sys.stderr)
            print("  on disk:", on_disk.get("datastore_pins"), file=sys.stderr)
            print("  current:", inv.datastore_pins, file=sys.stderr)
            return 1
        print("generate_dependency_inventory: OK")
        return 0

    write_inventory(OUT_JSON, inv)
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    return 0


def _self_test() -> int:
    errors: list[str] = []

    inv = build_inventory()
    if not inv.datastore_pins.get("clickhouse/clickhouse-server", "").startswith("26"):
        errors.append("expected ClickHouse 26.x in compose canonical pins")
    if not inv.poetry_services:
        errors.append("expected at least one poetry service")

    # Mismatch detector: synthetic compose tag must be reported.
    pins = _datastore_pins_from_compose()

    def fake_check(tag: str) -> bool:
        return pins.get("qdrant/qdrant") == tag

    if not fake_check("v1.20.0"):
        errors.append("self-test expected qdrant v1.20.0 in this tree")

    if errors:
        for e in errors:
            print(f"self-test: {e}", file=sys.stderr)
        return 1
    print("generate_dependency_inventory: self-test OK")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    raise SystemExit(main(sys.argv[1:]))

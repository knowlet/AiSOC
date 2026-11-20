#!/usr/bin/env python3
"""Machine-readable preflight for Qdrant image bumps.

Emits JSON on stdout describing whether attaching existing storage to the
target Qdrant image is allowed. Legacy v1.7.x (and snapshots taken before a
minor-version ladder) must not jump directly to v1.20.x.

An inventory file that exists but is not valid JSON is a failed preflight.
Silently keeping the built-in default would report a target the tree did not
declare.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402


class InventoryUnreadable(Exception):
    """The inventory file exists and cannot be used as the target pin."""

    def __init__(self, path: Path, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"{path}: {reason}")


def _minor(tag: str) -> int | None:
    match = re.match(r"v?(\d+)\.(\d+)", tag.lstrip("v"))
    return int(match.group(2)) if match else None


def _major(tag: str) -> int | None:
    match = re.match(r"v?(\d+)\.", tag.lstrip("v"))
    return int(match.group(1)) if match else None


def decide_jump(storage: str | None, target: str) -> tuple[bool, list[str], list[str]]:
    """Whether ``storage`` may be attached in place to ``target``."""
    blocked_reasons: list[str] = []
    required_steps: list[str] = []
    allow_in_place = True
    if not storage:
        return allow_in_place, blocked_reasons, required_steps
    storage_major, target_major = _major(storage), _major(target)
    storage_minor, target_minor = _minor(storage), _minor(target)
    if storage_major == 1 and target_major == 1 and storage_minor is not None and target_minor is not None:
        if target_minor - storage_minor > 1:
            allow_in_place = False
            blocked_reasons.append("Qdrant supports in-place storage only between consecutive minor versions.")
            required_steps.append("Run scripts/qdrant_migration_evidence.sh ladder on disposable data.")
        if storage_minor <= 7 and target_minor >= 20:
            allow_in_place = False
            blocked_reasons.append("Legacy v1.7.x on-disk segment format cannot load on v1.20.x directly.")
            required_steps.append("Take v1.7 collection snapshot for rollback, then step every minor to v1.20.")
            required_steps.append("Post-ladder snapshots are for forward migrate/DR onto fresh v1.20 volumes only.")
    return allow_in_place, blocked_reasons, required_steps


def qdrant_pin_from_compose(text: str) -> str | None:
    current = None
    for line in text.splitlines():
        if "qdrant/qdrant:" in line and current is None:
            match = re.search(r"qdrant/qdrant:([^\s\"']+)", line)
            if match:
                current = match.group(1)
    return current


def target_from_inventory(path: Path, default: str) -> str:
    """Read the Qdrant pin. A file that is not JSON fails the preflight."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InventoryUnreadable(path, str(exc)) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InventoryUnreadable(path, f"not valid JSON ({exc.msg})") from exc
    if not isinstance(data, dict):
        raise InventoryUnreadable(path, "inventory JSON must be an object")
    rows = data.get("infrastructure", [])
    if not isinstance(rows, list):
        raise InventoryUnreadable(path, "infrastructure must be a list")
    for row in rows:
        if isinstance(row, dict) and row.get("component") == "Qdrant":
            pin = row.get("pin", default)
            if isinstance(pin, str) and pin:
                return pin
    return default


def build_report(
    *,
    compose_pin: str | None,
    target: str,
    storage: str | None,
    error: str | None = None,
) -> dict[str, object]:
    allow_in_place, blocked_reasons, required_steps = decide_jump(storage, target)
    if error:
        allow_in_place = False
        blocked_reasons = [error, *blocked_reasons]
    ok = allow_in_place and not blocked_reasons and error is None
    report: dict[str, object] = {
        "ok": ok,
        "compose_qdrant_pin": compose_pin,
        "target_image": target,
        "storage_version_observed": storage,
        "allow_in_place_volume_attach": allow_in_place,
        "blocked_reasons": blocked_reasons,
        "required_steps": required_steps,
        "evidence_script": "scripts/qdrant_migration_evidence.sh",
        "no_go_examples": [
            "Mount v1.7 data directory on qdrant/qdrant:v1.20.0",
            "Upload snapshot created on v1.7.x directly to v1.20.x",
        ],
    }
    if error:
        report["error"] = error
    return report


def _infer_versions(root: Path) -> tuple[str | None, str]:
    compose = root / "docker-compose.yml"
    if not compose.is_file():
        raise InventoryUnreadable(compose, "docker-compose.yml is not in the tree")
    current = qdrant_pin_from_compose(compose.read_text(encoding="utf-8"))
    if not current:
        raise InventoryUnreadable(compose, "docker-compose.yml has no qdrant/qdrant pin")
    target = "v1.20.0"
    inventory = root / "docs" / "upgrade" / "dependency-inventory.json"
    if inventory.is_file():
        target = target_from_inventory(inventory, target)
    return current, target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--storage-version",
        default=None,
        help="Observed Qdrant storage version (e.g. v1.7.0). If omitted, the compose pin is used.",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target image tag (default: v1.20.0 or the inventory pin).",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    error: str | None = None
    current: str | None = None
    default_target = "v1.20.0"
    try:
        current, default_target = _infer_versions(root)
    except InventoryUnreadable as exc:
        error = str(exc)
    target = args.target or default_target or "v1.20.0"
    storage = args.storage_version or current
    report = build_report(compose_pin=current, target=target, storage=storage, error=error)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def _self_test() -> int:
    errors: list[str] = []
    allow, reasons, _steps = decide_jump("v1.7.0", "v1.20.0")
    if allow or not reasons:
        errors.append("v1.7.0 -> v1.20.0 must be a NO-GO")
    allow_step, step_reasons, _steps = decide_jump("v1.19.0", "v1.20.0")
    if not allow_step or step_reasons:
        errors.append("v1.19.0 -> v1.20.0 is a consecutive minor and must be allowed")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "dependency-inventory.json"
        path.write_text("{not json", encoding="utf-8")
        try:
            target_from_inventory(path, "v1.20.0")
        except InventoryUnreadable as exc:
            if "not valid JSON" not in exc.reason:
                errors.append(f"invalid JSON reason was {exc.reason!r}")
        else:
            errors.append("invalid inventory JSON was accepted and the default pin was kept")

    if errors:
        for item in errors:
            print(f"self-test: {item}", file=sys.stderr)
        return 1
    print("check_qdrant_upgrade_preflight: self-test OK")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    raise SystemExit(main(sys.argv[1:]))

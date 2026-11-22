#!/usr/bin/env python3
"""Machine-readable preflight for attaching an existing Qdrant volume to a new image.

Qdrant writes the release that created a collection into
``collections/<name>/version.info`` (the crate version, for example ``1.7.0``,
with no ``v`` prefix). ``Collection::load`` reads that file and panics when the
stored version cannot move to the running binary. v1.7.0 data on
``qdrant/qdrant:v1.20.0`` panics that way (``on_disk`` segment format, and the
collection version check).

The Compose image tag is the version about to start. It is not the version
stored in ``qdrant_data``. A run that cannot read a stored version is NO-GO:
using the pin in its place reports GO for a volume that will panic.

``volume_state``:

* ``observed`` — at least one ``collections/<name>/version.info`` was read.
  The oldest of those versions is the one the decision uses.
* ``empty`` — the directory exists and has no Qdrant payload.
* ``no-collections`` — raft or alias files are present and there is no
  collection directory. Qdrant writes ``version.info`` when it creates a
  collection; with none, there is no collection storage to attach.
* ``absent`` — Docker confirmed the named volume does not exist.
* ``unknown`` — a collection is present but its ``version.info`` was not
  readable, the path could not be read, or Docker could not be asked. NO-GO.

An inventory file that exists but is not valid JSON is a failed preflight.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]

_VERSION_TEXT = re.compile(r"v?\d+\.\d+\.\d+")
_VOLUME_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_IMAGE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]*")

# Printed into the JSON when the volume was not actually read. Kept as one
# sentence so a caller cannot mistake it for a version comparison.
_UNKNOWN_REASON = "Stored Qdrant version could not be read from the volume. The Compose image pin was not used as the installed version."

_READER_SCRIPT = r"""
set -eu
cd /qdrant/storage
if [ -d collections ]; then
  for dir in collections/*/; do
    [ -d "$dir" ] || continue
    if [ -f "${dir}version.info" ]; then
      printf 'VERSION %s ' "${dir%/}"
      tr -d '\r\n' < "${dir}version.info"
      printf '\n'
    else
      printf 'NOVERSION %s\n' "${dir%/}"
    fi
  done
fi
if [ -f raft_state.json ]; then printf 'MARKER raft_state.json\n'; fi
if [ -f aliases/data.json ]; then printf 'MARKER aliases/data.json\n'; fi
"""


class InventoryUnreadable(Exception):
    """The inventory file exists and cannot be used as the target pin."""

    def __init__(self, path: Path, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"{path}: {reason}")


@dataclass(frozen=True)
class StorageObservation:
    """What was read from a Qdrant storage directory or volume."""

    state: str
    version: str | None
    versions: tuple[str, ...]
    detail: str
    source: str


def _canonical(tag: str) -> str:
    return tag.strip().lstrip("vV")


def _version_key(tag: str) -> tuple[int, int, int]:
    match = re.match(r"v?(\d+)\.(\d+)\.(\d+)", tag.strip())
    if match is None:
        raise ValueError(tag)
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _minor(tag: str) -> int | None:
    match = re.match(r"v?(\d+)\.(\d+)", tag.lstrip("v"))
    return int(match.group(2)) if match else None


def _major(tag: str) -> int | None:
    match = re.match(r"v?(\d+)\.", tag.lstrip("v"))
    return int(match.group(1)) if match else None


def decide_jump(storage: str | None, target: str) -> tuple[bool, list[str], list[str]]:
    """Whether ``storage`` may be attached in place to ``target``.

    ``storage`` is a version read from the volume. ``None`` is not a version,
    and it is not permission to attach.
    """
    blocked_reasons: list[str] = []
    required_steps: list[str] = []
    if not storage or not storage.strip():
        return (
            False,
            [_UNKNOWN_REASON],
            ["Read collections/<name>/version.info from the existing qdrant_data volume."],
        )
    allow_in_place = True
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
    if storage_major is None or storage_minor is None:
        allow_in_place = False
        blocked_reasons.append(f"Stored version {storage!r} is not a Qdrant release.")
    return allow_in_place, blocked_reasons, required_steps


def qdrant_pin_from_compose(text: str) -> str | None:
    current = None
    for line in text.splitlines():
        if "qdrant/qdrant:" in line and current is None:
            match = re.search(r"qdrant/qdrant:([^\s\"']+)", line)
            if match:
                current = match.group(1)
    return current


def qdrant_pin_from_inventory(path: Path) -> str | None:
    """The inventory's Qdrant tag, or None when the document names none.

    ``datastore_pins`` is the generated shape. The older ``infrastructure``
    list is still accepted. A file that is not JSON fails the preflight.
    """
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

    from_pins: str | None = None
    pins = data.get("datastore_pins", None)
    if pins is not None:
        if not isinstance(pins, dict):
            raise InventoryUnreadable(path, "datastore_pins must be an object")
        pin = pins.get("qdrant/qdrant")
        if isinstance(pin, str) and pin.strip():
            from_pins = pin.strip()

    from_rows: str | None = None
    rows = data.get("infrastructure", None)
    if rows is not None:
        if not isinstance(rows, list):
            raise InventoryUnreadable(path, "infrastructure must be a list")
        for row in rows:
            if isinstance(row, dict) and row.get("component") == "Qdrant":
                pin = row.get("pin")
                if isinstance(pin, str) and pin.strip():
                    from_rows = pin.strip()
                    break

    if from_pins and from_rows and _canonical(from_pins) != _canonical(from_rows):
        raise InventoryUnreadable(path, "datastore_pins and infrastructure disagree on Qdrant")
    return from_pins or from_rows


def target_from_inventory(path: Path, default: str) -> str:
    """Read the Qdrant pin. A file that is not JSON fails the preflight."""
    pin = qdrant_pin_from_inventory(path)
    return pin if pin else default


def _safe_relative(text: str) -> Path:
    path = Path(text.strip())
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(text)
    return path


def read_storage_tree(path: Path, *, source: str) -> StorageObservation:
    """Read collection ``version.info`` files under a Qdrant storage root.

    The storage root is the directory mounted at ``/qdrant/storage``.
    """
    if not path.exists():
        return StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail=f"{path} does not exist",
            source=source,
        )
    if not path.is_dir():
        return StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail=f"{path} is not a directory",
            source=source,
        )

    versions: list[str] = []
    missing: list[str] = []
    saw_collection = False
    collections = path / "collections"
    if collections.is_dir():
        for child in sorted(entry for entry in collections.iterdir() if entry.is_dir()):
            saw_collection = True
            info = child / "version.info"
            if not info.is_file():
                missing.append(f"{child.name}: no version.info")
                continue
            try:
                raw = info.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                missing.append(f"{child.name}: {exc}")
                continue
            token = raw.strip().split()[0] if raw.strip() else ""
            if _VERSION_TEXT.fullmatch(token) is None:
                missing.append(f"{child.name}: version.info is {raw.strip()!r}")
                continue
            versions.append(token)

    markers: list[str] = []
    if (path / "raft_state.json").is_file():
        markers.append("raft_state.json")
    if (path / "aliases" / "data.json").is_file():
        markers.append("aliases/data.json")

    if missing:
        detail = "unreadable collection version: " + "; ".join(missing)
        return StorageObservation(state="unknown", version=None, versions=tuple(versions), detail=detail, source=source)
    if versions:
        oldest = min(versions, key=_version_key)
        listed = ", ".join(versions)
        return StorageObservation(
            state="observed",
            version=oldest,
            versions=tuple(versions),
            detail=f"collections/*/version.info ({listed}); decision uses {oldest}",
            source=source,
        )
    if saw_collection:
        return StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail="a collection directory is present but no collections/<name>/version.info was readable",
            source=source,
        )
    if markers:
        found = ", ".join(markers)
        return StorageObservation(
            state="no-collections",
            version=None,
            versions=(),
            detail=(
                f"Qdrant metadata is present ({found}) and there is no collection directory. "
                "version.info is written when a collection is created."
            ),
            source=source,
        )
    return StorageObservation(
        state="empty",
        version=None,
        versions=(),
        detail="storage directory has no Qdrant collections, raft_state.json, or aliases/data.json",
        source=source,
    )


def volume_name_from_config(config: object) -> str | None:
    """Resolved Docker volume name for ``qdrant_data`` from ``compose config`` JSON."""
    if not isinstance(config, dict):
        return None
    volumes = config.get("volumes")
    if not isinstance(volumes, dict):
        return None
    spec = volumes.get("qdrant_data")
    if not isinstance(spec, dict):
        return None
    name = spec.get("name")
    if isinstance(name, str) and _VOLUME_NAME.fullmatch(name):
        return name
    return None


def reader_argv(volume: str, image: str) -> list[str]:
    """A container that lists version files and does not start Qdrant.

    ``--entrypoint /bin/sh`` replaces the image entrypoint, and the volume is
    mounted read-only, so the Qdrant binary does not open the storage.
    """
    if _VOLUME_NAME.fullmatch(volume) is None:
        raise ValueError(f"refusing volume name {volume!r}")
    if _IMAGE_REF.fullmatch(image) is None:
        raise ValueError(f"refusing image reference {image!r}")
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--entrypoint",
        "/bin/sh",
        "-v",
        f"{volume}:/qdrant/storage:ro",
        image,
        "-c",
        _READER_SCRIPT,
    ]


def materialize_reader_transcript(text: str, dest: Path) -> None:
    """Turn the read-only container's stdout into a storage tree."""
    dest.mkdir(parents=True, exist_ok=True)
    for line in text.splitlines():
        if line.startswith("VERSION "):
            _, rel, version = line.split(" ", 2)
            path = dest / _safe_relative(rel) / "version.info"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(version.strip(), encoding="utf-8")
        elif line.startswith("NOVERSION "):
            rel = line.split(" ", 1)[1]
            path = dest / _safe_relative(rel)
            path.mkdir(parents=True, exist_ok=True)
            (path / "config.json").write_text("{}", encoding="utf-8")
        elif line.startswith("MARKER "):
            rel = line.split(" ", 1)[1]
            path = dest / _safe_relative(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}", encoding="utf-8")


def _completed(argv: Sequence[str], code: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(list(argv), code, stdout=stdout, stderr=stderr)


def default_runner(cwd: Path) -> Runner:
    def run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                list(argv),
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            return _completed(argv, 124, stderr=f"timed out: {exc}")
        except OSError as exc:
            return _completed(argv, 127, stderr=str(exc))

    return run


def _local_reader_image(runner: Runner) -> str | None:
    listed = runner(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])
    if listed.returncode != 0:
        return None
    names = {line.strip() for line in listed.stdout.splitlines() if line.strip() and "<none>" not in line}
    preferred = ("alpine:3.20", "alpine:latest", "busybox:latest", "postgres:16-alpine")
    for image in preferred:
        if image in names:
            return image
    for image in sorted(names):
        if image.startswith(("alpine:", "busybox:", "postgres:")):
            return image
    for image in sorted(names):
        if image.startswith("qdrant/qdrant:"):
            return image
    return None


def discover_compose_volume(root: Path, runner: Runner | None = None) -> StorageObservation:
    """Read the compose project's ``qdrant_data`` volume without starting Qdrant."""
    run = runner or default_runner(root)
    config_run = run(["docker", "compose", "config", "--format", "json"])
    if config_run.returncode != 0:
        detail = (config_run.stderr or config_run.stdout or "docker compose config failed").strip()
        return StorageObservation(state="unknown", version=None, versions=(), detail=detail, source="volume")
    try:
        config = json.loads(config_run.stdout)
    except json.JSONDecodeError as exc:
        return StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail=f"docker compose config was not JSON ({exc.msg})",
            source="volume",
        )
    name = volume_name_from_config(config)
    if not name:
        return StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail="docker compose config did not name the qdrant_data volume",
            source="volume",
        )
    inspected = run(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}", name])
    if inspected.returncode != 0:
        err = (inspected.stderr or inspected.stdout or "").strip()
        if "no such volume" in err.lower():
            return StorageObservation(
                state="absent",
                version=None,
                versions=(),
                detail=f"docker volume {name} does not exist",
                source="volume",
            )
        return StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail=err or f"docker volume inspect {name} failed",
            source="volume",
        )
    mount = Path(inspected.stdout.strip())
    mount_error = f"{mount} is not a readable directory"
    if mount.is_dir() and os.access(mount, os.R_OK | os.X_OK):
        try:
            return read_storage_tree(mount, source="volume-mount")
        except OSError as exc:
            mount_error = str(exc)
    image = _local_reader_image(run)
    if image is None:
        return StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail=(
                f"{mount_error}. No local image is available to copy version.info out "
                "with --entrypoint /bin/sh, and the preflight will not pull one or start Qdrant."
            ),
            source="volume",
        )
    try:
        argv = reader_argv(name, image)
    except ValueError as exc:
        return StorageObservation(state="unknown", version=None, versions=(), detail=str(exc), source="volume")
    copied = run(argv)
    if copied.returncode != 0:
        err = (copied.stderr or copied.stdout or "read-only copy failed").strip()
        return StorageObservation(state="unknown", version=None, versions=(), detail=err, source="volume")
    with tempfile.TemporaryDirectory(prefix="aisoc-qdrant-preflight-") as tmp:
        try:
            materialize_reader_transcript(copied.stdout, Path(tmp))
        except ValueError as exc:
            return StorageObservation(
                state="unknown",
                version=None,
                versions=(),
                detail=f"refusing reader output: {exc}",
                source="volume",
            )
        return read_storage_tree(Path(tmp), source="volume-copy")


def build_report(
    *,
    compose_pin: str | None,
    target: str,
    observation: StorageObservation,
    error: str | None = None,
) -> dict[str, object]:
    blocked_reasons: list[str] = []
    required_steps: list[str] = []
    allow_in_place = False
    if observation.state == "observed":
        allow_in_place, blocked_reasons, required_steps = decide_jump(observation.version, target)
    elif observation.state in {"absent", "empty", "no-collections"} and error is None:
        allow_in_place = True
    else:
        allow_in_place = False
        blocked_reasons = [_UNKNOWN_REASON]
        if observation.detail:
            blocked_reasons.append(observation.detail)
        required_steps = [
            "Inspect the existing qdrant_data volume (collections/<name>/version.info) before recreating Qdrant.",
        ]
    if error:
        allow_in_place = False
        blocked_reasons = [error, *blocked_reasons]
    ok = allow_in_place and not blocked_reasons and error is None
    report: dict[str, object] = {
        "ok": ok,
        "decision": "GO" if ok else "NO-GO",
        "compose_qdrant_pin": compose_pin,
        "target_image": target,
        "storage_version_observed": observation.version if observation.state == "observed" else None,
        "storage_versions_found": list(observation.versions),
        "volume_state": observation.state,
        "storage_source": observation.source,
        "volume_detail": observation.detail,
        "allow_in_place_volume_attach": allow_in_place and error is None,
        "blocked_reasons": blocked_reasons,
        "required_steps": required_steps,
        "evidence_script": "scripts/qdrant_migration_evidence.sh",
        "no_go_examples": [
            "Mount v1.7 data directory on qdrant/qdrant:v1.20.0",
            "Upload snapshot created on v1.7.x directly to v1.20.x",
            "Recreate Qdrant when collections/*/version.info cannot be read",
        ],
    }
    if error:
        report["error"] = error
    return report


def _infer_versions(root: Path) -> tuple[str, str | None]:
    compose = root / "docker-compose.yml"
    if not compose.is_file():
        raise InventoryUnreadable(compose, "docker-compose.yml is not in the tree")
    current = qdrant_pin_from_compose(compose.read_text(encoding="utf-8"))
    if not current:
        raise InventoryUnreadable(compose, "docker-compose.yml has no qdrant/qdrant pin")
    inventory_pin: str | None = None
    inventory = root / "docs" / "upgrade" / "dependency-inventory.json"
    if inventory.is_file():
        inventory_pin = qdrant_pin_from_inventory(inventory)
    return current, inventory_pin


def _summary(report: dict[str, object]) -> str:
    stored = report["storage_version_observed"] or report["volume_state"]
    return f"qdrant preflight: {report['decision']} (stored {stored}, target {report['target_image']})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--storage-dir",
        default=None,
        help="Qdrant storage root (the directory mounted at /qdrant/storage). Version is read from collections/<name>/version.info.",
    )
    parser.add_argument(
        "--storage-version",
        default=None,
        help="Optional check against the version read from --storage-dir. On its own it is not a volume read and the preflight is NO-GO.",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target image tag. Default: the qdrant/qdrant pin in docker-compose.yml.",
    )
    parser.add_argument("--self-test", action="store_true", help="Prove GO, NO-GO, and unknown, then exit.")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    root = repo_root()
    error: str | None = None
    compose_pin: str | None = None
    inventory_pin: str | None = None
    try:
        compose_pin, inventory_pin = _infer_versions(root)
    except InventoryUnreadable as exc:
        error = str(exc)
    if error is None and compose_pin and inventory_pin and _canonical(compose_pin) != _canonical(inventory_pin):
        error = f"dependency inventory pins qdrant/qdrant at {inventory_pin} but docker-compose.yml pins {compose_pin}"
    target = args.target or compose_pin or inventory_pin or ""
    if not target:
        error = error or "no Qdrant target tag"
    if args.storage_dir is not None:
        observation = read_storage_tree(Path(args.storage_dir), source="storage-dir")
        if args.storage_version and observation.version and _canonical(args.storage_version) != _canonical(observation.version):
            error = f"--storage-version {args.storage_version} does not match {observation.version} read from {args.storage_dir}"
    elif args.storage_version:
        observation = StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail=("--storage-version does not read the volume. Pass --storage-dir, or run with no flag so qdrant_data is inspected."),
            source="cli",
        )
    elif error and compose_pin is None:
        observation = StorageObservation(state="unknown", version=None, versions=(), detail=error, source="none")
    else:
        observation = discover_compose_volume(root)
    report = build_report(compose_pin=compose_pin, target=target, observation=observation, error=error)
    print(json.dumps(report, indent=2))
    print(_summary(report), file=sys.stderr)
    return 0 if report["ok"] else 1


def _capture_main(argv: list[str]) -> tuple[int, dict[str, object]]:
    stdout = StringIO()
    with redirect_stdout(stdout), redirect_stderr(StringIO()):
        code = main(argv)
    return code, json.loads(stdout.getvalue())


def _self_test() -> int:
    errors: list[str] = []
    allow, reasons, _steps = decide_jump("v1.7.0", "v1.20.0")
    if allow or not reasons:
        errors.append("v1.7.0 -> v1.20.0 must be a NO-GO")
    allow_step, step_reasons, _steps = decide_jump("v1.19.0", "v1.20.0")
    if not allow_step or step_reasons:
        errors.append("v1.19.0 -> v1.20.0 is a consecutive minor and must be allowed")
    allow_unknown, unknown_reasons, _steps = decide_jump(None, "v1.20.0")
    if allow_unknown or not unknown_reasons:
        errors.append("a missing stored version must be a NO-GO, not the target pin")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bad = root / "dependency-inventory.json"
        bad.write_text("{not json", encoding="utf-8")
        try:
            target_from_inventory(bad, "v1.20.0")
        except InventoryUnreadable as exc:
            if "not valid JSON" not in exc.reason:
                errors.append(f"invalid JSON reason was {exc.reason!r}")
        else:
            errors.append("invalid inventory JSON was accepted and the default pin was kept")

        pinned = root / "inventory.json"
        pinned.write_text(json.dumps({"datastore_pins": {"qdrant/qdrant": "v1.19.4"}}), encoding="utf-8")
        if qdrant_pin_from_inventory(pinned) != "v1.19.4":
            errors.append("datastore_pins qdrant/qdrant was not read")

    fixtures = repo_root() / "tests" / "fixtures" / "qdrant"
    expectations = (
        ("v1.7.0", 1, "NO-GO", "1.7.0"),
        ("v1.19.0", 0, "GO", "1.19.0"),
        ("unknown", 1, "NO-GO", None),
    )
    for name, code, decision, stored in expectations:
        path = fixtures / name
        if not path.is_dir():
            errors.append(f"missing fixture {path}")
            continue
        status, report = _capture_main(["--storage-dir", str(path), "--target", "v1.20.0"])
        if status != code or report.get("decision") != decision:
            errors.append(f"fixture {name}: exit {status} decision {report.get('decision')!r}, wanted {code} {decision}")
        if report.get("storage_version_observed") != stored:
            errors.append(f"fixture {name}: stored {report.get('storage_version_observed')!r}, wanted {stored!r}")
        pin = report.get("compose_qdrant_pin")
        observed = report.get("storage_version_observed")
        if stored is None and pin and observed == pin:
            errors.append(f"fixture {name}: storage version collapsed to the compose pin")

    invented = build_report(
        compose_pin="v1.20.0",
        target="v1.20.0",
        observation=StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail="not inspected",
            source="volume",
        ),
    )
    if invented["ok"] or invented["storage_version_observed"] is not None:
        errors.append("unknown storage was reported as the compose pin")

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

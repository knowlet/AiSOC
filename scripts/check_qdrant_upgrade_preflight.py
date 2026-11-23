#!/usr/bin/env python3
"""Refuse to attach an existing Qdrant volume to an image that cannot open it.

Qdrant loads on-disk collections only across consecutive minor releases. A
v1.7 volume mounted on v1.20 panics (`on_disk` segment payload). The compose
pin is the image we are about to start, not the version that wrote the
volume. Using it as the installed version makes v1.7 read as v1.20 and the
check reports GO.

What is actually on disk is not that release either. ``version.info`` is the
crate version (``0.4.2`` for the collection crate and ``0.6.0`` for the
segment crate), and those strings are unchanged from v1.7.0 through v1.20.0.
They are ignored. The application version is taken, in order, from:

1. the Qdrant process that has the volume open (``GET /``);
2. the image of the container that still has the volume mounted, when that
   image is not a target tag that already exited non-zero (a crashed recreate
   must not count as proof the volume was migrated);
3. ``aisoc-observed-version`` in the storage root, which this preflight writes
   after a real observation so a later ``compose down`` (the container is
   gone, the volume is not) can still be read.

If the volume has collections and none of those yield a version, the result
is NO-GO. An absent volume, or one with no collections, has nothing to
migrate and is GO.

An inventory file that exists but is not valid JSON is a failed preflight.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

MARKER_NAME = "aisoc-observed-version"
STORAGE_MOUNT = "/qdrant/storage"
_APP_VERSION = re.compile(r"v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)\Z")


def _read_volume_script() -> str:
    """List marker and collection files. The marker name is the only interpolation."""
    marker = MARKER_NAME
    return f"""
set -eu
root=/qdrant/storage
if [ -f "$root/{marker}" ]; then
  printf 'MARKER\\n'
  cat "$root/{marker}"
  printf '\\nENDMARKER\\n'
fi
if [ ! -d "$root/collections" ]; then
  printf 'EMPTY\\n'
  exit 0
fi
find "$root/collections" -type f \\( -name segment.json -o -name config.json -o -name version.info \\) -print 2>/dev/null |
  head -n 40 |
  while IFS= read -r f; do
    printf 'FILE %s\\n' "$f"
    cat "$f"
    printf '\\nENDFILE\\n'
  done
"""


class InventoryUnreadable(Exception):
    """The inventory file exists and cannot be used as the target pin."""

    def __init__(self, path: Path, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"{path}: {reason}")


class DockerUnavailable(Exception):
    """The daemon could not be asked what volume is already there."""


@dataclass
class StorageScan:
    """What a storage directory itself says, independent of any image tag."""

    state: str
    marker: str | None
    legacy_on_disk: bool
    detail: str


@dataclass
class Observation:
    """The installed version of one existing volume, and where it came from."""

    volume_state: str
    version: str | None
    source: str
    legacy_on_disk: bool
    detail: str
    storage_path: Path | None = None
    docker: list[str] | None = None
    container_id: str | None = None
    volume_name: str | None = None
    image_ref: str | None = None


def _minor(tag: str) -> int | None:
    match = re.match(r"v?(\d+)\.(\d+)", tag.lstrip("v"))
    return int(match.group(2)) if match else None


def _major(tag: str) -> int | None:
    match = re.match(r"v?(\d+)\.", tag.lstrip("v"))
    return int(match.group(1)) if match else None


def normalize_version(text: str | None) -> str | None:
    """An application release, or None.

    Crate ``version.info`` values (``0.4.2``, ``0.6.0``) match the shape of a
    semver and are the same on every release this tree cares about, so a
    major of 0 is not a Qdrant version.
    """
    if text is None:
        return None
    match = _APP_VERSION.fullmatch(text.strip())
    if not match or int(match.group("major")) < 1:
        return None
    return f"v{match.group('major')}.{match.group('minor')}.{match.group('patch')}"


def version_from_image_ref(image: str | None) -> str | None:
    """``qdrant/qdrant:v1.7.0`` → ``v1.7.0``. A floating tag is not a version."""
    if not image or ":" not in image:
        return None
    tag = image.split("@", 1)[0].rsplit(":", 1)[1]
    return normalize_version(tag)


def decide_jump(storage: str | None, target: str) -> tuple[bool, list[str], list[str]]:
    """Whether ``storage`` may be attached in place to ``target``.

    ``storage`` is the version that wrote the volume. Missing means the
    volume's version was not observed; that is NO-GO, not a permission to
    assume the compose pin.
    """
    if not storage:
        return (
            False,
            ["Installed Qdrant version is unknown, so the existing volume cannot be attached in place."],
            ["Observe the Qdrant that has the volume open, then rerun this preflight."],
        )
    blocked_reasons: list[str] = []
    required_steps: list[str] = []
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
    return allow_in_place, blocked_reasons, required_steps


def legacy_on_disk_blocks(target: str, legacy: bool) -> str | None:
    """v1.20 rejects the ``on_disk`` payload variant v1.7 wrote into segment.json."""
    if not legacy:
        return None
    major, minor = _major(target), _minor(target)
    if major == 1 and minor is not None and minor >= 20:
        return "Segment payload storage on this volume is on_disk, which v1.20.x cannot load."
    return None


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
    from_pins: str | None = None
    pins = data.get("datastore_pins")
    if pins is not None:
        if not isinstance(pins, dict):
            raise InventoryUnreadable(path, "datastore_pins must be an object")
        pin = pins.get("qdrant/qdrant")
        if isinstance(pin, str) and pin.strip():
            from_pins = pin.strip()
    from_rows: str | None = None
    rows = data.get("infrastructure", [])
    if not isinstance(rows, list):
        raise InventoryUnreadable(path, "infrastructure must be a list")
    for row in rows:
        if isinstance(row, dict) and row.get("component") == "Qdrant":
            pin = row.get("pin")
            if isinstance(pin, str) and pin.strip():
                from_rows = pin.strip()
                break
    if from_pins and from_rows and normalize_version(from_pins) != normalize_version(from_rows) and from_pins != from_rows:
        raise InventoryUnreadable(path, "datastore_pins and infrastructure disagree on Qdrant")
    return from_pins or from_rows or default


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


def _segment_is_legacy(doc: object) -> bool:
    if not isinstance(doc, dict):
        return False
    config = doc.get("config")
    if not isinstance(config, dict):
        return False
    payload = config.get("payload_storage_type")
    return isinstance(payload, dict) and payload.get("type") == "on_disk"


def _read_marker(path: Path) -> str | None:
    marker = path / MARKER_NAME
    try:
        if not marker.is_file():
            return None
        return normalize_version(marker.read_text(encoding="utf-8"))
    except OSError:
        return None


def scan_storage(path: Path) -> StorageScan:
    """Read one storage directory. Crate ``version.info`` is not a release."""
    try:
        if not path.exists():
            return StorageScan("unreadable", None, False, f"{path} does not exist")
        if not path.is_dir():
            return StorageScan("unreadable", None, False, f"{path} is not a directory")
    except OSError as exc:
        return StorageScan("unreadable", None, False, str(exc))
    marker = _read_marker(path)
    collections = path / "collections"
    try:
        if not collections.is_dir():
            return StorageScan("empty", marker, False, "no collections directory")
        configs = list(collections.glob("*/config.json"))
        segments = list(collections.glob("*/*/segments/*/segment.json"))[:40]
    except OSError as exc:
        return StorageScan("unreadable", marker, False, str(exc))
    legacy = False
    for segment in segments:
        try:
            legacy = legacy or _segment_is_legacy(json.loads(segment.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    if configs or segments:
        return StorageScan("present", marker, legacy, f"{len(configs)} collection config(s)")
    try:
        has_child = any(collections.iterdir())
    except OSError as exc:
        return StorageScan("unreadable", marker, False, str(exc))
    if has_child:
        return StorageScan("present", marker, legacy, "collection directory without a readable config")
    return StorageScan("empty", marker, False, "collections directory is empty")


def parse_volume_listing(text: str) -> StorageScan:
    """Parse the fixed listing produced inside a volume mount."""
    marker: str | None = None
    if "MARKER\n" in text and "\nENDMARKER\n" in text:
        raw = text.split("MARKER\n", 1)[1].split("\nENDMARKER\n", 1)[0]
        marker = normalize_version(raw)
    if "EMPTY\n" in text and "FILE " not in text:
        return StorageScan("empty", marker, False, "volume has no collections directory")
    legacy = False
    present = False
    chunks = text.split("FILE ")
    for chunk in chunks[1:]:
        body = chunk.split("\n", 1)[1] if "\n" in chunk else ""
        body = body.split("\nENDFILE\n", 1)[0]
        name = chunk.split("\n", 1)[0]
        if name.endswith("config.json") or name.endswith("version.info"):
            present = True
        if name.endswith("segment.json"):
            present = True
            try:
                legacy = legacy or _segment_is_legacy(json.loads(body))
            except json.JSONDecodeError:
                continue
    if present:
        return StorageScan("present", marker, legacy, "listed from the volume")
    return StorageScan("empty", marker, False, "no collection files in the volume")


def version_from_api_payload(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return None
    version = payload.get("version")
    if not isinstance(version, str):
        return None
    return normalize_version(version)


def read_api_version(base_url: str, timeout: float = 3) -> str | None:
    """``GET /`` on the Qdrant that has the volume open. Failure is unknown."""
    url = base_url.rstrip("/") + "/"
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, urllib.error.URLError):
        return None
    return version_from_api_payload(payload)


def trusted_image_version(
    image: str | None,
    *,
    running: bool,
    exit_code: int | None,
    target: str,
) -> str | None:
    """The container image is the installed version only while it still is.

    A container already recreated onto the target tag that then exited
    non-zero is how a refused jump looks after the fact. Its image tag is
    the target, not the version that wrote the volume.
    """
    version = version_from_image_ref(image)
    if version is None:
        return None
    if running:
        return version
    target_version = normalize_version(target) or (target if target.startswith("v") else None)
    if version == target_version and exit_code not in (0, None):
        return None
    return version


def pick_version(
    *,
    api: str | None,
    image: str | None,
    explicit: str | None,
    marker: str | None,
) -> tuple[str | None, str]:
    """First source that actually observed a release. The compose pin is not one."""
    if api:
        return api, "api"
    if image:
        return image, "container-image"
    if explicit:
        return explicit, "explicit"
    if marker:
        return marker, "storage-marker"
    return None, "unknown"


def write_marker(path: Path, version: str) -> None:
    normalized = normalize_version(version)
    if normalized is None:
        raise ValueError(f"refusing to record {version!r}")
    target = path / MARKER_NAME
    temporary = path / f".{MARKER_NAME}.tmp"
    temporary.write_text(normalized + "\n", encoding="utf-8")
    temporary.replace(target)


def build_report(
    *,
    compose_pin: str | None,
    target: str,
    observation: Observation,
    error: str | None = None,
) -> dict[str, object]:
    blocked_reasons: list[str] = []
    required_steps: list[str] = []
    if error:
        allow = False
        blocked_reasons.append(error)
    elif observation.volume_state in {"absent", "empty"}:
        allow = True
    elif observation.volume_state == "unreadable" or not observation.version:
        allow = False
        blocked_reasons.append(
            "Installed Qdrant version is unknown. The compose pin is the target image, "
            "not the version of the existing volume, so it is not used."
        )
        required_steps.append(
            "Leave the current Qdrant container in place and rerun this preflight so it "
            "can read that process, or restore a volume that already carries "
            f"{MARKER_NAME}."
        )
    else:
        allow, blocked_reasons, required_steps = decide_jump(observation.version, target)
    legacy = legacy_on_disk_blocks(target, observation.legacy_on_disk)
    if legacy and observation.volume_state == "present":
        allow = False
        blocked_reasons = [legacy, *blocked_reasons]
        required_steps.append("Do not mount this volume on qdrant/qdrant:v1.20.x.")
    ok = allow and not blocked_reasons and error is None
    report: dict[str, object] = {
        "ok": ok,
        "compose_qdrant_pin": compose_pin,
        "target_image": target,
        "storage_version_observed": observation.version,
        "storage_version_source": observation.source if observation.version else observation.source,
        "volume_state": observation.volume_state,
        "legacy_on_disk_payload": observation.legacy_on_disk,
        "allow_in_place_volume_attach": allow,
        "blocked_reasons": blocked_reasons,
        "required_steps": required_steps,
        "evidence_script": "scripts/qdrant_migration_evidence.sh",
        "detail": observation.detail,
        "no_go_examples": [
            "Mount v1.7 data directory on qdrant/qdrant:v1.20.0",
            "Upload snapshot created on v1.7.x directly to v1.20.x",
        ],
    }
    if error:
        report["error"] = error
    return report


def _run(argv: list[str], *, cwd: Path | None = None, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def docker_argv() -> list[str]:
    """``docker`` if the daemon answers, else ``sudo -n docker``. Never prompts."""
    if shutil.which("docker"):
        try:
            probe = _run(["docker", "info"], timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DockerUnavailable(str(exc)) from exc
        if probe.returncode == 0:
            return ["docker"]
    if shutil.which("sudo"):
        try:
            probe = _run(["sudo", "-n", "docker", "info"], timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DockerUnavailable(str(exc)) from exc
        if probe.returncode == 0:
            return ["sudo", "-n", "docker"]
    raise DockerUnavailable("docker is not available, so an existing qdrant_data volume cannot be read")


def _compose(docker: list[str], root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return _run([*docker, "compose", *args], cwd=root, timeout=30)


def _inspect_container(docker: list[str], container_id: str) -> dict[str, object] | None:
    try:
        proc = _run([*docker, "inspect", container_id], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return payload[0]
    return None


def _storage_mount(inspected: dict[str, object]) -> tuple[str, str] | None:
    mounts = inspected.get("Mounts")
    if not isinstance(mounts, list):
        return None
    for mount in mounts:
        if not isinstance(mount, dict) or mount.get("Destination") != STORAGE_MOUNT:
            continue
        if mount.get("Type") == "bind" and isinstance(mount.get("Source"), str):
            return ("bind", mount["Source"])
        if isinstance(mount.get("Name"), str):
            return ("volume", mount["Name"])
    return None


def _published_http(inspected: dict[str, object]) -> str | None:
    network = inspected.get("NetworkSettings")
    if not isinstance(network, dict):
        return None
    ports = network.get("Ports")
    if not isinstance(ports, dict):
        return None
    bindings = ports.get("6333/tcp")
    if not isinstance(bindings, list) or not bindings:
        return None
    first = bindings[0]
    if not isinstance(first, dict):
        return None
    host = first.get("HostIp") or "127.0.0.1"
    port = first.get("HostPort")
    if not isinstance(port, str) or not port:
        return None
    if host in {"0.0.0.0", "::", ""}:
        host = "127.0.0.1"
    return f"http://{host}:{port}"


def _container_facts(inspected: dict[str, object]) -> tuple[str | None, bool, int | None]:
    config = inspected.get("Config")
    image = config.get("Image") if isinstance(config, dict) else None
    image_ref = image if isinstance(image, str) else None
    state = inspected.get("State")
    running = isinstance(state, dict) and state.get("Status") == "running"
    exit_code: int | None = None
    if isinstance(state, dict) and isinstance(state.get("ExitCode"), int):
        exit_code = state["ExitCode"]
    return image_ref, running, exit_code


def _find_container_id(docker: list[str], root: Path) -> str | None:
    try:
        proc = _compose(docker, root, "ps", "-aq", "qdrant")
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return lines[-1] if lines else None


def _find_named_volume(docker: list[str], root: Path) -> str | None:
    try:
        proc = _run(
            [*docker, "volume", "ls", "--filter", "label=com.docker.compose.volume=qdrant_data", "--format", "{{.Name}}"],
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    root_resolved = str(root.resolve())
    for name in [line.strip() for line in proc.stdout.splitlines() if line.strip()]:
        try:
            inspected = _run([*docker, "volume", "inspect", name], timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if inspected.returncode != 0:
            continue
        try:
            payload = json.loads(inspected.stdout)
        except json.JSONDecodeError:
            continue
        if not payload or not isinstance(payload[0], dict):
            continue
        labels = payload[0].get("Labels") or {}
        if not isinstance(labels, dict):
            continue
        working = labels.get("com.docker.compose.project.working_dir")
        if isinstance(working, str) and str(Path(working).resolve()) == root_resolved:
            return name
    return None


def _run_in_volume(
    docker: list[str],
    image: str,
    volume: str,
    *,
    read_only: bool,
    script: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str] | None:
    mount = f"{volume}:{STORAGE_MOUNT}" + (":ro" if read_only else "")
    argv = [*docker, "run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", "-v", mount]
    for key, value in (env or {}).items():
        argv.extend(["-e", f"{key}={value}"])
    argv.extend([image, "-c", script])
    try:
        return _run(argv, timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _listing_from_mount(docker: list[str], image: str, volume: str) -> StorageScan | None:
    proc = _run_in_volume(docker, image, volume, read_only=True, script=_read_volume_script())
    if proc is None or proc.returncode != 0:
        return None
    return parse_volume_listing(proc.stdout)


def _write_marker_in_volume(docker: list[str], image: str, volume: str, version: str) -> bool:
    normalized = normalize_version(version)
    if normalized is None:
        return False
    script = f"printf '%s\\n' \"$AISOC_QDRANT_VERSION\" > {STORAGE_MOUNT}/{MARKER_NAME}\n"
    proc = _run_in_volume(
        docker,
        image,
        volume,
        read_only=False,
        script=script,
        env={"AISOC_QDRANT_VERSION": normalized},
    )
    return proc is not None and proc.returncode == 0


def _write_marker_exec(docker: list[str], container_id: str, version: str) -> bool:
    normalized = normalize_version(version)
    if normalized is None:
        return False
    script = f"printf '%s\\n' \"$AISOC_QDRANT_VERSION\" > {STORAGE_MOUNT}/{MARKER_NAME}"
    try:
        proc = _run(
            [*docker, "exec", "-e", f"AISOC_QDRANT_VERSION={normalized}", container_id, "/bin/sh", "-c", script],
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def persist_observation(observation: Observation, version: str) -> bool:
    """Record a version we actually observed into the volume itself.

    A running container is written with ``exec``. A second mount of a volume
    qdrant already has open is not used.
    """
    if observation.storage_path is not None:
        try:
            write_marker(observation.storage_path, version)
        except (OSError, ValueError):
            return False
        return True
    if observation.docker and observation.container_id and _write_marker_exec(observation.docker, observation.container_id, version):
        return True
    if observation.docker and observation.container_id:
        # exec failed because the container is stopped, or has no shell.
        # Fall through to a one-shot mount only when nothing is running it.
        return False if _container_is_running(observation.docker, observation.container_id) else _write_named(observation, version)
    return _write_named(observation, version)


def _container_is_running(docker: list[str], container_id: str) -> bool:
    inspected = _inspect_container(docker, container_id)
    if inspected is None:
        return False
    _image, running, _code = _container_facts(inspected)
    return running


def _write_named(observation: Observation, version: str) -> bool:
    if observation.docker and observation.volume_name and observation.image_ref:
        return _write_marker_in_volume(observation.docker, observation.image_ref, observation.volume_name, version)
    return False


def observe_storage_path(path: Path, *, url: str | None, explicit: str | None) -> Observation:
    scan = scan_storage(path)
    api = read_api_version(url) if url else None
    version, source = pick_version(api=api, image=None, explicit=normalize_version(explicit), marker=scan.marker)
    storage_path = path if path.is_dir() else None
    if scan.state != "present":
        return Observation(
            volume_state=scan.state,
            version=None,
            source="none" if scan.state in {"empty", "absent"} else "unknown",
            legacy_on_disk=scan.legacy_on_disk,
            detail=scan.detail,
            storage_path=storage_path,
        )
    if version is None:
        source = "unknown"
    return Observation(
        volume_state="present",
        version=version,
        source=source,
        legacy_on_disk=scan.legacy_on_disk,
        detail=scan.detail,
        storage_path=storage_path,
    )


def observe_deployment(root: Path, target: str) -> Observation:
    """The volume Compose would recreate, read without starting the new image's server."""
    try:
        docker = docker_argv()
    except DockerUnavailable as exc:
        return Observation("unreadable", None, "unknown", False, str(exc))
    container_id = _find_container_id(docker, root)
    reader_image = f"qdrant/qdrant:{target}"
    if container_id:
        inspected = _inspect_container(docker, container_id)
        if inspected is None:
            return Observation(
                "unreadable",
                None,
                "unknown",
                False,
                f"cannot inspect container {container_id}",
                docker=docker,
                container_id=container_id,
            )
        image_ref, running, exit_code = _container_facts(inspected)
        image_version = trusted_image_version(image_ref, running=running, exit_code=exit_code, target=target)
        api = read_api_version(_published_http(inspected) or "") if running and _published_http(inspected) else None
        mount = _storage_mount(inspected)
        scan = StorageScan("unreadable", None, False, "storage mount was not inspected")
        storage_path: Path | None = None
        volume_name: str | None = None
        if mount and mount[0] == "bind":
            storage_path = Path(mount[1])
            scan = scan_storage(storage_path)
        elif mount and mount[0] == "volume":
            volume_name = mount[1]
            listed = _listing_from_mount(docker, image_ref or reader_image, volume_name)
            scan = listed if listed is not None else StorageScan("unreadable", None, False, "volume listing failed")
        version, source = pick_version(api=api, image=image_version, explicit=None, marker=scan.marker)
        state = scan.state
        if state == "unreadable" and (api or image_version):
            # The process answered, or the container image is still the old
            # one. Not being able to list files is not the same as an empty
            # volume: collections are assumed present so a failed listing
            # cannot turn into GO.
            state = "present"
            if version is None:
                source = "unknown"
        if state == "present" and version is None:
            source = "unknown"
        return Observation(
            volume_state=state,
            version=version,
            source=source if state == "present" else "none",
            legacy_on_disk=scan.legacy_on_disk,
            detail=scan.detail,
            storage_path=storage_path,
            docker=docker,
            container_id=container_id,
            volume_name=volume_name,
            image_ref=image_ref or reader_image,
        )
    volume_name = _find_named_volume(docker, root)
    if volume_name is None:
        return Observation("absent", None, "none", False, "no qdrant container and no qdrant_data volume", docker=docker)
    listed = _listing_from_mount(docker, reader_image, volume_name)
    if listed is None:
        return Observation(
            "unreadable",
            None,
            "unknown",
            False,
            f"volume {volume_name} exists but could not be listed",
            docker=docker,
            volume_name=volume_name,
            image_ref=reader_image,
        )
    version, source = pick_version(api=None, image=None, explicit=None, marker=listed.marker)
    if listed.state == "present" and version is None:
        source = "unknown"
    return Observation(
        volume_state=listed.state,
        version=version,
        source=source if listed.state == "present" else "none",
        legacy_on_disk=listed.legacy_on_disk,
        detail=listed.detail,
        docker=docker,
        volume_name=volume_name,
        image_ref=reader_image,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--storage",
        "--storage-dir",
        default=None,
        dest="storage",
        help="Existing Qdrant storage directory (the volume mounted at /qdrant/storage).",
    )
    parser.add_argument("--url", default=None, help="Base URL of the Qdrant process that has that storage open.")
    parser.add_argument(
        "--storage-version",
        default=None,
        help="Explicit observed release. Not a default: omitting it never substitutes the compose pin.",
    )
    parser.add_argument("--target", default=None, help="Target image tag (default: the inventory pin).")
    parser.add_argument(
        "--record-only",
        action="store_true",
        help="Write the observed version into the volume and exit 0. make down uses this before it removes the container.",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    error: str | None = None
    compose_pin: str | None = None
    default_target = "v1.20.0"
    try:
        compose_pin, default_target = _infer_versions(root)
    except InventoryUnreadable as exc:
        error = str(exc)
    target = args.target or default_target or "v1.20.0"
    if args.storage:
        observation = observe_storage_path(Path(args.storage), url=args.url, explicit=args.storage_version)
    elif args.url or args.storage_version:
        stated = normalize_version(args.storage_version)
        api = read_api_version(args.url) if args.url else None
        version, source = pick_version(api=api, image=None, explicit=stated, marker=None)
        state = "present" if version else "unreadable"
        observation = Observation(state, version, source if version else "unknown", False, "no storage directory was passed")
    else:
        observation = observe_deployment(root, target)
    # Only a version we measured is written back. An explicit flag must not
    # stamp the volume, or a wrong --storage-version becomes the next run's
    # evidence.
    if observation.version and observation.volume_state == "present" and observation.source in {"api", "container-image"}:
        persist_observation(observation, observation.version)
    report = build_report(compose_pin=compose_pin, target=target, observation=observation, error=error)
    if args.record_only:
        report["recorded"] = bool(observation.version)
        print(json.dumps(report, indent=2))
        return 0
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
    unknown, unknown_reasons, _steps = decide_jump(None, "v1.20.0")
    if unknown or not unknown_reasons:
        errors.append("an unknown installed version must be a NO-GO, not the compose pin")
    if normalize_version("0.4.2") is not None or normalize_version("0.6.0") is not None:
        errors.append("crate version.info values were treated as Qdrant releases")

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

        storage = Path(tmp) / "storage"
        collection = storage / "collections" / "probe"
        segment = collection / "0" / "segments" / "abc"
        segment.mkdir(parents=True)
        (collection / "version.info").write_text("0.4.2", encoding="utf-8")
        (collection / "config.json").write_text("{}", encoding="utf-8")
        (segment / "segment.json").write_text(
            json.dumps({"config": {"payload_storage_type": {"type": "on_disk"}, "vector_data": {"": {"storage_type": "Memory"}}}}),
            encoding="utf-8",
        )
        scanned = scan_storage(storage)
        if scanned.state != "present" or scanned.marker is not None or not scanned.legacy_on_disk:
            errors.append(f"v1.7-shaped storage scanned as {scanned}")
        report = build_report(
            compose_pin="v1.20.0",
            target="v1.20.0",
            observation=Observation("present", None, "unknown", scanned.legacy_on_disk, scanned.detail),
        )
        if report["ok"] or report["storage_version_observed"] == "v1.20.0":
            errors.append("missing storage version fell back to the compose pin")
        write_marker(storage, "v1.19.0")
        marked = scan_storage(storage)
        if marked.marker != "v1.19.0":
            errors.append(f"marker read back as {marked.marker}")
        allowed = build_report(
            compose_pin="v1.20.0",
            target="v1.20.0",
            observation=Observation("present", marked.marker, "storage-marker", False, "marker"),
        )
        if not allowed["ok"]:
            errors.append("a stored v1.19.0 marker was refused for v1.20.0")
        if trusted_image_version("qdrant/qdrant:v1.20.0", running=False, exit_code=101, target="v1.20.0") is not None:
            errors.append("a crashed target image was trusted as the installed version")
        if trusted_image_version("qdrant/qdrant:v1.7.0", running=False, exit_code=0, target="v1.20.0") != "v1.7.0":
            errors.append("a stopped v1.7 container was not trusted")

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

"""Registry-host checks and the Qdrant preflight's unreadable-inventory path."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import check_qdrant_upgrade_preflight as preflight
import generate_dependency_inventory as inventory


@pytest.mark.parametrize(
    ("ref", "host"),
    [
        ("ghcr.io/beenuar/aisoc:latest", "ghcr.io"),
        ("mcr.microsoft.com/oss/nginx:1.27", "mcr.microsoft.com"),
        ("sub.ghcr.io/org/name:1", "sub.ghcr.io"),
        ("redis:7-alpine", None),
        ("library/redis:7", None),
        ("public.ecr.aws/docker/library/postgres:16", "public.ecr.aws"),
    ],
)
def test_image_registry_host(ref: str, host: str | None) -> None:
    assert inventory.image_registry_host(ref) == host


def test_substring_lookalikes_are_not_the_unmanaged_registries() -> None:
    """CodeQL's finding: the registry text may sit anywhere in the reference."""
    assert inventory._unmanaged_registry("ghcr.io/org/qdrant:v1.20.0")
    assert inventory._unmanaged_registry("mcr.microsoft.com/oss/nginx:1")
    assert inventory._unmanaged_registry("team.mcr.microsoft.com/oss/nginx:1")
    assert not inventory._unmanaged_registry("notghcr.io/qdrant/qdrant:v1.7.0")
    assert not inventory._unmanaged_registry("ghcr.io.attacker.example/qdrant:v1.7.0")
    assert not inventory._unmanaged_registry("mcr.microsoft.com.attacker.example/library/x:1")
    assert not inventory._unmanaged_registry("docker.io/library/redis:7")


def test_direct_qdrant_jump_is_refused_and_one_minor_is_not() -> None:
    allow, reasons, _steps = preflight.decide_jump("v1.7.0", "v1.20.0")
    assert allow is False
    assert reasons
    allow, reasons, _steps = preflight.decide_jump("v1.19.0", "v1.20.0")
    assert allow is True
    assert reasons == []


def test_invalid_inventory_json_is_a_failed_preflight(tmp_path: Path) -> None:
    path = tmp_path / "dependency-inventory.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(preflight.InventoryUnreadable, match="not valid JSON"):
        preflight.target_from_inventory(path, "v1.20.0")


def test_preflight_reports_a_missing_compose(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_REPO_ROOT", str(tmp_path))
    # repo_root() reads the env at call time. main() prints JSON and exits 1.
    assert preflight.main([]) == 1


def test_valid_inventory_pin_is_used(tmp_path: Path) -> None:
    path = tmp_path / "dependency-inventory.json"
    path.write_text(
        json.dumps({"infrastructure": [{"component": "Qdrant", "pin": "v1.19.4"}]}),
        encoding="utf-8",
    )
    assert preflight.target_from_inventory(path, "v1.20.0") == "v1.19.4"


def test_datastore_pins_qdrant_tag_is_the_inventory_pin(tmp_path: Path) -> None:
    path = tmp_path / "dependency-inventory.json"
    path.write_text(json.dumps({"datastore_pins": {"qdrant/qdrant": "v1.19.4"}}), encoding="utf-8")
    assert preflight.qdrant_pin_from_inventory(path) == "v1.19.4"


FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "qdrant"


def _report(argv: list[str]) -> tuple[int, dict[str, object]]:
    code, report = preflight._capture_main(argv)
    return code, report


def test_fixture_v17_volume_is_no_go() -> None:
    """The committed v1.7 tree is what CI refuses. The version comes from version.info."""
    code, report = _report(["--storage-dir", str(FIXTURES / "v1.7.0"), "--target", "v1.20.0"])
    assert code == 1
    assert report["decision"] == "NO-GO"
    assert report["storage_version_observed"] == "1.7.0"
    assert report["volume_state"] == "observed"
    assert report["compose_qdrant_pin"] != report["storage_version_observed"]


def test_fixture_v19_volume_is_go() -> None:
    code, report = _report(["--storage-dir", str(FIXTURES / "v1.19.0"), "--target", "v1.20.0"])
    assert code == 0
    assert report["decision"] == "GO"
    assert report["storage_version_observed"] == "1.19.0"
    assert report["allow_in_place_volume_attach"] is True


def test_fixture_unknown_volume_is_no_go() -> None:
    """Payload without version.info is not the Compose pin."""
    code, report = _report(["--storage-dir", str(FIXTURES / "unknown"), "--target", "v1.20.0"])
    assert code == 1
    assert report["decision"] == "NO-GO"
    assert report["volume_state"] == "unknown"
    assert report["storage_version_observed"] is None
    assert report["storage_version_observed"] != report["compose_qdrant_pin"]


def test_omitted_storage_does_not_borrow_the_compose_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    """The defect: no --storage-version made the Compose pin look like the installed version."""
    monkeypatch.setattr(
        preflight,
        "discover_compose_volume",
        lambda root, runner=None: preflight.StorageObservation(
            state="unknown",
            version=None,
            versions=(),
            detail="volume was not inspected",
            source="volume",
        ),
    )
    code, report = _report([])
    assert code == 1
    assert report["decision"] == "NO-GO"
    assert report["compose_qdrant_pin"] == "v1.20.0"
    assert report["storage_version_observed"] is None
    assert report["target_image"] == "v1.20.0"


def test_absent_volume_is_go_without_inventing_a_stored_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        preflight,
        "discover_compose_volume",
        lambda root, runner=None: preflight.StorageObservation(
            state="absent",
            version=None,
            versions=(),
            detail="docker volume aisoc_qdrant_data does not exist",
            source="volume",
        ),
    )
    code, report = _report([])
    assert code == 0
    assert report["decision"] == "GO"
    assert report["volume_state"] == "absent"
    assert report["storage_version_observed"] is None


def test_storage_version_flag_alone_is_not_a_volume_read() -> None:
    code, report = _report(["--storage-version", "v1.20.0", "--target", "v1.20.0"])
    assert code == 1
    assert report["storage_version_observed"] is None
    assert report["decision"] == "NO-GO"


def test_storage_version_flag_cannot_override_a_read_version(tmp_path: Path) -> None:
    collection = tmp_path / "collections" / "mig_probe"
    collection.mkdir(parents=True)
    (collection / "version.info").write_text("1.7.0", encoding="utf-8")
    code, report = _report(["--storage-dir", str(tmp_path), "--storage-version", "v1.20.0", "--target", "v1.20.0"])
    assert code == 1
    assert report["storage_version_observed"] == "1.7.0"
    assert report["decision"] == "NO-GO"


def test_oldest_collection_version_decides(tmp_path: Path) -> None:
    for name, version in (("newer", "1.19.0"), ("older", "1.7.0")):
        path = tmp_path / "collections" / name
        path.mkdir(parents=True)
        (path / "version.info").write_text(version, encoding="utf-8")
    code, report = _report(["--storage-dir", str(tmp_path), "--target", "v1.20.0"])
    assert code == 1
    assert report["storage_version_observed"] == "1.7.0"


def test_raft_without_a_collection_is_not_an_old_volume(tmp_path: Path) -> None:
    """Qdrant writes raft_state.json before any collection. That must not block the next start."""
    (tmp_path / "raft_state.json").write_text("{}", encoding="utf-8")
    code, report = _report(["--storage-dir", str(tmp_path), "--target", "v1.20.0"])
    assert code == 0
    assert report["volume_state"] == "no-collections"
    assert report["storage_version_observed"] is None
    assert report["decision"] == "GO"


def test_empty_storage_directory_is_not_an_old_volume(tmp_path: Path) -> None:
    empty = tmp_path / "storage"
    empty.mkdir()
    code, report = _report(["--storage-dir", str(empty), "--target", "v1.20.0"])
    assert code == 0
    assert report["volume_state"] == "empty"
    assert report["storage_version_observed"] is None


def test_missing_storage_dir_is_unknown(tmp_path: Path) -> None:
    code, report = _report(["--storage-dir", str(tmp_path / "missing"), "--target", "v1.20.0"])
    assert code == 1
    assert report["volume_state"] == "unknown"
    assert report["decision"] == "NO-GO"


def test_reader_container_does_not_start_qdrant() -> None:
    argv = preflight.reader_argv("aisoc_qdrant_data", "qdrant/qdrant:v1.20.0")
    assert argv[argv.index("--entrypoint") + 1] == "/bin/sh"
    assert "--read-only" in argv
    assert "aisoc_qdrant_data:/qdrant/storage:ro" in argv
    image_at = argv.index("qdrant/qdrant:v1.20.0")
    assert argv[image_at + 1] == "-c"
    assert "./qdrant" not in argv


def test_unreadable_mount_is_copied_without_starting_qdrant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mount = tmp_path / "mount"
    mount.mkdir()
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        if list(argv[:3]) == ["docker", "compose", "config"]:
            payload = {"volumes": {"qdrant_data": {"name": "aisoc_qdrant_data"}}}
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")
        if list(argv[:3]) == ["docker", "volume", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout=f"{mount}\n", stderr="")
        if list(argv[:3]) == ["docker", "image", "ls"]:
            return subprocess.CompletedProcess(argv, 0, stdout="postgres:16-alpine\n", stderr="")
        if list(argv[:2]) == ["docker", "run"]:
            return subprocess.CompletedProcess(argv, 0, stdout="VERSION collections/mig_probe 1.7.0\n", stderr="")
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="unexpected")

    monkeypatch.setattr(preflight.os, "access", lambda _path, _mode: False)
    observed = preflight.discover_compose_volume(tmp_path, runner)
    assert observed.state == "observed"
    assert observed.version == "1.7.0"
    assert observed.source == "volume-copy"
    run_argv = next(argv for argv in calls if argv[:2] == ["docker", "run"])
    assert run_argv[run_argv.index("--entrypoint") + 1] == "/bin/sh"
    assert "aisoc_qdrant_data:/qdrant/storage:ro" in run_argv
    assert run_argv[run_argv.index("postgres:16-alpine") + 1] == "-c"


def test_missing_docker_volume_is_absent_not_the_compose_pin(tmp_path: Path) -> None:
    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        if list(argv[:3]) == ["docker", "compose", "config"]:
            payload = {"volumes": {"qdrant_data": {"name": "aisoc_qdrant_data"}}}
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")
        if list(argv[:3]) == ["docker", "volume", "inspect"]:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="Error: No such volume: aisoc_qdrant_data\n")
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="unexpected")

    observed = preflight.discover_compose_volume(tmp_path, runner)
    assert observed.state == "absent"
    assert observed.version is None


def test_rehearsal_does_not_start_v120_on_the_v17_directory() -> None:
    text = (Path(__file__).resolve().parents[1] / "upgrade_rehearsal_disposable.sh").read_text(encoding="utf-8")
    preflight_at = text.index("check_qdrant_upgrade_preflight.py")
    assert "qdrant/qdrant:v1.20.0" not in text[preflight_at:]
    assert "--storage-dir" in text
    assert text.index("--storage-dir") > text.index("qdrant/qdrant:v1.7.0")

"""Registry-host checks and the Qdrant preflight's volume version."""

from __future__ import annotations

import io
import json
import sys
import threading
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import check_qdrant_upgrade_preflight as preflight
import generate_dependency_inventory as inventory

ROOT = Path(__file__).resolve().parents[2]


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


def test_datastore_pins_supply_the_qdrant_target(tmp_path: Path) -> None:
    path = tmp_path / "dependency-inventory.json"
    path.write_text(json.dumps({"datastore_pins": {"qdrant/qdrant": "v1.19.4"}}), encoding="utf-8")
    assert preflight.target_from_inventory(path, "v1.20.0") == "v1.19.4"


def test_unknown_installed_version_is_not_a_go() -> None:
    allow, reasons, _steps = preflight.decide_jump(None, "v1.20.0")
    assert allow is False
    assert reasons
    assert preflight.normalize_version("0.4.2") is None
    assert preflight.normalize_version("0.6.0") is None


def _compose_tree(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  qdrant:\n    image: qdrant/qdrant:v1.20.0\n",
        encoding="utf-8",
    )


def _v17_storage(path: Path) -> None:
    """The files a v1.7.0 process writes. version.info is the crate, not 1.7.0."""
    collection = path / "collections" / "probe"
    segment = collection / "0" / "segments" / "abc"
    segment.mkdir(parents=True)
    (collection / "version.info").write_text("0.4.2", encoding="utf-8")
    (collection / "config.json").write_text("{}", encoding="utf-8")
    (segment / "segment.json").write_text(
        json.dumps({"config": {"payload_storage_type": {"type": "on_disk"}}}),
        encoding="utf-8",
    )


def _run(argv: list[str]) -> tuple[int, dict[str, object]]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = preflight.main(argv)
    return code, json.loads(buf.getvalue())


def test_v17_shaped_storage_is_not_the_compose_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _compose_tree(tmp_path)
    storage = tmp_path / "qdrant_data"
    _v17_storage(storage)
    monkeypatch.setenv("AISOC_REPO_ROOT", str(tmp_path))
    code, report = _run(["--storage", str(storage)])
    assert code == 1
    assert report["ok"] is False
    assert report["compose_qdrant_pin"] == "v1.20.0"
    assert report["storage_version_observed"] is None
    assert report["storage_version_source"] == "unknown"
    assert report["legacy_on_disk_payload"] is True


class _VersionHandler(BaseHTTPRequestHandler):
    version = "1.7.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        body = json.dumps({"title": "qdrant - vector search engine", "version": type(self).version}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def test_api_version_is_recorded_and_reread_from_the_volume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _compose_tree(tmp_path)
    storage = tmp_path / "qdrant_data"
    _v17_storage(storage)
    monkeypatch.setenv("AISOC_REPO_ROOT", str(tmp_path))
    _VersionHandler.version = "1.7.0"
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VersionHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        code, report = _run(["--storage", str(storage), "--url", url])
    finally:
        server.shutdown()
        server.server_close()
    assert code == 1
    assert report["storage_version_observed"] == "v1.7.0"
    assert report["storage_version_source"] == "api"
    assert (storage / "aisoc-observed-version").read_text(encoding="utf-8").strip() == "v1.7.0"
    code, report = _run(["--storage", str(storage)])
    assert code == 1
    assert report["storage_version_observed"] == "v1.7.0"
    assert report["storage_version_source"] == "storage-marker"
    assert report["compose_qdrant_pin"] == "v1.20.0"


def test_explicit_version_cannot_hide_on_disk_segments(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _compose_tree(tmp_path)
    storage = tmp_path / "qdrant_data"
    _v17_storage(storage)
    monkeypatch.setenv("AISOC_REPO_ROOT", str(tmp_path))
    code, report = _run(["--storage", str(storage), "--storage-version", "v1.20.0"])
    assert code == 1
    assert report["ok"] is False
    assert report["legacy_on_disk_payload"] is True
    assert not (storage / "aisoc-observed-version").exists()


def test_consecutive_minor_marker_is_a_go(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _compose_tree(tmp_path)
    storage = tmp_path / "qdrant_data"
    collection = storage / "collections" / "probe"
    segment = collection / "0" / "segments" / "abc"
    segment.mkdir(parents=True)
    (collection / "config.json").write_text("{}", encoding="utf-8")
    (segment / "segment.json").write_text(
        json.dumps({"config": {"payload_storage_type": {"type": "mmap"}}}),
        encoding="utf-8",
    )
    (storage / "aisoc-observed-version").write_text("v1.19.0\n", encoding="utf-8")
    monkeypatch.setenv("AISOC_REPO_ROOT", str(tmp_path))
    code, report = _run(["--storage", str(storage)])
    assert code == 0
    assert report["ok"] is True
    assert report["storage_version_observed"] == "v1.19.0"
    assert report["storage_version_source"] == "storage-marker"


def test_windows_installer_runs_the_qdrant_preflight_before_compose_up() -> None:
    text = (ROOT / "install.ps1").read_text(encoding="utf-8-sig")
    preflight_at = text.index("check_qdrant_upgrade_preflight.py")
    compose_at = text.index("'up', '-d'")
    assert preflight_at < compose_at


def test_crashed_target_image_is_not_the_installed_version() -> None:
    assert preflight.trusted_image_version("qdrant/qdrant:v1.20.0", running=False, exit_code=101, target="v1.20.0") is None
    assert preflight.trusted_image_version("qdrant/qdrant:v1.7.0", running=False, exit_code=0, target="v1.20.0") == "v1.7.0"

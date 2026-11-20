"""Registry-host checks and the Qdrant preflight's unreadable-inventory path."""

from __future__ import annotations

import json
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

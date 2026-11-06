"""Offline checks of the actual image-verification shell and installed metadata.

Docker is replaced only at the process boundary: freeze, the verifier and
pip check run for real in an isolated interpreter with fixture distributions.
These tests do not claim to build or exercise service containers.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import venv
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/reproducible-builds.yml"
VERIFY = ROOT / "scripts/verify_runtime_requirements.py"


@pytest.fixture(scope="module")
def interpreter(tmp_path_factory):
    path = tmp_path_factory.mktemp("runtime-pip")
    venv.EnvBuilder(with_pip=True).create(path)
    return path / "bin/python"


def distribution(root, name, version, requires=()):
    metadata = root / f"{name.replace('-', '_')}-{version}.dist-info"
    metadata.mkdir(parents=True)
    fields = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    fields += [f"Requires-Dist: {item}" for item in requires]
    (metadata / "METADATA").write_text("\n".join(fields) + "\n")


@pytest.fixture
def runtime(tmp_path, interpreter):
    for build in ("first", "second"):
        for name, version in (("psycopg", "3.3.6"), ("psycopg-binary", "3.3.6"), ("typing-extensions", "4.16.0")):
            distribution(tmp_path / build, name, version)
    env = {**os.environ, "PYTHONPATH": str(tmp_path / "first"), "PIP_CONFIG_FILE": os.devnull}
    return tmp_path, interpreter, env


def run_verifier(runtime, text):
    path, python, env = runtime
    requirements = path / "expected.txt"
    requirements.write_text(text)
    return subprocess.run([str(python), str(VERIFY), str(requirements)], env=env, capture_output=True, text=True)


def test_self_test_and_required_input(runtime):
    _, python, env = runtime
    result = subprocess.run([str(python), str(VERIFY), "--self-test"], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    result = subprocess.run([str(python), str(VERIFY)], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "requirements file is required" in result.stderr


@pytest.mark.parametrize(
    ("requirements", "message"),
    [
        ("", "no applicable"),
        (" \n\t\n", "no applicable"),
        ('tzdata==2026.6 ; sys_platform == "win32"', "no applicable"),
        ("psycopg>=3.3.6", "one exact"),
        ("psycopg==3.3.*", "one exact"),
        ("psycopg==3.3.6,!=3.3.5", "one exact"),
        ("psycopg[binary]==3.3.6", "one exact"),
        ("psycopg @ file:///tmp/psycopg.whl", "one exact"),
        ("not a requirement", "invalid requirement"),
        ("absent==1.0", "missing installed"),
        ("psycopg==3.3.5", "installed 3.3.6"),
    ],
)
def test_rejects_incomplete_or_unpinned_expectations(runtime, requirements, message):
    result = run_verifier(runtime, requirements)
    assert result.returncode != 0
    assert message in result.stdout


def test_uses_image_markers_and_allows_unrelated_installed_packages(runtime):
    path, _, _ = runtime
    distribution(path / "first", "unrelated-base-package", "1.0")
    result = run_verifier(
        runtime,
        'psycopg==3.3.6\npsycopg-binary==3.3.6\ntyping_extensions==4.16.0\ntzdata==2026.6 ; sys_platform == "win32"\n',
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_local_version_is_not_the_locked_release(runtime):
    path, _, _ = runtime
    shutil.rmtree(path / "first" / "psycopg-3.3.6.dist-info")
    distribution(path / "first", "psycopg", "3.3.6+local")
    result = run_verifier(runtime, "psycopg==3.3.6")
    assert result.returncode != 0
    assert "installed 3.3.6+local" in result.stdout


def test_exact_prerelease_pin_passes(runtime):
    path, _, _ = runtime
    distribution(path / "first", "preview", "2.0rc1")
    result = run_verifier(runtime, "preview==2.0rc1")
    assert result.returncode == 0, result.stdout + result.stderr


def test_missing_package_is_not_satisfied_by_a_local_wheel(runtime):
    path, _, env = runtime
    wheels = path / "wheels"
    wheels.mkdir()
    # A valid local wheel would make an offline pip dry-run return success
    # with "Would install". Availability is not proof of installation.
    with zipfile.ZipFile(wheels / "absent-1.0-py3-none-any.whl", "w") as wheel:
        wheel.writestr("absent-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: absent\nVersion: 1.0\n")
        wheel.writestr("absent-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        wheel.writestr("absent-1.0.dist-info/RECORD", "")
    env["PIP_FIND_LINKS"] = str(wheels)
    available = subprocess.run(
        [str(runtime[1]), "-m", "pip", "install", "--dry-run", "--no-deps", "--no-index", "--no-cache-dir", "absent==1.0"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert available.returncode == 0, available.stderr
    assert "Would install absent-1.0" in available.stdout
    result = run_verifier(runtime, "absent==1.0")
    assert result.returncode != 0
    assert "missing installed" in result.stdout


DOCKER = """#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

args = sys.argv[1:]
assert args.pop(0) == "run"
assert args.pop(0) == "--rm"
mounts = {}
network = None
entrypoint = None
while args[0].startswith("--"):
    option = args.pop(0)
    value = args.pop(0)
    if option == "--entrypoint":
        entrypoint = value
    elif option == "--network":
        network = value
    elif option == "--mount":
        parts = dict(part.split("=", 1) for part in value.split(",") if "=" in part)
        assert value.endswith(",readonly")
        mounts[parts["dst"]] = parts["src"]
    else:
        raise AssertionError(option)
image = args.pop(0)
build = image.rsplit(":", 1)[1]
assert build in ("first", "second")
if args != ["freeze"]:
    assert network == "none"
with open(os.environ["DOCKER_CALLS"], "a") as output:
    output.write(json.dumps([build, entrypoint, args]) + "\\n")
if args == ["freeze"] and os.environ.get("EMPTY_FREEZE") == "1":
    raise SystemExit(0)
env = {**os.environ, "PYTHONPATH": str(Path(os.environ["FIXTURES"]) / build)}
command = [os.environ["RUNTIME_PYTHON"]]
if entrypoint == "pip":
    command += ["-m", "pip"]
else:
    assert entrypoint == "python"
command += [mounts.get(arg, arg) for arg in args]
raise SystemExit(subprocess.run(command, env=env).returncode)
"""


def run_workflow(runtime):
    path, python, env = runtime
    checkout = path / "checkout"
    checkout.mkdir()
    shutil.copytree(ROOT / "scripts", checkout / "scripts")
    shutil.copytree(ROOT / "services/escalations", checkout / "services/escalations")
    binaries = path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text(DOCKER)
    docker.chmod(0o755)
    workflow = yaml.safe_load(WORKFLOW.read_text())
    step = next(s for s in workflow["jobs"]["twice-all"]["steps"] if s.get("name") == "The two images must contain identical versions")
    env.update(
        {
            "PATH": str(binaries) + os.pathsep + env["PATH"],
            "RUNTIME_PYTHON": str(python),
            "FIXTURES": str(path),
            "DOCKER_CALLS": str(path / "calls.jsonl"),
            "GITHUB_STEP_SUMMARY": str(path / "summary.txt"),
            "AISOC_REPO_ROOT": str(checkout),
        }
    )
    result = subprocess.run(
        ["bash", "-c", step["run"].replace("${{ matrix.service }}", "escalations")],
        cwd=checkout,
        env=env,
        capture_output=True,
        text=True,
    )
    return result


def test_actual_workflow_accepts_small_complete_runtime(runtime):
    result = run_workflow(runtime)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [json.loads(line) for line in (runtime[0] / "calls.jsonl").read_text().splitlines()]
    for build in ("first", "second"):
        assert [build, "pip", ["check"]] in calls
        assert any(call[0] == build and call[1] == "python" for call in calls)


@pytest.mark.parametrize("missing", ["psycopg", "typing_extensions"])
def test_actual_workflow_rejects_same_missing_dependency_in_both_builds(runtime, missing):
    for build in ("first", "second"):
        for metadata in (runtime[0] / build).glob(f"{missing}-*.dist-info"):
            shutil.rmtree(metadata)
    result = run_workflow(runtime)
    assert result.returncode != 0
    assert "missing installed" in result.stdout


def test_actual_workflow_rejects_identical_wrong_versions(runtime):
    for build in ("first", "second"):
        shutil.rmtree(runtime[0] / build / "psycopg-3.3.6.dist-info")
        distribution(runtime[0] / build, "psycopg", "3.3.5")
    result = run_workflow(runtime)
    assert result.returncode != 0
    assert "installed 3.3.5" in result.stdout


def test_actual_workflow_rejects_different_freezes(runtime):
    distribution(runtime[0] / "second", "unrelated-base-package", "1.0")
    result = run_workflow(runtime)
    assert result.returncode != 0
    assert "resolved different versions" in result.stdout


def test_actual_workflow_rejects_empty_freezes(runtime):
    runtime[2]["EMPTY_FREEZE"] = "1"
    result = run_workflow(runtime)
    assert result.returncode != 0
    assert "returned no packages" in result.stdout


def test_actual_workflow_rejects_broken_dependency_metadata(runtime):
    for build in ("first", "second"):
        distribution(runtime[0] / build, "broken", "1.0", ["absent==1.0"])
    result = run_workflow(runtime)
    assert result.returncode != 0
    assert "requires absent" in result.stdout

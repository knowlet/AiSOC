#!/usr/bin/env python3
"""Check installed runtime versions against a nonempty, exact lock export.

Run inside the image being graded so markers use its Python and platform.
This reads installed metadata only: it never resolves or installs packages.
pip is already required for the workflow's freeze and consistency checks;
its vendored parser also works in images without standalone packaging.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import tempfile
from pathlib import Path
from unittest.mock import patch

from pip._vendor.packaging.requirements import InvalidRequirement, Requirement
from pip._vendor.packaging.version import Version


def verify(path: Path) -> list[str]:
    problems: list[str] = []
    applicable = 0
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement as exc:
            problems.append(f"line {number}: invalid requirement: {exc}")
            continue
        pins = list(requirement.specifier)
        if requirement.url or requirement.extras or len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
            problems.append(f"line {number}: expected one exact distribution pin: {line}")
            continue
        if requirement.marker and not requirement.marker.evaluate():
            continue
        applicable += 1
        try:
            installed = importlib.metadata.version(requirement.name)
        except importlib.metadata.PackageNotFoundError:
            problems.append(f"{requirement.name}: missing installed distribution")
            continue
        if Version(installed) != Version(pins[0].version):
            problems.append(f"{requirement.name}: installed {installed}, expected {requirement.specifier}")
    if not applicable:
        problems.append("no applicable runtime requirements; refusing an empty installation check")
    return problems


def self_test() -> int:
    def installed(name: str) -> str:
        if name == "present":
            return "1.0"
        raise importlib.metadata.PackageNotFoundError(name)

    cases = [
        ("exact installed pin", "present==1.0", True),
        ("empty export", "\n", False),
        ("inactive export", 'present==1.0 ; python_version < "0"', False),
        ("missing distribution", "absent==1.0", False),
        ("wrong version", "present==2.0", False),
        ("unpinned requirement", "present>=1.0", False),
        ("invalid requirement", "not a requirement", False),
    ]
    with tempfile.TemporaryDirectory() as directory:
        requirements = Path(directory) / "expected.txt"
        with patch("importlib.metadata.version", side_effect=installed):
            for label, text, expected in cases:
                requirements.write_text(text, encoding="utf-8")
                if (not verify(requirements)) != expected:
                    print(f"FAIL: self-test {label}")
                    return 1
    print(f"self-test: {len(cases)} controls passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("requirements", type=Path, nargs="?")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.requirements is None:
        parser.error("the requirements file is required unless --self-test is supplied")
    problems = verify(args.requirements)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}")
        return 1
    print("Every applicable runtime requirement is installed at its locked version")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

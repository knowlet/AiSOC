#!/usr/bin/env python3
"""Machine-readable preflight for Qdrant image bumps.

Emits JSON on stdout describing whether attaching existing storage to the
target Qdrant image is allowed. Legacy v1.7.x (and snapshots taken before a
minor-version ladder) must not jump directly to v1.20.x.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def _infer_versions(compose_path: Path) -> tuple[str | None, str | None]:
    text = compose_path.read_text(encoding="utf-8")
    current = None
    for line in text.splitlines():
        if "qdrant/qdrant:" in line and current is None:
            m = re.search(r"qdrant/qdrant:([^\s\"']+)", line)
            if m:
                current = m.group(1)
    # Target from inventory doc pin when present.
    target = "v1.20.0"
    inv = compose_path.parents[1] / "docs" / "upgrade" / "dependency-inventory.json"
    if inv.is_file():
        try:
            data = json.loads(inv.read_text(encoding="utf-8"))
            for row in data.get("infrastructure", []):
                if row.get("component") == "Qdrant":
                    target = row.get("pin", target)
        except json.JSONDecodeError:
            pass
    return current, target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--storage-version",
        default=None,
        help="Observed Qdrant storage version (e.g. v1.7.0). If omitted, only prints policy.",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target image tag (default: v1.20.0 or compose/inventory pin).",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    compose = root / "docker-compose.yml"
    current, default_target = _infer_versions(compose) if compose.is_file() else (None, "v1.20.0")
    target = args.target or default_target or "v1.20.0"
    storage = args.storage_version or current

    def minor(tag: str) -> int | None:
        m = re.match(r"v?(\d+)\.(\d+)", tag.lstrip("v"))
        return int(m.group(2)) if m else None

    def major(tag: str) -> int | None:
        m = re.match(r"v?(\d+)\.", tag.lstrip("v"))
        return int(m.group(1)) if m else None

    blocked_reasons: list[str] = []
    allow_in_place = True
    required_steps: list[str] = []

    if storage:
        sm, tm = major(storage), major(target)
        s_min, t_min = minor(storage), minor(target)
        if sm == 1 and tm == 1 and s_min is not None and t_min is not None:
            if t_min - s_min > 1:
                allow_in_place = False
                blocked_reasons.append(
                    "Qdrant supports in-place storage only between consecutive minor versions."
                )
                required_steps.append(
                    "Run scripts/qdrant_migration_evidence.sh ladder on disposable data."
                )
            if s_min is not None and s_min <= 7 and t_min is not None and t_min >= 20:
                allow_in_place = False
                blocked_reasons.append(
                    "Legacy v1.7.x on-disk segment format cannot load on v1.20.x directly."
                )
                required_steps.append(
                    "Take v1.7 collection snapshot for rollback, then step every minor to v1.20."
                )
                required_steps.append(
                    "Post-ladder snapshots are for forward migrate/DR onto fresh v1.20 volumes only."
                )

    out = {
        "ok": allow_in_place and not blocked_reasons,
        "compose_qdrant_pin": current,
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
    print(json.dumps(out, indent=2))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

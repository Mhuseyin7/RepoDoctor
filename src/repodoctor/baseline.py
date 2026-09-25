from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult

BASELINE_FILE = ".repodoctor-baseline.json"


def create(root: Path, result: ScanResult) -> Path:
    path = root / BASELINE_FILE
    payload = {"version": 1, "fingerprints": sorted(item.fingerprint for item in result.findings)}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load(root: Path) -> set[str]:
    path = root / BASELINE_FILE
    if not path.is_file():
        return set()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        values = raw.get("fingerprints", [])
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise ValueError("fingerprints must be a string list")
        return set(values)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"Invalid {BASELINE_FILE}: {exc}") from exc

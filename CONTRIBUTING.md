# Contributing

Use Python 3.11 or newer. Install with `python -m pip install -e ".[dev]"`, run `ruff check .`, then `pytest`. New rules must be deterministic, include remediation, avoid exposing secrets, and have focused tests for both detection and expected non-detection.

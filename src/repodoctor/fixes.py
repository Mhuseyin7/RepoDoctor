"""Conservative, opt-in repository hygiene fixes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import Config


@dataclass(frozen=True)
class PlannedFix:
    path: Path
    description: str
    operation: Callable[[], object]

    def apply(self) -> None:
        self.operation()


def planned_fixes(root: Path, config: Config) -> list[PlannedFix]:
    """Return non-destructive fixes; source code is intentionally never altered."""
    del config
    if not root.is_dir():
        raise ValueError(f"Repository root is not a directory: {root}")
    fixes: list[PlannedFix] = []
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        fixes.append(
            PlannedFix(
                gitignore,
                "Create a minimal .gitignore with environment-file protection",
                lambda: gitignore.write_text(".env\n.venv/\n__pycache__/\n", encoding="utf-8"),
            )
        )
    elif ".env" not in gitignore.read_text(encoding="utf-8", errors="replace"):
        fixes.append(
            PlannedFix(
                gitignore,
                "Add .env to .gitignore",
                lambda: gitignore.write_text(
                    gitignore.read_text(encoding="utf-8", errors="replace").rstrip() + "\n.env\n",
                    encoding="utf-8",
                ),
            )
        )
    return fixes

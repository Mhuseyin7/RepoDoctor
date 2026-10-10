from __future__ import annotations

import fnmatch
import os
import subprocess
from pathlib import Path

from .config import Config
from .models import RepositoryProfile

DEFAULT_IGNORES = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".next"}
LANGUAGE_SUFFIXES = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".php": "PHP",
}


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def discover(root: Path, config: Config) -> RepositoryProfile:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Repository root is not a directory: {root}")
    files: list[Path] = []
    skipped = 0
    gitignore = _gitignore_patterns(root)
    tracked_paths = _tracked_paths(root)
    for current, dirs, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = [
            name
            for name in dirs
            if name not in DEFAULT_IGNORES
            and not (current_path / name).is_symlink()
            and not _ignored((current_path / name).relative_to(root), gitignore, is_dir=True)
        ]
        for name in names:
            path = current_path / name
            if path.is_symlink() or not _is_within(path, root):
                skipped += 1
                continue
            relative = path.relative_to(root)
            if _ignored(relative, config.exclude, is_dir=False):
                skipped += 1
                continue
            # A .gitignore rule does not stop Git from retaining a file that was
            # committed earlier. Keep such environment files in scope so SEC-002
            # accurately reports them instead of silently skipping a credential risk.
            tracked_environment = (
                path.name.startswith(".env") and relative.as_posix() in tracked_paths
            )
            if _ignored(relative, gitignore, is_dir=False) and not tracked_environment:
                skipped += 1
                continue
            try:
                if path.stat().st_size > config.max_file_size_kb * 1024:
                    skipped += 1
                    continue
            except OSError:
                skipped += 1
                continue
            files.append(path)
    file_names = {p.name for p in files}
    languages = {
        LANGUAGE_SUFFIXES[p.suffix.lower()] for p in files if p.suffix.lower() in LANGUAGE_SUFFIXES
    }
    frameworks: set[str] = set()
    if {"next.config.js", "next.config.ts", "next.config.mjs"} & file_names:
        frameworks.add("Next.js")
    package_json = _read_optional(root / "package.json")
    sample_text = _all_text(files)
    if '"react"' in package_json:
        frameworks.add("React")
    if '"astro"' in package_json or "astro.config.mjs" in file_names:
        frameworks.add("Astro")
    if '"vue"' in package_json:
        frameworks.add("Vue")
    if '"express"' in package_json:
        frameworks.add("Express")
    if '"@nestjs/core"' in package_json:
        frameworks.add("NestJS")
    if '"fastapi"' in _read_optional(root / "pyproject.toml") or "fastapi" in sample_text:
        frameworks.add("FastAPI")
    if "manage.py" in file_names:
        frameworks.add("Django")
    if "flask" in sample_text:
        frameworks.add("Flask")
    if "artisan" in file_names or "laravel/framework" in _read_optional(root / "composer.json"):
        frameworks.add("Laravel")
    managers = {
        manager
        for marker, manager in {
            "package-lock.json": "npm",
            "pnpm-lock.yaml": "pnpm",
            "yarn.lock": "yarn",
            "bun.lockb": "bun",
            "pyproject.toml": "pyproject",
            "poetry.lock": "poetry",
            "uv.lock": "uv",
            "requirements.txt": "pip",
            "Cargo.toml": "cargo",
            "go.mod": "go modules",
            "composer.json": "composer",
        }.items()
        if marker in file_names
    }
    infrastructure = {
        label
        for marker, label in {
            "Dockerfile": "Docker",
            "docker-compose.yml": "Docker Compose",
            "docker-compose.yaml": "Docker Compose",
            "compose.yaml": "Docker Compose",
            "compose.yml": "Docker Compose",
            "Makefile": "Make",
            "nginx.conf": "Nginx",
        }.items()
        if marker in file_names
    }
    if any(path.suffix == ".tf" for path in files):
        infrastructure.add("Terraform")
    if "kustomization.yaml" in file_names or "kustomization.yml" in file_names:
        infrastructure.add("Kubernetes")
    if any(".github/workflows/" in p.as_posix() for p in files):
        infrastructure.add("GitHub Actions")
    return RepositoryProfile(
        root=root,
        files=files,
        languages=languages,
        frameworks=frameworks,
        package_managers=managers,
        infrastructure=infrastructure,
        skipped_files=skipped,
    )


def _gitignore_patterns(root: Path) -> list[str]:
    """Read a deliberately small, safe subset of gitignore syntax for traversal."""
    content = _read_optional(root / ".gitignore")
    return [
        line.strip().removeprefix("/")
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and not line.startswith("!")
    ]


def _tracked_paths(root: Path) -> set[str]:
    """Return Git-indexed paths without reading or executing repository code."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if completed.returncode != 0:
        return set()
    return {
        value.decode("utf-8", errors="surrogateescape")
        for value in completed.stdout.split(b"\0")
        if value
    }


def _ignored(path: Path, patterns: list[str], *, is_dir: bool) -> bool:
    value = path.as_posix()
    for raw in patterns:
        pattern = raw.rstrip("/")
        if not pattern:
            continue
        if fnmatch.fnmatch(value, pattern) or path.match(pattern):
            return True
        if is_dir and (raw.endswith("/") or "/" not in pattern) and path.name == pattern:
            return True
    return False


def _read_optional(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    except OSError:
        return ""


def _all_text(files: list[Path]) -> str:
    # Bounded framework hint only; discovery never loads the full repository at once.
    return "\n".join(_read_optional(path)[:20_000] for path in files[:100])

"""Built-in deterministic rules. They inspect only local files and never execute code."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Literal

from .models import Category, Finding, RepositoryProfile, Rule, Severity

RuleCheck = Callable[[RepositoryProfile], Iterable[Finding]]


def rule(
    rule_id: str,
    title: str,
    category: Category,
    severity: Severity,
    remediation: str,
    description: str,
    confidence: Literal["low", "medium", "high"] = "high",
) -> Rule:
    return Rule(
        id=rule_id,
        title=title,
        category=category,
        severity=severity,
        remediation=remediation,
        description=description,
        confidence=confidence,
    )


RULES: dict[str, Rule] = {
    "SEC-001": rule(
        "SEC-001",
        "Possible committed secret",
        Category.SECURITY,
        Severity.HIGH,
        "Revoke the credential if it is live, move it to environment configuration, "
        "and use a placeholder.",
        "A high-confidence credential-like value was found in a tracked text file.",
    ),
    "SEC-002": rule(
        "SEC-002",
        "Tracked environment file",
        Category.SECURITY,
        Severity.HIGH,
        "Remove secrets from version control, add the file to .gitignore, "
        "and commit a .env.example instead.",
        "Environment files frequently contain credentials and should not normally be tracked.",
    ),
    "SEC-003": rule(
        "SEC-003",
        "Dangerous dynamic evaluation",
        Category.SECURITY,
        Severity.MEDIUM,
        "Avoid dynamic evaluation. Parse a constrained format or use a safe API instead.",
        "eval-like APIs can turn untrusted input into code execution.",
        "medium",
    ),
    "SEC-004": rule(
        "SEC-004",
        "Unsafe shell execution",
        Category.SECURITY,
        Severity.MEDIUM,
        "Avoid shell=True or shell command interpolation; "
        "pass an argument vector and validate inputs.",
        "Shell execution with interpolated input can enable command injection.",
        "medium",
    ),
    "SEC-005": rule(
        "SEC-005",
        "Credentialed wildcard CORS",
        Category.SECURITY,
        Severity.HIGH,
        "Use an explicit origin allow-list when credentials are enabled; never combine "
        "credentials with a wildcard origin.",
        "Wildcard CORS combined with credential support can expose authenticated responses "
        "to untrusted origins.",
        "medium",
    ),
    "SEC-006": rule(
        "SEC-006",
        "Debug mode enabled",
        Category.SECURITY,
        Severity.MEDIUM,
        "Disable debug mode in production and configure it through environment-specific settings.",
        "Debug mode can disclose stack traces, configuration, or development-only behavior.",
        "medium",
    ),
    "DOCKER-001": rule(
        "DOCKER-001",
        "Container runs as root",
        Category.DOCKER,
        Severity.MEDIUM,
        "Create and switch to a non-root USER in the final image stage.",
        "No non-root USER instruction was found in the Dockerfile.",
        "medium",
    ),
    "DOCKER-002": rule(
        "DOCKER-002",
        "Privileged Docker service",
        Category.DOCKER,
        Severity.HIGH,
        "Remove privileged mode and grant only the minimum required capabilities.",
        "Privileged containers substantially weaken isolation.",
    ),
    "DOCKER-003": rule(
        "DOCKER-003",
        "Docker socket mounted",
        Category.DOCKER,
        Severity.HIGH,
        "Avoid mounting the host Docker socket; use a narrowly scoped build service "
        "or rootless alternative.",
        "A Docker socket mount can grant effective control of the host Docker daemon.",
    ),
    "DOCKER-004": rule(
        "DOCKER-004",
        "Host networking enabled",
        Category.DOCKER,
        Severity.MEDIUM,
        "Use explicit port mappings and service networks instead of host networking "
        "where possible.",
        "Host networking removes network namespace isolation.",
        "medium",
    ),
    "CICD-001": rule(
        "CICD-001",
        "Workflow has broad permissions",
        Category.CICD,
        Severity.HIGH,
        "Set minimal workflow or job permissions, preferably permissions: read-all.",
        "write-all permissions grant every GitHub token scope.",
    ),
    "CICD-002": rule(
        "CICD-002",
        "GitHub Action not pinned",
        Category.CICD,
        Severity.LOW,
        "Pin third-party actions to a full commit SHA for stronger supply-chain protection.",
        "Mutable action references may change between workflow runs.",
        "medium",
    ),
    "GIT-001": rule(
        "GIT-001",
        "Missing .gitignore",
        Category.GIT,
        Severity.MEDIUM,
        "Add a .gitignore appropriate for this project's tools and generated output.",
        "A repository without .gitignore is more likely to accumulate generated or secret files.",
    ),
    "GIT-002": rule(
        "GIT-002",
        "Environment files not ignored",
        Category.GIT,
        Severity.MEDIUM,
        "Add .env and appropriate variants to .gitignore; keep .env.example explicitly allowed.",
        "Environment files are not excluded by .gitignore.",
    ),
    "DOC-001": rule(
        "DOC-001",
        "Missing README",
        Category.DOCUMENTATION,
        Severity.MEDIUM,
        "Add a README covering purpose, installation, and development or usage instructions.",
        "New contributors need a primary project entry point.",
    ),
    "DOC-002": rule(
        "DOC-002",
        "Missing license",
        Category.DOCUMENTATION,
        Severity.LOW,
        "Add a LICENSE file before publishing so users know the terms of use.",
        "Public repositories benefit from explicit licensing.",
    ),
    "TEST-001": rule(
        "TEST-001",
        "No test files detected",
        Category.TESTING,
        Severity.MEDIUM,
        "Add focused automated tests and run them in CI.",
        "No conventional test file names or test directories were detected.",
        "medium",
    ),
    "DEP-001": rule(
        "DEP-001",
        "Missing dependency lockfile",
        Category.DEPENDENCIES,
        Severity.LOW,
        "Commit the package manager's lockfile for reproducible application installs.",
        "A dependency manifest was found without its conventional lockfile.",
        "medium",
    ),
    "CODE-001": rule(
        "CODE-001",
        "Large source file",
        Category.CODE_QUALITY,
        Severity.LOW,
        "Consider splitting the file into focused modules where that improves "
        "ownership and testability.",
        "Very large source files are harder to review and maintain.",
        "medium",
    ),
    "CODE-002": rule(
        "CODE-002",
        "Empty exception handler",
        Category.CODE_QUALITY,
        Severity.MEDIUM,
        "Handle, log, or deliberately document the exception rather than silently swallowing it.",
        "An empty exception handler can hide operational failures.",
        "medium",
    ),
}

SECRET_PATTERNS = [
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"']([^\"'\s]{12,})"),
]
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".go", ".rs", ".java"}


def _text(path: Path) -> list[str]:
    try:
        if b"\0" in path.read_bytes()[:4096]:
            return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _finding(
    profile: RepositoryProfile,
    rule_id: str,
    *,
    path: Path | None = None,
    line: int | None = None,
    message: str | None = None,
    excerpt: str | None = None,
) -> Finding:
    spec = RULES[rule_id]
    relative = path.relative_to(profile.root).as_posix() if path else None
    stable = f"{rule_id}|{relative or ''}|{line or 0}|{message or spec.title}"
    return Finding(
        id=hashlib.sha256(stable.encode()).hexdigest()[:16],
        rule_id=rule_id,
        severity=spec.severity,
        confidence=spec.confidence,
        message=message or spec.title,
        file=relative,
        start_line=line,
        end_line=line,
        code_excerpt=excerpt,
        remediation=spec.remediation,
        fingerprint=hashlib.sha256(stable.encode()).hexdigest(),
        category=spec.category,
    )


def run_rules(profile: RepositoryProfile) -> list[Finding]:
    findings: list[Finding] = []
    names = {path.name for path in profile.files}
    root = profile.root
    if ".gitignore" not in names:
        findings.append(_finding(profile, "GIT-001"))
    else:
        ignored = (root / ".gitignore").read_text(encoding="utf-8", errors="replace")
        if not re.search(r"^\.env(?:\.|$|\*)", ignored, re.MULTILINE):
            findings.append(_finding(profile, "GIT-002", path=root / ".gitignore"))
    if not any(name.lower().startswith("readme") for name in names):
        findings.append(_finding(profile, "DOC-001"))
    if not any(name.lower().startswith("license") or name.lower() == "copying" for name in names):
        findings.append(_finding(profile, "DOC-002"))
    if not any(
        "test" in p.name.lower() or any(part in {"tests", "test", "__tests__"} for part in p.parts)
        for p in profile.files
    ):
        findings.append(_finding(profile, "TEST-001"))
    _dependency_rules(profile, findings)
    for path in profile.files:
        relative = path.relative_to(root).as_posix()
        lines = _text(path)
        if path.name.startswith(".env") and path.name not in {
            ".env.example",
            ".env.sample",
            ".env.template",
        }:
            findings.append(
                _finding(profile, "SEC-002", path=path, message="Tracked environment file detected")
            )
        # Credentials frequently live in YAML, JSON, shell, and environment
        # configuration rather than source code. Secret detection therefore
        # covers every eligible text file; executable-code rules stay scoped to
        # source files to avoid documentation false positives.
        for number, raw in enumerate(lines, 1):
            has_secret = any(pattern.search(raw) for pattern in SECRET_PATTERNS)
            if has_secret and not _looks_like_placeholder(raw):
                findings.append(
                    _finding(
                        profile,
                        "SEC-001",
                        path=path,
                        line=number,
                        message="Possible committed secret detected",
                        excerpt=_redact(raw),
                    )
                )
        if path.suffix.lower() in SOURCE_SUFFIXES:
            source = "\n".join(lines)
            if _has_credentialed_wildcard_cors(source):
                findings.append(_finding(profile, "SEC-005", path=path))
            if len(lines) > 1000:
                findings.append(
                    _finding(
                        profile,
                        "CODE-001",
                        path=path,
                        message=f"Source file has {len(lines)} lines",
                    )
                )
            for number, raw in enumerate(lines, 1):
                executable = _code_without_strings(raw, path.suffix.lower())
                if _debug_enabled(executable):
                    findings.append(
                        _finding(
                            profile, "SEC-006", path=path, line=number, excerpt=raw.strip()[:200]
                        )
                    )
                if re.search(r"\b(?:eval|exec)\s*\(", executable) or "Function(" in executable:
                    findings.append(
                        _finding(
                            profile, "SEC-003", path=path, line=number, excerpt=raw.strip()[:200]
                        )
                    )
                if (path.suffix == ".py" and "shell=True" in executable) or re.search(
                    r"(?:child_process\.)?exec\s*\(", executable
                ):
                    findings.append(
                        _finding(
                            profile, "SEC-004", path=path, line=number, excerpt=raw.strip()[:200]
                        )
                    )
                if re.search(
                    r"except\s*(?:\w+|Exception)?\s*:\s*(?:pass|\.\.\.)\s*$", raw
                ) or re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", raw):
                    findings.append(
                        _finding(
                            profile, "CODE-002", path=path, line=number, excerpt=raw.strip()[:200]
                        )
                    )
        if path.name == "Dockerfile":
            docker = "\n".join(lines)
            if not re.search(r"^\s*USER\s+(?!root\b)\S+", docker, re.MULTILINE | re.IGNORECASE):
                findings.append(_finding(profile, "DOCKER-001", path=path))
        if path.name in {
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        }:
            for number, raw in enumerate(lines, 1):
                if re.match(r"\s*privileged\s*:\s*true\b", raw, re.IGNORECASE):
                    findings.append(
                        _finding(profile, "DOCKER-002", path=path, line=number, excerpt=raw.strip())
                    )
                if re.search(r"/var/run/docker\.sock\s*:", raw):
                    findings.append(
                        _finding(profile, "DOCKER-003", path=path, line=number, excerpt=raw.strip())
                    )
                if re.match(r"\s*network_mode\s*:\s*[\"']?host", raw, re.IGNORECASE):
                    findings.append(
                        _finding(profile, "DOCKER-004", path=path, line=number, excerpt=raw.strip())
                    )
        if relative.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
            _workflow_rules(profile, path, lines, findings)
    return findings


def _dependency_rules(profile: RepositoryProfile, findings: list[Finding]) -> None:
    names = {p.name for p in profile.files}
    pairs = {
        "package.json": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"),
        "pyproject.toml": ("poetry.lock", "uv.lock", "requirements.txt"),
        "composer.json": ("composer.lock",),
    }
    for manifest, locks in pairs.items():
        if manifest in names and not any(lock in names for lock in locks):
            findings.append(
                _finding(
                    profile,
                    "DEP-001",
                    path=profile.root / manifest,
                    message=f"{manifest} has no conventional lockfile",
                )
            )


def _workflow_rules(
    profile: RepositoryProfile, path: Path, lines: list[str], findings: list[Finding]
) -> None:
    for number, raw in enumerate(lines, 1):
        if re.match(r"\s*permissions\s*:\s*write-all\s*$", raw):
            findings.append(
                _finding(profile, "CICD-001", path=path, line=number, excerpt=raw.strip())
            )
        match = re.search(r"\buses:\s*([^\s#]+)", raw)
        if match:
            reference = match.group(1)
            if "@" in reference and not re.search(r"@[a-fA-F0-9]{40}$", reference):
                findings.append(
                    _finding(
                        profile,
                        "CICD-002",
                        path=path,
                        line=number,
                        message=f"Action is not SHA-pinned: {reference}",
                        excerpt=raw.strip(),
                    )
                )


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(
        item in lowered
        for item in (
            "example",
            "placeholder",
            "changeme",
            "change-me",
            "set-a-",
            "set_",
            "your_",
            "dummy",
            "<secret",
            "abcdefghijklmnopqrstuvwxyz",
        )
    )


def _has_credentialed_wildcard_cors(source: str) -> bool:
    lowered = source.lower()
    wildcard = bool(re.search(r"(?:allow_origins|origin)\s*[:=]\s*\[?\s*[\"']\*[\"']", lowered))
    credentials = bool(re.search(r"(?:allow_credentials|credentials)\s*[:=]\s*true", lowered))
    return wildcard and credentials


def _debug_enabled(executable: str) -> bool:
    return bool(
        re.search(r"\bdebug\s*=\s*true\b", executable, re.IGNORECASE)
        or re.search(r"\bdebug\s*:\s*true\b", executable, re.IGNORECASE)
    )


def _code_without_strings(value: str, suffix: str) -> str:
    """Remove quoted literals before searching for executable call syntax."""
    line = value.split("#", 1)[0] if suffix == ".py" else value.split("//", 1)[0]
    return re.sub(r"(?:'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\")", "", line)


def _redact(value: str) -> str:
    return re.sub(r"([:=]\s*[\"']?)[^\s\"']+", r"\1[REDACTED]", value.strip()[:200])

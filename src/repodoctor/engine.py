from __future__ import annotations

from pathlib import Path

from . import __version__
from .config import Config, load_config
from .discovery import discover
from .models import Finding, ScanResult, Severity
from .rules import RULES, run_rules


class ConfigurationError(ValueError):
    """A user-controlled configuration or filesystem input is invalid."""


def scan(
    root: Path, *, config: Config | None = None, baseline: set[str] | None = None
) -> ScanResult:
    try:
        effective_config = config or load_config(root)
        profile = discover(root, effective_config)
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
    findings = run_rules(profile)
    findings = [item for item in findings if effective_config.is_rule_enabled(item.rule_id)]
    findings = [
        item for item in findings if not effective_config.is_suppressed(item.rule_id, item.file)
    ]
    if baseline:
        findings = [item for item in findings if item.fingerprint not in baseline]
    findings.sort(
        key=lambda item: (
            -item.severity.weight,
            item.file or "",
            item.start_line or 0,
            item.rule_id,
        )
    )
    return ScanResult(
        root=str(profile.root),
        findings=findings,
        scores=_scores(findings),
        languages=sorted(profile.languages),
        frameworks=sorted(profile.frameworks),
        package_managers=sorted(profile.package_managers),
        skipped_files=profile.skipped_files,
        scanned_files=len(profile.files),
        version=__version__,
    )


def _scores(findings: list[Finding]) -> dict[str, int]:
    categories = {rule.category.value for rule in RULES.values()}
    return {
        category: max(
            0,
            100 - sum(item.severity.weight for item in findings if item.category.value == category),
        )
        for category in sorted(categories)
    }


def should_fail(result: ScanResult, fail_on: Severity | None) -> bool:
    return bool(fail_on and any(item.severity.weight >= fail_on.weight for item in result.findings))

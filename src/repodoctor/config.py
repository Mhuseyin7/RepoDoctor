from __future__ import annotations

from pathlib import Path

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import Severity


class RuleOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True


class IgnoreRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule: str
    path: str = "**"
    reason: str | None = None


class SeverityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fail_on: Severity | None = None


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = 1
    exclude: list[str] = Field(default_factory=list)
    severity: SeverityConfig = Field(default_factory=SeverityConfig)
    rules: dict[str, RuleOverride] = Field(default_factory=dict)
    ignore: list[IgnoreRule] = Field(default_factory=list)
    scores: bool = True
    max_file_size_kb: int = Field(default=1024, ge=1, le=10240)

    def is_rule_enabled(self, rule_id: str) -> bool:
        return self.rules.get(rule_id, RuleOverride()).enabled

    def is_suppressed(self, rule_id: str, relative_path: str | None) -> bool:
        if relative_path is None:
            return False
        return any(
            item.rule == rule_id and Path(relative_path).match(item.path) for item in self.ignore
        )


def load_config(root: Path) -> Config:
    path = root / ".repodoctor.yml"
    if not path.is_file():
        return Config()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return Config.model_validate(data)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ValueError(f"Invalid {path.name}: {exc}") from exc


DEFAULT_CONFIG = """# RepoDoctor configuration
version: 1

# Files excluded in addition to .gitignore.
exclude:
  - vendor/**
  - fixtures/**

severity:
  # CI exits with 1 when a finding at or above this severity is present.
  fail_on: high

# Disable or enable individual rules.
rules: {}

# Suppress a scoped rule with an optional auditable reason.
ignore: []
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def weight(self) -> int:
        return {Severity.LOW: 2, Severity.MEDIUM: 7, Severity.HIGH: 18}[self]


class Category(StrEnum):
    SECURITY = "security"
    GIT = "git"
    DOCUMENTATION = "documentation"
    TESTING = "testing"
    CICD = "ci_cd"
    DOCKER = "docker"
    DEPENDENCIES = "dependencies"
    CODE_QUALITY = "code_quality"
    DEVELOPER_EXPERIENCE = "developer_experience"


class Rule(BaseModel):
    id: str
    title: str
    description: str
    category: Category
    severity: Severity
    confidence: Literal["low", "medium", "high"] = "high"
    remediation: str
    references: list[str] = Field(default_factory=list)
    version: str = "1"
    autofix_capability: Literal["none", "safe"] = "none"


class Finding(BaseModel):
    id: str
    rule_id: str
    severity: Severity
    confidence: Literal["low", "medium", "high"]
    message: str
    file: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    code_excerpt: str | None = None
    remediation: str
    documentation_url: str | None = None
    fingerprint: str
    category: Category


class RepositoryProfile(BaseModel):
    root: Path
    files: list[Path]
    languages: set[str] = Field(default_factory=set)
    frameworks: set[str] = Field(default_factory=set)
    package_managers: set[str] = Field(default_factory=set)
    infrastructure: set[str] = Field(default_factory=set)
    skipped_files: int = 0


class ScanResult(BaseModel):
    root: str
    findings: list[Finding]
    scores: dict[str, int]
    languages: list[str]
    frameworks: list[str]
    package_managers: list[str]
    skipped_files: int
    version: str
    scanned_files: int = 0

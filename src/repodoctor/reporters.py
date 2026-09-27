from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Literal

from rich.console import Console
from rich.table import Table

from .models import ScanResult
from .rules import RULES

OutputFormat = Literal["terminal", "json", "sarif", "markdown"]


def render(result: ScanResult, output_format: OutputFormat, console: Console) -> None:
    if output_format == "json":
        console.print(result.model_dump_json(indent=2))
    elif output_format == "sarif":
        console.print(json.dumps(to_sarif(result), indent=2))
    elif output_format == "markdown":
        console.print(to_markdown(result))
    else:
        terminal(result, console)


def serialize(result: ScanResult, output_format: OutputFormat) -> str:
    """Serialize a report without terminal formatting, for CI artifacts."""
    if output_format == "json":
        return result.model_dump_json(indent=2)
    if output_format == "sarif":
        return json.dumps(to_sarif(result), indent=2)
    if output_format == "markdown":
        return to_markdown(result)
    raise ValueError("Terminal output cannot be written as a report file")


def write_report(result: ScanResult, output_format: OutputFormat, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(serialize(result, output_format) + "\n", encoding="utf-8")


def terminal(result: ScanResult, console: Console) -> None:
    console.print("[bold cyan]RepoDoctor[/bold cyan]\n")
    console.print(f"Repository Analysis  [dim]{result.root}[/dim]")
    scores = Table(show_header=False, box=None, pad_edge=False)
    scores.add_column("Category", style="bold")
    scores.add_column("Score", justify="right")
    for category, score in result.scores.items():
        scores.add_row(category.replace("_", " ").title(), f"{score}/100")
    console.print(scores)
    summary = Counter(item.severity.value for item in result.findings)
    console.print(
        f"\n[bold]{len(result.findings)} findings[/bold]  "
        + "  ".join(
            f"{summary[level]} {level.title()}"
            for level in ("high", "medium", "low")
            if summary[level]
        )
    )
    if not result.findings:
        console.print("[green]No enabled findings.[/green]")
        return
    table = Table(title="Findings", show_lines=True)
    table.add_column("Severity", style="bold", width=9)
    table.add_column("Rule", style="cyan", width=10)
    table.add_column("Location")
    table.add_column("What to do")
    for item in result.findings:
        location = item.file or "repository"
        if item.start_line:
            location += f":{item.start_line}"
        table.add_row(
            item.severity.value.upper(),
            item.rule_id,
            location,
            f"{item.message}\n[dim]{item.remediation}[/dim]",
        )
    console.print(table)


def to_sarif(result: ScanResult) -> dict[str, object]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoDoctor",
                        "version": result.version,
                        "rules": [
                            {
                                "id": spec.id,
                                "name": spec.title,
                                "shortDescription": {"text": spec.description},
                                "help": {"text": spec.remediation},
                            }
                            for spec in RULES.values()
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": item.rule_id,
                        "level": _sarif_level(item.severity.value),
                        "message": {"text": item.message},
                        "partialFingerprints": {"repodoctor": item.fingerprint},
                        **(
                            {
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": item.file},
                                            "region": {"startLine": item.start_line or 1},
                                        }
                                    }
                                ]
                            }
                            if item.file
                            else {}
                        ),
                    }
                    for item in result.findings
                ],
            }
        ],
    }


def _sarif_level(severity: str) -> str:
    return {"high": "error", "medium": "warning", "low": "note"}[severity]


def to_markdown(result: ScanResult) -> str:
    lines = [
        "# RepoDoctor report",
        "",
        f"Scanned `{result.root}`: **{len(result.findings)} findings**.",
        "",
        "| Severity | Rule | Location | Finding |",
        "| --- | --- | --- | --- |",
    ]
    for item in result.findings:
        location = item.file or "repository"
        if item.start_line:
            location += f":{item.start_line}"
        lines.append(
            f"| {item.severity.value.upper()} | {item.rule_id} | {location} | {item.message} |"
        )
    return "\n".join(lines)

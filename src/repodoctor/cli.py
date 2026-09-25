from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from . import __version__
from .baseline import create as create_baseline
from .baseline import load as load_baseline
from .config import DEFAULT_CONFIG, load_config
from .engine import ConfigurationError, scan, should_fail
from .models import Severity
from .reporters import OutputFormat, render
from .rules import RULES

app = typer.Typer(no_args_is_help=True, help="Local-first repository health and security auditing.")
baseline_app = typer.Typer(no_args_is_help=True, help="Manage finding baselines.")
app.add_typer(baseline_app, name="baseline")
console = Console()


@app.command(name="scan")
def scan_command(
    path: Annotated[Path, typer.Argument(help="Repository directory to scan.")] = Path("."),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = "terminal",
    severity: Annotated[
        Severity | None, typer.Option("--severity", help="Only show this severity or higher.")
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option("--fail-on", help="Override configured CI failure severity."),
    ] = None,
    use_baseline: Annotated[
        bool,
        typer.Option(
            "--baseline/--no-baseline", help="Hide fingerprints in .repodoctor-baseline.json."
        ),
    ] = True,
) -> None:
    """Scan a repository without uploading its source anywhere."""
    try:
        root = path.resolve()
        config = load_config(root)
        result = scan(root, config=config, baseline=load_baseline(root) if use_baseline else None)
        if severity:
            result.findings = [
                item for item in result.findings if item.severity.weight >= severity.weight
            ]
        render(result, output_format, console)
        if should_fail(result, fail_on or config.severity.fail_on):
            raise typer.Exit(1)
    except ConfigurationError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    except ValueError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        console.print(f"[red]RepoDoctor internal error:[/red] {exc}")
        raise typer.Exit(3) from exc


@app.command()
def doctor() -> None:
    """Verify the local installation and print privacy behavior."""
    console.print(f"[green]RepoDoctor {__version__} is ready.[/green]")
    console.print(
        "Scans are local-only. RepoDoctor does not execute repository code or upload source."
    )


@app.command()
def init(path: Annotated[Path, typer.Argument()] = Path(".")) -> None:
    """Create a conservative .repodoctor.yml without overwriting an existing config."""
    destination = path.resolve() / ".repodoctor.yml"
    if destination.exists():
        console.print(f"[yellow]Already exists:[/yellow] {destination}")
        raise typer.Exit(2)
    destination.write_text(DEFAULT_CONFIG, encoding="utf-8")
    console.print(f"Created [green]{destination}[/green]")


@app.command()
def explain(rule_id: Annotated[str, typer.Argument(help="Rule ID, such as SEC-001.")]) -> None:
    """Explain a built-in rule and its remediation."""
    spec = RULES.get(rule_id.upper())
    if not spec:
        console.print(f"[red]Unknown rule:[/red] {rule_id}")
        raise typer.Exit(2)
    console.print(
        f"[bold]{spec.id} — {spec.title}[/bold]\n{spec.description}\n\n"
        f"Severity: {spec.severity.value.title()}\nConfidence: {spec.confidence.title()}\n\n"
        f"[bold]Remediation[/bold]\n{spec.remediation}"
    )


@baseline_app.command("create")
def baseline_create(path: Annotated[Path, typer.Argument()] = Path(".")) -> None:
    """Record current findings, so later scans report newly introduced issues."""
    try:
        root = path.resolve()
        result = scan(root, config=load_config(root))
        destination = create_baseline(root, result)
        console.print(
            f"Baseline with {len(result.findings)} findings written to [green]{destination}[/green]"
        )
    except (ConfigurationError, ValueError) as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc


if __name__ == "__main__":
    app()

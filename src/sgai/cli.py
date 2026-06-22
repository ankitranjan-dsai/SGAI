"""Command-line interface for SGAI.

Usage::

    sgai scan <path-to-repo> [--output report.md]

Runs a full deterministic audit — dependency CVE check, static analysis, risk
scoring — and writes a Markdown report.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from sgai.models import Severity
from sgai.risk import severity_counts
from sgai.runner import run_scan

console = Console()

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.UNKNOWN: "dim",
}


def _scan(path: str, output: str, explain: bool) -> int:
    target = Path(path).resolve()
    if not target.is_dir():
        console.print(f"[red]error:[/red] {path!r} is not a directory")
        return 1

    console.print(f"[bold]SGAI[/bold] auditing [cyan]{target}[/cyan] …")
    if explain:
        # Deterministic scan, then the multi-agent narration layer writes the report.
        from sgai.agent_runner import run_agent_report

        console.print("[dim]Running multi-agent narration (triage → report) …[/dim]")
        findings, report = asyncio.run(run_agent_report(str(target)))
    else:
        findings, report = asyncio.run(run_scan(path))

    if not findings:
        console.print("[green]✓ No vulnerabilities found.[/green]")
    else:
        counts = severity_counts(findings)
        table = Table(title=f"{len(findings)} findings")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        for sev, count in counts.items():
            table.add_row(f"[{_SEVERITY_STYLE[sev]}]{sev.label}[/]", str(count))
        console.print(table)

    Path(output).write_text(report)
    console.print(f"Report written to [bold]{output}[/bold]")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sgai", description="Multi-agent security review.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Audit a repository for vulnerabilities.")
    scan.add_argument("path", help="Path to the repository to audit.")
    scan.add_argument(
        "-o", "--output", default="sgai_report.md", help="Where to write the Markdown report."
    )
    scan.add_argument(
        "--explain",
        action="store_true",
        help="Use the multi-agent narration layer (Gemini) to write the report.",
    )

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.path, args.output, args.explain)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

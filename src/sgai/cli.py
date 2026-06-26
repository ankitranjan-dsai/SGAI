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


def _audit(repo_dir: str, label: str, output: str, explain: bool, deep: bool, sarif: str | None) -> int:
    """Audit a local directory and write the report. Shared by path and URL scans."""
    console.print(f"[bold]SGAI[/bold] auditing [cyan]{label}[/cyan] …")
    if deep:
        console.print("[dim]Deep mode: running Semgrep multi-language analysis …[/dim]")
    if explain:
        # Deterministic scan, then the multi-agent narration layer writes the report.
        from sgai.agent_runner import run_agent_report

        console.print("[dim]Running multi-agent narration (triage → report) …[/dim]")
        findings, report = asyncio.run(run_agent_report(repo_dir, label=label, deep=deep))
    else:
        findings, report = asyncio.run(run_scan(repo_dir, label=label, deep=deep))

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
    if sarif:
        from sgai.sarif import to_sarif_json

        Path(sarif).write_text(to_sarif_json(findings))
        console.print(f"SARIF written to [bold]{sarif}[/bold]")
    return 0


def _scan(path: str, output: str, explain: bool, deep: bool, sarif: str | None) -> int:
    from sgai.github import CloneError, cloned_repo, is_remote

    # Remote repository: shallow-clone into a temp dir, then audit it.
    if is_remote(path):
        try:
            with cloned_repo(path) as repo_dir:
                console.print(f"[dim]Cloned {path}[/dim]")
                return _audit(str(repo_dir), path, output, explain, deep, sarif)
        except CloneError as exc:
            console.print(f"[red]error:[/red] {exc}")
            return 1

    # Local path.
    target = Path(path).resolve()
    if not target.is_dir():
        console.print(f"[red]error:[/red] {path!r} is not a directory or repo URL")
        return 1
    return _audit(str(target), str(target), output, explain, deep, sarif)


def _fix(path: str, open_pr: bool, branch: str) -> int:
    from sgai.fix import apply_fixes, build_pr_body, plan_fixes
    from sgai.github import CloneError, PRError, cloned_repo, is_remote, open_pull_request

    def _plan_and_show(repo_dir: str) -> list:
        fixes = asyncio.run(plan_fixes(repo_dir))
        if not fixes:
            console.print("[green]✓ No vulnerable PyPI pins to upgrade.[/green]")
            return fixes
        table = Table(title=f"{len(fixes)} dependency upgrade(s)")
        table.add_column("Package")
        table.add_column("From")
        table.add_column("To", style="green")
        for fx in fixes:
            table.add_row(fx.package, fx.old_version, fx.new_version)
        console.print(table)
        return fixes

    # Remote URL: dry-run only (can't push to a repo you don't own).
    if is_remote(path):
        if open_pr:
            console.print("[red]error:[/red] --open-pr needs a local repo you can push to.")
            return 1
        try:
            with cloned_repo(path) as repo_dir:
                _plan_and_show(str(repo_dir))
        except CloneError as exc:
            console.print(f"[red]error:[/red] {exc}")
            return 1
        console.print("[dim]Dry run — clone the repo locally and re-run with --open-pr.[/dim]")
        return 0

    target = Path(path).resolve()
    if not target.is_dir():
        console.print(f"[red]error:[/red] {path!r} is not a directory or repo URL")
        return 1
    fixes = _plan_and_show(str(target))
    if not fixes:
        return 0

    if not open_pr:
        console.print("\n[bold]PR preview[/bold]:\n" + build_pr_body(fixes))
        console.print("\n[dim]Dry run — re-run with --open-pr to open the pull request.[/dim]")
        return 0

    apply_fixes(str(target), fixes)
    try:
        url = open_pull_request(
            str(target), branch, "SGAI: upgrade vulnerable dependencies", build_pr_body(fixes)
        )
    except PRError as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 1
    console.print(f"[green]Opened PR:[/green] {url}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sgai", description="Multi-agent security review.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Audit a repository for vulnerabilities.")
    scan.add_argument("path", help="Local path or a GitHub URL / owner/repo to audit.")
    scan.add_argument(
        "-o", "--output", default="sgai_report.md", help="Where to write the Markdown report."
    )
    scan.add_argument(
        "--explain",
        action="store_true",
        help="Use the multi-agent narration layer (Gemini) to write the report.",
    )
    scan.add_argument(
        "--deep",
        action="store_true",
        help="Also run Semgrep multi-language static analysis (JS, Go, Java, …).",
    )
    scan.add_argument(
        "--sarif", metavar="PATH", help="Also write findings as a SARIF 2.1.0 file."
    )

    fix = sub.add_parser("fix", help="Propose dependency upgrades and optionally open a PR.")
    fix.add_argument("path", help="Local path or a GitHub URL / owner/repo.")
    fix.add_argument(
        "--open-pr", action="store_true", help="Open a pull request (local repo you own)."
    )
    fix.add_argument("--branch", default="sgai/dependency-fixes", help="Branch name for the PR.")

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.path, args.output, args.explain, args.deep, args.sarif)
    if args.command == "fix":
        return _fix(args.path, args.open_pr, args.branch)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

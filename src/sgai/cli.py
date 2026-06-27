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

from sgai.memory import ScanDiff, ScanMemory
from sgai.models import Severity
from sgai.risk import severity_counts
from sgai.runner import run_scan, target_key

console = Console()


def _print_change_banner(diff: ScanDiff) -> None:
    """Show a one-glance summary of what changed since the last recorded scan."""
    if diff.is_first_scan:
        console.print("[dim]Memory: first recorded scan — baseline saved.[/dim]")
        return
    parts = [
        f"[red]{len(diff.new)} new[/red]",
        f"[green]{len(diff.resolved)} fixed[/green]",
        f"[yellow]{len(diff.persisting)} still open[/yellow]",
    ]
    if diff.accepted:
        parts.append(f"[dim]{len(diff.accepted)} accepted[/dim]")
    console.print(
        f"[bold]Changes since {diff.previous_at}:[/bold] " + " · ".join(parts)
    )

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.UNKNOWN: "dim",
}


def _audit(
    repo_dir: str,
    label: str,
    output: str,
    explain: bool,
    deep: bool,
    sarif: str | None,
    remember: bool,
) -> int:
    """Audit a local directory and write the report. Shared by path and URL scans."""
    console.print(f"[bold]SGAI[/bold] auditing [cyan]{label}[/cyan] …")
    if deep:
        console.print("[dim]Deep mode: running Semgrep multi-language analysis …[/dim]")
    memory = ScanMemory() if remember else None
    if explain:
        # Deterministic scan, then the multi-agent narration layer writes the report.
        from sgai.agent_runner import run_agent_report

        console.print("[dim]Running multi-agent narration (triage → report) …[/dim]")
        findings, report, diff = asyncio.run(
            run_agent_report(repo_dir, label=label, deep=deep, memory=memory)
        )
    else:
        findings, report, diff = asyncio.run(
            run_scan(repo_dir, label=label, deep=deep, memory=memory)
        )

    if diff is not None:
        _print_change_banner(diff)

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


def _scan(
    path: str, output: str, explain: bool, deep: bool, sarif: str | None, remember: bool
) -> int:
    from sgai.github import CloneError, cloned_repo, is_remote

    # Remote repository: shallow-clone into a temp dir, then audit it.
    if is_remote(path):
        try:
            with cloned_repo(path) as repo_dir:
                console.print(f"[dim]Cloned {path}[/dim]")
                return _audit(str(repo_dir), path, output, explain, deep, sarif, remember)
        except CloneError as exc:
            console.print(f"[red]error:[/red] {exc}")
            return 1

    # Local path.
    target = Path(path).resolve()
    if not target.is_dir():
        console.print(f"[red]error:[/red] {path!r} is not a directory or repo URL")
        return 1
    return _audit(str(target), str(target), output, explain, deep, sarif, remember)


def _history(path: str) -> int:
    """Show the recorded scan timeline for a target."""
    memory = ScanMemory()
    key = target_key(path, path)
    snapshots = memory.history(key)
    if not snapshots:
        console.print(f"[dim]No scan history for[/dim] {key}")
        console.print("[dim]Run `sgai scan` on it first to start tracking.[/dim]")
        return 0
    table = Table(title=f"Scan history — {key}")
    table.add_column("#", justify="right")
    table.add_column("When (UTC)")
    table.add_column("Findings", justify="right")
    table.add_column("Top severity")
    table.add_column("Risk score", justify="right")
    for i, snap in enumerate(snapshots, 1):
        table.add_row(
            str(i), snap.at, str(len(snap.findings)), snap.top_severity, str(snap.risk_score)
        )
    console.print(table)
    accepted = memory.accepted(key)
    if accepted:
        console.print(f"[dim]{len(accepted)} accepted risk(s) on this target.[/dim]")
    return 0


def _accept(path: str, finding_id: str, reason: str) -> int:
    """Mark a finding as an accepted risk so future scans stop flagging it as new."""
    memory = ScanMemory()
    key = target_key(path, path)
    last = memory.last_snapshot(key)
    if last is None:
        console.print(f"[red]error:[/red] no scan history for {key}; scan it first.")
        return 1
    # Accept by exact fingerprint, or match a finding whose id was given.
    if finding_id in last.findings:
        fp = finding_id
    else:
        matches = [fp for fp, meta in last.findings.items() if meta.get("id") == finding_id]
        if not matches:
            console.print(f"[red]error:[/red] {finding_id!r} not found in the last scan.")
            console.print("[dim]Use the fingerprint or finding id from `sgai history`.[/dim]")
            return 1
        if len(matches) > 1:
            console.print(f"[yellow]{finding_id!r} matches {len(matches)} findings; accepting all.[/yellow]")
        for fp in matches:
            memory.accept(key, fp, reason)
        console.print(f"[green]Accepted[/green] {len(matches)} finding(s) for {key}.")
        return 0
    memory.accept(key, fp, reason)
    console.print(f"[green]Accepted[/green] {fp} for {key}.")
    return 0


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
    scan.add_argument(
        "--no-memory",
        action="store_true",
        help="Don't record this scan or diff it against prior scans.",
    )

    history = sub.add_parser("history", help="Show the recorded scan timeline for a target.")
    history.add_argument("path", help="Local path or a GitHub URL / owner/repo.")

    accept = sub.add_parser(
        "accept", help="Mark a finding as an accepted risk (won't flag as new again)."
    )
    accept.add_argument("path", help="Local path or a GitHub URL / owner/repo.")
    accept.add_argument("finding", help="Finding id or fingerprint (see `sgai history`).")
    accept.add_argument("--reason", default="", help="Why this risk is accepted.")

    fix = sub.add_parser("fix", help="Propose dependency upgrades and optionally open a PR.")
    fix.add_argument("path", help="Local path or a GitHub URL / owner/repo.")
    fix.add_argument(
        "--open-pr", action="store_true", help="Open a pull request (local repo you own)."
    )
    fix.add_argument("--branch", default="sgai/dependency-fixes", help="Branch name for the PR.")

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(
            args.path, args.output, args.explain, args.deep, args.sarif, not args.no_memory
        )
    if args.command == "history":
        return _history(args.path)
    if args.command == "accept":
        return _accept(args.path, args.finding, args.reason)
    if args.command == "fix":
        return _fix(args.path, args.open_pr, args.branch)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

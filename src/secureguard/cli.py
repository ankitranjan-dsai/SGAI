"""Command-line interface for SecureGuard AI.

Usage::

    secureguard scan <path-to-repo>

Day 1: the CLI parses arguments and prints the planned pipeline. Wiring it to the
orchestrator agent is the next milestone (see docs/architecture.md).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

console = Console()


def _scan(path: str) -> int:
    target = Path(path).resolve()
    if not target.is_dir():
        console.print(f"[red]error:[/red] {path!r} is not a directory")
        return 1

    console.print(f"[bold]SecureGuard AI[/bold] — target: [cyan]{target}[/cyan]")
    console.print("Pipeline: scan → (deps ∥ static) → risk → remediation → report")
    console.print("[yellow]Agent pipeline not yet wired — coming in the next milestone.[/yellow]")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secureguard", description="Multi-agent security review.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Audit a repository for vulnerabilities.")
    scan.add_argument("path", help="Path to the repository to audit.")

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.path)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

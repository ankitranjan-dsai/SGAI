"""Deployable HTTP service for SGAI.

A small, stateless FastAPI app that exposes the audit core over HTTP so SGAI can
run as a container (e.g. on Cloud Run). Submitted ``requirements.txt`` content
and Python source are written to a throwaway temp directory, audited through the
same sandboxed security tools the agents use, then discarded.

Run locally::

    uv run uvicorn sgai.api:app --reload

Endpoints:
    GET  /health   liveness probe
    POST /scan     audit submitted requirements + code
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from sgai.mcp_server import server
from sgai.report import build_markdown_report
from sgai.risk import assess

app = FastAPI(title="SGAI", description="Multi-agent security review service.", version="0.1.0")

_INDEX_HTML = (Path(__file__).parent / "web" / "index.html").read_text()


class ScanRequest(BaseModel):
    requirements: str = ""  # contents of a requirements.txt
    code: str = ""  # a Python source file to statically analyze
    github_url: str = ""  # a public repo URL / owner-repo to clone and audit
    explain: bool = False  # narrate the findings with the multi-agent layer


class FindingOut(BaseModel):
    id: str
    source: str
    severity: str
    location: str
    title: str
    remediation: str


class ScanResponse(BaseModel):
    finding_count: int
    findings: list[FindingOut]
    report_markdown: str


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """Serve the mobile-friendly web UI."""
    return _INDEX_HTML


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "service": "sgai"}


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    """Audit submitted requirements and/or source code.

    Everything is written to an isolated temp directory that acts as the sandbox
    root, audited, and then removed — the service keeps no state between calls.
    A ``github_url`` instead clones a public repo and audits it whole.
    """
    label = "submitted code"

    # Branch 1: audit a whole public repository by URL.
    if req.github_url.strip():
        from sgai.github import CloneError, cloned_repo
        from sgai.runner import run_scan

        label = req.github_url.strip()
        try:
            with cloned_repo(label) as repo_dir:
                findings, report = await run_scan(str(repo_dir), label=label)
        except CloneError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Branch 2: audit submitted requirements and/or code.
    else:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dep_result: dict = {"vulnerable": [], "clean": [], "skipped": []}
            if req.requirements.strip():
                (root / "requirements.txt").write_text(req.requirements)
                dep_result = await server.scan_requirements_file("requirements.txt", str(root))

            static_result: dict = {"findings": []}
            if req.code.strip():
                (root / "submitted.py").write_text(req.code)
                static_result = server.run_static_analysis("submitted.py", str(root))

            findings = assess(dep_result, static_result)
            report = build_markdown_report(label, findings)

    # Optionally let the multi-agent layer narrate the report. If no key is
    # configured or the model errors (e.g. rate limit), fall back to the
    # deterministic report so the endpoint always succeeds.
    if req.explain and findings:
        try:
            from sgai.agent_runner import narrate_findings

            report = await narrate_findings(findings, label)
        except Exception:  # noqa: BLE001 — never fail the scan over narration
            report += "\n\n_(AI narration unavailable — showing the deterministic report.)_"

    return ScanResponse(
        finding_count=len(findings),
        findings=[
            FindingOut(
                id=f.id,
                source=f.source,
                severity=f.severity.label,
                location=f.location,
                title=f.title,
                remediation=f.remediation,
            )
            for f in findings
        ],
        report_markdown=report,
    )

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

from fastapi import FastAPI
from pydantic import BaseModel

from sgai.mcp_server import server
from sgai.report import build_markdown_report
from sgai.risk import assess

app = FastAPI(title="SGAI", description="Multi-agent security review service.", version="0.1.0")


class ScanRequest(BaseModel):
    requirements: str = ""  # contents of a requirements.txt
    code: str = ""  # a Python source file to statically analyze


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


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "service": "sgai"}


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    """Audit submitted requirements and/or source code.

    Everything is written to an isolated temp directory that acts as the sandbox
    root, audited, and then removed — the service keeps no state between calls.
    """
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
        report = build_markdown_report("submitted code", findings)

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

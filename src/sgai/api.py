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

import json
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
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
    remember: bool = True  # track this target across scans (repo URLs only)


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
    changes: dict | None = None  # diff vs. the previous recorded scan, if tracked


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
    diff = None

    # Branch 1: audit a whole public repository by URL.
    if req.github_url.strip():
        from sgai.github import CloneError, cloned_repo
        from sgai.memory import ScanMemory
        from sgai.runner import run_scan

        label = req.github_url.strip()
        # Repo URLs are a stable identity, so we can track them across scans.
        memory = ScanMemory() if req.remember else None
        try:
            with cloned_repo(label) as repo_dir:
                findings, report, diff = await run_scan(
                    str(repo_dir), label=label, memory=memory
                )
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
        changes=diff.summary() if diff is not None else None,
    )


def _findings_out(findings) -> list[dict]:
    return [
        {
            "id": f.id,
            "source": f.source,
            "severity": f.severity.label,
            "location": f.location,
            "title": f.title,
            "remediation": f.remediation,
        }
        for f in findings
    ]


async def _scan_events(req: ScanRequest):
    """Yield newline-delimited JSON progress events for a streaming scan."""

    def line(obj: dict) -> str:
        return json.dumps(obj) + "\n"

    label = req.github_url.strip() or "submitted code"
    report = ""
    diff = None

    # Gather findings, streaming a stage event for each step.
    if req.github_url.strip():
        from sgai.github import CloneError, cloned_repo
        from sgai.memory import ScanMemory
        from sgai.runner import run_scan

        memory = ScanMemory() if req.remember else None
        yield line({"event": "stage", "name": "clone", "status": "running", "detail": label})
        try:
            with cloned_repo(label) as repo_dir:
                yield line({"event": "stage", "name": "clone", "status": "done"})
                yield line({"event": "stage", "name": "audit", "status": "running"})
                findings, report, diff = await run_scan(
                    str(repo_dir), label=label, memory=memory
                )
        except CloneError as exc:
            yield line({"event": "error", "detail": str(exc)})
            return
        yield line({"event": "stage", "name": "audit", "status": "done", "detail": f"{len(findings)} findings"})
        if diff is not None:
            yield line({"event": "memory", "status": "done", "changes": diff.summary()})
    else:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yield line({"event": "stage", "name": "dependencies", "status": "running"})
            dep_result: dict = {"vulnerable": []}
            if req.requirements.strip():
                (root / "requirements.txt").write_text(req.requirements)
                dep_result = await server.scan_requirements_file("requirements.txt", str(root))
            yield line({"event": "stage", "name": "dependencies", "status": "done",
                        "detail": f"{len(dep_result.get('vulnerable', []))} vulnerable"})

            yield line({"event": "stage", "name": "static analysis", "status": "running"})
            static_result: dict = {"findings": []}
            if req.code.strip():
                (root / "submitted.py").write_text(req.code)
                static_result = server.run_static_analysis("submitted.py", str(root))
            yield line({"event": "stage", "name": "static analysis", "status": "done",
                        "detail": f"{static_result.get('count', 0)} issues"})

            findings = assess(dep_result, static_result)
            report = build_markdown_report(label, findings)

    # Optional multi-agent narration, streaming one event per agent.
    if req.explain and findings:
        try:
            from google.adk.runners import InMemoryRunner
            from google.genai import types

            from sgai.agents.narrator import build_narration_pipeline

            runner = InMemoryRunner(agent=build_narration_pipeline(), app_name="sgai")
            await runner.session_service.create_session(app_name="sgai", user_id="u", session_id="s")
            payload = json.dumps(_findings_out(findings), indent=2)
            msg = types.Content(role="user", parts=[types.Part(text=f"Target: {label}\nFindings:\n{payload}")])
            seen: set[str] = set()
            async for ev in runner.run_async(user_id="u", session_id="s", new_message=msg):
                author = getattr(ev, "author", None)
                if author and author not in seen:
                    seen.add(author)
                    yield line({"event": "agent", "name": author, "status": "running"})
                if ev.is_final_response() and ev.content and ev.content.parts:
                    report = ev.content.parts[0].text or report
            yield line({"event": "agent", "name": "narration", "status": "done"})
        except Exception:  # noqa: BLE001 — narration is best-effort
            yield line({"event": "agent", "name": "narration", "status": "skipped"})

    yield line({"event": "complete", "finding_count": len(findings),
                "findings": _findings_out(findings), "report_markdown": report,
                "changes": diff.summary() if diff is not None else None})


@app.post("/scan/stream")
async def scan_stream(req: ScanRequest) -> StreamingResponse:
    """Stream scan progress as newline-delimited JSON so the UI shows live work."""
    return StreamingResponse(_scan_events(req), media_type="application/x-ndjson")

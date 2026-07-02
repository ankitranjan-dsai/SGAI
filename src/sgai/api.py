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
from sgai.risk import apply_reachability, assess, build_import_graph

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
            findings = apply_reachability(findings, build_import_graph(str(root)))
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
            findings = apply_reachability(findings, build_import_graph(str(root)))
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


# --------------------------------------------------------------------------- #
# Code Playground: self-healing patch preview
# --------------------------------------------------------------------------- #
class HealRequest(BaseModel):
    code: str = ""  # a Python source file to patch
    deep: bool = False  # also consider Semgrep findings


class PatchOut(BaseModel):
    line: int
    rule: str
    description: str
    original_line: str
    patched_line: str


class HealResponse(BaseModel):
    original: str
    patched: str
    diff: str
    patches: list[PatchOut]


def _plan_submitted_code(code: str, deep: bool):
    """Run static analysis over a submitted snippet and plan AST-safe patches."""
    from sgai.fix import plan_code_patches

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "submitted.py").write_text(code)
        static_result = server.run_static_analysis("submitted.py", str(root))
        semgrep_result = server.run_semgrep("submitted.py", str(root)) if deep else None
        findings = assess({"vulnerable": []}, static_result, semgrep_result)
        plan = plan_code_patches(str(root), findings)
        patched = plan.new_contents.get("submitted.py", code)
        diff = plan.diff("submitted.py") if "submitted.py" in plan.new_contents else ""
        return findings, plan, patched, diff


@app.post("/heal", response_model=HealResponse)
def heal(req: HealRequest) -> HealResponse:
    """Preview the self-healing patches for a submitted Python snippet.

    Runs Bandit (and optionally Semgrep) over the code, maps findings to
    AST-safe refactorings, and returns the before/after text plus a unified
    diff for the side-by-side playground viewer. Nothing is executed; the
    snippet is written to a throwaway temp dir and discarded.
    """
    _findings, plan, patched, diff = _plan_submitted_code(req.code, req.deep)
    return HealResponse(
        original=req.code,
        patched=patched,
        diff=diff,
        patches=[
            PatchOut(
                line=p.line,
                rule=p.rule,
                description=p.description,
                original_line=p.original_line,
                patched_line=p.patched_line,
            )
            for p in plan.patches
        ],
    )


# --------------------------------------------------------------------------- #
# Commit Patch: write a validated patch into a sandboxed local project
# --------------------------------------------------------------------------- #
class CommitPatchRequest(BaseModel):
    root: str  # sandbox root: the local project directory being healed
    file_path: str  # file to patch, relative to root
    diff: str = ""  # unified diff to apply to the file's current content
    content: str = ""  # alternative: full replacement content
    run_tests: bool = True  # re-run validate_patch after committing


class CommitPatchResponse(BaseModel):
    committed: bool
    file: str
    validation: dict | None = None  # validate_patch output when run_tests is set


# Roots too broad to ever be a project sandbox — refuse them outright.
_FORBIDDEN_ROOTS = {Path("/"), Path.home()}


@app.post("/commit-patch", response_model=CommitPatchResponse)
def commit_patch(req: CommitPatchRequest) -> CommitPatchResponse:
    """Write a patch to a file inside a sandboxed local project root.

    The target path must resolve inside ``root`` via ``safe_resolve`` — path
    traversal and symlink escapes are rejected. The patch arrives either as a
    unified ``diff`` (applied strictly against the file's current content) or
    as full replacement ``content``. When ``run_tests`` is set, the project's
    own test suite is re-run through the sandboxed ``validate_patch`` tool so
    the caller immediately learns whether the committed fix is non-breaking.
    """
    from sgai.fix import DiffApplyError, apply_unified_diff
    from sgai.mcp_server.sandbox import SandboxError, safe_resolve

    root = Path(req.root).resolve()
    if not root.is_dir():
        raise HTTPException(status_code=400, detail=f"root {req.root!r} is not a directory")
    if root in _FORBIDDEN_ROOTS:
        raise HTTPException(status_code=400, detail="root is too broad to be a project sandbox")

    try:
        target = safe_resolve(str(root), req.file_path)
    except SandboxError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if req.diff.strip():
        if not target.is_file():
            raise HTTPException(status_code=400, detail=f"{req.file_path!r} is not a file")
        try:
            patched = apply_unified_diff(target.read_text(), req.diff)
        except DiffApplyError as exc:
            raise HTTPException(status_code=409, detail=f"diff does not apply: {exc}") from exc
        target.write_text(patched)
    elif req.content:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(req.content)
    else:
        raise HTTPException(status_code=400, detail="provide either a diff or content")

    validation = server.validate_patch(str(root)) if req.run_tests else None
    return CommitPatchResponse(
        committed=True, file=str(target.relative_to(root)), validation=validation
    )


# --------------------------------------------------------------------------- #
# Interactive Agent Chat (SSE): refine remediation patches conversationally
# --------------------------------------------------------------------------- #
class ChatRequest(BaseModel):
    code: str = ""
    message: str = ""
    history: list[dict] = []  # [{role, content}, …]
    deep: bool = False


_APPLY_INTENT = ("apply", "fix it", "go ahead", "do it", "patch it", "yes", "accept")


def _patch_summary(plan) -> str:
    if not plan.patches:
        return "No automatic patch applies to this code."
    return "\n".join(
        f"- line {p.line}: {p.description} (`{p.original_line.strip()}` → `{p.patched_line.strip()}`)"
        for p in plan.patches
    )


def _fallback_reply(message: str, plan, patched: str) -> tuple[str, bool]:
    """Deterministic remediation reply used when no LLM is configured.

    Returns ``(reply_text, includes_patch)`` — the second flag tells the UI to
    refresh the diff viewer with the patched code.
    """
    lowered = message.lower().strip()
    if not plan.patches:
        return (
            "I don't see an unsafe pattern I can auto-patch here. If you paste code "
            "with an eval(), yaml.load(), subprocess(shell=True), a weak hash, or a "
            "hardcoded secret, I'll propose a safe rewrite.",
            False,
        )
    if any(kw in lowered for kw in _APPLY_INTENT):
        return (
            "Done — I applied these AST-safe patches and the diff viewer now shows the "
            "result:\n" + _patch_summary(plan) + "\n\nEach rewrite preserves behavior; "
            "run your tests (or `sgai heal`) to confirm.",
            True,
        )
    return (
        "Here's what I'd change to make this safe:\n"
        + _patch_summary(plan)
        + "\n\nSay “apply” and I'll patch it, or ask me to explain any one of these.",
        False,
    )


async def _chat_events(req: ChatRequest):
    """Server-Sent-Events stream for the interactive remediation chat.

    Frames follow the SSE wire format (``data: <json>\\n\\n``). The model reply
    is streamed word-by-word so the UI types it out live; when a patch results,
    a final ``done`` frame carries the updated code and diff for the playground.
    """

    def sse(obj: dict) -> str:
        return f"data: {json.dumps(obj)}\n\n"

    _findings, plan, patched, diff = _plan_submitted_code(req.code, req.deep)
    summary = _patch_summary(plan)

    yield sse({"event": "start"})

    reply = ""
    includes_patch = False
    from sgai.agent_runner import refine_patch_chat

    try:
        reply = await refine_patch_chat(req.code, req.message, req.history, summary)
        includes_patch = "```" in reply  # the agent returned a code block
    except Exception:  # noqa: BLE001 — always answer, even with no model
        reply, includes_patch = _fallback_reply(req.message, plan, patched)

    # Stream the reply word-by-word for a live-typing feel.
    words = reply.split(" ")
    for i, word in enumerate(words):
        yield sse({"event": "token", "text": word + (" " if i < len(words) - 1 else "")})

    yield sse({
        "event": "done",
        "reply": reply,
        "applied_patch": includes_patch,
        "patched": patched if includes_patch else None,
        "diff": diff if includes_patch else None,
    })


@app.post("/chat")
async def chat(req: ChatRequest) -> StreamingResponse:
    """Chat with the remediation agent over SSE to refine patches dynamically."""
    return StreamingResponse(
        _chat_events(req),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

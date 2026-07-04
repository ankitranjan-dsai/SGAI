"""Risk scoring and normalization for SGAI.

Turns the raw output of the security MCP tools into a unified, de-duplicated,
risk-ranked list of :class:`~sgai.models.Finding` objects. This is the
deterministic core the report builder and the LLM agents both consume.

It also performs *dependency reachability analysis*: a static call graph of
first-party imports decides whether a vulnerable package is actually used by
the code. Reachable vulnerabilities get upgraded (they are exploitable today);
unreached ones get downgraded (real, but not on any execution path).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from sgai.models import Finding, Severity

# Bandit reports severity as a string; map it to our normalized scale.
_BANDIT_SEVERITY = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}

# Confidence weights, used only to break ties between equal-severity findings.
_CONFIDENCE_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Semgrep severities map onto our normalized scale.
_SEMGREP_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}

# Named severities used by the container/IaC and secret scanners.
_NAMED_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

# Concise remediation guidance for the Bandit tests our example surface triggers.
# Extend as coverage grows; unmapped tests fall back to the issue text.
_STATIC_REMEDIATION = {
    "B602": "Avoid shell=True; pass arguments as a list to subprocess.",
    "B307": "Replace eval() with ast.literal_eval() or an explicit parser.",
    "B506": "Use yaml.safe_load() instead of yaml.load().",
    "B105": "Move secrets to environment variables or a secrets manager.",
    "B101": "Do not rely on assert for security checks; raise explicitly.",
    "B404": "Review subprocess usage; ensure inputs are validated.",
}


def findings_from_static_analysis(result: dict) -> list[Finding]:
    """Convert ``run_static_analysis`` output into normalized findings."""
    findings: list[Finding] = []
    for r in result.get("findings", []):
        test_id = r.get("test_id", "?")
        severity = _BANDIT_SEVERITY.get((r.get("severity") or "").upper(), Severity.UNKNOWN)
        location = f"{r.get('file', '?')}:{r.get('line', '?')}"
        findings.append(
            Finding(
                id=test_id,
                source="static",
                title=r.get("issue", "Static analysis finding"),
                severity=severity,
                location=location,
                detail=r.get("issue", ""),
                remediation=_STATIC_REMEDIATION.get(test_id, "Review and remediate the flagged pattern."),
                confidence=(r.get("confidence") or "").upper(),
            )
        )
    return findings


def findings_from_semgrep(result: dict) -> list[Finding]:
    """Convert ``run_semgrep`` output into normalized findings (multi-language)."""
    findings: list[Finding] = []
    for r in result.get("findings", []):
        check_id = r.get("check_id") or "semgrep"
        severity = _SEMGREP_SEVERITY.get((r.get("severity") or "").upper(), Severity.LOW)
        message = (r.get("message") or check_id).strip()
        findings.append(
            Finding(
                id=check_id,
                source="semgrep",
                title=message[:140],
                severity=severity,
                location=f"{r.get('file', '?')}:{r.get('line', '?')}",
                detail=message,
                remediation="Review and fix the flagged pattern (see the Semgrep rule).",
            )
        )
    return findings


def findings_from_dependency_scan(result: dict) -> list[Finding]:
    """Convert ``scan_requirements_file`` output into normalized findings.

    The batch OSV query returns advisory IDs without CVSS, so a known CVE in a
    pinned dependency is treated as HIGH by default — a defensible floor, since
    an unpatched, publicly disclosed vulnerability is shipping in the build.
    """
    findings: list[Finding] = []
    for v in result.get("vulnerable", []):
        package, version = v.get("package", "?"), v.get("version", "?")
        ecosystem = v.get("ecosystem", "PyPI")
        ids = v.get("vuln_ids", [])
        findings.append(
            Finding(
                id=ids[0] if ids else f"{package}-vuln",
                source="dependency",
                title=f"{package} {version} ({ecosystem}) has {len(ids)} known vulnerabilit"
                + ("y" if len(ids) == 1 else "ies"),
                severity=Severity.HIGH,
                location=f"{ecosystem}:{package}@{version}",
                detail="Advisories: " + ", ".join(ids),
                remediation=f"Upgrade {package} to a patched version; review {ids[0] if ids else 'the advisories'}.",
                references=ids,
                manifest=v.get("manifest", ""),
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Dependency reachability
# --------------------------------------------------------------------------- #

# Directories that never hold first-party source.
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".uv"}

# PyPI distribution names whose import name differs beyond simple normalization.
_PACKAGE_MODULE_ALIASES = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "opencv-python": "cv2",
    "python-dateutil": "dateutil",
    "python-dotenv": "dotenv",
    "msgpack-python": "msgpack",
    "attrs": "attr",
    "setuptools": "pkg_resources",
}


# File-name patterns that mark a file as test code in each language.
_TEST_FILE_RE = re.compile(
    r"(?:^|[/\\])(?:test_[^/\\]*\.py|[^/\\]*_test\.(?:py|go)|conftest\.py"
    r"|[^/\\]*\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs))$"
)
# Directory segments that hold test/fixture code regardless of file naming.
# Example/demo directories count too: code there is shipped for illustration,
# never on a production execution path, so it must not gate a build.
_TEST_DIR_SEGMENTS = {
    "tests", "test", "__tests__", "spec", "specs", "fixtures", "mocks", "testdata", "e2e",
    "examples", "example", "samples", "sample", "demo", "demos",
}


def is_test_file(path: str) -> bool:
    """Classify a repo-relative path as test/fixture code (vs production code).

    Purely pattern-based so it works identically across languages: Python
    (``test_*.py``, ``*_test.py``, ``conftest.py``), Go (``*_test.go``), and
    JS/TS (``*.test.ts``, ``*.spec.js``), plus any file living under a
    conventional test or example directory (``tests/``, ``fixtures/``,
    ``examples/``…).
    """
    normalized = path.replace("\\", "/")
    if _TEST_FILE_RE.search(normalized):
        return True
    return bool(_TEST_DIR_SEGMENTS & {seg.lower() for seg in normalized.split("/")[:-1]})


# ---- per-language import extraction ----------------------------------------

_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# `import x from 'pkg'`, `import 'pkg'`, `import * as x from "pkg"`,
# `export { y } from 'pkg'` — the specifier is always the quoted string.
_JS_IMPORT = re.compile(
    r"""(?:^|\s)(?:import|export)\s+(?:[\w*\s{},$-]+?\s+from\s+)?['"]([^'"\n]+)['"]""",
    re.MULTILINE,
)
# CommonJS `require('pkg')` and dynamic `import('pkg')`.
_JS_REQUIRE = re.compile(r"""(?:require|import)\s*\(\s*['"]([^'"\n]+)['"]\s*\)""")

_GO_IMPORT_LINE = re.compile(r'^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"')
_GO_BLOCK_ENTRY = re.compile(r'^\s*(?:[\w.]+\s+)?"([^"]+)"')

_RUST_USE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([A-Za-z_][A-Za-z0-9_]*)")
_RUST_EXTERN = re.compile(r"^\s*extern\s+crate\s+([A-Za-z_][A-Za-z0-9_]*)")
# `use` roots that never name an external crate.
_RUST_FIRST_PARTY = {"crate", "self", "super", "std", "core", "alloc"}


def _python_imports(source: str) -> set[str]:
    """Top-level modules a Python file imports (absolute imports only)."""
    tree = ast.parse(source)  # SyntaxError propagates; the caller skips the file
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module.split(".")[0])
    return modules


def _js_package(specifier: str) -> str:
    """The npm package a specifier resolves to; relative paths stay verbatim."""
    if specifier.startswith("."):
        return specifier  # first-party relative import — resolved in the closure
    parts = specifier.split("/")
    if specifier.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2])  # scoped package: @scope/name
    return parts[0]


def _js_imports(source: str) -> set[str]:
    specs = {m.group(1) for m in _JS_IMPORT.finditer(source)}
    specs |= {m.group(1) for m in _JS_REQUIRE.finditer(source)}
    return {_js_package(s) for s in specs if s}


def _go_imports(source: str) -> set[str]:
    imports: set[str] = set()
    in_block = False
    for raw in source.splitlines():
        line = raw.split("//")[0].rstrip()
        if re.match(r"^\s*import\s*\(", line):
            in_block = True
            continue
        if in_block:
            if line.strip() == ")":
                in_block = False
                continue
            m = _GO_BLOCK_ENTRY.match(line)
        else:
            m = _GO_IMPORT_LINE.match(line)
        if m:
            imports.add(m.group(1))
    return imports


def _rust_imports(source: str) -> set[str]:
    crates: set[str] = set()
    for raw in source.splitlines():
        m = _RUST_USE.match(raw) or _RUST_EXTERN.match(raw)
        if m and m.group(1) not in _RUST_FIRST_PARTY:
            crates.add(m.group(1))
    return crates


def build_import_graph(repo_dir: str) -> dict[str, set[str]]:
    """Static import graph of first-party source: file → modules it imports.

    Multi-language: ``.py`` files are parsed with :mod:`ast` (top-level module
    per absolute import), JS/TS files via ``import``/``require()`` specifiers
    (npm package names; relative paths kept for the closure), ``.go`` files via
    single and block ``import`` forms (full module paths), and ``.rs`` files
    via ``use``/``extern crate`` roots. Vendored/venv directories are excluded
    and files that don't parse are skipped — reachability must never crash a
    scan.
    """
    root = Path(repo_dir).resolve()
    graph: dict[str, set[str]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _SKIP_DIRS & set(path.parts):
            continue
        suffix = path.suffix.lower()
        try:
            if suffix == ".py":
                modules = _python_imports(path.read_text())
            elif suffix in _JS_EXTENSIONS:
                modules = _js_imports(path.read_text())
            elif suffix == ".go":
                modules = _go_imports(path.read_text())
            elif suffix == ".rs":
                modules = _rust_imports(path.read_text())
            else:
                continue
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        if modules:
            graph[str(path.relative_to(root))] = modules
    return graph


# ---- transitive closure -----------------------------------------------------

def _first_party_index(graph: dict[str, set[str]]) -> dict[str, list[str]]:
    """Map a first-party Python module name to the files that define it."""
    index: dict[str, list[str]] = {}
    for file in graph:
        if not file.endswith(".py"):
            continue
        parts = file[:-3].replace("\\", "/").split("/")
        top = parts[0]
        if top in ("src", "lib") and len(parts) > 1:
            top = parts[1]  # src-layout: src/pkg/… is imported as pkg
        index.setdefault(top, []).append(file)
    return index


def _resolve_js_relative(spec: str, importer: str, files: set[str]) -> list[str]:
    """Resolve a relative JS/TS specifier to graph files, Node-style."""
    import posixpath

    base = posixpath.dirname(importer.replace("\\", "/"))
    target = posixpath.normpath(posixpath.join(base, spec))
    candidates = [target]
    candidates += [target + ext for ext in _JS_EXTENSIONS]
    candidates += [posixpath.join(target, "index" + ext) for ext in _JS_EXTENSIONS]
    return [c for c in candidates if c in files]


def transitive_import_closure(graph: dict[str, set[str]]) -> dict[str, set[str]]:
    """File → every module reachable through its first-party import chain.

    ``app.py`` importing ``util`` (a first-party module) whose file imports
    ``yaml`` means ``yaml`` is on ``app.py``'s execution path even though it
    never imports it directly. Computed as a fixed point: each file's effective
    import set absorbs the sets of the first-party files it imports until
    nothing changes.
    """
    index = _first_party_index(graph)
    files = set(graph)

    edges: dict[str, set[str]] = {}
    for file, mods in graph.items():
        deps: set[str] = set()
        for m in mods:
            if m.startswith("."):
                deps.update(_resolve_js_relative(m, file, files))
            else:
                deps.update(index.get(m, ()))
        deps.discard(file)
        edges[file] = deps

    closure = {f: set(mods) for f, mods in graph.items()}
    changed = True
    while changed:  # terminates: sets only grow, bounded by the module universe
        changed = False
        for file, deps in edges.items():
            for dep in deps:
                extra = closure[dep] - closure[file]
                if extra:
                    closure[file] |= extra
                    changed = True
    return closure


# ---- reachability scoring ---------------------------------------------------

def _module_candidates(package: str) -> set[str]:
    """Import names a PyPI distribution plausibly installs under."""
    lowered = package.lower()
    candidates = {lowered, lowered.replace("-", "_")}
    if lowered in _PACKAGE_MODULE_ALIASES:
        candidates.add(_PACKAGE_MODULE_ALIASES[lowered].lower())
    return candidates


# Which source-file extensions can produce evidence for each OSV ecosystem.
# Without at least one such file in the graph there is no reachability signal,
# and the finding is left untouched rather than wrongly downgraded.
_ECOSYSTEM_EXTENSIONS: dict[str, set[str]] = {
    "PyPI": {".py"},
    "npm": _JS_EXTENSIONS,
    "Go": {".go"},
    "crates.io": {".rs"},
}


def _ecosystem_candidates(ecosystem: str, package: str) -> set[str]:
    """Import identifiers under which a package appears in source."""
    if ecosystem == "PyPI":
        return _module_candidates(package)
    if ecosystem == "crates.io":
        lowered = package.lower()
        return {lowered, lowered.replace("-", "_")}  # crate foo-bar is used as foo_bar
    return {package.lower()}  # npm names / Go module paths


def _imports_match(ecosystem: str, candidates: set[str], imports: set[str]) -> bool:
    lowered = {m.lower() for m in imports}
    if ecosystem == "Go":
        # An import of module/subpkg reaches the module: prefix match.
        return any(i == c or i.startswith(c + "/") for c in candidates for i in lowered)
    return bool(candidates & lowered)


def apply_reachability(findings: list[Finding], graph: dict[str, set[str]]) -> list[Finding]:
    """Adjust dependency findings by whether — and from where — they are imported.

    The import graph is first expanded to its transitive closure, then split by
    :func:`is_test_file` into production and test-only import sets:

    * imported from **production** code → upgraded one level (the vulnerable
      code is on a real execution path today);
    * imported **only from test** code → downgraded one level (real, but not
      shipped on a production path);
    * **never imported** → downgraded one level (likely an unused dependency).

    Ecosystems with no matching source in the graph (e.g. an npm finding in a
    repo with no JS files) are left untouched — no signal, no adjustment.

    Returns the findings re-scored and re-ranked.
    """
    closure = transitive_import_closure(graph)
    languages = {Path(f).suffix.lower() for f in graph}
    prod_imports: set[str] = set()
    test_imports: set[str] = set()
    for file, mods in closure.items():
        (test_imports if is_test_file(file) else prod_imports).update(mods)

    for f in findings:
        if f.source != "dependency":
            continue
        # A pin that lives only in a test/example manifest is scoped to fixture
        # code by construction — production imports of the same module resolve
        # against the production manifest's (different) pin, not this one.
        if f.manifest and is_test_file(f.manifest):
            f.reachable = True
            f.reachability = "test_only"
            f.severity = Severity(max(int(f.severity) - 1, int(Severity.LOW)))
            f.confidence = "MEDIUM"
            f.detail = (f.detail + " " if f.detail else "") + (
                f"Reachability: pinned only by a test/example manifest ({f.manifest}) — "
                "not part of the production dependency set."
            )
            continue
        ecosystem, _, rest = f.location.partition(":")
        extensions = _ECOSYSTEM_EXTENSIONS.get(ecosystem)
        if not extensions or not (extensions & languages):
            continue  # no source in this language — no reachability signal
        package = rest.partition("@")[0]
        candidates = _ecosystem_candidates(ecosystem, package)
        if _imports_match(ecosystem, candidates, prod_imports):
            f.reachable = True
            f.reachability = "production"
            f.severity = Severity(min(int(f.severity) + 1, int(Severity.CRITICAL)))
            f.confidence = "HIGH"
            f.detail = (f.detail + " " if f.detail else "") + (
                "Reachability: first-party code imports this package — "
                "the vulnerable code is on an execution path."
            )
        elif _imports_match(ecosystem, candidates, test_imports):
            f.reachable = True
            f.reachability = "test_only"
            f.severity = Severity(max(int(f.severity) - 1, int(Severity.LOW)))
            f.confidence = "MEDIUM"
            f.detail = (f.detail + " " if f.detail else "") + (
                "Reachability: only test/fixture code imports this package — "
                "not on a production execution path (still worth upgrading)."
            )
        else:
            f.reachable = False
            f.reachability = "unreached"
            f.severity = Severity(max(int(f.severity) - 1, int(Severity.LOW)))
            f.confidence = "LOW"
            f.detail = (f.detail + " " if f.detail else "") + (
                "Reachability: no first-party import of this package found — "
                "likely an unused dependency (still worth removing or upgrading)."
            )
    return score_findings(findings)


def findings_from_container_scan(result: dict, location_file: str) -> list[Finding]:
    """Convert ``scan_dockerfile`` output into normalized findings."""
    findings: list[Finding] = []
    for r in result.get("findings", []):
        severity = _NAMED_SEVERITY.get((r.get("severity") or "").upper(), Severity.MEDIUM)
        findings.append(
            Finding(
                id=r.get("check_id", "SGAI-CONTAINER"),
                source="container",
                title=r.get("title", "Container misconfiguration"),
                severity=severity,
                location=f"{location_file}:{r.get('line', '?')}",
                detail=r.get("detail", ""),
                remediation=r.get("remediation", "Review the flagged configuration."),
            )
        )
    return findings


def findings_from_secret_scan(result: dict) -> list[Finding]:
    """Convert ``scan_secrets`` output into normalized findings.

    A live credential in production source is directly exploitable, so those
    floor at HIGH. Findings the scanner classified as test/mock/fixture context
    arrive as INFO — real matches, but not live production secrets. Each
    finding carries the scanner's deterministic ``rotation_urgency``.
    """
    findings: list[Finding] = []
    for r in result.get("findings", []):
        entropy = r.get("entropy")
        urgency = r.get("rotation_urgency")
        severity = _NAMED_SEVERITY.get((r.get("severity") or "HIGH").upper(), Severity.HIGH)
        detail = r.get("title", "Potential secret")
        if entropy is not None:
            detail += f" (masked: {r.get('match', '****')}, entropy {entropy})"
        if r.get("is_in_test_file"):
            detail += " Found in test/fixture context — downgraded to Info."
        if urgency:
            detail += f" Rotation urgency: {urgency}."
        if severity == Severity.INFO:
            remediation = (
                "Appears to be test/fixture data. Confirm it is not a real credential; "
                "if it ever was live, rotate it and replace the fixture with an "
                "obviously fake value."
            )
        else:
            remediation = (
                "Remove the secret from source, rotate it immediately, and load it "
                "from an environment variable or secrets manager."
            )
        findings.append(
            Finding(
                id=r.get("check_id", "SGAI-SECRET"),
                source="secret",
                title=r.get("title", "Potential leaked secret"),
                severity=severity,
                location=f"{r.get('file', '?')}:{r.get('line', '?')}",
                detail=detail,
                remediation=remediation,
                rotation_urgency=urgency,
            )
        )
    return findings


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Drop duplicate findings, keeping the highest-severity instance.

    Two findings are duplicates when they share an id and a location. On a
    severity tie, an instance pinned by a production manifest wins over one
    pinned by a test/example manifest, so a fixture duplicate can never mask
    a production dependency vulnerability.
    """

    def _fixture_pinned(f: Finding) -> bool:
        return bool(f.manifest) and is_test_file(f.manifest)

    best: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.id, f.location)
        cur = best.get(key)
        if (
            cur is None
            or f.severity > cur.severity
            or (f.severity == cur.severity and _fixture_pinned(cur) and not _fixture_pinned(f))
        ):
            best[key] = f
    return list(best.values())


def score_findings(findings: list[Finding]) -> list[Finding]:
    """Assign a risk score to each finding and return them ranked, highest first.

    The score is ``severity * 10`` plus a small confidence weight, so severity
    dominates while confidence breaks ties between equal-severity findings.
    """
    for f in findings:
        f.risk_score = int(f.severity) * 10 + _CONFIDENCE_WEIGHT.get(f.confidence, 0)
    return sorted(findings, key=lambda f: f.risk_score, reverse=True)


# --------------------------------------------------------------------------- #
# False-positive suppression
# --------------------------------------------------------------------------- #

def _finding_fingerprint(f: Finding) -> str:
    """The stable ``source:id:location`` fingerprint (mirrors memory.fingerprint)."""
    return f"{f.source}:{f.id}:{f.location}"


def is_finding_dismissed(finding: Finding, dismissals: dict) -> bool:
    """Whether ``finding`` matches a dismissal record.

    A finding is dismissed when its fingerprint is explicitly dismissed, or when
    it matches a dismissal *pattern* — every present key of ``source``,
    ``finding_id`` (exact), and ``location_glob`` (fnmatch) must match.
    """
    import fnmatch

    if _finding_fingerprint(finding) in dismissals.get("fingerprints", {}):
        return True
    for pattern in dismissals.get("patterns", []):
        if "source" in pattern and pattern["source"] != finding.source:
            continue
        if "finding_id" in pattern and pattern["finding_id"] != finding.id:
            continue
        if "location_glob" in pattern and not fnmatch.fnmatch(
            finding.location, pattern["location_glob"]
        ):
            continue
        return True
    return False


def suppress_dismissed(findings: list[Finding], dismissals: dict) -> list[Finding]:
    """Drop findings the team has dismissed as false positives.

    Called after scoring so suppression never changes how surviving findings are
    ranked. An empty/None dismissals record is a no-op.
    """
    if not dismissals or not (dismissals.get("fingerprints") or dismissals.get("patterns")):
        return findings
    return [f for f in findings if not is_finding_dismissed(f, dismissals)]


def severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Count findings by severity (only severities that appear)."""
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[0], reverse=True))


def assess(
    dependency_result: dict,
    static_result: dict,
    semgrep_result: dict | None = None,
    extra: list[Finding] | None = None,
) -> list[Finding]:
    """Full deterministic assessment: normalize, de-duplicate, and rank.

    Args:
        dependency_result: Output of the MCP ``scan_manifest`` tool.
        static_result: Output of the MCP ``run_static_analysis`` tool.
        semgrep_result: Optional output of the MCP ``run_semgrep`` tool.
        extra: Already-normalized findings from other scanners (container/IaC
            misconfigurations, leaked secrets) to fold into the same ranking.

    Returns:
        Risk-ranked, de-duplicated findings (highest risk first).
    """
    findings = findings_from_dependency_scan(dependency_result)
    findings += findings_from_static_analysis(static_result)
    if semgrep_result:
        findings += findings_from_semgrep(semgrep_result)
    if extra:
        findings += extra
    return score_findings(deduplicate(findings))

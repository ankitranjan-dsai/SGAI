"""Threat modeling: chain individual findings into end-to-end exploit paths.

A single finding is a weakness; an *exploit chain* is an attack. SGAI tags each
finding with the attacker *capability* it grants (code execution, secret
disclosure, path traversal, …) and matches those capabilities against a library
of chain templates. A path-traversal bug plus a hardcoded API key, for example,
becomes "read arbitrary files → recover the credential → authenticate as the
service" — a story a defender can prioritize.

The detection is fully deterministic (no LLM); the triage agent is separately
instructed to narrate these chains, and each chain renders to a Mermaid.js
graph embedded in the Markdown report.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from sgai.models import Finding, Severity

# Attacker capabilities a finding can grant. A finding may grant several.
CODE_EXEC = "code_execution"
CMD_INJECTION = "command_injection"
DESERIALIZATION = "unsafe_deserialization"
SECRET = "secret_exposure"
PATH_TRAVERSAL = "path_traversal"
SQL_INJECTION = "sql_injection"
WEAK_CRYPTO = "weak_crypto"
INSECURE_TRANSPORT = "insecure_transport"
SSRF = "ssrf"
VULN_DEP = "vulnerable_dependency"

# Bandit test id → capabilities it grants.
_BANDIT_CAPABILITIES: dict[str, set[str]] = {
    "B102": {CODE_EXEC},  # exec()
    "B307": {CODE_EXEC},  # eval()
    "B301": {DESERIALIZATION, CODE_EXEC},  # pickle
    "B506": {DESERIALIZATION, CODE_EXEC},  # yaml.load
    "B602": {CMD_INJECTION, CODE_EXEC},  # subprocess shell=True
    "B603": {CMD_INJECTION},
    "B604": {CMD_INJECTION, CODE_EXEC},
    "B605": {CMD_INJECTION, CODE_EXEC},  # os.system
    "B609": {CMD_INJECTION},
    "B105": {SECRET},  # hardcoded password string
    "B106": {SECRET},  # hardcoded password func arg
    "B107": {SECRET},  # hardcoded password default
    "B303": {WEAK_CRYPTO},  # md5/sha1
    "B324": {WEAK_CRYPTO},  # weak hash
    "B501": {INSECURE_TRANSPORT},  # requests verify=False
    "B502": {INSECURE_TRANSPORT},  # ssl bad version
    "B608": {SQL_INJECTION},  # SQL string building
    "B310": {SSRF},  # urllib urlopen
    "B321": {SSRF},  # ftplib
}

# Substrings matched against a finding's id/title for scanners other than Bandit
# (Semgrep check ids, dependency titles) whose ids we don't enumerate.
_KEYWORD_CAPABILITIES: list[tuple[str, str]] = [
    ("traversal", PATH_TRAVERSAL),
    ("path-injection", PATH_TRAVERSAL),
    ("zip-slip", PATH_TRAVERSAL),
    ("ssrf", SSRF),
    ("server-side-request", SSRF),
    ("sql", SQL_INJECTION),
    ("command-injection", CMD_INJECTION),
    ("os-command", CMD_INJECTION),
    ("code-injection", CODE_EXEC),
    ("eval", CODE_EXEC),
    ("deserial", DESERIALIZATION),
    ("pickle", DESERIALIZATION),
    ("yaml", DESERIALIZATION),
    ("hardcoded", SECRET),
    ("secret", SECRET),
    ("api-key", SECRET),
    ("credential", SECRET),
    ("md5", WEAK_CRYPTO),
    ("sha1", WEAK_CRYPTO),
    ("weak-hash", WEAK_CRYPTO),
    ("verify=false", INSECURE_TRANSPORT),
    ("tls", INSECURE_TRANSPORT),
]


def capabilities_of(finding: Finding) -> set[str]:
    """The attacker capabilities a single finding grants."""
    caps: set[str] = set()
    if finding.source == "dependency":
        caps.add(VULN_DEP)
    caps |= _BANDIT_CAPABILITIES.get(finding.id, set())
    haystack = f"{finding.id} {finding.title} {finding.detail}".lower()
    for needle, cap in _KEYWORD_CAPABILITIES:
        if needle in haystack:
            caps.add(cap)
    return caps


# --------------------------------------------------------------------------- #
# Internet-facing entry-point detection
# --------------------------------------------------------------------------- #

# Path fragments that mark a file as an externally reachable entry point: an
# HTTP route/handler, an API surface, or a process main. A chain that begins on
# one of these is reachable by an unauthenticated attacker, so it is worse.
_INTERNET_FACING_RE = re.compile(
    r"(?:^|[/_\-.])(?:api|apis|routes?|routers?|controllers?|handlers?|views?"
    r"|endpoints?|main|app|server|wsgi|asgi|urls|graphql|webhooks?)(?:[/_\-.]|$)"
)


def is_internet_facing(location: str) -> bool:
    """Whether a finding's file path looks like an internet-facing entry point."""
    file = location.replace("\\", "/").rsplit(":", 1)[0]  # strip trailing :line
    return any(_INTERNET_FACING_RE.search(seg.lower()) for seg in file.split("/"))


def mark_internet_facing(findings: list[Finding]) -> list[Finding]:
    """Tag each code finding with whether it sits on an internet-facing file."""
    for f in findings:
        if f.source in ("static", "semgrep", "secret") and ":" in f.location:
            f.internet_facing = is_internet_facing(f.location)
    return findings


@dataclass(frozen=True)
class ChainTemplate:
    """A named attack pattern: an ordered list of capability slots to fill."""

    name: str
    slots: tuple[tuple[str, ...], ...]  # each slot lists acceptable capabilities
    impact: str
    narrative: str


# Ordered chain templates. Each slot is a tuple of acceptable capabilities; a
# chain matches only when every slot can be filled by a *distinct* finding.
_CHAIN_TEMPLATES: list[ChainTemplate] = [
    ChainTemplate(
        name="Path traversal → credential disclosure",
        slots=((PATH_TRAVERSAL,), (SECRET,)),
        impact="Unauthenticated read of arbitrary files, then recovery of the hardcoded credential.",
        narrative=(
            "An attacker abuses the path-traversal flaw to read files outside the intended "
            "directory, locates the source containing the hardcoded secret, and authenticates "
            "as the service."
        ),
    ),
    ChainTemplate(
        name="Arbitrary code execution → credential exfiltration",
        slots=((CODE_EXEC, CMD_INJECTION), (SECRET,)),
        impact="Remote code execution that exfiltrates the in-process secret for lateral movement.",
        narrative=(
            "The code-execution primitive lets an attacker run arbitrary code in the process, "
            "read the hardcoded secret from memory or source, and pivot to other systems with it."
        ),
    ),
    ChainTemplate(
        name="Unsafe deserialization → remote code execution",
        slots=((DESERIALIZATION,), (CMD_INJECTION, CODE_EXEC, VULN_DEP)),
        impact="A malicious payload is deserialized into a live code-execution gadget.",
        narrative=(
            "Untrusted input reaches an unsafe deserializer; combined with a reachable command "
            "or code-execution sink, the attacker turns a crafted document into remote code "
            "execution."
        ),
    ),
    ChainTemplate(
        name="Reachable vulnerable dependency → code execution",
        slots=((VULN_DEP,), (CODE_EXEC, CMD_INJECTION, DESERIALIZATION)),
        impact="A known CVE in an imported package is reachable through an unsafe code path.",
        narrative=(
            "First-party code imports the vulnerable package and feeds it into a dangerous sink, "
            "so the published CVE is exploitable in this application rather than merely present."
        ),
    ),
    ChainTemplate(
        name="SQL injection → weakly hashed credential theft",
        slots=((SQL_INJECTION,), (WEAK_CRYPTO,)),
        impact="Injected queries dump password hashes that weak hashing makes trivial to crack.",
        narrative=(
            "The injection lets an attacker read the credentials table; because the hashes use a "
            "broken algorithm, the plaintext passwords fall in minutes."
        ),
    ),
    ChainTemplate(
        name="Insecure transport → credential interception",
        slots=((INSECURE_TRANSPORT,), (SECRET,)),
        impact="Credentials travel over an unverified TLS channel and can be intercepted.",
        narrative=(
            "With certificate verification disabled, a network attacker man-in-the-middles the "
            "connection and captures the credential in transit."
        ),
    ),
    ChainTemplate(
        name="SSRF → internal credential disclosure",
        slots=((SSRF,), (SECRET,)),
        impact="Server-side requests reach internal metadata endpoints and leak credentials.",
        narrative=(
            "The SSRF primitive lets an attacker coerce the server into requesting internal URLs "
            "(e.g. cloud metadata), harvesting credentials that the hardcoded-secret flaw confirms "
            "are trusted by the app."
        ),
    ),
]


# All capability constants, keyed by name, so custom templates in JSON can
# reference them symbolically (e.g. "PATH_TRAVERSAL") or by their string value.
_CAPABILITY_ALIASES: dict[str, str] = {
    name: value
    for name, value in globals().items()
    if name.isupper() and isinstance(value, str) and not name.startswith("_")
}


def _resolve_capability(token: str) -> str:
    """Map a JSON slot token onto a known capability string."""
    token = token.strip()
    return _CAPABILITY_ALIASES.get(token.upper(), token.lower())


def load_custom_chains(repo_dir: str) -> list[ChainTemplate]:
    """Load user-defined chain templates from ``custom_chains.json`` in the repo.

    The file (repo root) is a JSON array of objects with ``name``, ``slots``
    (a list of lists of capability tokens), ``impact``, and ``narrative``. Slot
    tokens may be capability constant names (``"PATH_TRAVERSAL"``) or their
    string values (``"path_traversal"``). A missing or malformed file yields no
    templates — a bad custom file must never crash threat modeling.
    """
    path = Path(repo_dir) / "custom_chains.json"
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(raw, list):
        return []

    templates: list[ChainTemplate] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        slots_raw = entry.get("slots")
        if not name or not isinstance(slots_raw, list) or not slots_raw:
            continue
        slots: list[tuple[str, ...]] = []
        for slot in slots_raw:
            options = [slot] if isinstance(slot, str) else slot
            if not isinstance(options, list):
                continue
            resolved = tuple(_resolve_capability(str(o)) for o in options if str(o).strip())
            if resolved:
                slots.append(resolved)
        if len(slots) < 2:
            continue  # a chain needs at least two links
        templates.append(
            ChainTemplate(
                name=str(name),
                slots=tuple(slots),
                impact=str(entry.get("impact", "")),
                narrative=str(entry.get("narrative", "")),
            )
        )
    return templates


@dataclass
class ExploitChain:
    """A matched multi-finding attack path."""

    name: str
    impact: str
    narrative: str
    severity: Severity
    findings: list[Finding] = field(default_factory=list)
    # True when the first link sits on an internet-facing entry point.
    internet_facing: bool = False

    @property
    def recommended_fix_order(self) -> list[dict]:
        """Which link to fix first to break the chain, ranked.

        Fixing any single link breaks the chain, so the cheapest, highest-
        leverage link should go first. We rank by: internet-facing entry points
        first (cut the attacker's entry), then higher severity, then earlier
        position in the chain. Each entry is JSON-friendly for the API/UI.
        """
        ordered = sorted(
            enumerate(self.findings),
            key=lambda pair: (
                not pair[1].internet_facing,          # entry points first
                -int(pair[1].severity),               # then most severe
                pair[0],                              # then earliest link
            ),
        )
        return [
            {
                "rank": rank,
                "step": idx + 1,
                "id": f.id,
                "location": f.location,
                "title": f.title,
                "severity": f.severity.label,
                "internet_facing": f.internet_facing,
                "reason": (
                    "Internet-facing entry point — fixing it removes the attacker's "
                    "unauthenticated foothold."
                    if f.internet_facing
                    else "Highest-severity link remaining; fixing it breaks the chain."
                ),
            }
            for rank, (idx, f) in enumerate(ordered, 1)
        ]

    def mermaid(self) -> str:
        """Render the chain as a Mermaid left-to-right flow graph."""
        lines = ["graph LR", "    attacker([\"🧑‍💻 Attacker\"])"]
        prev = "attacker"
        for i, f in enumerate(self.findings):
            node = f"step{i}"
            label = _mermaid_label(f"{i + 1}. {f.title}", f.location)
            lines.append(f'    {node}["{label}"]')
            lines.append(f"    {prev} --> {node}")
            prev = node
        impact_label = _mermaid_label("💥 " + self.impact, "")
        lines.append(f'    impact[["{impact_label}"]]')
        lines.append(f"    {prev} --> impact")
        return "\n".join(lines)


# Characters that break Mermaid node labels even inside quotes.
_MERMAID_UNSAFE = re.compile(r'["\[\]{}|<>()#]')


def _mermaid_label(text: str, location: str) -> str:
    """Sanitize free text into a single-line, Mermaid-safe node label."""
    body = _MERMAID_UNSAFE.sub("", text).strip()
    body = re.sub(r"\s+", " ", body)
    if len(body) > 70:
        body = body[:67].rstrip() + "…"
    if location:
        loc = _MERMAID_UNSAFE.sub("", location)
        return f"{body}<br/><small>{loc}</small>"
    return body


def _severity_of(findings: list[Finding], internet_facing: bool = False) -> Severity:
    """A chain is at least as severe as its worst link, bumped one level.

    An internet-facing entry point earns an extra bump: the chain is reachable
    without a prior foothold, so it is materially more dangerous.
    """
    worst = max((f.severity for f in findings), default=Severity.MEDIUM)
    bump = 2 if internet_facing else 1
    return Severity(min(int(worst) + bump, int(Severity.CRITICAL)))


def detect_exploit_chains(
    findings: list[Finding], repo_dir: str | None = None
) -> list[ExploitChain]:
    """Match findings against the chain templates, highest-severity chains first.

    Each finding is tagged with the capabilities it grants; a template matches
    when every slot can be filled by a distinct finding. Within a template we
    greedily assign the highest-severity unused finding to each slot, so the
    most dangerous instance of each capability anchors the chain. When the
    chain's first link sits on an internet-facing entry point, its severity is
    bumped an extra level.

    Args:
        findings: The findings to correlate. They are tagged in place with
            ``internet_facing``.
        repo_dir: When given, user-defined templates from ``custom_chains.json``
            in the repo root are appended to the built-in library.
    """
    mark_internet_facing(findings)
    tagged = [(f, capabilities_of(f)) for f in findings]
    chains: list[ExploitChain] = []

    templates = list(_CHAIN_TEMPLATES)
    if repo_dir:
        templates += load_custom_chains(repo_dir)

    for template in templates:
        used: set[int] = set()
        picked: list[Finding] = []
        ok = True
        for slot in template.slots:
            slot_caps = set(slot)
            candidates = [
                (idx, f)
                for idx, (f, caps) in enumerate(tagged)
                if idx not in used and (caps & slot_caps)
            ]
            if not candidates:
                ok = False
                break
            idx, chosen = max(candidates, key=lambda pair: int(pair[1].severity))
            used.add(idx)
            picked.append(chosen)
        if ok and len(picked) >= 2:
            entry_facing = picked[0].internet_facing
            chains.append(
                ExploitChain(
                    name=template.name,
                    impact=template.impact,
                    narrative=template.narrative,
                    severity=_severity_of(picked, internet_facing=entry_facing),
                    findings=picked,
                    internet_facing=entry_facing,
                )
            )

    chains.sort(key=lambda c: int(c.severity), reverse=True)
    return chains


def render_threat_section(chains: list[ExploitChain]) -> list[str]:
    """Render matched exploit chains as a Markdown section with Mermaid graphs."""
    if not chains:
        return []
    lines = [
        "## Threat Model & Exploit Chains",
        "",
        (
            f"SGAI correlated the findings into **{len(chains)} exploit "
            f"chain{'s' if len(chains) != 1 else ''}** — attack paths where individual "
            "weaknesses combine into a materially worse outcome. Fixing any single link "
            "breaks the chain."
        ),
        "",
    ]
    for i, chain in enumerate(chains, 1):
        entry = " · 🌐 internet-facing entry point" if chain.internet_facing else ""
        lines += [
            f"### {i}. {chain.name} ({chain.severity.label}){entry}",
            "",
            chain.narrative,
            "",
            "```mermaid",
            chain.mermaid(),
            "```",
            "",
            f"**Impact:** {chain.impact}",
            "",
            "**Chain links:**",
            "",
        ]
        for f in chain.findings:
            flag = " 🌐" if f.internet_facing else ""
            lines.append(f"- `{f.location}` — {f.title} ({f.severity.label}){flag}")
        lines += ["", "**Recommended fix order (break the chain):**", ""]
        for step in chain.recommended_fix_order:
            lines.append(
                f"{step['rank']}. `{step['location']}` — {step['id']} "
                f"({step['severity']}) — {step['reason']}"
            )
        lines.append("")
    return lines

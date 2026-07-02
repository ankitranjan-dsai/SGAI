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

import re
from dataclasses import dataclass, field

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


@dataclass
class ExploitChain:
    """A matched multi-finding attack path."""

    name: str
    impact: str
    narrative: str
    severity: Severity
    findings: list[Finding] = field(default_factory=list)

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


def _severity_of(findings: list[Finding]) -> Severity:
    """A chain is at least as severe as its worst link, bumped one level."""
    worst = max((f.severity for f in findings), default=Severity.MEDIUM)
    return Severity(min(int(worst) + 1, int(Severity.CRITICAL)))


def detect_exploit_chains(findings: list[Finding]) -> list[ExploitChain]:
    """Match findings against the chain templates, highest-severity chains first.

    Each finding is tagged with the capabilities it grants; a template matches
    when every slot can be filled by a distinct finding. Within a template we
    greedily assign the highest-severity unused finding to each slot, so the
    most dangerous instance of each capability anchors the chain.
    """
    tagged = [(f, capabilities_of(f)) for f in findings]
    chains: list[ExploitChain] = []

    for template in _CHAIN_TEMPLATES:
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
            chains.append(
                ExploitChain(
                    name=template.name,
                    impact=template.impact,
                    narrative=template.narrative,
                    severity=_severity_of(picked),
                    findings=picked,
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
        lines += [
            f"### {i}. {chain.name} ({chain.severity.label})",
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
            lines.append(f"- `{f.location}` — {f.title} ({f.severity.label})")
        lines.append("")
    return lines

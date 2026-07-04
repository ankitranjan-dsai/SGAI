"""Typosquatting detection for dependency names (deterministic, zero-LLM).

Supply-chain attackers publish packages whose names are one keystroke away from
a popular library — ``requests2``, ``crypt0graphy``, ``python3-dateutil`` — hoping
a typo pulls their code into a build before any CVE is ever filed. SGAI catches
these *before* they have advisories by comparing every declared dependency name
against a curated list of high-traffic packages and flagging near-misses.

Detection is pure string analysis (edit distance, homoglyph normalization,
affix stripping) — no network, no LLM — so it runs in the same deterministic
fast path as the rest of SGAI's detection.
"""

from __future__ import annotations

from sgai.models import Finding, Severity

# Curated high-traffic package names per ecosystem. A dependency that is a
# near-miss of one of these — but not itself on the list — is suspicious.
POPULAR_PACKAGES: dict[str, set[str]] = {
    "PyPI": {
        "requests", "urllib3", "numpy", "pandas", "flask", "django", "jinja2",
        "pyyaml", "cryptography", "setuptools", "boto3", "scipy", "click",
        "certifi", "six", "python-dateutil", "pytz", "wheel", "pillow",
        "sqlalchemy", "redis", "celery", "pytest", "aiohttp", "fastapi",
        "pydantic", "tensorflow", "torch", "scikit-learn", "matplotlib",
        "beautifulsoup4", "lxml", "openpyxl", "colorama", "tqdm", "packaging",
        "attrs", "idna", "charset-normalizer", "werkzeug", "httpx", "starlette",
    },
    "npm": {
        "lodash", "react", "react-dom", "express", "axios", "chalk", "commander",
        "debug", "request", "moment", "async", "bluebird", "underscore", "webpack",
        "jquery", "vue", "typescript", "eslint", "mocha", "uuid", "dotenv",
        "next", "socket.io", "body-parser", "cors", "mongoose", "redux", "rxjs",
    },
}

# Digits that impersonate letters, for homoglyph normalization.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})

# Affixes commonly appended to a legitimate name to squat it.
_SUSPICIOUS_AFFIXES = ("2", "3", "-js", "js", "-py", "py", "-python", "python", "-", "_")


def levenshtein(a: str, b: str) -> int:
    """Edit distance between two strings (iterative DP, O(len(a)·len(b)))."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                prev[j] + 1,        # deletion
                cur[j - 1] + 1,     # insertion
                prev[j - 1] + (ca != cb),  # substitution
            ))
        prev = cur
    return prev[-1]


def _normalize(name: str) -> str:
    """Lowercase and collapse PyPI's dash/underscore/dot equivalence."""
    return name.lower().replace("_", "-").replace(".", "-")


def _affix_stripped(name: str) -> str:
    """Strip a single suspicious affix, e.g. ``requests2`` → ``requests``."""
    for affix in _SUSPICIOUS_AFFIXES:
        if name.startswith(affix) and len(name) > len(affix) + 2:
            return name[len(affix):]
        if name.endswith(affix) and len(name) > len(affix) + 2:
            return name[: -len(affix)]
    return name


def _is_adjacent_transposition(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ only by swapping two adjacent characters."""
    if len(a) != len(b):
        return False
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    return (
        len(diffs) == 2
        and diffs[1] == diffs[0] + 1
        and a[diffs[0]] == b[diffs[1]]
        and a[diffs[1]] == b[diffs[0]]
    )


def _match_reason(name: str, popular: str) -> str | None:
    """Why ``name`` looks like a squat of ``popular`` — or None if it doesn't.

    Checks are ordered most-specific-first so the reported reason is the most
    informative one (a digit-for-letter swap is reported as a homoglyph even
    though it is also technically a single edit).
    """
    n, p = _normalize(name), _normalize(popular)
    if n == p:
        return None  # exact match: this *is* the popular package
    if n.translate(_HOMOGLYPHS) == p.translate(_HOMOGLYPHS):
        return "homoglyph substitution (digits impersonating letters)"
    if _is_adjacent_transposition(n, p):
        return "adjacent characters transposed"
    if levenshtein(n, p) == 1:
        return "one edit away"
    if _normalize(_affix_stripped(n)) == p:
        return "popular name with an added prefix/suffix"
    return None


def find_typosquats(packages: list[dict]) -> list[dict]:
    """Flag declared packages whose names are near-misses of popular ones.

    ``packages`` is a list of ``{name, version, ecosystem}``. Names already on
    the popular list (and names under 3 chars, too short to squat meaningfully)
    are never flagged. Returns ``{name, version, ecosystem, target, reason}``.
    """
    suspects: list[dict] = []
    for pkg in packages:
        ecosystem = pkg.get("ecosystem", "")
        popular = POPULAR_PACKAGES.get(ecosystem)
        if not popular:
            continue  # ecosystem uses full module paths, not bare squattable names
        name = pkg.get("name", "")
        norm = _normalize(name)
        if len(norm) < 3 or norm in {_normalize(p) for p in popular}:
            continue
        for target in popular:
            reason = _match_reason(name, target)
            if reason is not None:
                suspects.append({
                    "name": name,
                    "version": pkg.get("version", "?"),
                    "ecosystem": ecosystem,
                    "target": target,
                    "reason": reason,
                })
                break  # one confident match is enough
    return suspects


def findings_from_typosquats(suspects: list[dict]) -> list[Finding]:
    """Normalize typosquat suspects into HIGH-severity :class:`Finding` objects."""
    findings: list[Finding] = []
    for s in suspects:
        findings.append(Finding(
            id=f"typosquat-{s['name']}",
            source="typosquat",
            title=f"Possible typosquat of '{s['target']}' ({s['reason']})",
            severity=Severity.HIGH,
            location=f"{s['ecosystem']}:{s['name']}@{s['version']}",
            detail=(
                f"The dependency '{s['name']}' closely resembles the popular package "
                f"'{s['target']}' ({s['reason']}). Typosquatted packages are a common "
                "supply-chain attack vector and often have no CVE yet."
            ),
            remediation=(
                f"Confirm '{s['name']}' is the package you intended. If you meant "
                f"'{s['target']}', correct the name; otherwise verify the publisher."
            ),
        ))
    return findings


def scan_typosquats(repo_dir: str) -> list[Finding]:
    """Collect a repo's declared dependencies and flag typosquat suspects."""
    from sgai.sbom import collect_packages

    return findings_from_typosquats(find_typosquats(collect_packages(repo_dir)))

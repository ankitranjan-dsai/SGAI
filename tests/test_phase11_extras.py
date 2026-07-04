"""Follow-up features: typosquat detection, tri-state reachability, numbered fix order."""

from sgai.models import Finding, Severity
from sgai.risk import apply_reachability, build_import_graph
from sgai.threats import detect_exploit_chains
from sgai.typosquat import (
    find_typosquats,
    findings_from_typosquats,
    levenshtein,
    scan_typosquats,
)


# --------------------------------------------------------------------------- #
# #15 Typosquatting detector
# --------------------------------------------------------------------------- #
def test_levenshtein_distance():
    assert levenshtein("requests", "requests") == 0
    assert levenshtein("requests", "requsts") == 1  # deletion
    assert levenshtein("requests", "requests2") == 1  # insertion
    assert levenshtein("lodash", "lodahs") == 2


def test_detects_one_edit_typosquat():
    suspects = find_typosquats([{"name": "requsts", "version": "1.0", "ecosystem": "PyPI"}])
    assert len(suspects) == 1
    assert suspects[0]["target"] == "requests"
    assert "edit" in suspects[0]["reason"]


def test_detects_affix_typosquat():
    suspects = find_typosquats([{"name": "requests2", "version": "1.0", "ecosystem": "PyPI"}])
    assert suspects and suspects[0]["target"] == "requests"


def test_detects_homoglyph_typosquat():
    # crypt0graphy → cryptography (0 impersonating o)
    suspects = find_typosquats([{"name": "crypt0graphy", "version": "1.0", "ecosystem": "PyPI"}])
    assert suspects and suspects[0]["target"] == "cryptography"
    assert "homoglyph" in suspects[0]["reason"]


def test_legitimate_package_not_flagged():
    assert find_typosquats([{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}]) == []


def test_unrelated_package_not_flagged():
    assert find_typosquats([{"name": "my-internal-lib", "version": "1.0", "ecosystem": "PyPI"}]) == []


def test_short_names_not_flagged():
    # Too short to squat meaningfully; avoids noise.
    assert find_typosquats([{"name": "os", "version": "1.0", "ecosystem": "PyPI"}]) == []


def test_npm_typosquat():
    suspects = find_typosquats([{"name": "lodahs", "version": "1.0", "ecosystem": "npm"}])
    assert suspects and suspects[0]["target"] == "lodash"


def test_ecosystem_without_list_skipped():
    # Go/crates use full module paths — not covered by bare-name squat detection.
    assert find_typosquats([{"name": "gin", "version": "1.0", "ecosystem": "Go"}]) == []


def test_findings_from_typosquats_shape():
    findings = findings_from_typosquats([
        {"name": "requsts", "version": "1.0", "ecosystem": "PyPI",
         "target": "requests", "reason": "one edit away"},
    ])
    f = findings[0]
    assert f.source == "typosquat"
    assert f.severity == Severity.HIGH
    assert f.location == "PyPI:requsts@1.0"
    assert "requests" in f.title


def test_scan_typosquats_reads_manifest(tmp_path):
    (tmp_path / "requirements.txt").write_text("requsts==1.0\nflask==2.0\n")
    findings = scan_typosquats(str(tmp_path))
    names = {f.id for f in findings}
    assert "typosquat-requsts" in names
    assert not any("flask" in n for n in names)  # flask is legitimate


def test_typosquat_surfaces_in_full_scan(tmp_path):
    import asyncio

    from sgai.runner import gather_findings

    (tmp_path / "requirements.txt").write_text("requsts==1.0\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    findings = asyncio.run(gather_findings(str(tmp_path)))
    assert any(f.source == "typosquat" for f in findings)


# --------------------------------------------------------------------------- #
# #3 Tri-state reachability field
# --------------------------------------------------------------------------- #
def _dep(package, ecosystem="PyPI"):
    return Finding(
        id=f"GHSA-{package}", source="dependency", title=f"{package} vuln",
        severity=Severity.HIGH, location=f"{ecosystem}:{package}@1.0.0",
    )


def test_reachability_field_production(tmp_path):
    (tmp_path / "app.py").write_text("import jinja2\n")
    ranked = apply_reachability([_dep("jinja2")], build_import_graph(str(tmp_path)))
    assert ranked[0].reachability == "production"
    assert ranked[0].reachable is True


def test_reachability_field_test_only(tmp_path):
    (tmp_path / "test_app.py").write_text("import jinja2\n")
    ranked = apply_reachability([_dep("jinja2")], build_import_graph(str(tmp_path)))
    assert ranked[0].reachability == "test_only"
    assert ranked[0].reachable is True  # bool back-compat preserved


def test_reachability_field_unreached(tmp_path):
    (tmp_path / "app.py").write_text("import os\n")
    ranked = apply_reachability([_dep("jinja2")], build_import_graph(str(tmp_path)))
    assert ranked[0].reachability == "unreached"
    assert ranked[0].reachable is False


def test_reachability_field_none_without_signal(tmp_path):
    (tmp_path / "app.py").write_text("import os\n")
    # npm finding in a Python-only repo → no signal, field stays None.
    ranked = apply_reachability([_dep("lodash", "npm")], build_import_graph(str(tmp_path)))
    assert ranked[0].reachability is None
    assert ranked[0].reachable is None


# --------------------------------------------------------------------------- #
# #7 Numbered fix-order in the Mermaid graph
# --------------------------------------------------------------------------- #
def _static(id, title, location, sev=Severity.HIGH):
    return Finding(id=id, source="static", title=title, severity=sev, location=location)


def test_mermaid_annotates_fix_rank():
    chains = detect_exploit_chains([
        _static("path-traversal", "traversal", "lib/files.py:20", Severity.HIGH),
        _static("B105", "secret", "api/config.py:5", Severity.LOW),
    ])
    chain = next(c for c in chains if c.name.startswith("Path traversal"))
    mermaid = chain.mermaid()
    # The internet-facing api/config.py link is fix #1 and must be tagged.
    assert "🔧1" in mermaid
    assert "🔧2" in mermaid
    # Still a well-formed graph.
    assert mermaid.startswith("graph LR")
    assert mermaid.count("-->") == len(chain.findings) + 1

"""Phase 4: custom chains, fix order, internet-facing weighting, Mermaid to LLM."""

import json

from sgai.models import Finding, Severity
from sgai.threats import (
    detect_exploit_chains,
    is_internet_facing,
    load_custom_chains,
    mark_internet_facing,
    render_threat_section,
)


def _static(test_id: str, title: str, location: str, severity=Severity.HIGH) -> Finding:
    return Finding(
        id=test_id, source="static", title=title, severity=severity, location=location
    )


# --------------------------------------------------------------------------- #
# Internet-facing entry points
# --------------------------------------------------------------------------- #
def test_internet_facing_paths():
    assert is_internet_facing("api/users.py:10")
    assert is_internet_facing("app/routes/auth.py:3")
    assert is_internet_facing("main.py:1")
    assert is_internet_facing("cmd/server/main.go:20")
    assert is_internet_facing("src/handlers/webhook.js:5")
    assert not is_internet_facing("lib/crypto/hash.py:2")
    assert not is_internet_facing("utils/helpers.py:9")


def test_mark_internet_facing_tags_findings():
    findings = [
        _static("B307", "eval", "api/handler.py:5"),
        _static("B105", "secret", "lib/util.py:9"),
    ]
    mark_internet_facing(findings)
    assert findings[0].internet_facing is True
    assert findings[1].internet_facing is False


def test_internet_facing_entry_bumps_chain_severity():
    on_edge = detect_exploit_chains([
        _static("path-traversal", "traversal", "api/files.py:20", Severity.MEDIUM),
        _static("B105", "secret", "api/files.py:5", Severity.MEDIUM),
    ])
    internal = detect_exploit_chains([
        _static("path-traversal", "traversal", "lib/files.py:20", Severity.MEDIUM),
        _static("B105", "secret", "lib/files.py:5", Severity.MEDIUM),
    ])
    edge_chain = next(c for c in on_edge if c.name.startswith("Path traversal"))
    internal_chain = next(c for c in internal if c.name.startswith("Path traversal"))
    # MEDIUM worst link: internet-facing gets +2 (HIGH... capped) vs +1 internal.
    assert int(edge_chain.severity) > int(internal_chain.severity)
    assert edge_chain.internet_facing is True
    assert internal_chain.internet_facing is False


# --------------------------------------------------------------------------- #
# Recommended fix order
# --------------------------------------------------------------------------- #
def test_recommended_fix_order_prioritizes_entry_point():
    chains = detect_exploit_chains([
        _static("path-traversal", "traversal", "lib/files.py:20", Severity.HIGH),
        _static("B105", "secret", "api/config.py:5", Severity.LOW),
    ])
    chain = next(c for c in chains if c.name.startswith("Path traversal"))
    order = chain.recommended_fix_order
    # The internet-facing link is ranked first even though it's lower severity.
    assert order[0]["location"] == "api/config.py:5"
    assert order[0]["internet_facing"] is True
    assert order[0]["rank"] == 1


def test_recommended_fix_order_falls_back_to_severity():
    chains = detect_exploit_chains([
        _static("path-traversal", "traversal", "lib/a.py:20", Severity.MEDIUM),
        _static("B105", "secret", "lib/b.py:5", Severity.HIGH),
    ])
    chain = next(c for c in chains if c.name.startswith("Path traversal"))
    order = chain.recommended_fix_order
    assert order[0]["severity"] == "High"  # no entry point → most severe first


# --------------------------------------------------------------------------- #
# Custom chain templates
# --------------------------------------------------------------------------- #
def test_load_custom_chains_from_json(tmp_path):
    (tmp_path / "custom_chains.json").write_text(json.dumps([
        {
            "name": "Weak crypto → secret theft",
            "slots": [["WEAK_CRYPTO"], ["secret_exposure"]],
            "impact": "Cracked hashes reveal the stored credential.",
            "narrative": "The weak hash is reversed and the secret recovered.",
        }
    ]))
    templates = load_custom_chains(str(tmp_path))
    assert len(templates) == 1
    assert templates[0].slots == (("weak_crypto",), ("secret_exposure",))


def test_custom_chain_detected(tmp_path):
    (tmp_path / "custom_chains.json").write_text(json.dumps([
        {
            "name": "Custom weak crypto plus secret",
            "slots": [["WEAK_CRYPTO"], ["SECRET"]],
            "impact": "demo impact",
            "narrative": "demo narrative",
        }
    ]))
    findings = [
        _static("B324", "weak md5 hash", "lib/h.py:3"),
        _static("B105", "hardcoded secret", "lib/c.py:9"),
    ]
    chains = detect_exploit_chains(findings, repo_dir=str(tmp_path))
    assert any(c.name == "Custom weak crypto plus secret" for c in chains)


def test_malformed_custom_chains_ignored(tmp_path):
    (tmp_path / "custom_chains.json").write_text("{ not valid json")
    assert load_custom_chains(str(tmp_path)) == []


def test_custom_chain_needs_two_slots(tmp_path):
    (tmp_path / "custom_chains.json").write_text(json.dumps([
        {"name": "one slot", "slots": [["SECRET"]], "impact": "", "narrative": ""}
    ]))
    assert load_custom_chains(str(tmp_path)) == []


def test_no_custom_file_yields_no_templates(tmp_path):
    assert load_custom_chains(str(tmp_path)) == []


# --------------------------------------------------------------------------- #
# Report rendering
# --------------------------------------------------------------------------- #
def test_render_includes_fix_order_and_entry_flag():
    chains = detect_exploit_chains([
        _static("path-traversal", "traversal", "api/files.py:20"),
        _static("B105", "secret", "api/files.py:5"),
    ])
    md = "\n".join(render_threat_section(chains))
    assert "Recommended fix order" in md
    assert "internet-facing entry point" in md
    assert "```mermaid" in md

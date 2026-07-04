"""Phase 3: masked LLM context, test-file downgrade, rotation urgency."""

from sgai.mcp_server import server
from sgai.mcp_server.server import (
    _find_secret_candidates,
    _is_secret_test_context,
    _mask_secret,
    _rotation_urgency,
    _secret_context_block,
    scan_secrets,
)
from sgai.models import Severity
from sgai.risk import findings_from_secret_scan

AWS_KEY = "AKIAIOSFODNN7EXPMPL1"
GENERIC = "zk9!pQ2#Vx7$Lm4@Rw8&"


# --------------------------------------------------------------------------- #
# Masking
# --------------------------------------------------------------------------- #
def test_mask_keeps_prefix_and_suffix():
    masked = _mask_secret(AWS_KEY)
    assert masked.startswith("AKIA")
    assert masked.endswith("PL1")
    assert "*" in masked
    assert AWS_KEY not in masked
    assert len(masked) == len(AWS_KEY)


def test_mask_short_values_fully():
    assert _mask_secret("abc1234") == "*******"


def test_context_lines_are_masked():
    text = f'db_password = "{GENERIC}"\nother = 1\n'
    candidates = _find_secret_candidates(text, "config.py")
    assert candidates
    for c in candidates:
        for line in c["context"]["surrounding_lines"]:
            assert GENERIC not in line


def test_context_masks_neighboring_secrets():
    """One candidate's context must not leak another candidate's value."""
    text = f'a_token = "{GENERIC}"\nb_key = "{AWS_KEY}"\n'
    candidates = _find_secret_candidates(text, "config.py")
    for c in candidates:
        joined = "\n".join(c["context"]["surrounding_lines"])
        assert GENERIC not in joined
        assert AWS_KEY not in joined


def test_context_captures_variable_and_comments():
    text = f'# production database credential\ndb_password = "{GENERIC}"\n'
    candidates = _find_secret_candidates(text, "config.py")
    c = next(x for x in candidates if x["check_id"] == "generic-credential")
    assert c["variable"] == "db_password"
    assert any("production database" in cm for cm in c["context"]["comments"])


def test_llm_prompt_block_contains_no_raw_secret():
    text = f'api_key = "{GENERIC}"\n'
    c = _find_secret_candidates(text, "settings.py")[0]
    block = _secret_context_block(0, c)
    assert GENERIC not in block
    assert "file_path: settings.py" in block
    assert "is_in_test_file: False" in block


# --------------------------------------------------------------------------- #
# Test-context classification & downgrade
# --------------------------------------------------------------------------- #
def test_test_context_paths():
    assert _is_secret_test_context("tests/conf.py")
    assert _is_secret_test_context("test_config.py")
    assert _is_secret_test_context("src/mocks/aws.js")
    assert _is_secret_test_context("fixtures/creds.yml")
    assert _is_secret_test_context("examples/demo.py")
    assert not _is_secret_test_context("src/app.py")
    assert not _is_secret_test_context("attestation.py")


def test_scan_downgrades_test_files_to_info(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "conf.py").write_text(f'aws_key = "{AWS_KEY}"\n')
    (tmp_path / "app.py").write_text(f'aws_key = "{AWS_KEY}"\n')

    result = scan_secrets(".", str(tmp_path))
    by_file = {f["file"]: f for f in result["findings"] if f["check_id"] == "aws-access-key"}
    assert by_file["tests/conf.py"]["severity"] == "INFO"
    assert by_file["tests/conf.py"]["rotation_urgency"] == "low"
    assert by_file["app.py"]["severity"] == "HIGH"
    assert by_file["app.py"]["rotation_urgency"] == "immediate"


def test_scan_output_never_contains_value_or_context(tmp_path):
    (tmp_path / "app.py").write_text(f'key = "{AWS_KEY}"\n')
    result = scan_secrets(".", str(tmp_path))
    for f in result["findings"]:
        assert "value" not in f
        assert "context" not in f


def test_llm_only_sees_production_candidates(tmp_path, monkeypatch):
    (tmp_path / "test_conf.py").write_text(f'k1 = "{AWS_KEY}"\n')
    (tmp_path / "app.py").write_text(f'k2 = "{GENERIC}"\n')

    seen: list[list[dict]] = []

    def fake_filter(candidates):
        seen.append(candidates)
        return candidates

    monkeypatch.setattr(server, "_llm_filter_dummy_secrets", fake_filter)
    result = scan_secrets(".", str(tmp_path), use_llm=True)

    assert len(seen) == 1
    assert all(not c["is_in_test_file"] for c in seen[0])  # test files never sent
    files = {f["file"] for f in result["findings"]}
    assert "test_conf.py" in files  # ...but the Info finding is still reported


# --------------------------------------------------------------------------- #
# Rotation urgency
# --------------------------------------------------------------------------- #
def test_rotation_urgency_ladder():
    assert _rotation_urgency("aws-access-key", 3.0, in_test_file=False) == "immediate"
    assert _rotation_urgency("private-key", 0.0, in_test_file=False) == "immediate"
    assert _rotation_urgency("generic-credential", 4.7, in_test_file=False) == "high"
    assert _rotation_urgency("generic-credential", 3.2, in_test_file=False) == "medium"
    assert _rotation_urgency("aws-access-key", 5.0, in_test_file=True) == "low"


# --------------------------------------------------------------------------- #
# Normalization into Findings
# --------------------------------------------------------------------------- #
def test_findings_carry_severity_and_urgency():
    result = {
        "findings": [
            {"check_id": "aws-access-key", "title": "AWS key", "file": "app.py",
             "line": 1, "entropy": 3.5, "match": "AKIA…", "severity": "HIGH",
             "rotation_urgency": "immediate"},
            {"check_id": "aws-access-key", "title": "AWS key", "file": "tests/c.py",
             "line": 1, "entropy": 3.5, "match": "AKIA…", "severity": "INFO",
             "rotation_urgency": "low", "is_in_test_file": True},
        ]
    }
    findings = findings_from_secret_scan(result)
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rotation_urgency == "immediate"
    assert findings[1].severity == Severity.INFO
    assert "test/fixture" in findings[1].detail


def test_findings_default_to_high_without_severity():
    """Old-shape scanner dicts (no severity key) still floor at HIGH."""
    result = {"findings": [{"check_id": "generic-credential", "title": "cred",
                            "file": "a.py", "line": 2, "entropy": 4.1, "match": "x…"}]}
    assert findings_from_secret_scan(result)[0].severity == Severity.HIGH

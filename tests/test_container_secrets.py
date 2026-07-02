"""Tests for container/IaC misconfiguration and secret scanning (offline)."""

from sgai.manifests import parse_compose, parse_dockerfile, parse_terraform
from sgai.mcp_server import server
from sgai.mcp_server.server import (
    _find_secret_candidates,
    _llm_filter_dummy_secrets,
    _looks_like_dummy,
    _shannon_entropy,
)


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def test_parse_dockerfile_folds_continuations():
    instrs = parse_dockerfile(
        "# comment\nFROM python:3.12\nRUN apt-get update \\\n && apt-get install -y curl\nUSER app\n"
    )
    kinds = [(i["instruction"], i["line"]) for i in instrs]
    assert ("FROM", 2) in kinds
    run = next(i for i in instrs if i["instruction"] == "RUN")
    assert "apt-get update" in run["argument"]
    assert "apt-get install -y curl" in run["argument"]  # continuation folded in
    assert run["line"] == 3


def test_parse_compose_extracts_security_fields():
    compose = parse_compose(
        "services:\n"
        "  web:\n"
        "    image: nginx:latest\n"
        "    privileged: true\n"
        "    cap_add: [SYS_ADMIN]\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
    )
    svc = compose["services"][0]
    assert svc["name"] == "web"
    assert svc["privileged"] is True
    assert svc["cap_add"] == ["SYS_ADMIN"]


def test_parse_terraform_blocks_and_assignments():
    tf = parse_terraform(
        'resource "aws_security_group" "open" {\n'
        "  cidr_blocks = \"0.0.0.0/0\"\n"
        '  password = "hunter2hunter2"\n'
        "}\n"
    )
    assert tf["blocks"][0]["labels"] == ["aws_security_group", "open"]
    keys = {a["key"] for a in tf["assignments"]}
    assert {"cidr_blocks", "password"} <= keys


# --------------------------------------------------------------------------- #
# scan_dockerfile tool
# --------------------------------------------------------------------------- #
def test_scan_dockerfile_flags_latest_and_root(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\nRUN echo hi\n")
    result = server.scan_dockerfile("Dockerfile", str(tmp_path))
    ids = {f["check_id"] for f in result["findings"]}
    assert "SGAI-DOCKER-BASE" in ids  # :latest base image
    assert "SGAI-DOCKER-ROOT" in ids  # no USER instruction
    assert result["kind"] == "dockerfile"


def test_scan_dockerfile_nonroot_user_clears_root_finding(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nUSER app\n")
    result = server.scan_dockerfile("Dockerfile", str(tmp_path))
    ids = {f["check_id"] for f in result["findings"]}
    assert "SGAI-DOCKER-ROOT" not in ids
    assert "SGAI-DOCKER-BASE" not in ids  # pinned tag


def test_scan_dockerfile_flags_curl_pipe_shell(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:12\nUSER app\nRUN curl https://example.com/i.sh | sh\n"
    )
    result = server.scan_dockerfile("Dockerfile", str(tmp_path))
    assert any(f["check_id"] == "SGAI-DOCKER-CURL-PIPE" for f in result["findings"])


def test_scan_dockerfile_dispatches_compose(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: postgres:16\n    privileged: true\n"
    )
    result = server.scan_dockerfile("docker-compose.yml", str(tmp_path))
    assert result["kind"] == "compose"
    assert any(f["check_id"] == "SGAI-COMPOSE-PRIVILEGED" for f in result["findings"])


def test_scan_dockerfile_dispatches_terraform(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_security_group_rule" "in" {\n  cidr_blocks = "0.0.0.0/0"\n}\n'
    )
    result = server.scan_dockerfile("main.tf", str(tmp_path))
    assert result["kind"] == "terraform"
    assert any(f["check_id"] == "SGAI-TF-OPEN-CIDR" for f in result["findings"])


def test_scan_dockerfile_respects_sandbox(tmp_path):
    result = server.scan_dockerfile("../../etc/hosts", str(tmp_path))
    assert "outside the sandbox" in result.get("error", "")


# --------------------------------------------------------------------------- #
# Secret detection helpers
# --------------------------------------------------------------------------- #
def test_shannon_entropy_ranks_random_higher():
    assert _shannon_entropy("aaaaaaaa") < _shannon_entropy("aB3xZ9qL")


def test_dummy_detection():
    assert _looks_like_dummy("changeme")
    assert _looks_like_dummy("your-api-key-here")
    assert _looks_like_dummy("xxxxxxxxxxxx")
    assert _looks_like_dummy("short")
    assert not _looks_like_dummy("AKIA5GH7QP2XR9ZLMN3W")


def test_find_secret_candidates_known_formats():
    text = 'aws_key = "AKIAIOSFODNN7EXAMPLE"\ntok = "ghp_' + "a" * 36 + '"\n'
    cands = _find_secret_candidates(text, "cfg.py")
    ids = {c["check_id"] for c in cands}
    assert "aws-access-key" in ids
    assert "github-token" in ids


def test_find_secret_candidates_masks_value():
    cands = _find_secret_candidates('key = "AKIAIOSFODNN7EXAMPLE"', "c.py")
    aws = next(c for c in cands if c["check_id"] == "aws-access-key")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws["match"]
    assert aws["match"].startswith("AKIA")


# --------------------------------------------------------------------------- #
# scan_secrets tool
# --------------------------------------------------------------------------- #
def test_scan_secrets_finds_real_drops_dummy(tmp_path):
    (tmp_path / "config.py").write_text(
        'API_KEY = "sk_live_' + "a1B2c3D4e5F6g7H8i9J0k1L2" + '"\n'
        'EXAMPLE_KEY = "your-api-key-here"\n'
        'DB_PASSWORD = "changeme"\n'
    )
    result = server.scan_secrets(".", str(tmp_path))
    titles = " ".join(f["title"] for f in result["findings"])
    # The stripe-format live key survives; the placeholder values are filtered.
    assert result["count"] >= 1
    assert "changeme" not in titles
    # No raw secret value is ever returned.
    for f in result["findings"]:
        assert "value" not in f


def test_scan_secrets_no_findings_on_clean_file(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\nname = 'hello world'\n")
    result = server.scan_secrets(".", str(tmp_path))
    assert result["count"] == 0


def test_scan_secrets_respects_sandbox(tmp_path):
    result = server.scan_secrets("../outside", str(tmp_path))
    assert "outside the sandbox" in result.get("error", "")


def test_llm_filter_uses_injected_classifier():
    cands = [
        {"title": "a", "value": "realsecretvalue1", "entropy": 3.9},
        {"title": "b", "value": "realsecretvalue2", "entropy": 3.9},
    ]
    kept = _llm_filter_dummy_secrets(cands, classifier=lambda c: [True, False])
    assert kept == [cands[0]]


def test_llm_filter_falls_back_on_error():
    cands = [{"title": "a", "value": "x", "entropy": 1.0}]

    def boom(_):
        raise RuntimeError("no api key")

    assert _llm_filter_dummy_secrets(cands, classifier=boom) == cands

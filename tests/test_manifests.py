"""Tests for the multi-ecosystem manifest parsers (pure, no network)."""

from pathlib import Path

from sgai.manifests import parse_manifest


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def test_parse_requirements_pypi(tmp_path):
    p = _write(tmp_path, "requirements.txt", "jinja2==2.11.2\n# comment\nrequests>=2.0\n")
    pkgs = parse_manifest(p)
    assert {"name": "jinja2", "version": "2.11.2", "ecosystem": "PyPI"} in pkgs
    assert len(pkgs) == 1  # the >= line is skipped (not a pin)


def test_parse_package_lock_npm(tmp_path):
    p = _write(
        tmp_path,
        "package-lock.json",
        '{"lockfileVersion":3,"packages":{"":{"name":"x"},'
        '"node_modules/lodash":{"version":"4.17.11"}}}',
    )
    pkgs = parse_manifest(p)
    assert pkgs == [{"name": "lodash", "version": "4.17.11", "ecosystem": "npm"}]


def test_parse_go_mod_normalizes_version(tmp_path):
    p = _write(
        tmp_path,
        "go.mod",
        "module demo\n\nrequire (\n\tgithub.com/dgrijalva/jwt-go v3.2.0+incompatible\n)\n",
    )
    pkgs = parse_manifest(p)
    assert pkgs == [
        {"name": "github.com/dgrijalva/jwt-go", "version": "3.2.0", "ecosystem": "Go"}
    ]


def test_parse_cargo_lock_crates(tmp_path):
    p = _write(
        tmp_path,
        "Cargo.lock",
        'version = 3\n\n[[package]]\nname = "time"\nversion = "0.1.42"\n',
    )
    pkgs = parse_manifest(p)
    assert pkgs == [{"name": "time", "version": "0.1.42", "ecosystem": "crates.io"}]

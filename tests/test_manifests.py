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


def test_parse_pyproject_pep621_and_poetry(tmp_path):
    p = _write(
        tmp_path,
        "pyproject.toml",
        '[project]\ndependencies = ["jinja2==2.11.2", "rich[jupyter]==13.0.0 ; python_version >= \'3.11\'", "httpx>=0.27"]\n'
        '[project.optional-dependencies]\nweb = ["flask==0.12.2"]\n'
        "[dependency-groups]\ndev = [\"pytest==7.0.0\"]\n"
        '[tool.poetry.dependencies]\npython = "^3.11"\ndjango = "3.2.0"\nclick = {version = "8.0.0"}\nloose = "^2.0"\n',
    )
    pkgs = parse_manifest(p)
    names = {(x["name"], x["version"]) for x in pkgs}
    assert ("jinja2", "2.11.2") in names
    assert ("rich", "13.0.0") in names  # extras + marker stripped
    assert ("flask", "0.12.2") in names
    assert ("pytest", "7.0.0") in names
    assert ("django", "3.2.0") in names
    assert ("click", "8.0.0") in names
    assert all(n != "httpx" for n, _ in names)  # range pins are not auditable
    assert all(n != "loose" for n, _ in names)  # caret constraint skipped
    assert all(n != "python" for n, _ in names)
    assert all(x["ecosystem"] == "PyPI" for x in pkgs)


def test_parse_poetry_lock(tmp_path):
    p = _write(
        tmp_path,
        "poetry.lock",
        '[[package]]\nname = "urllib3"\nversion = "1.24.1"\n'
        '[[package]]\nname = "certifi"\nversion = "2018.11.29"\n',
    )
    pkgs = parse_manifest(p)
    assert {"name": "urllib3", "version": "1.24.1", "ecosystem": "PyPI"} in pkgs
    assert len(pkgs) == 2


def test_parse_uv_lock_registry_only(tmp_path):
    p = _write(
        tmp_path,
        "uv.lock",
        'version = 1\n\n[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
        '\n[[package]]\nname = "idna"\nversion = "2.7"\nsource = { registry = "https://pypi.org/simple" }\n',
    )
    pkgs = parse_manifest(p)
    assert pkgs == [{"name": "idna", "version": "2.7", "ecosystem": "PyPI"}]


def test_parse_pipfile_lock(tmp_path):
    p = _write(
        tmp_path,
        "Pipfile.lock",
        '{"default": {"requests": {"version": "==2.19.1"}}, '
        '"develop": {"pytest": {"version": "==4.0.0"}, "editable-thing": {"path": "."}}}',
    )
    pkgs = parse_manifest(p)
    names = {(x["name"], x["version"]) for x in pkgs}
    assert names == {("requests", "2.19.1"), ("pytest", "4.0.0")}


def test_parse_manifest_malformed_returns_empty(tmp_path):
    assert parse_manifest(_write(tmp_path, "pyproject.toml", "not = [valid")) == []
    assert parse_manifest(_write(tmp_path, "Pipfile.lock", "{broken json")) == []


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

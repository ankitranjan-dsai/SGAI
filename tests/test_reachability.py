"""Tests for dependency reachability analysis (offline)."""

from sgai.models import Finding, Severity
from sgai.risk import apply_reachability, build_import_graph


def _dep_finding(package: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=f"GHSA-{package}",
        source="dependency",
        title=f"{package} has known vulnerabilities",
        severity=severity,
        location=f"PyPI:{package}@1.0.0",
    )


def test_import_graph_collects_top_level_modules(tmp_path):
    (tmp_path / "app.py").write_text("import jinja2\nfrom yaml import safe_load\n")
    (tmp_path / "util.py").write_text("import os.path\nfrom requests.adapters import HTTPAdapter\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "vendored.py").write_text("import flask\n")

    graph = build_import_graph(str(tmp_path))

    assert graph["app.py"] == {"jinja2", "yaml"}
    assert graph["util.py"] == {"os", "requests"}
    assert not any(".venv" in file for file in graph)  # vendored code is not first-party


def test_import_graph_skips_unparseable_files(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    (tmp_path / "good.py").write_text("import requests\n")
    graph = build_import_graph(str(tmp_path))
    assert "bad.py" not in graph
    assert graph["good.py"] == {"requests"}


def test_reachable_package_upgraded(tmp_path):
    (tmp_path / "app.py").write_text("import jinja2\n")
    findings = [_dep_finding("jinja2")]

    ranked = apply_reachability(findings, build_import_graph(str(tmp_path)))

    f = ranked[0]
    assert f.reachable is True
    assert f.severity == Severity.CRITICAL  # HIGH + reachable → CRITICAL
    assert "imports this package" in f.detail


def test_unreached_package_downgraded(tmp_path):
    (tmp_path / "app.py").write_text("import os\n")
    findings = [_dep_finding("jinja2")]

    ranked = apply_reachability(findings, build_import_graph(str(tmp_path)))

    f = ranked[0]
    assert f.reachable is False
    assert f.severity == Severity.MEDIUM  # HIGH - unreached → MEDIUM
    assert "no first-party import" in f.detail


def test_alias_distribution_names_resolve(tmp_path):
    (tmp_path / "app.py").write_text("import yaml\nfrom PIL import Image\n")
    findings = [_dep_finding("PyYAML"), _dep_finding("Pillow")]

    ranked = apply_reachability(findings, build_import_graph(str(tmp_path)))

    assert all(f.reachable for f in ranked)


def test_dashes_normalize_to_underscores(tmp_path):
    (tmp_path / "app.py").write_text("import dateutil\n")
    findings = [_dep_finding("python-dateutil")]
    ranked = apply_reachability(findings, build_import_graph(str(tmp_path)))
    assert ranked[0].reachable is True


def test_non_pypi_and_static_findings_untouched(tmp_path):
    (tmp_path / "app.py").write_text("import os\n")
    npm = Finding(
        id="GHSA-x", source="dependency", title="lodash vuln",
        severity=Severity.HIGH, location="npm:lodash@4.0.0",
    )
    static = Finding(
        id="B506", source="static", title="yaml.load",
        severity=Severity.MEDIUM, location="app.py:3",
    )
    ranked = apply_reachability([npm, static], build_import_graph(str(tmp_path)))

    by_id = {f.id: f for f in ranked}
    assert by_id["GHSA-x"].reachable is None
    assert by_id["GHSA-x"].severity == Severity.HIGH
    assert by_id["B506"].reachable is None
    assert by_id["B506"].severity == Severity.MEDIUM


def test_reachability_reranks_findings(tmp_path):
    (tmp_path / "app.py").write_text("import flask\n")
    reachable = _dep_finding("flask", Severity.MEDIUM)  # MEDIUM → HIGH (reachable)
    unreached = _dep_finding("jinja2", Severity.HIGH)  # HIGH → MEDIUM (unreached)

    ranked = apply_reachability([unreached, reachable], build_import_graph(str(tmp_path)))

    assert [f.id for f in ranked] == ["GHSA-flask", "GHSA-jinja2"]

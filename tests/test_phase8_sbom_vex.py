"""Phase 8: SBOM (CycloneDX/SPDX) and VEX export."""

from fastapi.testclient import TestClient

from sgai.api import app
from sgai.models import Finding, Severity
from sgai.sbom import build_sbom, collect_packages, purl, to_cyclonedx, to_spdx
from sgai.vex import (
    STATUS_AFFECTED,
    STATUS_NOT_AFFECTED,
    STATUS_UNDER_INVESTIGATION,
    build_vex,
    vex_statements,
)

client = TestClient(app)


def _repo(tmp_path):
    (tmp_path / "requirements.txt").write_text("jinja2==2.11.2\nrequests==2.19.1\n")
    (tmp_path / "go.mod").write_text('module x\n\nrequire github.com/gin-gonic/gin v1.6.0\n')
    return tmp_path


# --------------------------------------------------------------------------- #
# Package collection & PURLs
# --------------------------------------------------------------------------- #
def test_collect_packages_multi_ecosystem(tmp_path):
    pkgs = collect_packages(str(_repo(tmp_path)))
    names = {(p["ecosystem"], p["name"]) for p in pkgs}
    assert ("PyPI", "jinja2") in names
    assert ("Go", "github.com/gin-gonic/gin") in names


def test_purl_formats():
    assert purl({"name": "jinja2", "version": "2.11.2", "ecosystem": "PyPI"}) == "pkg:pypi/jinja2@2.11.2"
    assert purl({"name": "lodash", "version": "4.0.0", "ecosystem": "npm"}) == "pkg:npm/lodash@4.0.0"
    assert purl({"name": "serde", "version": "1.0", "ecosystem": "crates.io"}) == "pkg:cargo/serde@1.0"


# --------------------------------------------------------------------------- #
# CycloneDX
# --------------------------------------------------------------------------- #
def test_cyclonedx_shape(tmp_path):
    doc = build_sbom(str(_repo(tmp_path)), fmt="cyclonedx", name="demo")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    refs = {c["purl"] for c in doc["components"]}
    assert "pkg:pypi/jinja2@2.11.2" in refs
    assert all(c["type"] == "library" for c in doc["components"])


def test_cyclonedx_deterministic_ordering(tmp_path):
    a = to_cyclonedx(collect_packages(str(_repo(tmp_path))), "x")
    b = to_cyclonedx(collect_packages(str(_repo(tmp_path))), "x")
    assert [c["purl"] for c in a["components"]] == [c["purl"] for c in b["components"]]


# --------------------------------------------------------------------------- #
# SPDX
# --------------------------------------------------------------------------- #
def test_spdx_shape(tmp_path):
    doc = build_sbom(str(_repo(tmp_path)), fmt="spdx", name="demo")
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    purls = {
        ref["referenceLocator"]
        for p in doc["packages"] for ref in p.get("externalRefs", [])
    }
    assert "pkg:pypi/requests@2.19.1" in purls
    # Every non-root package is DEPENDS_ON-linked to the root.
    depends = [r for r in doc["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
    assert len(depends) == len(doc["packages"]) - 1


def test_empty_repo_sbom(tmp_path):
    doc = build_sbom(str(tmp_path), fmt="cyclonedx")
    assert doc["components"] == []


# --------------------------------------------------------------------------- #
# VEX
# --------------------------------------------------------------------------- #
def _dep(location, reachable, refs=None):
    return Finding(
        id="CVE-1", source="dependency", title="vuln", severity=Severity.HIGH,
        location=location, reachable=reachable, references=refs or ["CVE-1"],
    )


def test_vex_status_mapping():
    findings = [
        _dep("PyPI:jinja2@2.11.2", reachable=True),
        _dep("PyPI:unused@1.0", reachable=False),
        _dep("PyPI:maybe@1.0", reachable=None),
    ]
    stmts = vex_statements(findings)
    by_product = {s["products"][0]["@id"]: s for s in stmts}
    assert by_product["pkg:pypi/jinja2@2.11.2"]["status"] == STATUS_AFFECTED
    assert by_product["pkg:pypi/unused@1.0"]["status"] == STATUS_NOT_AFFECTED
    assert by_product["pkg:pypi/unused@1.0"]["justification"] == "vulnerable_code_not_in_execute_path"
    assert by_product["pkg:pypi/maybe@1.0"]["status"] == STATUS_UNDER_INVESTIGATION


def test_vex_one_statement_per_advisory():
    findings = [_dep("PyPI:pkg@1.0", reachable=True, refs=["CVE-1", "CVE-2"])]
    stmts = vex_statements(findings)
    assert {s["vulnerability"]["name"] for s in stmts} == {"CVE-1", "CVE-2"}


def test_vex_ignores_non_dependency_findings():
    static = Finding(id="B307", source="static", title="eval", severity=Severity.HIGH,
                     location="app.py:3")
    assert vex_statements([static]) == []


def test_build_vex_document():
    doc = build_vex([_dep("PyPI:jinja2@2.11.2", reachable=True)], target="demo")
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["author"] == "SGAI"
    assert doc["statements"][0]["status"] == STATUS_AFFECTED


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
def test_sbom_endpoint(tmp_path):
    resp = client.get("/sbom", params={"repo_dir": str(_repo(tmp_path))})
    assert resp.status_code == 200
    assert resp.json()["bomFormat"] == "CycloneDX"


def test_sbom_endpoint_spdx(tmp_path):
    resp = client.get("/sbom", params={"repo_dir": str(_repo(tmp_path)), "format": "spdx"})
    assert resp.json()["spdxVersion"] == "SPDX-2.3"


def test_sbom_endpoint_bad_format(tmp_path):
    resp = client.get("/sbom", params={"repo_dir": str(tmp_path), "format": "bogus"})
    assert resp.status_code == 400


def test_sbom_endpoint_requires_target():
    assert client.get("/sbom").status_code == 400


def test_vex_endpoint(tmp_path):
    # No network dependency lookups needed: an empty repo yields an empty VEX.
    resp = client.get("/vex", params={"repo_dir": str(tmp_path)})
    assert resp.status_code == 200
    assert resp.json()["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert resp.json()["statements"] == []

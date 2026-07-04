"""Phase 2: test-file classification, transitive closure, multi-language graph."""

from sgai.models import Finding, Severity
from sgai.risk import (
    apply_reachability,
    build_import_graph,
    is_test_file,
    transitive_import_closure,
)


def _dep(package: str, ecosystem: str = "PyPI", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=f"GHSA-{package.replace('/', '-')}",
        source="dependency",
        title=f"{package} has known vulnerabilities",
        severity=severity,
        location=f"{ecosystem}:{package}@1.0.0",
    )


# --------------------------------------------------------------------------- #
# Production vs. test classification
# --------------------------------------------------------------------------- #
def test_test_file_patterns():
    assert is_test_file("test_app.py")
    assert is_test_file("pkg/handlers_test.go")
    assert is_test_file("src/app.test.ts")
    assert is_test_file("src/Button.spec.jsx")
    assert is_test_file("conftest.py")
    assert is_test_file("tests/helper.py")
    assert is_test_file("src/__tests__/util.js")
    assert is_test_file("fixtures/sample.py")


def test_production_file_patterns():
    assert not is_test_file("app.py")
    assert not is_test_file("src/main.go")
    assert not is_test_file("src/index.ts")
    assert not is_test_file("attestation.py")  # "test" inside a word is not a test
    assert not is_test_file("src/contest/rank.py")


# --------------------------------------------------------------------------- #
# Multi-language import graph
# --------------------------------------------------------------------------- #
def test_js_imports_parsed(tmp_path):
    (tmp_path / "app.js").write_text(
        "import express from 'express';\n"
        "import { pick } from \"lodash/fp\";\n"
        "import '@scope/pkg/dist/style.css';\n"
        "const yaml = require('js-yaml');\n"
        "const dyn = await import('axios');\n"
        "import util from './util';\n"
    )
    graph = build_import_graph(str(tmp_path))
    assert graph["app.js"] == {"express", "lodash", "@scope/pkg", "js-yaml", "axios", "./util"}


def test_go_imports_parsed(tmp_path):
    (tmp_path / "main.go").write_text(
        'package main\n'
        'import "fmt"\n'
        'import (\n'
        '    "net/http"\n'
        '    gin "github.com/gin-gonic/gin"\n'
        '    "github.com/lib/pq" // driver\n'
        ')\n'
    )
    graph = build_import_graph(str(tmp_path))
    assert graph["main.go"] == {"fmt", "net/http", "github.com/gin-gonic/gin", "github.com/lib/pq"}


def test_rust_imports_parsed(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use serde_json::Value;\n"
        "pub use tokio::net::TcpListener;\n"
        "extern crate openssl;\n"
        "use crate::config::Settings;\n"
        "use std::io;\n"
    )
    graph = build_import_graph(str(tmp_path))
    assert graph["main.rs"] == {"serde_json", "tokio", "openssl"}


# --------------------------------------------------------------------------- #
# Transitive import closure
# --------------------------------------------------------------------------- #
def test_python_transitive_closure(tmp_path):
    (tmp_path / "app.py").write_text("import util\n")
    (tmp_path / "util.py").write_text("import yaml\n")
    closure = transitive_import_closure(build_import_graph(str(tmp_path)))
    assert "yaml" in closure["app.py"]  # nested import is on app.py's path


def test_src_layout_transitive_closure(tmp_path):
    (tmp_path / "app.py").write_text("import mypkg\n")
    pkg = tmp_path / "src" / "mypkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("import requests\n")
    closure = transitive_import_closure(build_import_graph(str(tmp_path)))
    assert "requests" in closure["app.py"]


def test_js_relative_transitive_closure(tmp_path):
    (tmp_path / "app.js").write_text("import util from './util';\n")
    (tmp_path / "util.js").write_text("import lodash from 'lodash';\n")
    closure = transitive_import_closure(build_import_graph(str(tmp_path)))
    assert "lodash" in closure["app.js"]


def test_closure_handles_cycles(tmp_path):
    (tmp_path / "a.py").write_text("import b\nimport yaml\n")
    (tmp_path / "b.py").write_text("import a\nimport requests\n")
    closure = transitive_import_closure(build_import_graph(str(tmp_path)))
    assert {"yaml", "requests"} <= closure["a.py"]
    assert {"yaml", "requests"} <= closure["b.py"]


def test_transitive_import_upgrades_finding(tmp_path):
    """A CVE reached only through a nested first-party import is still upgraded."""
    (tmp_path / "app.py").write_text("import util\n")
    (tmp_path / "util.py").write_text("import jinja2\n")
    ranked = apply_reachability([_dep("jinja2")], build_import_graph(str(tmp_path)))
    assert ranked[0].reachable is True
    assert ranked[0].severity == Severity.CRITICAL


# --------------------------------------------------------------------------- #
# Production vs. test reachability outcomes
# --------------------------------------------------------------------------- #
def test_test_only_import_downgraded(tmp_path):
    (tmp_path / "test_app.py").write_text("import jinja2\n")
    ranked = apply_reachability([_dep("jinja2")], build_import_graph(str(tmp_path)))
    f = ranked[0]
    assert f.reachable is True
    assert f.severity == Severity.MEDIUM  # HIGH − test-only → MEDIUM
    assert "test/fixture" in f.detail


def test_production_import_beats_test_import(tmp_path):
    (tmp_path / "app.py").write_text("import jinja2\n")
    (tmp_path / "test_app.py").write_text("import jinja2\n")
    ranked = apply_reachability([_dep("jinja2")], build_import_graph(str(tmp_path)))
    assert ranked[0].severity == Severity.CRITICAL  # production wins


# --------------------------------------------------------------------------- #
# Multi-ecosystem reachability
# --------------------------------------------------------------------------- #
def test_npm_reachability_with_js_source(tmp_path):
    (tmp_path / "app.js").write_text("const _ = require('lodash');\n")
    reachable = _dep("lodash", "npm")
    unreached = _dep("express", "npm")
    ranked = apply_reachability([reachable, unreached], build_import_graph(str(tmp_path)))
    by_id = {f.id: f for f in ranked}
    assert by_id["GHSA-lodash"].reachable is True
    assert by_id["GHSA-lodash"].severity == Severity.CRITICAL
    assert by_id["GHSA-express"].reachable is False
    assert by_id["GHSA-express"].severity == Severity.MEDIUM


def test_go_module_prefix_match(tmp_path):
    (tmp_path / "main.go").write_text(
        'package main\nimport "github.com/gin-gonic/gin/render"\n'
    )
    ranked = apply_reachability(
        [_dep("github.com/gin-gonic/gin", "Go")], build_import_graph(str(tmp_path))
    )
    assert ranked[0].reachable is True  # subpackage import reaches the module


def test_crates_hyphen_underscore_match(tmp_path):
    (tmp_path / "main.rs").write_text("use serde_json::Value;\n")
    ranked = apply_reachability(
        [_dep("serde-json", "crates.io")], build_import_graph(str(tmp_path))
    )
    assert ranked[0].reachable is True


def test_no_language_signal_leaves_finding_untouched(tmp_path):
    """An npm finding in a Python-only repo must not be falsely downgraded."""
    (tmp_path / "app.py").write_text("import os\n")
    ranked = apply_reachability([_dep("lodash", "npm")], build_import_graph(str(tmp_path)))
    assert ranked[0].reachable is None
    assert ranked[0].severity == Severity.HIGH

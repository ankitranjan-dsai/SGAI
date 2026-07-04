# Changelog

All notable changes to SGAI are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-07-04

First tagged release: the complete multi-agent security review system, from
the original scan pipeline through the v3 advanced suite.

### Core pipeline
- Multi-agent architecture on Google ADK: an orchestrator coordinating
  specialist agents for dependency auditing, static analysis, triage, and
  remediation, bound to a custom security MCP server with least-privilege
  tool allowlists.
- Deterministic detection core: all findings come from fast local analysis
  (OSV.dev, Bandit, Semgrep); the LLM only narrates, triages, and powers the
  chat copilot.
- Dependency CVE scanning across **PyPI, npm, Go, and crates.io** manifests
  via OSV.dev, with severity mapped from each advisory's **CVSS vector**
  (v4 > v3 > v2, standard qualitative bands) rather than a flat HIGH.
- Risk-ranked, de-duplicated Markdown reports plus **SARIF** output for
  GitHub code scanning.
- Scan any public GitHub repository by URL, or a local path.

### Advanced suite
- **Self-healing** (`sgai heal`): auto-generated patches validated against
  the project's own test suite (pytest/npm/go/cargo), confidence scoring,
  and binary-search rollback to isolate breaking hunks.
- **Dependency reachability**: a multi-language import graph classifies each
  vulnerable package as `production` / `test_only` / `unreached` and adjusts
  severity accordingly.
- **Exploit-chain threat modeling**: findings composed into attack chains
  with Mermaid graphs, numbered fix order, and custom chain templates.
- **Typosquatting detector** for supply-chain risk (edit distance,
  homoglyphs, affixes) with zero network calls.
- **Context-aware secret scanning** with masked LLM verification and
  rotation-urgency scoring; container/IaC misconfiguration scanning.
- **Policy-as-Code**: `.sgai/policy.yml` gates enforced by `sgai check`
  (non-zero exit for CI).
- **PR differential scanning**: only findings newly introduced by a diff;
  `POST /scan/pr` posts inline GitHub review comments.
- **SBOM & VEX export**: CycloneDX/SPDX and OpenVEX (reachability mapped to
  `affected` / `not_affected` / `under_investigation`).
- False-positive dismissals persisted across scans; historical trend
  dashboard from `ScanMemory`.

### Interfaces & deployment
- Three front-ends from one codebase: CLI, mobile-friendly web app (three-tab
  UI with SSE + WebSocket chat copilot), and a reusable MCP server.
- Container image published to `ghcr.io/ankitranjan-dsai/sgai`; deploys to
  Cloud Run or any container host.
- CI/CD templates: reusable `sgai-security.yml` PR gate, weekly
  `sgai-dependency-audit.yml` that opens fix PRs, and a self-auditing CI
  (`sgai check` runs on SGAI's own repository).

[0.1.0]: https://github.com/ankitranjan-dsai/SGAI/releases/tag/v0.1.0

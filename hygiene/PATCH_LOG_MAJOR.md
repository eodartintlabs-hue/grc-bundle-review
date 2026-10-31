# Major Releases & Baselines Ledger (`hygiene/PATCH_LOG_MAJOR.md`)

<p align="center">
  <a href="../README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/DATAFLOW.md"><b>🔄 Data Flow</b></a> &nbsp;·&nbsp;
  <a href="../SECURITY.md"><b>🛡️ Security Policy</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/GOVERNANCE.md"><b>⚖️ Governance & Mandates</b></a> &nbsp;·&nbsp;
  <a href="../testing/TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="../testing/live-demo.md"><b>🎬 Live Demo</b></a> &nbsp;·&nbsp;
  <a href="RELEASE_NOTES.md"><b>🚀 Release Notes</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG.md"><b>🩹 Patch Log Index</b></a> &nbsp;·&nbsp;
  <a href="ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="RELEASING.md"><b>🏷️ Releasing</b></a> &nbsp;·&nbsp;
  <a href="../docs/scan-transform-guide.md"><b>📊 Scan-to-POA&M Guide</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc-bundle-use-case.md"><b>📑 Bundle Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="../docs/test-dummies-guide.md"><b>🎯 Test Dummies Guide</b></a>
</p>

<p align="center">
  <b>Sub-Ledgers</b>: 
  <a href="PATCH_LOG_BUG.md"><b>🐛 Bug Fixes & Patches</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG_MINOR.md"><b>✨ Minor Releases</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG_MAJOR.md"><b>🏛️ Major Releases & Baselines</b></a>
</p>

> **Ledger Scope**: **Major Architectural Baselines & Lifecycle Milestones (`vX.0.0`)**  
> **Active Series Codename**: `Yokosuka` (`v1.0.0` Baseline) · Next: `Pearl Harbor` (`v2.0.0` GA)  
> **Companion Documents**: See [`PATCH_LOG_BUG.md`](PATCH_LOG_BUG.md) for bug fixes and patches, [`PATCH_LOG_MINOR.md`](PATCH_LOG_MINOR.md) for minor features, [`RELEASE_NOTES.md`](RELEASE_NOTES.md) for narrative notes, and [`RELEASING.md`](RELEASING.md) for release procedures.

---

## 1. Running Major Baseline & Milestone Table

This ledger tracks the foundational lifecycle baselines and major generation milestones across **GRCx** (*The GRC eXperience*), maintaining full commit, architecture-scope, and **Author / POC** accountability.

| Version | Commit | Date | Category | Subsystem / Files Affected | Summary of Changes | Author / POC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`v1.0.0`** | `9bc27c3` | `2026-10-18` | `Beta Baseline` | `./grc`, `scripts/*`, `docker/*`, `rules/*`, `docs/*` | Initial Restricted Beta baseline (for designated integration testing) of the 5-phase GRC Bundle & AMI Review Pipeline, 7-engine air-gapped Docker scanner suite, 37 custom Semgrep AOC rules, and Phase 4 SCR/SCN compliance reporting engine. | Byron Turner |
| *`v2.0.0`<br/>(`Pearl Harbor`)* | *Planned* | *TBD* | *Full Release (GA)* | *All Subsystems* | *Planned Full Production Release (General Availability) launching the Hawaiian military base cities series (`Pearl Harbor`) and introducing **Helm chart compliance auditing (`./grc scan --engine helm`)** with offline template rendering and DISA K8s STIG / NSA-CISA checks.* | Byron Turner |
| *`v2.1.0+`<br/>(`Kaneohe`)* | *Planned* | *TBD* | *Post-GA Release* | *All Subsystems* | *Planned Post-GA Hawaiian series release lifting execution to cloud-hosted environments (**AWS EC2 & Bottlerocket**), integrating the air-gapped local LLM baseline (`Gemma` / `GPT-OSS`) alongside **dynamic endpoint RAM-adaptive scaling** for POA&M synthesis, and adding **NIST OSCAL 1.1.x** export (see [`hygiene/ROADMAP.md`](ROADMAP.md)).* | Byron Turner |

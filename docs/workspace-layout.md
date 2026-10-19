# DevSecOps Engineering & Compliance Workspace Layout (`docs/workspace-layout.md`)

<p align="center">
  <a href="../README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/DATAFLOW.md"><b>🔄 Data Flow</b></a> &nbsp;·&nbsp;
  <a href="../SECURITY.md"><b>🛡️ Security Policy</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/GOVERNANCE.md"><b>⚖️ Governance & Mandates</b></a> &nbsp;·&nbsp;
  <a href="../testing/TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="../testing/live-demo.md"><b>🎬 Live Demo</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/RELEASE_NOTES.md"><b>🚀 Release Notes</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/PATCH_LOG.md"><b>🩹 v1 Patch Log</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="grc-bundle-use-case.md"><b>📑 Use Case Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="test-dummies-guide.md"><b>🎯 Test Dummies Guide</b></a>
</p>

> **Classification / Use**: Internal Engineering & Compliance Specification  
> **Target Frameworks**: DISA STIG, NIST SP 800-53 Rev. 5, FedRAMP High, OWASP Top 10  
> **Environment Status**: Active Workstation & Enclave Baseline (`v1.x — Yokosuka` & `v2.x — Pearl Harbor`)

---

## 1. Minimum & Recommended System Requirements

Because all host orchestration scripts ([`scripts/`](../scripts/)) use **100% Python 3 Standard Library** modules and all third-party security scanners execute inside the isolated **`grc-scanner:local`** Docker container (`--network none`), the host workstation requires **zero `pip` package installations** and incurs **\$0.00 in cloud compute costs** during local verification.

### 1.1 Hardware Requirements Matrix

| Resource | Minimum Required (`v1.x` Baseline) | Recommended (`v1.x` Pro / `v2.0+` Local LLM) | Reference Developer Baseline | Sizing Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **CPU Architecture** | `64-bit` (`arm64` / Apple Silicon or `x86_64` / `amd64`) | **4+ vCPUs / Performance Cores** | Apple Silicon (`M5 Pro` / `ARM64`) | Multi-threaded AST rule evaluation (`Semgrep`), IaC graph checks (`Checkov`), and SBOM indexing (`Syft`). |
| **System RAM** | **8 GB RAM** *(4 GB allocated to Docker Desktop / VM)* | **16 GB – 32 GB+ RAM** *(8 GB+ allocated to Docker VM)* | 32 GB+ Unified Memory | Prevents container OOM kills during large repository/IaC scans and supports `v2.0+` local `Gemma` / `GPT-OSS` inference. |
| **Disk Storage** | **10 GB Free SSD** | **25 GB+ Free NVMe SSD** | NVMe Internal SSD | ~3.5 GB for `grc-scanner:local` image and offline NVD/GHSA CVE databases + temporary space for `.bundle` / AMI extraction. |
| **Network Posture** | **One-time internet/mirror access** *(during `./grc docker-build`)* | **100% Air-Gapped at Runtime (`--network none`)** | Air-Gapped Container Bridge | Guarantees zero external telemetry or data exfiltration during Phase 3 scanning. |

### 1.2 Software & Runtime Prerequisites

| Requirement | Minimum Supported Version | Recommended Version | Purpose in Pipeline | Quick Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Operating System** | **macOS 13+** (Ventura+), **Linux** (Debian 12+, Ubuntu 22.04+, RHEL/Rocky 9+), or **Windows 11 WSL2** | **macOS 15+**, **Ubuntu 24.04 LTS**, or **Debian 12 (Bookworm)** | Host execution environment *(Universal plug-and-play hardening in `v1.2.0 — Sasebo`)* | `uname -srm` |
| **Bash Shell** | **`bash` $\ge$ `3.2`** *(macOS default)* | **`bash` $\ge$ `5.0+`** | Runs root [`./grc`](../grc) CLI dispatcher and [`docker/scan_orchestrator.sh`](../docker/scan_orchestrator.sh) | `bash --version` |
| **Git CLI** | **`git` $\ge$ `2.30+`** | **`git` $\ge$ `2.43+`** | Phase 1 `git bundle verify` and Phase 2 read-only workspace restoration | `git --version` |
| **Python 3** | **`python3` $\ge$ `3.9+`** *(Standard Library only)* | **`python3` $\ge$ `3.11+`** | Executes `grc_bundle.py`, `grc_ami.py`, `crypto_lib_scan.py`, `sbom_analyzer.py`, and `grc_reporter.py` | `python3 --version` |
| **Container Engine** | **Docker Engine $\ge$ `24.0+`** or **Docker Desktop $\ge$ `4.25+`** | **Docker Desktop `4.30+`**, **Colima**, or **Rootless Podman** | Builds and runs the isolated `grc-scanner:local` image with `--network none` | `docker info` |
| **SHA-256 Utility** | `shasum` *(macOS)* or `sha256sum` *(Linux coreutils)* | Native OS cryptographic hashing utility | Computes tamper-evident `sha256sum` seals over `evidence/<target>/` | `shasum -a 256 --version` |
| **Optional Utilities** | `jq` $\ge$ `1.6` *(host inspection)*, `aws-cli` v2 *(live AMI cold-mount)* | `jq` `1.7+`, `aws-cli` `2.15+` | Ad-hoc terminal JSON querying (`jq`) and live AWS EBS snapshot attachment (`grc ami` without `--mock`) | `jq --version` |

---

## 2. Integrated 9-Engine Compliance & Security Suite

### 2.1 Containerized Security Scanners (`grc-scanner:local` — Debian Bookworm / Python 3.11)
All third-party static analysis and vulnerability tools execute inside the isolated `grc-scanner:local` container (`docker/Dockerfile.scanner`):

| Engine | Scanning Domain | Coverage / Purpose | Output Artifact |
| :--- | :--- | :--- | :--- |
| **Semgrep** | SAST / AST Policy | Evaluates source code against the **37-rule custom AOC baseline** ([`rules/custom-baseline-ruleset.yaml`](../rules/custom-baseline-ruleset.yaml)) | `semgrep_findings.json` |
| **Gitleaks** | Secret Detection | Scans files and Git history for hardcoded API keys, tokens, and PEM private keys | `gitleaks_findings.json` |
| **Checkov** | IaC Security | Audits Terraform, CloudFormation, Kubernetes, Ansible, and Dockerfiles against CIS/STIG rules | `checkov_findings.json` |
| **Syft** | SBOM Generation | Generates CycloneDX Software Bills of Materials across application and OS layers | `sbom.cdx.json` |
| **Grype** | CVE Vulnerability Scanner | Matches SBOM components against offline NVD/GHSA vulnerability databases | `grype_findings.json` |
| **Trivy** | Multi-Target Scanner | Secondary vulnerability and filesystem misconfiguration verification | `trivy_findings.json` |
| **OpenSCAP (`oscap`)** | OS STIG Evaluator | Evaluates cold-mounted AMI filesystems against DISA STIG XCCDF benchmarks | `oscap_results.xml` |

### 2.2 Zero-Dependency Host Python Engines (`scripts/`)
* **Git Bundle Manager ([`scripts/grc_bundle.py`](../scripts/grc_bundle.py))**: Validates SHA-256 digests and `git bundle verify` headers, extracts read-only (`0444`) workspaces, and writes `bundle_provenance.json`.
* **AMI Cold-Mount Manager ([`scripts/grc_ami.py`](../scripts/grc_ami.py))**: Validates KMS encryption, cold-mounts EBS snapshots (`ro,noload,noexec,nosuid`), supports `$0` `--mock` testing, and writes `ami_provenance.json`.
* **Cryptographic Library Scanner ([`scripts/crypto_lib_scan.py`](../scripts/crypto_lib_scan.py))**: Audits dependency manifests and native binaries against [`rules/crypto_catalog.json`](../rules/crypto_catalog.json) (`crypto_findings.json`).
* **DISA STIG SBOM Mapper ([`scripts/sbom_analyzer.py`](../scripts/sbom_analyzer.py))**: Maps CycloneDX/SPDX SBOM components to applicable DISA STIGs and DoD SRGs (`stig_matrix.md`, `stig_applicability.json`).
* **Phase 4 SCR/SCN Reporter ([`scripts/grc_reporter.py`](../scripts/grc_reporter.py))**: Aggregates all engine outputs into formal FedRAMP POA&Ms, NIST 800-53 matrices, ruleset validation logs, and cryptographic seals.

---

## 3. Work Products & Phase 4 Compliance Deliverables

Every completed scan populates `evidence/<target-name>/` with a sealed, audit-ready package:

| Deliverable | File Name | Format | Purpose / Recipient |
| :--- | :--- | :--- | :--- |
| **Chain-of-Custody Provenance** | `bundle_provenance.json` / `ami_provenance.json` | JSON | Cryptographic SHA-256 digest, Git commit/tag or AMI/KMS ARN, and session timestamps |
| **Software Bill of Materials (SBOM)** | `sbom.cdx.json` | JSON (CycloneDX) | Complete software supply chain component inventory (`CM-8`) |
| **DISA STIG Applicability Matrix** | `stig_matrix.md` & `stig_applicability.json` | Markdown / JSON | Maps discovered software packages to governing DISA STIG and DoD SRG benchmarks |
| **Ruleset Validation Audit Log** | `ruleset_validation.md` | Markdown | Itemized pass/fail audit log across all **37 custom Semgrep AST rules** |
| **Plan of Action & Milestones (POA&M)** | `poam_data.md` | Markdown | Itemized findings with FedRAMP High SLAs (30d CAT I / 60d CAT II / 90d CAT III) and remediation plans |
| **NIST SP 800-53 Traceability Matrix** | `controls.md` | Markdown | Control-by-control compliance rollup across `AC`, `CM`, `IA`, `RA`, `SC`, and `SI` families |
| **Consolidated SCR/SCN Package** | `scr_scn_package.json` | JSON | Unified machine-readable compliance payload for eMASS, ServiceNow GRC, or Jira ingestion |
| **Cryptographic Evidence Seal** | `sha256sum` | Text | SHA-256 integrity manifest computed across all files in the evidence package |
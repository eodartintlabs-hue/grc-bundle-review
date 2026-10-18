# Release Notes (`hygiene/RELEASE_NOTES.md`)

<p align="center">
  <a href="../README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/DATAFLOW.md"><b>🔄 Data Flow</b></a> &nbsp;·&nbsp;
  <a href="../SECURITY.md"><b>🛡️ Security Policy</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/GOVERNANCE.md"><b>⚖️ Governance & Mandates</b></a> &nbsp;·&nbsp;
  <a href="../testing/TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="../testing/live-demo.md"><b>🎬 Live Demo</b></a> &nbsp;·&nbsp;
  <a href="RELEASE_NOTES.md"><b>🚀 Release Notes</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG.md"><b>🩹 v1 Patch Log</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc-bundle-use-case.md"><b>📑 Use Case Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="../docs/test-dummies-guide.md"><b>🎯 Test Dummies Guide</b></a>
</p>

> **Project**: GRC Bundle & AMI Review Pipeline (`grc-bundle-review`)  
> **Active Release Series**: `v1.x` — Codename **Yokosuka**  
> **Quick Patch Ledger**: See **[`hygiene/PATCH_LOG.md`](PATCH_LOG.md)** for the condensed running table of all `v1` patches.

---

## Versioning & Codename Convention

All releases follow **Semantic Versioning (`v<MAJOR>.<MINOR>.<PATCH>`)** paired with a **Release Series Codename**:
* **Format**: `Release v<MAJOR>.<MINOR>.<PATCH> - <Codename>: <Summary>`
* **Current Series (`v1.x`)**: **Yokosuka**
  * **MAJOR (`v1.0.0`)**: Architectural baseline and major compliance milestones.
  * **MINOR (`v1.x.0`)**: New backward-compatible scanners, CLI subcommands, or compliance frameworks.
  * **PATCH (`v1.0.x`)**: Bug fixes, rule tuning, offline CVE database refreshes, documentation, and repository hygiene.

---

## 🐛 `v1.0.4` — Yokosuka (Patch 4: Unified 9-Engine Scan Fix & Independent Engine Dispatch)
**Release Date**: October 18, 2026  
**Tag**: `v1.0.4`  
**Type**: Bug Fix & CLI Enhancement (`Bug Fix`)

### Highlights & Changes
* **Bug Fix — Automatic `crypto_lib_scan.py` & `sbom_analyzer.py` Execution in `./grc scan`**:
  * Fixed an orchestration omission where running `./grc scan` executed the 7 containerized scanners and immediately ran `grc_reporter.py` without first invoking `scripts/crypto_lib_scan.py` (`crypto_findings.json`) and `scripts/sbom_analyzer.py` (`stig_matrix.md` and `stig_applicability.json`).
  * Full scans (`./grc scan` / `./grc scan --all`) now execute all **9 compliance engines** end-to-end before synthesizing Phase 4 deliverables (`poam_data.md`, `controls.md`, `ruleset_validation.md`, `scr_scn_package.json`, `sha256sum`).
* **Independent Compliance Engine Selection (`--engine <name>` / `--<engine>`)**:
  * Updated [`./grc`](../grc) and [`docker/scan_orchestrator.sh`](../docker/scan_orchestrator.sh) so auditors can invoke the full suite (`all` / `--all`) or any individual compliance engine independently:
    * Containerized engines: `semgrep`, `gitleaks`, `checkov`, `syft`, `grype` (auto-runs `syft` if `sbom.cdx.json` is missing), `trivy`, `oscap`.
    * Host Python engines: `crypto` (`crypto_lib_scan.py`) and `sbom` (`sbom_analyzer.py`, auto-generating `sbom.cdx.json` via `syft` if missing).
  * Added `--no-report` flag to optionally skip Phase 4 report synthesis when running targeted single-engine checks, and `--help` (`./grc scan --help`) for CLI reference.
* **Provenance Chain-of-Custody Preservation**:
  * Both [`./grc`](../grc) and [`docker/scan_orchestrator.sh`](../docker/scan_orchestrator.sh) now automatically copy `bundle_provenance.json` and `ami_provenance.json` from the ephemeral workspace into the target `evidence/` directory across all scan modes.

---

## 🩹 `v1.0.3` — Yokosuka (Patch 3: Production vs. Demo Evidence Segregation & Ledger Refinement)
**Release Date**: October 18, 2026  
**Tag**: `v1.0.3` (`48a43ff`)  
**Type**: Patch Release (Evidence Vault Hygiene & Patch Ledger)

### Highlights & Changes
* **Production vs. Demo Evidence Segregation (`testing/demo-evidence/`)**:
  * Relocated all synthetic test bundle outputs (`aoc-04-command-injection`, `aoc-07-iac-misconfig`, `aoc-09-eol-libraries`, `aoc-10-critical-cves`) into [`testing/demo-evidence/`](../testing/demo-evidence/).
  * Added `evidence/.gitkeep` so the root `evidence/` directory remains tracked as a pristine vault strictly reserved for real production bundle reviews.
  * Updated [`testing/live-demo.md`](../testing/live-demo.md), [`amplifying-info/DATAFLOW.md`](../amplifying-info/DATAFLOW.md), and [`amplifying-info/GOVERNANCE.md`](../amplifying-info/GOVERNANCE.md) to target `testing/demo-evidence/`.
* **Patch Ledger Table Optimization ([`hygiene/PATCH_LOG.md`](PATCH_LOG.md))**:
  * Removed redundant duplicate version/tag and codename columns.
  * Added explicit `Commit` SHA tracking and a rightmost **`Author / POC`** attribution column.
  * Bumped the `grcfetch` version banner in [`./grc`](../grc) and [`README.md`](../README.md) to `GRC Bundle Reviewer v1.0.3 (Yokosuka)`.

---

## 🩹 `v1.0.2` — Yokosuka (Patch 2: Modular Directory Reorganization)
**Release Date**: October 18, 2026  
**Tag**: `v1.0.2` (`3445ac6`)  
**Type**: Patch Release (Repository Hygiene & Directory Architecture)

### Highlights & Changes
* **Modular Documentation Folders (`amplifying-info/`, `testing/`, `hygiene/`)**:
  * Streamlined the repository root so only [`README.md`](../README.md) and [`SECURITY.md`](../SECURITY.md) remain at top-level to power GitHub's native repository tabs.
  * Created **`amplifying-info/`** housing [`ARCHITECTURE.md`](../amplifying-info/ARCHITECTURE.md), [`DATAFLOW.md`](../amplifying-info/DATAFLOW.md), and [`GOVERNANCE.md`](../amplifying-info/GOVERNANCE.md).
  * Created **`testing/`** housing [`TESTING.md`](../testing/TESTING.md) and [`live-demo.md`](../testing/live-demo.md).
  * Created **`hygiene/`** housing [`RELEASE_NOTES.md`](RELEASE_NOTES.md) and [`PATCH_LOG.md`](PATCH_LOG.md).
* **Cross-Repository Link & Asset Synchronization**:
  * Updated all top navigation bars, relative Markdown links, and SVG diagram paths (`../docs/assets/tech-stack.svg`, `../docs/assets/data-flow.svg`) across all 10 documentation pages.
  * Bumped the `grcfetch` version banner in [`./grc`](../grc) and [`README.md`](../README.md) to `GRC Bundle Reviewer v1.0.2 (Yokosuka)`.

---

## 🩹 `v1.0.1` — Yokosuka (Patch 1: Initial Repo Hygiene, Release Ledger & Evidence Refresh)
**Release Date**: October 18, 2026  
**Tag**: `v1.0.1` (`d038e81`)  
**Type**: Patch Release (Hygiene, Documentation & Evidence Refresh)

### Highlights & Changes
* **Version Naming & CLI Branding (`Yokosuka`)**:
  * Formalized the `v1.x - Yokosuka` version naming convention across Git annotated tags and documentation.
  * Updated the `grcfetch` ASCII banner in [`./grc`](../grc) and [`README.md`](../README.md) to display the `(Yokosuka)` release series codename.
* **Repository Hygiene & File Naming**:
  * Relocated and standardized the root use-case walkthrough from `grc-bundle Use Case.md` to clean kebab-case at [`docs/grc-bundle-use-case.md`](../docs/grc-bundle-use-case.md) to eliminate URL-encoded spaces (`%20`).
  * Standardized Git author/tagger identity to use GitHub `noreply` privacy email (`eodartintlabs-hue@users.noreply.github.com`).
* **Release Tracking & Live Demo Runbook**:
  * Added [`PATCH_LOG.md`](PATCH_LOG.md) to maintain a single-table ledger of all `v1.x` patches.
  * Added [`RELEASE_NOTES.md`](RELEASE_NOTES.md) for narrative release tracking.
  * Added [`live-demo.md`](../testing/live-demo.md) providing a step-by-step live presentation script for **AOC-09 (EOL Crypto)**, **AOC-10 (Critical CVEs)**, and **AOC-04 (Command Injection)**.
* **Compliance Evidence Refresh**:
  * Added complete Phase 4 compliance deliverable packages under `evidence/` for `aoc-04-command-injection`, `aoc-09-eol-libraries`, and `aoc-10-critical-cves`.

---

## 🚀 `v1.0.0` — Yokosuka (Initial Production Release)
**Release Date**: October 18, 2026  
**Tag**: `v1.0.0` (`9bc27c3`)  
**Annotation**: `Release v1.0.0 - Yokosuka: Initial working 5-phase GRC Bundle Review Pipeline`

### Executive Summary
`v1.0.0 - Yokosuka` marks the first complete, end-to-end operational release of the **GRC Bundle & AMI Review Pipeline**. Engineered for high-assurance federal and defense environments (**FedRAMP High**, **DISA STIG**, **NIST SP 800-53 Rev. 5**, **DoD RMF**), the pipeline performs cryptographic pre-verification, read-only ephemeral restoration, air-gapped multi-engine static analysis, and automated **Security Change Request / Security Change Notification (SCR/SCN)** evidence synthesis.

### Key Capabilities Delivered in `v1.0.0`

#### 1. Five-Phase Out-of-Band (OOB) Audit Lifecycle
* **Phase 1 (Pull & Verify)**: Cryptographic SHA-256 checksum validation and `git bundle verify` object graph checks ([`scripts/grc_bundle.py`](../scripts/grc_bundle.py)), plus AWS AMI KMS CMK encryption verification ([`scripts/grc_ami.py`](../scripts/grc_ami.py)).
* **Phase 2 (Ephemeral Restore)**: Zero-execution extraction (`chmod 0444` write-locks for Git bundles; `mount -o ro,noload,noexec,nosuid` cold-mounting for AMI EBS snapshots) and automatic emission of `bundle_provenance.json` / `ami_provenance.json`.
* **Phase 3 (Air-Gapped Multi-Engine Scan)**: Containerized analysis inside `grc-scanner:local` running with `--network none` and `/workspace:ro`.
* **Phase 4 (SCR/SCN Compliance Synthesis)**: Automated generation of `poam_data.md`, `controls.md`, `ruleset_validation.md`, `scr_scn_package.json`, and cryptographic `sha256sum` seals ([`scripts/grc_reporter.py`](../scripts/grc_reporter.py)).
* **Phase 5 (Ephemeral Teardown)**: Complete workspace sanitization and volume detachment (`./grc bundle clean`, `./grc ami clean`).

#### 2. Seven Integrated Security & Compliance Engines
* **Semgrep OSS**: Evaluates 37 custom AST rules ([`rules/custom-baseline-ruleset.yaml`](../rules/custom-baseline-ruleset.yaml)) covering AOC 02 through AOC 140 across Python, Go, Java, and JavaScript/TypeScript.
* **Gitleaks**: High-entropy secret and private key detection.
* **Checkov**: Offline Infrastructure-as-Code (Terraform, Kubernetes, Dockerfile, CloudFormation) compliance auditing.
* **Syft**: CycloneDX (`sbom.cdx.json`) Software Bill of Materials generation.
* **Grype & Trivy**: Dual-engine offline CVE vulnerability matching against pre-cached NVD/GHSA databases.
* **OpenSCAP (`oscap`)**: OS-level DISA STIG XCCDF evaluation for cold-mounted AMIs.
* **Custom Python Auditors**: Zero-dependency host scripts for EOL/non-FIPS cryptographic library detection ([`scripts/crypto_lib_scan.py`](../scripts/crypto_lib_scan.py)) and CycloneDX-to-DISA STIG applicability mapping ([`scripts/sbom_analyzer.py`](../scripts/sbom_analyzer.py)).

#### 3. Comprehensive Architecture & Governance Documentation Suite
* **[`README.md`](../README.md)**: Master lifecycle overview, AOC coverage matrix, and `./grc` CLI command reference.
* **[`amplifying-info/ARCHITECTURE.md`](../amplifying-info/ARCHITECTURE.md)**: 8-layer visual technology stack (`docs/assets/tech-stack.svg`), component breakdown, and `$0` operational cost analysis.
* **[`amplifying-info/DATAFLOW.md`](../amplifying-info/DATAFLOW.md)**: End-to-end telemetry lineage (`docs/assets/data-flow.svg`), trust boundary zones, and SBOM fan-out architecture.
* **[`SECURITY.md`](../SECURITY.md)**: Runtime air-gap verification (`--network none`), scanner telemetry suppression, and 7-point threat model.
* **[`amplifying-info/GOVERNANCE.md`](../amplifying-info/GOVERNANCE.md)**: Statutory traceability across NIST SP 800-53 R5, NIST 800-218 (SSDF), NIST 800-161 (C-SCRM), FIPS 140-3, DoDI 8510.01 (RMF), DoD CC SRG, DISA STIGs, and EO 14028.
* **[`testing/TESTING.md`](../testing/TESTING.md)** & **[`docs/test-dummies-guide.md`](../docs/test-dummies-guide.md)**: Formal verification test plan and negative-testing guide paired with [`grc-test-dummies`](https://github.com/eodartintlabs-hue/grc-test-dummies).

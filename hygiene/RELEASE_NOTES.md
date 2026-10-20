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
  <a href="ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="../docs/scan-transform-guide.md"><b>📊 Scan-to-POA&M Guide</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc-bundle-use-case.md"><b>📑 Bundle Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="../docs/test-dummies-guide.md"><b>🎯 Test Dummies Guide</b></a>
</p>

> **Project**: GRCx — The GRC eXperience (`grcx`)  
> **Active Release Series**: `v1.2.x` — Codename **Misawa** *(Restricted Beta / Integration Testing)*  
> **Upcoming Full Production Release (`v2.0.0`)**: **`Pearl Harbor`** *(First in the Hawaiian Military Base Cities Series — see **[`hygiene/ROADMAP.md`](ROADMAP.md)**)*  
> **Quick Patch Ledger**: See **[`hygiene/PATCH_LOG.md`](PATCH_LOG.md)** for the condensed running table of all `v1` patches.

---

## Release Series Roadmap & Codename Convention

All releases follow **Semantic Versioning (`v<MAJOR>.<MINOR>.<PATCH>`)** paired with a **Geographic Military Base Codename** that denotes the maturity phase of the pipeline:

| Major Series | Lifecycle Phase | Access & Scope | Geographic Theme | Active / Candidate Codenames |
| :--- | :--- | :--- | :--- | :--- |
| **`v1.x`** | **Restricted Beta & Integration Testing** | Limited access for designated integration testers, security assessors, and pilot engineering teams validating end-to-end bundle & AMI workflows. | 🇯🇵 **Japan** *(U.S. Military Installations)* | **`Yokosuka`** *(`v1.0.x`)* · **`Kadena`** *(`v1.1.0` `GRCx` Rebrand)* · **`Misawa`** *(Active — `v1.2.x` Scan-to-POA&M Transformer)* · **`Sasebo`** *(`v1.3.0` Workstation Portability)* |
| **`v2.x`** | **Full Production Release (GA)** | General Availability across production enclaves after Beta integration sign-off. | 🌺 **Hawaii** *(Cities with U.S. Military Bases)* | **`Pearl Harbor`** *(`v2.0.0` GA Launch & Helm Auditing)* · **`Kaneohe`** *(`v2.1.0+` Cloud Lift, Local LLM & RAM-Adaptive Scaling)* · `Wahiawa` (`v2.2.0`), `Kunia`, `Kekaha` |

### Semantic Versioning Rules
* **Format**: `Release v<MAJOR>.<MINOR>.<PATCH> - <Codename>: <Summary>`
* **MAJOR (`v1.0.0` Beta $\rightarrow$ `v2.0.0` Full Release)**: Lifecycle milestone transitions (Beta Integration Testing in `v1.x` to Full Production GA in `v2.0.0`).
* **MINOR (`v1.x.0`)**: New backward-compatible scanners, CLI subcommands, compliance frameworks, or major platform identity milestones introduced during the series.
* **PATCH (`v1.x.y`)**: Bug fixes, rule tuning, offline CVE database refreshes, documentation, and repository hygiene.

---

## 🛩️ `v1.2.0` — Misawa (Minor Release: Standalone Tenable & AWS Inspector Scan-to-FedRAMP POA&M Transformation Engine)
**Release Date**: October 20, 2026  
**Tag**: `v1.2.0`  
**Type**: Minor Release (`Misawa` — Standalone Scan-to-POA&M Transformation Engine, Open $\rightarrow$ Closed Reconciliation, Remediation URL Drafter & SLA Aging Analyzer)

### Highlights & Changes
* **New Standalone Native Python Compliance Engine ([`scripts/transform_scans.py`](../scripts/transform_scans.py) & `./grc transform`)**:
  * Engineered a 100% Python 3 Standard Library compliance transformation engine designed for direct, standalone daily use by GRC analysts (requiring no Docker container, no `.bundle` file, and no `pip` installs).
  * Automatically detects and parses **Tenable (Nessus / Tenable.sc / Tenable.io)** and **AWS Inspector** vulnerability scan exports in both **`.csv`** and **`.xlsx`** formats, mapping each unique `(Vulnerability + Asset)` combination into its own row across the 27 columns of the official FedRAMP POA&M templates.
* **Bundled Official OPEN & CLOSED FedRAMP POA&M Templates ([`templates/`](../templates/))**:
  * Integrated [`templates/OPEN FedRAMP-POAM-Template.xlsx`](../templates/OPEN%20FedRAMP-POAM-Template.xlsx) (*`Open POA&M Items`, Columns `B..AB`, Row 5+*) and [`templates/CLOSED LEGACY FedRAMP-POAM-Template.xlsx`](../templates/CLOSED%20LEGACY%20FedRAMP-POAM-Template.xlsx) (*`Closed POA&M Items`, Columns `A..AA`, Row 3+*).
  * Extended the `OPEN` template's Risk Rating dropdown validation and Column `M` (`Scheduled Completion Date`) Excel formula to support **`Critical` (`+30d`)**, **`High` (`+30d`)**, **`Moderate` (`+90d`)**, and **`Low` (`+180d`)**.
* **Automated Open $\rightarrow$ Closed POA&M Delta Reconciliation**:
  * Prompts for (or accepts via `--previous-open`) a previously filled-out **OPEN FedRAMP POA&M** workbook.
  * **Carried-Over Open Findings**: Retain their existing `POAM ID`, immutable `Original Detection Date` (`Column L`), and analyst-curated fields while updating `Status Date` (`Column N`).
  * **Remediated / Closed Findings**: Entries present in the previous OPEN POA&M that are no longer present in the new scan (or marked `False Positive = Yes`) are automatically removed from the OPEN POA&M and moved to the **CLOSED FedRAMP POA&M** template with a verification timestamp.
* **Interactive Missing Remediation Plan Drafter (`[y/n]`) with Official Tenable & AWS URLs**:
  * Identifies any OPEN POA&M entries missing a `Remediation Plan` (`Column K`) and asks the user (`y/n`) whether **GRCx** should draft them.
  * When confirmed (`y`), populates `Column K` with remediation steps and authoritative URLs (`https://www.tenable.com/plugins/nessus/<Plugin_ID>`, `https://explore.alas.aws.amazon.com/<ALAS_ID>.html`, AWS Inspector remediation docs, and `https://nvd.nist.gov/vuln/detail/<CVE>`).
* **SLA Breach Count & Finding Age Reporting**:
  * Reports the exact count of finished OPEN POA&M entries whose `Scheduled Completion Date` (SLA) has passed and prints an itemized aging table showing how many days old each finding is from its `Original Detection Date` (also saved to `poam_transform_summary.md` for previewing in Cursor).
* **Standalone Analyst Guide & Sample Scan Fixtures ([`docs/scan-transform-guide.md`](../docs/scan-transform-guide.md) & [`testing/sample-scans/`](../testing/sample-scans/))**:
  * Added a dedicated standalone analyst guide ([`docs/scan-transform-guide.md`](../docs/scan-transform-guide.md)), sample Tenable & AWS Inspector CSVs, a sample previous OPEN POA&M workbook, and pre-generated transformation evidence in [`testing/demo-evidence/`](../testing/demo-evidence/).

---

## 🦅 `v1.1.0` — Kadena (Minor Release: Platform Rebrand to `GRCx — "The GRC eXperience"` & New Brand Identity)
**Release Date**: October 20, 2026  
**Tag**: `v1.1.0`  
**Type**: Minor Release (`Kadena` — Platform Rebrand, Visual Identity & CLI Standardization)

### Highlights & Changes
* **Platform Rebrand to `GRCx` ("The GRC eXperience")**:
  * Transitioned the platform identity from *GRC Bundle Review Pipeline* to **`GRCx` (*The GRC eXperience*)**, reflecting the application's evolution beyond `.bundle` inspection into a comprehensive, multi-engine, air-gapped compliance automation and synthesis platform.
  * Standardized all active documentation, architectural specifications, test plans, runbooks, and Python CLI analyzer metadata (`scripts/sbom_analyzer.py`, `scripts/grc_bundle.py`) to `GRCx`.
* **New Brand Logo Lockups ([`assets/logo/`](../assets/logo/))**:
  * Added high-contrast monochrome Light Mode ([`assets/logo/grcx-logo-light.png`](../assets/logo/grcx-logo-light.png)) and Dark Mode ([`assets/logo/grcx-logo-dark.png`](../assets/logo/grcx-logo-dark.png)) brand lockups featuring a soaring seagull silhouette escaping a receding square enclosure above slab-serif **`GRCx`** and **`The GRC eXperience`** typography.
  * Integrated a GitHub theme-adaptive `<picture>` header (`prefers-color-scheme: dark` / `light`) at the top of [`README.md`](../README.md).
* **Upgraded `grcfetch` Terminal Banner ([`./grc`](../grc) & [`README.md`](../README.md))**:
  * Extended the `@GGG` ASCII art banner in [`./grc`](../grc) (`./grc fetch`) and [`README.md`](../README.md) to render **`GRCx`** with the centered slogan **`───  T h e   G R C   e X p e r i e n c e  ───`** and bumped the version string to `GRCx v1.1.0 (Kadena)`.
* **Dedicated Onboarding & Command Guides ([`INSTALL.md`](../INSTALL.md) & [`COMMANDS.md`](../COMMANDS.md)) & Documentation Consolidation**:
  * Added [`INSTALL.md`](../INSTALL.md) at the repository root to guide new users step-by-step from downloading `GRCx` off GitHub and building `grc-scanner:local` to executing their first bundle scan and viewing rendered Markdown/JSON deliverables in **Cursor**.
  * Added [`COMMANDS.md`](../COMMANDS.md) at the repository root providing an isolated, plain-English reference of every command and flag accepted by `./grc`.
  * Removed 3 redundant legacy files in `docs/` (`workspace-layout.md`, `review-workflow.md`, and `design-rules-and-aocs.md`) and slimmed down [`README.md`](../README.md) Section 8 to link directly to `INSTALL.md` and `COMMANDS.md`.

---

## 🖥️ `v1.0.6` — Yokosuka (Patch 6: Minimum & Recommended System Requirements & 4-AOC Combo Verification)
**Release Date**: October 19, 2026  
**Tag**: `v1.0.6` (`bf1c799`)  
**Type**: Patch Release (`Hygiene & Docs` — System Requirements & Multi-AOC Verification Evidence)

### Highlights & Changes
* **Minimum & Recommended System Requirements (`README.md` Section 7 & [`docs/workspace-layout.md`](../docs/workspace-layout.md))**:
  * Documented explicit minimum (`v1.x` baseline) and recommended (`v1.x` & `v2.0+` local LLM) hardware specifications (`64-bit` CPU, `8 GB` min / `16–32 GB+` recommended RAM, `10 GB` min / `25 GB+` recommended SSD, air-gapped `--network none` runtime).
  * Added a software prerequisites matrix (`bash >= 3.2`, `git >= 2.30+`, `python3 >= 3.9+` standard library, `Docker >= 24.0+` / Docker Desktop `4.25+`, optional `aws-cli` v2) with quick verification commands.
  * Upgraded [`docs/workspace-layout.md`](../docs/workspace-layout.md) to reflect all 9 compliance engines, top navigation links, and Phase 4 deliverable schemas.
* **Multi-AOC Combined Synthetic Verification ([`testing/demo-evidence/aoc-combo-4x/`](../testing/demo-evidence/aoc-combo-4x/))**:
  * Verified end-to-end 9-engine detection and Phase 4 synthesis against a 4-in-1 synthetic bundle (`aoc-combo-4x.bundle`) combining **AOC-02** (Password Hygiene), **AOC-04** (Command Injection), **AOC-07** (IaC Misconfigurations), and **AOC-09** (Unsupported Crypto Libraries), generating 19 normalized POA&M findings across 7 NIST SP 800-53 controls.
  * Bumped the `grcfetch` CLI banner in [`./grc`](../grc) and [`README.md`](../README.md) to `GRC Bundle Reviewer v1.0.6 (Yokosuka)`.

---

## 🗺️ `v1.0.5` — Yokosuka (Patch 5: Product Roadmap Specification — `Sasebo`, `Misawa` & `Pearl Harbor` GA)
**Release Date**: October 19, 2026  
**Tag**: `v1.0.5` (`48d1d34`)  
**Type**: Patch Release (`Hygiene & Docs` — Product Roadmap & Navigation Synchronization)

### Highlights & Changes
* **Dedicated Product Roadmap ([`hygiene/ROADMAP.md`](ROADMAP.md)) & `README.md` Roadmap Section**:
  * Authored a comprehensive forward-looking product roadmap detailing the multi-stage progression from the active `v1.0.x — Yokosuka` Beta baseline through upcoming Japan-series minor updates and the `v2.x` Hawaiian General Availability (GA) series:
    * **`v1.2.0 — Sasebo` (Universal Workstation Portability)**: Out-of-the-box compatibility across macOS (`arm64`/`amd64`), Linux, and Windows WSL2—resolving Linux container UID/GID root ownership on `evidence/`, adding SELinux (`:Z`) and Podman support, pinning deterministic `Dockerfile.scanner` tool versions, and adding `./grc doctor`.
    * **`v1.3.0 — Misawa` (Tenable & AWS Inspector CSV Ingest $\rightarrow$ Official FedRAMP POA&M `.xlsx`)**: Multi-source vulnerability CSV ingestion (`./grc ingest`), cross-scanner CVE deduplication, and automated population of the official FedRAMP POA&M Excel spreadsheet (`.xlsx`).
    * **`v2.0.0 — Pearl Harbor` (Full Production GA Launch)**: Cloud enclave execution on hardened **AWS EC2** and immutable **AWS Bottlerocket** container hosts, offline **Helm Chart compliance auditing (`./grc scan --engine helm`)**, and a baseline air-gapped local LLM (`Gemma` / `GPT-OSS`) synthesis engine.
    * **`v2.1.0 — Kaneohe` (RAM-Adaptive LLM Scaling & OSCAL)**: Dynamic endpoint RAM profiler (`8GB` to `64GB+`) that automatically selects the optimal quantized `Gemma` / `GPT-OSS` model tier based on host memory configuration, plus NIST OSCAL 1.1.x export.
* **Cross-Repository Navigation & Version Bump**:
  * Added **`🗺️ Roadmap`** to the top navigation bar across all documentation pages and updated [`hygiene/PATCH_LOG.md`](PATCH_LOG.md).
  * Bumped the `grcfetch` CLI banner in [`./grc`](../grc) and [`README.md`](../README.md) to `GRC Bundle Reviewer v1.0.5 (Yokosuka)`.

---

## 🐛 `v1.0.4` — Yokosuka (Patch 4: Unified 9-Engine Scan Fix & Independent Engine Dispatch)
**Release Date**: October 18, 2026  
**Tag**: `v1.0.4` (`19c41dc`)  
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

## 🚀 `v1.0.0` — Yokosuka (Initial Beta Baseline — Integration Testing)
**Release Date**: October 18, 2026  
**Tag**: `v1.0.0` (`9bc27c3`)  
**Stage**: Restricted Beta (Integration Testing Access Only)  
**Annotation**: `Release v1.0.0 - Yokosuka: Initial working 5-phase GRC Bundle Review Pipeline`

### Executive Summary
`v1.0.0 - Yokosuka` marks the initial end-to-end **Beta baseline** of the **GRC Bundle & AMI Review Pipeline**, released to designated integration testers prior to the upcoming **`v2.0.0` Full Production Release**. Engineered for high-assurance federal and defense environments (**FedRAMP High**, **DISA STIG**, **NIST SP 800-53 Rev. 5**, **DoD RMF**), the pipeline performs cryptographic pre-verification, read-only ephemeral restoration, air-gapped multi-engine static analysis, and automated **Security Change Request / Security Change Notification (SCR/SCN)** evidence synthesis.

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

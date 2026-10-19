# v1.x Running Patch Ledger (`hygiene/PATCH_LOG.md`)

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
  <a href="../docs/grc-bundle-use-case.md"><b>📑 Use Case Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="../docs/test-dummies-guide.md"><b>🎯 Test Dummies Guide</b></a>
</p>

> **Active Major Series**: `v1.x` — **Restricted Beta & Integration Testing** *(Limited Access)*  
> **Active Series Codename**: `Yokosuka` *(Japan Military Installation Theme)*  
> **Next Major Series (`v2.0.0`)**: **`Pearl Harbor`** — **Full Production Release (GA)** *(Hawaiian Military Base Cities Theme — see **[`hygiene/ROADMAP.md`](ROADMAP.md)**)*  
> **Versioning Standard**: Semantic Versioning (`v<MAJOR>.<MINOR>.<PATCH> - <Codename>`)  
> **Companion Document**: See **[`hygiene/RELEASE_NOTES.md`](RELEASE_NOTES.md)** for full narrative release notes and **[`hygiene/ROADMAP.md`](ROADMAP.md)** for the `v2.0.0` product roadmap.

---

## 1. v1.x ("Yokosuka" — Beta & Integration Testing) Running Patch Table

This ledger tracks the initial Beta baseline (`v1.0.0`) and all incremental integration-testing patches (`v1.0.x`) across the **v1 Beta lifecycle** of the **GRC Bundle & AMI Review Pipeline** prior to the **`v2.0.0` Full Release**.

| Version | Commit | Date | Category | Subsystem / Files Affected | Summary of Changes | Author / POC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`v1.0.0`** | `9bc27c3` | `2026-10-18` | `Beta Baseline` | `./grc`, `scripts/*`, `docker/*`, `rules/*`, `docs/*` | Initial Restricted Beta baseline (for designated integration testing) of the 5-phase GRC Bundle & AMI Review Pipeline, 7-engine air-gapped Docker scanner suite, 37 custom Semgrep AOC rules, and Phase 4 SCR/SCN compliance reporting engine. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.1`** | `d038e81` | `2026-10-18` | `Hygiene & Docs` | `./grc`, `README.md`, `docs/grc-bundle-use-case.md`, `RELEASE_NOTES.md`, `PATCH_LOG.md`, `live-demo.md` | Adopted `Yokosuka` release codename in `grcfetch` CLI banner; standardized Git author identity to GitHub `noreply`; relocated and kebab-cased `docs/grc-bundle-use-case.md`; added initial `RELEASE_NOTES.md`, `PATCH_LOG.md`, and `live-demo.md`; refreshed AOC-04, AOC-09, and AOC-10 evidence packages. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.2`** | `3445ac6` | `2026-10-18` | `Hygiene & Docs` | `amplifying-info/*`, `testing/*`, `hygiene/*`, `README.md`, `SECURITY.md`, `./grc` | Reorganized root documentation into modular domain directories (`amplifying-info/`, `testing/`, `hygiene/`) while preserving `README.md` and `SECURITY.md` at the root for native GitHub tabs; updated all cross-file navigation bars and SVG asset paths; bumped CLI banner to `v1.0.2 (Yokosuka)`. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.3`** | `48a43ff` | `2026-10-18` | `Hygiene & Docs` | `testing/demo-evidence/*`, `evidence/.gitkeep`, `hygiene/PATCH_LOG.md`, `testing/live-demo.md`, `./grc` | Segregated synthetic test outputs into `testing/demo-evidence/` so root `evidence/` is reserved exclusively for real production bundles; streamlined `PATCH_LOG.md` table to eliminate redundant version/codename columns and added `Commit` and `Author / POC` columns; bumped CLI banner to `v1.0.3 (Yokosuka)`. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.4`** | `19c41dc` | `2026-10-18` | `Bug Fix` | `./grc`, `docker/scan_orchestrator.sh`, `README.md`, `testing/live-demo.md`, `hygiene/*` | Fixed bug where `./grc scan` omitted `crypto_lib_scan.py` and `sbom_analyzer.py` prior to Phase 4 synthesis; added `--all` and `--engine <name>` (`semgrep`, `gitleaks`, `checkov`, `syft`, `grype`, `trivy`, `oscap`, `crypto`, `sbom`) flags for independent engine execution; documented `v1.x` Restricted Beta (`Yokosuka`) vs. `v2.0.0` Full Release (Hawaiian military base cities) lifecycle. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.5`** | `48d1d34` | `2026-10-19` | `Hygiene & Docs` | `hygiene/ROADMAP.md`, `hygiene/RELEASE_NOTES.md`, `hygiene/PATCH_LOG.md`, `README.md`, `SECURITY.md`, `amplifying-info/*`, `testing/*`, `docs/grc-bundle-use-case.md`, `./grc` | Added [`hygiene/ROADMAP.md`](ROADMAP.md) and `README.md` roadmap section detailing the product roadmap across Japan (`v1.2.0 — Sasebo` Universal Workstation Portability, `v1.3.0 — Misawa` Tenable & AWS Inspector CSV Ingest $\rightarrow$ Official FedRAMP POA&M `.xlsx`) and Hawaii (`v2.0.0 — Pearl Harbor` Cloud Lift, Helm Chart Auditing & Local LLM Baseline, `v2.1.0 — Kaneohe` RAM-Adaptive LLM Scaling); synchronized top navigation bars across all documentation files; bumped CLI banner to `v1.0.5 (Yokosuka)`. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.6`** | `HEAD` | `2026-10-19` | `Hygiene & Docs` | `README.md`, `docs/workspace-layout.md`, `testing/demo-evidence/aoc-combo-4x/*`, `hygiene/RELEASE_NOTES.md`, `hygiene/PATCH_LOG.md`, `./grc` | Added **Minimum & Recommended System Requirements (Hardware & Software)** tables to `README.md` (Section 7) and [`docs/workspace-layout.md`](../docs/workspace-layout.md); added 4-in-1 multi-AOC synthetic verification evidence package (`testing/demo-evidence/aoc-combo-4x/` combining AOC-02, AOC-04, AOC-07, and AOC-09); bumped CLI banner to `v1.0.6 (Yokosuka)`. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| *`v1.0.7`* | *Pending* | *TBD* | *TBD* | *TBD* | *Reserved for next incremental Beta integration patch in the `v1.x - Yokosuka` series.* | *TBD* |
| *`v1.2.0`<br/>(`Sasebo`)* | *Planned* | *TBD* | *Minor Release* | `./grc`, `docker/*`, `scripts/*` | *Planned Japan-series minor release dedicated to **Universal Workstation Portability** across macOS (`arm64`/`amd64`), Linux, and Windows WSL2—resolving Linux container UID/GID root ownership on `evidence/`, adding SELinux (`:Z`) and Podman support, pinning `Dockerfile.scanner` versions, and introducing `./grc doctor`.* | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue) |
| *`v1.3.0`<br/>(`Misawa`)* | *Planned* | *TBD* | *Minor Release* | `scripts/grc_ingest.py`, `scripts/grc_reporter.py`, `./grc` | *Planned Japan-series minor release introducing **Tenable & AWS Inspector CSV Ingestion (`./grc ingest`)**, cross-scanner CVE deduplication, and automated transformation into the **official FedRAMP POA&M Excel spreadsheet (`.xlsx`)**.* | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue) |
| *`v2.0.0`<br/>(`Pearl Harbor`)* | *Planned* | *TBD* | *Full Release (GA)* | *All Subsystems* | *Planned Full Production Release (General Availability) launching the Hawaiian military base cities series (`Pearl Harbor`). Lifts execution to cloud-hosted environments (**AWS EC2 & Bottlerocket**), adds **Helm chart compliance auditing (`./grc scan --engine helm`)**, and integrates a baseline air-gapped local LLM (`Gemma` / `GPT-OSS`) for POA&M synthesis (with dynamic endpoint RAM-adaptive scaling following in `v2.1.0 — Kaneohe`; see [`hygiene/ROADMAP.md`](ROADMAP.md)).* | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue) |

---

## 2. Patch Classification Key

| Category | Version Increment | Typical Scope |
| :--- | :--- | :--- |
| **`Hygiene & Docs`** | `v1.0.x` (Patch) | Documentation updates, diagram refreshes, filename standardization, `.gitignore` rules, and repository formatting. |
| **`Bug Fix`** | `v1.0.x` (Patch) | Fixes to CLI argument parsing, path resolution, Markdown formatting, or scanner invocation flags without breaking existing workflows. |
| **`Rule / Catalog Tuning`** | `v1.0.x` (Patch) | False-positive reductions in `rules/custom-baseline-ruleset.yaml` or EOL version updates in `rules/crypto_catalog.json`. |
| **`Security / Container Patch`** | `v1.0.x` (Patch) | Rebuilding `grc-scanner:local` to update offline CVE databases (Grype/Trivy) or base Debian Bookworm packages. |

---

## 3. How to Cut & Record a New Patch (`v1.0.x`)

1. **Add a row** to the table in Section 1 above and add a summary section in [`hygiene/RELEASE_NOTES.md`](RELEASE_NOTES.md).
2. **Update the version string** in [`./grc`](../grc) and [`README.md`](../README.md) (e.g., `GRC Bundle Reviewer v1.0.1 (Yokosuka)`).
3. **Commit all changes** and create an annotated Git tag:
   ```bash
   git add -A && git commit -m "chore(release): bump version to v1.0.1 (Yokosuka)"
   git tag -a v1.0.1 -m "Release v1.0.1 - Yokosuka: Repo hygiene, docs standardization, and patch ledger"
   git push origin main --tags
   ```

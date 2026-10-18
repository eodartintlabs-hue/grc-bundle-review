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
  <a href="../docs/grc-bundle-use-case.md"><b>📑 Use Case Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="../docs/test-dummies-guide.md"><b>🎯 Test Dummies Guide</b></a>
</p>

> **Active Major Series**: `v1.x`  
> **Release Codename**: `Yokosuka`  
> **Versioning Standard**: Semantic Versioning (`v<MAJOR>.<MINOR>.<PATCH> - <Codename>`)  
> **Companion Document**: See **[`hygiene/RELEASE_NOTES.md`](RELEASE_NOTES.md)** for full narrative release notes.

---

## 1. v1.x ("Yokosuka") Running Patch Table

This ledger tracks all baseline releases and incremental patches (`v1.0.x`) across the **v1 lifecycle** of the **GRC Bundle & AMI Review Pipeline**.

| Version | Commit | Date | Category | Subsystem / Files Affected | Summary of Changes | Author / POC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`v1.0.0`** | `9bc27c3` | `2026-10-18` | `Baseline Release` | `./grc`, `scripts/*`, `docker/*`, `rules/*`, `docs/*` | Initial production baseline of the 5-phase GRC Bundle & AMI Review Pipeline, 7-engine air-gapped Docker scanner suite, 37 custom Semgrep AOC rules, and Phase 4 SCR/SCN compliance reporting engine. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.1`** | `d038e81` | `2026-10-18` | `Hygiene & Docs` | `./grc`, `README.md`, `docs/grc-bundle-use-case.md`, `RELEASE_NOTES.md`, `PATCH_LOG.md`, `live-demo.md` | Adopted `Yokosuka` release codename in `grcfetch` CLI banner; standardized Git author identity to GitHub `noreply`; relocated and kebab-cased `docs/grc-bundle-use-case.md`; added initial `RELEASE_NOTES.md`, `PATCH_LOG.md`, and `live-demo.md`; refreshed AOC-04, AOC-09, and AOC-10 evidence packages. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.2`** | `3445ac6` | `2026-10-18` | `Hygiene & Docs` | `amplifying-info/*`, `testing/*`, `hygiene/*`, `README.md`, `SECURITY.md`, `./grc` | Reorganized root documentation into modular domain directories (`amplifying-info/`, `testing/`, `hygiene/`) while preserving `README.md` and `SECURITY.md` at the root for native GitHub tabs; updated all cross-file navigation bars and SVG asset paths; bumped CLI banner to `v1.0.2 (Yokosuka)`. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.3`** | `48a43ff` | `2026-10-18` | `Hygiene & Docs` | `testing/demo-evidence/*`, `evidence/.gitkeep`, `hygiene/PATCH_LOG.md`, `testing/live-demo.md`, `./grc` | Segregated synthetic test outputs into `testing/demo-evidence/` so root `evidence/` is reserved exclusively for real production bundles; streamlined `PATCH_LOG.md` table to eliminate redundant version/codename columns and added `Commit` and `Author / POC` columns; bumped CLI banner to `v1.0.3 (Yokosuka)`. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| **`v1.0.4`** | `HEAD` | `2026-10-18` | `Bug Fix` | `./grc`, `docker/scan_orchestrator.sh`, `README.md`, `testing/live-demo.md`, `hygiene/*` | Fixed bug where `./grc scan` omitted `crypto_lib_scan.py` and `sbom_analyzer.py` prior to Phase 4 synthesis; added `--all` and `--engine <name>` (`semgrep`, `gitleaks`, `checkov`, `syft`, `grype`, `trivy`, `oscap`, `crypto`, `sbom`) flags so all 9 compliance engines can run together or independently; preserved `bundle_provenance.json`/`ami_provenance.json` in `evidence/` across all scan modes. | **Byron Turner**<br/>[`@eodartintlabs-hue`](https://github.com/eodartintlabs-hue)<br/>`eodartintlabs-hue@users.noreply.github.com` |
| *`v1.0.5`* | *Pending* | *TBD* | *TBD* | *TBD* | *Reserved for next incremental patch in the `v1.x - Yokosuka` release series.* | *TBD* |

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

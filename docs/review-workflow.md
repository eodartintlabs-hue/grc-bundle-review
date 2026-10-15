# GRC Bundle Review Workflow

## Purpose and Expected Outcome

### Main Build Pipeline
1. GitHub Release bundle is created with a tag (e.g., v1.0.0).
2. Bundle is extracted into permanent storage for ingestion.
3. Bundle is retrieved by ingestor.

### GRC Bundle Review Process

**Pull & Verify** 
- Receive a read-only copy of the bundle before it is placed in permanent storage.
- Verify integrity.
- Record SHA-256 for this session.

**Restore** 
- Extract and restore the bundle into the workspace.
- Run `grc bundle restore`.

**Analyze** 
- Run `semgrep`, `trivy`, `gitleaks`, `checkov`, `syft`, and `grype`.
- Run `custom-baseline-ruleset.yaml` with semgrep.
- Run `crypto_lib_scan.py`.
- Run `sbom_analyzer.py`.   
- Generate POA&M datapoints.

**Evidence** 
- JSON-formatted reports of findings.
- Triage of findings.
- STIG applicability matrix.
- Software Bill of Materials (SBOM).
- Compliance reports.
- `sha256sum` file containing SHA-256 hashes of all generated files for integrity verification.

**SCR/SCN Package** 
- JSON-formatted evidence for SCR/SCN.
- POA&M datapoints (`poam_data.md`).
- Controls mapping file (`controls.md`).
- Ruleset validation logs in markdown format.


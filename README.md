# GRC Bundle Review Pipeline

> **Classification**: Internal DevSecOps & Security Compliance Specification  
> **Target Frameworks**: DISA STIG, NIST SP 800-53 Rev. 5, FedRAMP, OWASP Top 10  
> **Operational Model**: Out-of-Band (OOB), Fail-Open, Ephemeral Workspace Execution  

---

## Overview

The **GRC Bundle Review Pipeline** provides an automated, cryptographic verification and security analysis framework for evaluating software release bundles out-of-band. It guarantees audit completeness against federal and defense security baselines without gating or impacting developer deployment velocity.

```mermaid
flowchart LR
    A["Release Bundle (.bundle)"] --> B["1. Pull & Verify (SHA-256)"]
    B --> C["2. Restore Workspace"]
    C --> D["3. Analyze (Semgrep + Crypto + SBOM)"]
    D --> E["4. Compliance Evidence"]
    E --> F["5. Ephemeral Teardown (Clean)"]
```

---

## Core Capabilities

* **Cryptographic Provenance**: Enforces SHA-256 verification and `git bundle verify` before extraction, emitting immutable `bundle_provenance.json` records.
* **37-Rule Semgrep Policy Engine**: Scans Go, Java, Python, and JavaScript against **AOC 02–140** (NIST IA-2, SI-4, SI-16, SI-17, RA-5).
* **Cryptographic Provider & EOL Scanner**: Statically audits dependencies against [`crypto_catalog.json`](rules/crypto_catalog.json) to flag unsupported/EOL libraries like OpenSSL 1.1.1 and PyCrypto (**AOC 09**).
* **DISA STIG SBOM Applicability Engine**: Parses CycloneDX and SPDX SBOMs to generate STIG & SRG compliance matrices (**AOC 11**).
* **Ephemeral Hygiene**: Automated workspace cleanup ensures zero unvetted code persistence on audit workstations.

---

## Quickstart

Use the root CLI wrapper `./grc` to manage the complete bundle review lifecycle:

```bash
# 1. Verify bundle cryptographic integrity
./grc bundle verify release-v1.0.0.bundle --expected-sha256 <SHA256_HASH>

# 2. Extract into ephemeral workspace with read-only protection
./grc bundle restore release-v1.0.0.bundle --workspace ./ephemeral_workspace --ref v1.0.0 --read-only

# 3. Execute custom baseline Semgrep scan
semgrep scan --config="rules/custom-baseline-ruleset.yaml" --json -o ./ephemeral_workspace/semgrep_findings.json ./ephemeral_workspace

# 4. Scan cryptographic libraries & EOL versions
./grc crypto --workspace ./ephemeral_workspace --format json -o ./ephemeral_workspace/crypto_findings.json

# 5. Generate DISA STIG SBOM Applicability Matrix
./grc sbom --sbom ./ephemeral_workspace/bom.json --format markdown -o ./ephemeral_workspace/stig_matrix.md

# 6. Tear down ephemeral workspace post-review
./grc bundle clean --workspace ./ephemeral_workspace --delete-bundle release-v1.0.0.bundle
```

---

## Testing & Verification

A comprehensive, end-to-end verification test plan has been established to validate the pipeline using synthetic fixtures:

👉 **[Read the Full Verification Test Plan (TESTING.md)](TESTING.md)**

---

## Repository Structure

```text
grc-bundle-review/
├── README.md                      # Primary project overview and quickstart
├── TESTING.md                     # End-to-end audit verification test plan
├── grc                            # Root CLI dispatcher wrapper
├── .gitignore                     # Ignores temporary workspaces and bundles
│
├── docs/                          # Governance & architecture specifications
│   ├── design-rules-and-aocs.md   # Core design principles and AOC matrix
│   ├── review-workflow.md         # 5-stage review operational lifecycle
│   └── workspace-layout.md        # Workstation baseline and tooling specs
│
├── rules/                         # Declarative compliance policies
│   ├── custom-baseline-ruleset.yaml # 37-rule Semgrep baseline (AOC 02-140)
│   └── crypto_catalog.json        # Cryptographic library EOL & FIPS catalog
│
└── scripts/                       # Automation engines
    ├── grc_bundle.py              # Ingestion, restoration, and cleanup manager
    ├── crypto_lib_scan.py         # Static crypto library auditor
    └── sbom_analyzer.py           # CycloneDX & SPDX to DISA STIG mapper
```

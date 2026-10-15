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
* **EBS Snapshot Cold-Mount Engine**: Audits Amazon Machine Images (AMIs) out-of-band by cold-mounting root EBS snapshots read-only (`ro,noload,noexec,nosuid`), guaranteeing zero untrusted code execution and zero state mutation (`ami_provenance.json`).
* **37-Rule Semgrep Policy Engine**: Scans Go, Java, Python, and JavaScript against **AOC 02–140** (NIST IA-2, SI-4, SI-16, SI-17, RA-5).
* **Cryptographic Provider & EOL Scanner**: Statically audits dependencies against [`crypto_catalog.json`](rules/crypto_catalog.json) to flag unsupported/EOL libraries like OpenSSL 1.1.1 and PyCrypto (**AOC 09**).
* **DISA STIG SBOM Applicability Engine**: Parses CycloneDX and SPDX SBOMs to generate STIG & SRG compliance matrices (**AOC 11**).
* **Ephemeral Hygiene**: Automated workspace cleanup ensures zero unvetted code persistence on audit workstations.

---

## Quickstart

Use the root CLI wrapper `./grc` to manage both Git release bundle and AMI review lifecycles:

### Git Bundle Review Workflow

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

# 6. Execute full containerized security suite & synthesize Phase 4 compliance deliverables
# (Automatically generates poam_data.md, controls.md, ruleset_validation.md, scr_scn_package.json, sha256sum)
./grc scan -w ./ephemeral_workspace

# 7. Tear down ephemeral workspace post-review
./grc bundle clean --workspace ./ephemeral_workspace --delete-bundle release-v1.0.0.bundle
```

### AMI Review Workflow (EBS Snapshot Cold-Mount)

```bash
# 1. Verify AMI metadata, KMS encryption & root snapshot integrity
./grc ami verify ami-0123456789abcdef0 --region us-east-1

# 2. Cold-mount AMI snapshot into ephemeral read-only workspace
./grc ami restore ami-0123456789abcdef0 --workspace ./ephemeral_ami_workspace --region us-east-1

# 3. Scan cryptographic libraries on the cold-mounted rootfs
./grc crypto --workspace ./ephemeral_ami_workspace/mnt --format json -o ./ephemeral_ami_workspace/crypto_findings.json

# 4. Generate DISA STIG OS & package applicability matrix from Syft SBOM
./grc sbom --sbom ./ephemeral_ami_workspace/ami_sbom.cdx.json --format markdown -o ./ephemeral_ami_workspace/stig_matrix.md

# 5. Tear down ephemeral volume and audit mount
./grc ami clean --workspace ./ephemeral_ami_workspace --region us-east-1
```

---

## Testing & Verification

A comprehensive, end-to-end verification test plan has been established to validate the pipeline using synthetic fixtures:

* 📘 **[Negative Testing & Scanner Verification Help Guide (docs/test-dummies-guide.md)](docs/test-dummies-guide.md)** — Step-by-step cheat sheet, automated evidence isolation guide, and copy-pasteable scan commands for synthetic test dummies (`aoc-02` through `aoc-12`).
* 📋 **[Full Verification Test Plan (TESTING.md)](TESTING.md)** — Architectural test strategy, pre-flight environment checks, and compliance deliverable acceptance criteria.

---

## Repository Structure

```text
grc-bundle-review/
├── README.md                      # Primary project overview and quickstart
├── TESTING.md                     # End-to-end audit verification test plan
├── grc                            # Root CLI dispatcher wrapper
├── .gitignore                     # Ignores temporary workspaces and bundles
│
├── docker/                        # Containerized scanning suite (100% local, $0)
│   ├── Dockerfile.scanner         # Recipe bundling Semgrep, Checkov, Gitleaks, Syft, Grype, Trivy
│   ├── scan_orchestrator.sh       # In-container automated scanning orchestrator
│   └── README.md                  # Docker build and isolation documentation
│
├── docs/                          # Governance & architecture specifications
│   ├── ami-review-workflow.md     # AMI EBS snapshot cold-mount audit specification
│   ├── design-rules-and-aocs.md   # Core design principles and AOC matrix
│   ├── review-workflow.md         # 5-stage Git bundle review lifecycle
│   ├── test-dummies-guide.md      # Master verification cheat sheet & test dummies guide
│   └── workspace-layout.md        # Workstation baseline and tooling specs
│
├── rules/                         # Declarative compliance policies
│   ├── custom-baseline-ruleset.yaml # 37-rule Semgrep baseline (AOC 02-140)
│   └── crypto_catalog.json        # Cryptographic library EOL & FIPS catalog
│
└── scripts/                       # Automation engines
    ├── grc_bundle.py              # Git bundle ingestion, restoration, and cleanup manager
    ├── grc_ami.py                 # AMI cold-mount restoration, verification, and cleanup
    ├── grc_reporter.py            # Phase 4 compliance report & SCR/SCN package synthesizer
    ├── crypto_lib_scan.py         # Static crypto library auditor
    └── sbom_analyzer.py           # CycloneDX & SPDX to DISA STIG mapper
```

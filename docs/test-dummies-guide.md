# GRC Pipeline Verification & Test Dummies Help Guide (`docs/test-dummies-guide.md`)

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

> **Classification**: Internal DevSecOps & Security Compliance Specification  
> **Target Frameworks**: DISA STIG, NIST SP 800-53 Rev. 5, FedRAMP High, DoD Cloud Computing SRG  
> **Companion Repository**: [`grc-test-dummies`](https://github.com/eodartintlabs-hue/grc-test-dummies) (`../GRC-Test-Dummies`)  
> **Operational Pattern**: Negative Testing, Control Verification & Ephemeral Isolation (\$0 Cloud Cost)  

---

## Table of Contents

1. [Quickstart: The 2-Step Testing Lifecycle](#1-quickstart-the-2-step-testing-lifecycle)
2. [Automated Evidence Isolation & Directory Structure](#2-automated-evidence-isolation--directory-structure)
3. [Master AOC Verification Cheat Sheet (All 12 Bundles)](#3-master-aoc-verification-cheat-sheet-all-12-bundles)
   * [AOC-02: Password Hygiene (`IA-2`)](#-aoc-02-password-hygiene-nist-sp-800-53-ia-2)
   * [AOC-03: Weak Encryption Check (`SI-16`)](#️-aoc-03-weak-encryption-check-nist-sp-800-53-si-16)
   * [AOC-04: Command Injection (`SI-4`)](#-aoc-04-command-injection-nist-sp-800-53-si-4)
   * [AOC-05: Improper TLS (`SI-17`)](#-aoc-05-improper-tls-nist-sp-800-53-si-17)
   * [AOC-06: Secrets Management (`SC-12`)](#-aoc-06-secrets-management-nist-sp-800-53-sc-12)
   * [AOC-07: Infrastructure-as-Code Misconfiguration (`AC-6, CM-6`)](#️-aoc-07-infrastructure-as-code-iac-misconfiguration-nist-sp-800-53-ac-6-cm-6)
   * [AOC-09: Unsupported Cryptographic Libraries (`SI-7`)](#-aoc-09-unsupported-cryptographic-libraries-nist-sp-800-53-si-7)
   * [AOC-10: CRITICAL Severity Vulnerabilities (`RA-5, SI-2`)](#-aoc-10-critical-severity-vulnerabilities-nist-sp-800-53-ra-5-si-2)
   * [AOC-11: Category I DISA STIG Violations (`SI-2`)](#️-aoc-11-category-i-disa-stig-violations-nist-sp-800-53-si-2)
   * [AOC-12: Lack of FIPS Mode (`SC-13`)](#️-aoc-12-lack-of-fips-mode-nist-sp-800-53-sc-13)
   * [AOC-140: Organization-Specific Guardrails (`CM-6`)](#-aoc-140-organization-specific-guardrails-nist-sp-800-53-cm-6)
   * [AOC-Combo-4x: 4-in-1 Multi-Engine Combined Bundle (`02 + 04 + 07 + 09`)](#-aoc-combo-4x-4-in-1-multi-engine-combined-bundle-aoc-02--04--07--09)
4. [Automated Batch Verification (Run All Tests)](#4-automated-batch-verification-run-all-tests)
5. [AMI Review Cold-Mount Verification (Zero Cloud Compute Cost)](#5-ami-review-cold-mount-verification-zero-cloud-compute-cost)
6. [Auditor Evidence Deliverables & `jq` Inspection Cheat Sheet](#6-auditor-evidence-deliverables--jq-inspection-cheat-sheet)
7. [IDE & JSON Formatting Guide](#7-ide--json-formatting-guide)
8. [Troubleshooting & Frequently Asked Questions (FAQ)](#8-troubleshooting--frequently-asked-questions-faq)
9. [Ephemeral Workspace Teardown](#9-ephemeral-workspace-teardown)

---

## 1. Quickstart: The 2-Step Testing Lifecycle

Whenever you test a new Area of Concern (AOC), follow the exact same two commands: **Restore $\rightarrow$ Scan**.

```mermaid
flowchart LR
    A["GRC-Test-Dummies/*.bundle"] --> B["1. grc bundle restore\n(--force --read-only)"]
    B --> C["2. grc scan\n(grc-scanner:local)"]
    C --> D["evidence/<bundle-name>/\n(*_findings.json)"]
```

```bash
# 1. Restore the bundle into the ephemeral workspace (--force wipes previous test runs)
./grc bundle restore ../GRC-Test-Dummies/bundles/<bundle-name>.bundle \
  --workspace ./ephemeral_workspace \
  --ref v1.0.0 \
  --force --read-only

# 2. Run the containerized security scan suite
./grc scan -w ./ephemeral_workspace
```

The pipeline automatically handles:
- Cryptographic provenance logging (`bundle_provenance.json`).
- Locking extracted source code to read-only (`chmod -R 0444`) to guarantee zero unauthorized code mutation.
- Isolated container execution via `grc-scanner:local` (`--network none`, read-only workspace mount).
- Automatic evidence segregation into `evidence/<bundle-name>/`.
- Automatic multi-line JSON pretty-printing.

---

## 2. Automated Evidence Isolation & Directory Structure

To prevent audit work papers and scan findings from cross-contaminating across test runs, `./grc scan` automatically inspects `bundle_provenance.json` and creates a **dedicated, isolated subfolder** for each bundle under `evidence/`:

```text
evidence/
├── aoc-02-weak-passwords/         <-- 16 hardcoded password/token findings across 4 languages
│   ├── bundle_provenance.json     # Ingestion & verification session record
│   ├── semgrep_findings.json      # Raw AST scanner output
│   ├── checkov_findings.json      # Raw IaC scanner output
│   ├── sbom.cdx.json              # CycloneDX system bill of materials
│   ├── poam_data.md               # Synthesized Plan of Action & Milestones (FedRAMP High)
│   ├── controls.md                # NIST SP 800-53 Rev. 5 Traceability Matrix
│   ├── ruleset_validation.md      # Itemized 37-rule Semgrep baseline log
│   ├── scr_scn_package.json       # Consolidated machine-readable SCR/SCN payload
│   └── sha256sum                  # Cryptographic evidence seal
│
├── aoc-03-legacy-crypto/          <-- MD5, SHA-1, DES, RC4, AES/ECB violations
│   ├── poam_data.md & controls.md
│   └── semgrep_findings.json
│
├── aoc-07-iac-misconfig/          <-- Open S3 buckets, 0.0.0.0/0 SSH, unencrypted EBS
│   ├── poam_data.md & controls.md
│   └── checkov_findings.json
│
├── aoc-10-critical-cves/          <-- Log4Shell, Spring4Shell CVSS 9.8+ vulnerabilities
│   ├── poam_data.md & controls.md
│   └── grype_findings.json
│
└── aoc-combo-4x/                  <-- 4-in-1 combined bundle (AOC-02 + AOC-04 + AOC-07 + AOC-09)
    ├── poam_data.md & controls.md
    └── 19 normalized findings across Semgrep, Checkov & CryptoScan
```

> [!TIP]
> **Custom Evidence Path**: You can explicitly override the target evidence directory at any time using the `-e` flag:
> ```bash
> ./grc scan -w ./ephemeral_workspace -e evidence/custom_audit_run_2026_10/
> ```

---

## 3. Master AOC Verification Cheat Sheet (All 12 Bundles)

Use these exact copy-pasteable commands to test any specific Area of Concern:

### 🔑 AOC-02: Password Hygiene (`NIST SP 800-53 IA-2`)
* **Target Flaws**: Hardcoded static passwords, database credentials, API tokens, and secret keys in Python, Go, Java, and JavaScript.
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-02-weak-passwords.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: **16 findings** populated inside `evidence/aoc-02-weak-passwords/semgrep_findings.json`.
* **Quick Verification**:
  ```bash
  cat evidence/aoc-02-weak-passwords/semgrep_findings.json | jq -r '.results[] | "\(.extra.metadata.aoc) | \(.path):\(.start.line) | \(.extra.message)"'
  ```

---

### 🛡️ AOC-03: Weak Encryption Check (`NIST SP 800-53 SI-16`)
* **Target Flaws**: Broken hash algorithms (`MD5`, `SHA-1`), broken symmetric ciphers (`DES`, `RC4`), and insecure `AES/ECB` block modes.
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-03-legacy-crypto.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: Policy violations flagged in `evidence/aoc-03-legacy-crypto/semgrep_findings.json`.
* **Quick Verification**:
  ```bash
  cat evidence/aoc-03-legacy-crypto/semgrep_findings.json | jq -r '.results[] | "\(.check_id) | \(.path):\(.start.line)"'
  ```

---

### 💻 AOC-04: Command Injection (`NIST SP 800-53 SI-4`)
* **Target Flaws**: Unsanitized runtime shell execution via `os.system()`, `subprocess.Popen(shell=True)`, Go `exec.Command("bash", ...)`, and Java `Runtime.getRuntime().exec()`.
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-04-command-injection.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: High-severity injection findings in `evidence/aoc-04-command-injection/semgrep_findings.json`.
* **Quick Verification**:
  ```bash
  cat evidence/aoc-04-command-injection/semgrep_findings.json | jq -r '.results[] | "\(.extra.severity) | \(.path):\(.start.line) | \(.extra.metadata.cwe[0])"'
  ```

---

### 🔒 AOC-05: Improper TLS (`NIST SP 800-53 SI-17`)
* **Target Flaws**: Deprecated `TLS 1.0/1.1` protocols, disabled certificate verification (`verify=False`, `InsecureSkipVerify: true`, `rejectUnauthorized: false`).
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-05-improper-tls.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: Deprecated TLS and certificate check violations in `evidence/aoc-05-improper-tls/semgrep_findings.json`.

---

### 🗝️ AOC-06: Secrets Management (`NIST SP 800-53 SC-12`)
* **Target Flaws**: Embedded PEM/PKCS cryptographic private keys (`RSA PRIVATE KEY`, `OPENSSH PRIVATE KEY`) committed to source control.
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-06-secrets-management.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: Private key violations flagged in `evidence/aoc-06-secrets-management/semgrep_findings.json` and `gitleaks_findings.json`.

---

### ☁️ AOC-07: Infrastructure-as-Code (IaC) Misconfiguration (`NIST SP 800-53 AC-6, CM-6`)
* **Target Flaws**: Public S3 buckets (`acl = "public-read"`), open `0.0.0.0/0` ingress SSH/RDP security groups, unencrypted EBS volumes in Terraform; disabled SELinux in Ansible playbooks.
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-07-iac-misconfig.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: Policy check failures populated in `evidence/aoc-07-iac-misconfig/checkov_findings.json`.
* **Quick Verification**:
  ```bash
  cat evidence/aoc-07-iac-misconfig/checkov_findings.json | jq '.results.failed_checks[] | {check_name: .check_name, resource: .resource, status: .check_result.result}'
  ```

---

### 📦 AOC-09: Unsupported Cryptographic Libraries (`NIST SP 800-53 SI-7`)
* **Target Flaws**: Deprecated, unmaintained, and EOL libraries: `pycrypto` (unmaintained since 2013), OpenSSL 1.1.1 (EOL September 2023), Bouncy Castle `< 1.70`.
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-09-eol-libraries.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: `CRITICAL` EOL alerts in `evidence/aoc-09-eol-libraries/crypto_findings.json`.
* **Quick Verification**:
  ```bash
  cat evidence/aoc-09-eol-libraries/crypto_findings.json | jq '.findings[] | {library: .library_name, version: .detected_version, status: .compliance_status, remediation: .remediation}'
  ```

---

### 🚨 AOC-10: CRITICAL Severity Vulnerabilities (`NIST SP 800-53 RA-5, SI-2`)
* **Target Flaws**: Dependencies containing known, weaponized CVSS 9.8–10.0 vulnerabilities:
  * Log4Shell (`log4j-core:2.14.1` — CVE-2021-44228)
  * Spring4Shell (`spring-beans:5.3.17` — CVE-2022-22965)
  * Text4Shell (`commons-text:1.9` — CVE-2022-42889)
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-10-critical-cves.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: Critical CVE detections in `evidence/aoc-10-critical-cves/grype_findings.json` and `trivy_findings.json`.
* **Quick Verification**:
  ```bash
  cat evidence/aoc-10-critical-cves/grype_findings.json | jq -r '.matches[] | select(.vulnerability.severity == "Critical") | "\(.vulnerability.id) | \(.artifact.name):\(.artifact.version)"'
  ```

---

### 🏛️ AOC-11: Category I DISA STIG Violations (`NIST SP 800-53 SI-2`)
* **Target Flaws**: Framework debug mode bound to `0.0.0.0`, plaintext HTTP listener (`http.ListenAndServe`), Java XML External Entity (XXE) processing enabled, and insecure cookie flags (`secure: false, httpOnly: false`).
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-11-stig-cat1.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: All 4 `grc-aoc11-*` CAT I rules triggered in `evidence/aoc-11-stig-cat1/semgrep_findings.json`.

---

### 🛡️ AOC-12: Lack of FIPS Mode (`NIST SP 800-53 SC-13`)
* **Target Flaws**: Linux kernel bootloader with `fips=0` in GRUB parameters, system-wide crypto policies set to `DEFAULT` instead of `FIPS`, OpenSSL 3.0 configuration missing `[fips_sect] activate = 1`.
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-12-no-fips-mode.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: Non-FIPS configuration flags recorded in `evidence/aoc-12-no-fips-mode/semgrep_findings.json`.

---

### 🏢 AOC-140: Organization-Specific Guardrails (`NIST SP 800-53 CM-6`)
* **Target Flaws**: Cleartext passwords, tokens, and API keys printed to `stdout`, `logging`, or `console.log` across Python, Go, Java, and JavaScript.
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-140-org-guardrails.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: All 4 `grc-aoc140-*` rules triggered in `evidence/aoc-140-org-guardrails/semgrep_findings.json`.

---

### 🧩 AOC-Combo-4x: 4-in-1 Multi-Engine Combined Bundle (`AOC-02 + 04 + 07 + 09`)
* **Target Flaws**: Combines hardcoded credentials (`AOC-02`), command injection (`AOC-04`), Terraform S3/SG/EBS misconfigurations (`AOC-07`), and EOL `pycrypto` / outdated `cryptography` (`AOC-09`) inside a single release bundle.
* **Commands**:
  ```bash
  ./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-combo-4x.bundle -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ./grc scan -w ./ephemeral_workspace
  ```
* **Expected Output**: **19 total findings** (14 `CRITICAL / CAT I`, 5 `HIGH / CAT II`) across `Semgrep`, `Checkov`, and `CryptoScan` in `evidence/aoc-combo-4x/poam_data.md`.

---

## 4. Automated Batch Verification (Run All Tests)

To audit and verify the entire 12-bundle test corpus in a single pass without manual intervention, run this loop from the root of the `GRC-Bundle-Review_Pipeline` directory:

```bash
DUMMY_DIR="../GRC-Test-Dummies/bundles"

for bundle in "${DUMMY_DIR}"/*.bundle; do
    bundle_name="$(basename "${bundle}" .bundle)"
    echo "=========================================================="
    echo "  [+] Testing: ${bundle_name}"
    echo "=========================================================="
    
    # 1. Restore bundle with force overwrite and read-only protection
    ./grc bundle restore "${bundle}" \
      --workspace ./ephemeral_workspace \
      --ref v1.0.0 \
      --force --read-only
      
    # 2. Run all 9 compliance engines + Phase 4 synthesis (outputs to evidence/<bundle-name>/)
    ./grc scan -w ./ephemeral_workspace
done

echo "[*] All 12 synthetic bundles audited! Check the evidence/ directory for deliverables."
```

---

## 5. AMI Review Cold-Mount Verification (Zero Cloud Compute Cost)

The pipeline supports out-of-band auditing of Amazon Machine Images (AMIs) using the **EBS Snapshot Cold-Mount** pattern. You can test this workflow offline on your local Mac with **$0 cloud compute cost** using the `--mock` flag:

```bash
# 1. Verify AMI metadata, KMS CMK encryption & snapshot integrity (Mock Mode)
./grc ami verify ami-0123456789abcdef0 --mock --json

# 2. Cold-mount AMI snapshot into ephemeral read-only workspace (Mock Simulation)
./grc ami restore ami-0123456789abcdef0 \
  --workspace ./ephemeral_mock_ami \
  --mock \
  --force

# 3. Inspect generated AMI provenance record
cat ./ephemeral_mock_ami/ami_provenance.json | jq .

# 4. Tear down the ephemeral mock mount
./grc ami clean --workspace ./ephemeral_mock_ami --mock
```

---

## 6. Auditor Evidence Deliverables & `jq` Inspection Cheat Sheet

### Phase 3: Raw Engine Findings & Manifests
| Deliverable File | Producing Engine | Control Mapping | Auditor Inspection One-Liner (`jq`) |
| :--- | :--- | :--- | :--- |
| **`bundle_provenance.json`** | `grc_bundle.py` | NIST CM-8<br>DoD Provenance | `cat bundle_provenance.json \| jq '{id: .bundle_identifier, sha: .bundle_sha256, files: .total_files}'` |
| **`semgrep_findings.json`** | Semgrep | NIST IA-2, SI-4,<br>SI-16, SI-17 | `cat semgrep_findings.json \| jq -r '.results[] \| "\(.extra.metadata.aoc) \| \(.path):\(.start.line) \| \(.extra.message)"'` |
| **`checkov_findings.json`** | Checkov | NIST AC-6, CM-6<br>FedRAMP IaC | `cat checkov_findings.json \| jq '.[].results.failed_checks[] \| {check: .check_name, resource: .resource}'` |
| **`sbom.cdx.json`** | Syft | NIST CM-8, SI-7<br>CycloneDX | `cat sbom.cdx.json \| jq '.components[] \| {name: .name, version: .version, type: .type}'` |
| **`grype_findings.json`** | Grype | NIST RA-5, SI-2<br>POA&M Ingestion | `cat grype_findings.json \| jq -r '.matches[] \| "\(.vulnerability.severity) \| \(.vulnerability.id) \| \(.artifact.name):\(.artifact.version)"'` |
| **`crypto_findings.json`** | `crypto_lib_scan.py` | NIST SI-7, SC-13<br>AOC-09 | `cat crypto_findings.json \| jq '.findings[] \| {library: .library_name, version: .detected_version, status: .compliance_status}'` |

### Phase 4: SCR/SCN Compliance Packages (Synthesized by `grc_reporter.py`)
| Deliverable File | Producing Engine | Format | FedRAMP / DoD Compliance Purpose |
| :--- | :--- | :--- | :--- |
| **`poam_data.md`** | `grc_reporter.py` | Markdown | **Plan of Action & Milestones**: Itemizes all findings with SLAs (30d CAT I, 60d CAT II, 90d CAT III), remediation steps, and target completion dates. |
| **`controls.md`** | `grc_reporter.py` | Markdown | **NIST SP 800-53 Rev. 5 Traceability Matrix**: Rollup and itemized breakdown across AC, IA, SC, SI, CM, and RA control families. |
| **`ruleset_validation.md`** | `grc_reporter.py` | Markdown | **37-Rule Baseline Validation Audit Log**: Itemized audit log showing which Semgrep baseline rules triggered vs. passed clean. |
| **`scr_scn_package.json`** | `grc_reporter.py` | JSON | **Consolidated SCR/SCN Payload**: Machine-readable evidence package for automated ingestion into ServiceNow, Jira, or DoD eMASS. |
| **`sha256sum`** | `grc_reporter.py` | Text | **Cryptographic Evidence Seal**: SHA-256 hash manifest verifying the immutability of all deliverables in the evidence folder. |

---

## 7. IDE & JSON Formatting Guide

### Automatic Multi-Line Formatting
`./grc scan` automatically pipes all scanner outputs through `python3 -m json.tool` so every JSON deliverable is saved with **2-space indented multi-line structure**.

### IDE Formatting Shortcut
If a JSON document ever opens on a single line or unformatted in your IDE, use the universal format document shortcut:
* **macOS**: `Shift + Option + F`
* **Linux / Windows**: `Shift + Alt + F`
* **Command Palette**: `Cmd + Shift + P` $\rightarrow$ type `"Format Document"` $\rightarrow$ press `Enter`.

---

## 8. Troubleshooting & Frequently Asked Questions (FAQ)

### Q1: `docker: command not found` error on macOS
* **Cause**: Docker Desktop installs CLI binaries into `~/.docker/bin` or `/Applications/Docker.app/Contents/Resources/bin`, which may not be in standard terminal `$PATH`.
* **Fix**: `./grc` automatically injects these paths into `$PATH`. Ensure Docker Desktop is launched and running.

### Q2: Error: `Destination directory already exists. Use --force to overwrite.`
* **Cause**: You are restoring a bundle into a workspace that already contains files from a previous run.
* **Fix**: Supply the `-f` / `--force` flag:
  ```bash
  ./grc bundle restore <bundle> -w ./ephemeral_workspace -r v1.0.0 -f --read-only
  ```

### Q3: Why are extracted files set to `0444` (read-only)?
* **Compliance Rationale**: Under the GRC pipeline's **Zero Untrusted Execution** model, audited source code must be protected against accidental modification, build-script execution, or tampering while in the review workspace. The `--read-only` flag ensures files cannot be edited during an audit.

### Q4: How do I rebuild the Docker scanner image after updating rules?
* **Command**:
  ```bash
  ./grc docker-build
  ```

---

## 9. Ephemeral Workspace Teardown

After completing your audit verification and archiving your evidence deliverables, securely wipe the ephemeral test workspace:

```bash
# Safely wipe the ephemeral workspace (preserves your isolated evidence/ folders!)
./grc bundle clean --workspace ./ephemeral_workspace
```

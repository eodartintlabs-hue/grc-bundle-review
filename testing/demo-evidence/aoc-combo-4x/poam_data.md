# Plan of Action and Milestones (POA&M) Datapoints

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD CC SRG / SCR-SCN)  
> **Audit Target Identifier**: `001b61db92be9f9b7ddd0d5d0d8f32a20edab91d1e0f033a30448a8f77ee3dbb`  
> **Source Subject**: `/Users/byronturner-pro/.gemini/antigravity/brain/a02fc92f-c7d7-4544-b1f1-0a72d57cfeff/scratch/bundles/aoc-combo-4x.bundle`  
> **Cryptographic Hash (SHA-256)**: `001b61db92be9f9b7ddd0d5d0d8f32a20edab91d1e0f033a30448a8f77ee3dbb`  
> **Review Session ID**: `6eb152ba-a455-4b5e-886f-7f8fb5b69794`  
> **Evaluation Timestamp**: `2026-10-19 14:29:47 UTC`  
> **Overall Audit Posture**: **NON-COMPLIANT (Remediation Gating Enforced)**  

---

## 1. Executive Vulnerability & Risk Summary

The following risk rollup aggregates all findings detected across static AST analysis (Semgrep), dependency scanning (Grype/Trivy), secret scanning (Gitleaks), Infrastructure-as-Code policy validation (Checkov), and cryptographic library audits:

| Severity Level | DISA STIG Impact Category | Active Findings Count | Mandatory Remediation SLA | Compliance Status |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | **Category I (CAT I)** | **14** | **30 Calendar Days** | ❌ Non-Compliant |
| **HIGH** | **Category II (CAT II)** | **5** | **60 Calendar Days** | ❌ Non-Compliant |
| **MEDIUM** | **Category III (CAT III)** | **0** | **90 Calendar Days** | ✅ Clear |
| **LOW / INFO** | Informational | **0** | 180 Calendar Days | ✅ Monitored |
| **TOTAL** | — | **19** | — | **NON-COMPLIANT (Remediation Gating Enforced)** |

---

## 2. Standardized POA&M Itemization Table

All line items below are structured for automated ingestion into formal Enterprise POA&M tracking systems (eMASS, Archer, ServiceNow GRC, Jira Security):

| POAM ID | Primary NIST Control | Weakness / Finding Name | Severity / CAT | Source Engine | Affected Asset / File | Target Completion | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **POAM-001** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `app.py:5` | `2026-12-18` | Open |
| **POAM-002** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `app.py:6` | `2026-12-18` | Open |
| **POAM-003** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `app.py:10` | `2026-11-18` | Open |
| **POAM-004** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `app.py:11` | `2026-11-18` | Open |
| **POAM-005** | `AC-3, CM-6` | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 | **CRITICAL / CAT I** | `Checkov` | `main.tf:6 (Resource: aws_security_group.wide_open_ssh)` | `2026-11-18` | Open |
| **POAM-006** | `AC-3, CM-6` | Ensure every security group and rule has a description | **CRITICAL / CAT I** | `Checkov` | `main.tf:6 (Resource: aws_security_group.wide_open_ssh)` | `2026-11-18` | Open |
| **POAM-007** | `SC-13, SC-28` | Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK) | **HIGH / CAT II** | `Checkov` | `main.tf:18 (Resource: aws_ebs_volume.unencrypted_data)` | `2026-12-18` | Open |
| **POAM-008** | `SC-13, SC-28` | Ensure all data stored in the EBS is securely encrypted | **HIGH / CAT II** | `Checkov` | `main.tf:18 (Resource: aws_ebs_volume.unencrypted_data)` | `2026-12-18` | Open |
| **POAM-009** | `AC-6, CM-6, SC-28` | Ensure S3 buckets should have event notifications enabled | **CRITICAL / CAT I** | `Checkov` | `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)` | `2026-11-18` | Open |
| **POAM-010** | `AC-3, CM-6` | Ensure that Security Groups are attached to another resource | **CRITICAL / CAT I** | `Checkov` | `main.tf:6 (Resource: aws_security_group.wide_open_ssh)` | `2026-11-18` | Open |
| **POAM-011** | `AC-6, CM-6, SC-28` | Ensure that an S3 bucket has a lifecycle configuration | **CRITICAL / CAT I** | `Checkov` | `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)` | `2026-11-18` | Open |
| **POAM-012** | `AC-6, CM-6, SC-28` | Ensure the S3 bucket has access logging enabled | **CRITICAL / CAT I** | `Checkov` | `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)` | `2026-11-18` | Open |
| **POAM-013** | `AC-6, CM-6, SC-28` | Ensure that S3 bucket has cross-region replication enabled | **CRITICAL / CAT I** | `Checkov` | `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)` | `2026-11-18` | Open |
| **POAM-014** | `AC-6, CM-6, SC-28` | Ensure that S3 buckets are encrypted with KMS by default | **CRITICAL / CAT I** | `Checkov` | `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)` | `2026-11-18` | Open |
| **POAM-015** | `AC-6, CM-6, SC-28` | Ensure that S3 bucket has a Public Access block | **CRITICAL / CAT I** | `Checkov` | `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)` | `2026-11-18` | Open |
| **POAM-016** | `AC-6, CM-6, SC-28` | S3 Bucket has an ACL defined which allows public READ access. | **CRITICAL / CAT I** | `Checkov` | `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)` | `2026-11-18` | Open |
| **POAM-017** | `AC-6, CM-6, SC-28` | Ensure all data stored in the S3 bucket have versioning enabled | **CRITICAL / CAT I** | `Checkov` | `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)` | `2026-11-18` | Open |
| **POAM-018** | `SI-7, SC-13` | Unsupported/Deprecated Cryptographic Library: pycrypto (2.6.1) | **CRITICAL / CAT I** | `CryptoScan` | `Dependency Manifest / System Libraries` | `2026-11-18` | Open |
| **POAM-019** | `SI-7, SC-13` | Unsupported/Deprecated Cryptographic Library: cryptography (38.0.1) | **HIGH / CAT II** | `CryptoScan` | `Dependency Manifest / System Libraries` | `2026-12-18` | Open |

---

## 3. Remediation & Corrective Action Plans

### 3.001 [POAM-001] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `app.py:5`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-python-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-18` (60 days)

### 3.002 [POAM-002] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `app.py:6`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-python-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-18` (60 days)

### 3.003 [POAM-003] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `app.py:10`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-python-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution via shell invocation in Python. Use subprocess.run with arguments list and shell=False.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.004 [POAM-004] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `app.py:11`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-python-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution via shell invocation in Python. Use subprocess.run with arguments list and shell=False.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.005 [POAM-005] Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
* **Affected Asset**: `main.tf:6 (Resource: aws_security_group.wide_open_ssh)`
* **Governing Controls**: `AC-3, CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_24` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_security_group.wide_open_ssh': Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.006 [POAM-006] Ensure every security group and rule has a description
* **Affected Asset**: `main.tf:6 (Resource: aws_security_group.wide_open_ssh)`
* **Governing Controls**: `AC-3, CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_23` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_security_group.wide_open_ssh': Ensure every security group and rule has a description
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.007 [POAM-007] Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK)
* **Affected Asset**: `main.tf:18 (Resource: aws_ebs_volume.unencrypted_data)`
* **Governing Controls**: `SC-13, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_189` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_ebs_volume.unencrypted_data': Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK)
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-18` (60 days)

### 3.008 [POAM-008] Ensure all data stored in the EBS is securely encrypted
* **Affected Asset**: `main.tf:18 (Resource: aws_ebs_volume.unencrypted_data)`
* **Governing Controls**: `SC-13, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_3` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_ebs_volume.unencrypted_data': Ensure all data stored in the EBS is securely encrypted
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-18` (60 days)

### 3.009 [POAM-009] Ensure S3 buckets should have event notifications enabled
* **Affected Asset**: `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_62` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.public_audit_logs': Ensure S3 buckets should have event notifications enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.010 [POAM-010] Ensure that Security Groups are attached to another resource
* **Affected Asset**: `main.tf:6 (Resource: aws_security_group.wide_open_ssh)`
* **Governing Controls**: `AC-3, CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_5` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_security_group.wide_open_ssh': Ensure that Security Groups are attached to another resource
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.011 [POAM-011] Ensure that an S3 bucket has a lifecycle configuration
* **Affected Asset**: `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_61` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.public_audit_logs': Ensure that an S3 bucket has a lifecycle configuration
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.012 [POAM-012] Ensure the S3 bucket has access logging enabled
* **Affected Asset**: `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_18` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.public_audit_logs': Ensure the S3 bucket has access logging enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.013 [POAM-013] Ensure that S3 bucket has cross-region replication enabled
* **Affected Asset**: `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_144` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.public_audit_logs': Ensure that S3 bucket has cross-region replication enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.014 [POAM-014] Ensure that S3 buckets are encrypted with KMS by default
* **Affected Asset**: `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_145` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.public_audit_logs': Ensure that S3 buckets are encrypted with KMS by default
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.015 [POAM-015] Ensure that S3 bucket has a Public Access block
* **Affected Asset**: `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_6` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.public_audit_logs': Ensure that S3 bucket has a Public Access block
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.016 [POAM-016] S3 Bucket has an ACL defined which allows public READ access.
* **Affected Asset**: `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_20` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.public_audit_logs': S3 Bucket has an ACL defined which allows public READ access.
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.017 [POAM-017] Ensure all data stored in the S3 bucket have versioning enabled
* **Affected Asset**: `main.tf:1 (Resource: aws_s3_bucket.public_audit_logs)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_21` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.public_audit_logs': Ensure all data stored in the S3 bucket have versioning enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.018 [POAM-018] Unsupported/Deprecated Cryptographic Library: pycrypto (2.6.1)
* **Affected Asset**: `Dependency Manifest / System Libraries`
* **Governing Controls**: `SI-7, SC-13` | **Area of Concern**: `AOC-09: Crypto Dependencies on Unsupported Libraries`
* **Detection Identifier**: `CRYPTO-PYCRYPTO-FAIL_DEPRECATED` (CryptoScan)
* **Detailed Finding**: Detected cryptographic library 'pycrypto' version '2.6.1' with status 'FAIL_DEPRECATED'.
* **Prescribed Action / Fix**: Migrate all cryptographic operations to 'cryptography' (pyca/cryptography) or 'pycryptodome'.
* **Scheduled Completion SLA**: `2026-11-18` (30 days)

### 3.019 [POAM-019] Unsupported/Deprecated Cryptographic Library: cryptography (38.0.1)
* **Affected Asset**: `Dependency Manifest / System Libraries`
* **Governing Controls**: `SI-7, SC-13` | **Area of Concern**: `AOC-09: Crypto Dependencies on Unsupported Libraries`
* **Detection Identifier**: `CRYPTO-CRYPTOGRAPHY-WARN_OUTDATED` (CryptoScan)
* **Detailed Finding**: Detected cryptographic library 'cryptography' version '38.0.1' with status 'WARN_OUTDATED'.
* **Prescribed Action / Fix**: Ensure version >= 41.0.0 to incorporate latest memory-safety improvements (Rust bindings).
* **Scheduled Completion SLA**: `2026-12-18` (60 days)


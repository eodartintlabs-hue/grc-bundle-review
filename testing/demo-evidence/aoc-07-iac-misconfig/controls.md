# NIST SP 800-53 Rev. 5 Controls Traceability Matrix

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD RMF / SCR-SCN)  
> **Audit Target Identifier**: `aoc-07-iac-misconfig`  
> **Evaluation Timestamp**: `2026-10-15 22:50:41 UTC`  

---

## 1. Compliance Status by Control Family

| Control ID | Control Name | Control Family | DISA STIG Impact | Audit Findings Count | Compliance Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AC-3** | Access Enforcement | Access Control (AC) | `CAT I` | 3 | ❌ **NON-COMPLIANT (3)** |
| **AC-6** | Least Privilege | Access Control (AC) | `CAT I` | 9 | ❌ **NON-COMPLIANT (9)** |
| **CM-6** | Configuration Settings | Configuration Management (CM) | `CAT II` | 21 | ❌ **NON-COMPLIANT (21)** |
| **CM-8** | Information System Component Inventory | Configuration Management (CM) | `CAT II` | 0 | ✅ **COMPLIANT** |
| **IA-2** | Identification and Authentication (Organizational Users) | Identification and Authentication (IA) | `CAT I` | 1 | ❌ **NON-COMPLIANT (1)** |
| **IA-7** | Cryptographic Module Authentication | Identification and Authentication (IA) | `CAT II` | 0 | ✅ **COMPLIANT** |
| **RA-5** | Vulnerability Monitoring and Scanning | Risk Assessment (RA) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SC-12** | Cryptographic Key Establishment and Management | System and Communications Protection (SC) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SC-13** | Cryptographic Protection (FIPS 140 Validation) | System and Communications Protection (SC) | `CAT I` | 2 | ❌ **NON-COMPLIANT (2)** |
| **SC-28** | Protection of Information at Rest | System and Communications Protection (SC) | `CAT I` | 11 | ❌ **NON-COMPLIANT (11)** |
| **SC-8** | Transmission Confidentiality and Integrity | System and Communications Protection (SC) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-10** | Information Input Validation | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-16** | Memory Protection / Cryptographic Hash Integrity | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-17** | Fail-Secure / Secure Communications Initiation | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-2** | Flaw Remediation | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-4** | Information System Monitoring | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-7** | Software, Firmware, and Information Integrity | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |

---

## 2. Detailed Control Breakdown & Evidence Mapping

### AC-3: Access Enforcement — ❌ NON-COMPLIANT
* **Control Family**: Access Control (AC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Enforce approved authorizations for logical access to information and system resources (e.g. security group ingress rules).
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-002** | `Checkov` | `CKV_AWS_24` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |
| **POAM-003** | `Checkov` | `CKV_AWS_25` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |
| **POAM-016** | `Checkov` | `CKV2_AWS_5` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |

### AC-6: Least Privilege — ❌ NON-COMPLIANT
* **Control Family**: Access Control (AC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Employ the principle of least privilege, allowing only authorized accesses necessary for accomplishing assigned tasks (e.g., prohibiting public cloud buckets).
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-014** | `Checkov` | `CKV_AWS_57` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-015** | `Checkov` | `CKV2_AWS_62` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-017** | `Checkov` | `CKV_AWS_20` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-018** | `Checkov` | `CKV2_AWS_61` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-019** | `Checkov` | `CKV_AWS_144` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-020** | `Checkov` | `CKV_AWS_18` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-021** | `Checkov` | `CKV2_AWS_6` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-022** | `Checkov` | `CKV_AWS_21` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-023** | `Checkov` | `CKV_AWS_145` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |

### CM-6: Configuration Settings — ❌ NON-COMPLIANT
* **Control Family**: Configuration Management (CM)
* **DISA STIG Baseline**: `CAT II`
* **Control Objective**: Establish and document mandatory configuration settings for IT products using hardened baselines (DISA STIG / CIS).
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-002** | `Checkov` | `CKV_AWS_24` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |
| **POAM-003** | `Checkov` | `CKV_AWS_25` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |
| **POAM-006** | `Checkov` | `CKV_AWS_289` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-007** | `Checkov` | `CKV_AWS_290` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-008** | `Checkov` | `CKV_AWS_355` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-009** | `Checkov` | `CKV_AWS_63` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-010** | `Checkov` | `CKV_AWS_286` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-011** | `Checkov` | `CKV_AWS_287` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-012** | `Checkov` | `CKV_AWS_62` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-013** | `Checkov` | `CKV_AWS_288` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-014** | `Checkov` | `CKV_AWS_57` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-015** | `Checkov` | `CKV2_AWS_62` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-016** | `Checkov` | `CKV2_AWS_5` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |
| **POAM-017** | `Checkov` | `CKV_AWS_20` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-018** | `Checkov` | `CKV2_AWS_61` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-019** | `Checkov` | `CKV_AWS_144` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-020** | `Checkov` | `CKV_AWS_18` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-021** | `Checkov` | `CKV2_AWS_6` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-022** | `Checkov` | `CKV_AWS_21` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-023** | `Checkov` | `CKV_AWS_145` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-024** | `Checkov` | `CKV2_AWS_40` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |

### CM-8: Information System Component Inventory — ✅ COMPLIANT
* **Control Family**: Configuration Management (CM)
* **DISA STIG Baseline**: `CAT II`
* **Control Objective**: Develop and document an inventory of information system components (SBOM) detailing name, version, and license.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### IA-2: Identification and Authentication (Organizational Users) — ❌ NON-COMPLIANT
* **Control Family**: Identification and Authentication (IA)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Uniquely identify and authenticate organizational users (or processes acting on their behalf). Prohibits hardcoded static credentials, default passwords, and unmanaged API tokens.
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-001** | `Checkov` | `CKV_SECRET_6` | `ansible/playbook.yml:11 (Resource: c5012a876a4f516b230d4b0f1cdf6216a1b0f54b)` | **CRITICAL** |

### IA-7: Cryptographic Module Authentication — ✅ COMPLIANT
* **Control Family**: Identification and Authentication (IA)
* **DISA STIG Baseline**: `CAT II`
* **Control Objective**: Authenticate to cryptographic modules using mechanisms meeting applicable federal laws, regulations, and standards.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### RA-5: Vulnerability Monitoring and Scanning — ✅ COMPLIANT
* **Control Family**: Risk Assessment (RA)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Monitor and scan for vulnerabilities in the system and hosted applications, prioritizing remediation of critical CVEs.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SC-12: Cryptographic Key Establishment and Management — ✅ COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Establish and manage cryptographic keys in accordance with NIST SP 800-56A/B and applicable FIPS guidelines.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SC-13: Cryptographic Protection (FIPS 140 Validation) — ❌ NON-COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Implement cryptographic modules validated under FIPS 140-2 / 140-3. Enforce OS kernel FIPS mode and validated security providers.
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-004** | `Checkov` | `CKV_AWS_189` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | **HIGH** |
| **POAM-005** | `Checkov` | `CKV_AWS_3` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | **HIGH** |

### SC-28: Protection of Information at Rest — ❌ NON-COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Protect the confidentiality and integrity of information at rest (e.g., EBS volume encryption, S3 SSE-KMS).
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-004** | `Checkov` | `CKV_AWS_189` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | **HIGH** |
| **POAM-005** | `Checkov` | `CKV_AWS_3` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | **HIGH** |
| **POAM-014** | `Checkov` | `CKV_AWS_57` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-015** | `Checkov` | `CKV2_AWS_62` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-017** | `Checkov` | `CKV_AWS_20` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-018** | `Checkov` | `CKV2_AWS_61` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-019** | `Checkov` | `CKV_AWS_144` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-020** | `Checkov` | `CKV_AWS_18` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-021** | `Checkov` | `CKV2_AWS_6` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-022** | `Checkov` | `CKV_AWS_21` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-023** | `Checkov` | `CKV_AWS_145` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |

### SC-8: Transmission Confidentiality and Integrity — ✅ COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Protect the confidentiality and integrity of transmitted information using strong cryptography (TLS 1.2+ / 1.3).
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-10: Information Input Validation — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Validate information inputs to syntax rules, character sets, and payload limits before runtime interpretation.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-16: Memory Protection / Cryptographic Hash Integrity — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Protect memory integrity and enforce strong cryptographic hash algorithms. Prohibits MD5, SHA-1, DES, and RC4.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-17: Fail-Secure / Secure Communications Initiation — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Ensure the system fails to a secure state. Prohibits disabled TLS certificate validation and deprecated TLS 1.0/1.1 protocols.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-2: Flaw Remediation — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Identify, report, and correct system flaws (vulnerabilities and CVEs) within defined remediation timeframes.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-4: Information System Monitoring — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Monitor system execution to detect attacks and indicators of potential compromise. Prohibits unsanitized runtime shell execution (command injection).
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-7: Software, Firmware, and Information Integrity — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Employ integrity verification tools to detect unauthorized changes and prohibit use of unsupported, unmaintained, or EOL libraries and providers.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.


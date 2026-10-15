# Plan of Action and Milestones (POA&M) Datapoints

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD CC SRG / SCR-SCN)  
> **Audit Target Identifier**: `aoc-07-iac-misconfig`  
> **Source Subject**: `Local Audit Evidence`  
> **Cryptographic Hash (SHA-256)**: `N/A`  
> **Review Session ID**: `N/A`  
> **Evaluation Timestamp**: `2026-10-15 22:50:41 UTC`  
> **Overall Audit Posture**: **NON-COMPLIANT (Remediation Gating Enforced)**  

---

## 1. Executive Vulnerability & Risk Summary

The following risk rollup aggregates all findings detected across static AST analysis (Semgrep), dependency scanning (Grype/Trivy), secret scanning (Gitleaks), Infrastructure-as-Code policy validation (Checkov), and cryptographic library audits:

| Severity Level | DISA STIG Impact Category | Active Findings Count | Mandatory Remediation SLA | Compliance Status |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | **Category I (CAT I)** | **13** | **30 Calendar Days** | ❌ Non-Compliant |
| **HIGH** | **Category II (CAT II)** | **11** | **60 Calendar Days** | ❌ Non-Compliant |
| **MEDIUM** | **Category III (CAT III)** | **0** | **90 Calendar Days** | ✅ Clear |
| **LOW / INFO** | Informational | **0** | 180 Calendar Days | ✅ Monitored |
| **TOTAL** | — | **24** | — | **NON-COMPLIANT (Remediation Gating Enforced)** |

---

## 2. Standardized POA&M Itemization Table

All line items below are structured for automated ingestion into formal Enterprise POA&M tracking systems (eMASS, Archer, ServiceNow GRC, Jira Security):

| POAM ID | Primary NIST Control | Weakness / Finding Name | Severity / CAT | Source Engine | Affected Asset / File | Target Completion | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **POAM-001** | `IA-2` | Base64 High Entropy String | **CRITICAL / CAT I** | `Checkov` | `ansible/playbook.yml:11 (Resource: c5012a876a4f516b230d4b0f1cdf6216a1b0f54b)` | `2026-11-14` | Open |
| **POAM-002** | `AC-3, CM-6` | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | `2026-11-14` | Open |
| **POAM-003** | `AC-3, CM-6` | Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | `2026-11-14` | Open |
| **POAM-004** | `SC-13, SC-28` | Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK) | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | `2026-12-14` | Open |
| **POAM-005** | `SC-13, SC-28` | Ensure all data stored in the EBS is securely encrypted | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | `2026-12-14` | Open |
| **POAM-006** | `CM-6` | Ensure IAM policies does not allow permissions management / resource exposure without constraints | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-007** | `CM-6` | Ensure IAM policies does not allow write access without constraints | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-008** | `CM-6` | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-009** | `CM-6` | Ensure no IAM policies documents allow "*" as a statement's actions | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-010** | `CM-6` | Ensure IAM policies does not allow privilege escalation | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-011** | `CM-6` | Ensure IAM policies does not allow credentials exposure | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-012** | `CM-6` | Ensure IAM policies that allow full "*-*" administrative privileges are not created | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-013** | `CM-6` | Ensure IAM policies does not allow data exfiltration | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-014** | `AC-6, CM-6, SC-28` | S3 Bucket has an ACL defined which allows public WRITE access. | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-11-14` | Open |
| **POAM-015** | `AC-6, CM-6, SC-28` | Ensure S3 buckets should have event notifications enabled | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-11-14` | Open |
| **POAM-016** | `AC-3, CM-6` | Ensure that Security Groups are attached to another resource | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | `2026-11-14` | Open |
| **POAM-017** | `AC-6, CM-6, SC-28` | S3 Bucket has an ACL defined which allows public READ access. | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-11-14` | Open |
| **POAM-018** | `AC-6, CM-6, SC-28` | Ensure that an S3 bucket has a lifecycle configuration | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-11-14` | Open |
| **POAM-019** | `AC-6, CM-6, SC-28` | Ensure that S3 bucket has cross-region replication enabled | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-11-14` | Open |
| **POAM-020** | `AC-6, CM-6, SC-28` | Ensure the S3 bucket has access logging enabled | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-11-14` | Open |
| **POAM-021** | `AC-6, CM-6, SC-28` | Ensure that S3 bucket has a Public Access block | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-11-14` | Open |
| **POAM-022** | `AC-6, CM-6, SC-28` | Ensure all data stored in the S3 bucket have versioning enabled | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-11-14` | Open |
| **POAM-023** | `AC-6, CM-6, SC-28` | Ensure that S3 buckets are encrypted with KMS by default | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-11-14` | Open |
| **POAM-024** | `CM-6` | Ensure AWS IAM policy does not allow full IAM privileges | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |

---

## 3. Remediation & Corrective Action Plans

### 3.001 [POAM-001] Base64 High Entropy String
* **Affected Asset**: `ansible/playbook.yml:11 (Resource: c5012a876a4f516b230d4b0f1cdf6216a1b0f54b)`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `CKV_SECRET_6` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'c5012a876a4f516b230d4b0f1cdf6216a1b0f54b': Base64 High Entropy String
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.002 [POAM-002] Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
* **Affected Asset**: `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)`
* **Governing Controls**: `AC-3, CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_24` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_security_group.open_management_sg': Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.003 [POAM-003] Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389
* **Affected Asset**: `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)`
* **Governing Controls**: `AC-3, CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_25` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_security_group.open_management_sg': Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.004 [POAM-004] Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK)
* **Affected Asset**: `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)`
* **Governing Controls**: `SC-13, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_189` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_ebs_volume.unencrypted_volume': Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK)
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.005 [POAM-005] Ensure all data stored in the EBS is securely encrypted
* **Affected Asset**: `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)`
* **Governing Controls**: `SC-13, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_3` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_ebs_volume.unencrypted_volume': Ensure all data stored in the EBS is securely encrypted
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.006 [POAM-006] Ensure IAM policies does not allow permissions management / resource exposure without constraints
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_289` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow permissions management / resource exposure without constraints
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.007 [POAM-007] Ensure IAM policies does not allow write access without constraints
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_290` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow write access without constraints
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.008 [POAM-008] Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_355` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.009 [POAM-009] Ensure no IAM policies documents allow "*" as a statement's actions
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_63` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure no IAM policies documents allow "*" as a statement's actions
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.010 [POAM-010] Ensure IAM policies does not allow privilege escalation
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_286` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow privilege escalation
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.011 [POAM-011] Ensure IAM policies does not allow credentials exposure
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_287` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow credentials exposure
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.012 [POAM-012] Ensure IAM policies that allow full "*-*" administrative privileges are not created
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_62` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies that allow full "*-*" administrative privileges are not created
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.013 [POAM-013] Ensure IAM policies does not allow data exfiltration
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_288` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow data exfiltration
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.014 [POAM-014] S3 Bucket has an ACL defined which allows public WRITE access.
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_57` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': S3 Bucket has an ACL defined which allows public WRITE access.
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.015 [POAM-015] Ensure S3 buckets should have event notifications enabled
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_62` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure S3 buckets should have event notifications enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.016 [POAM-016] Ensure that Security Groups are attached to another resource
* **Affected Asset**: `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)`
* **Governing Controls**: `AC-3, CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_5` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_security_group.open_management_sg': Ensure that Security Groups are attached to another resource
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.017 [POAM-017] S3 Bucket has an ACL defined which allows public READ access.
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_20` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': S3 Bucket has an ACL defined which allows public READ access.
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.018 [POAM-018] Ensure that an S3 bucket has a lifecycle configuration
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_61` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure that an S3 bucket has a lifecycle configuration
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.019 [POAM-019] Ensure that S3 bucket has cross-region replication enabled
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_144` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure that S3 bucket has cross-region replication enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.020 [POAM-020] Ensure the S3 bucket has access logging enabled
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_18` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure the S3 bucket has access logging enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.021 [POAM-021] Ensure that S3 bucket has a Public Access block
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_6` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure that S3 bucket has a Public Access block
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.022 [POAM-022] Ensure all data stored in the S3 bucket have versioning enabled
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_21` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure all data stored in the S3 bucket have versioning enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.023 [POAM-023] Ensure that S3 buckets are encrypted with KMS by default
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_145` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure that S3 buckets are encrypted with KMS by default
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-11-14` (30 days)

### 3.024 [POAM-024] Ensure AWS IAM policy does not allow full IAM privileges
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_40` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure AWS IAM policy does not allow full IAM privileges
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)


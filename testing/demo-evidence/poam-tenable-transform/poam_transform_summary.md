# GRCx FedRAMP POA&M Scan Transformation & SLA Aging Report

- **Transformation Date**: `2026-10-20`
- **Generated OPEN FedRAMP POA&M**: `OPEN FedRAMP-POAM.xlsx`
- **Generated CLOSED FedRAMP POA&M**: `CLOSED FedRAMP-POAM.xlsx`
- **Total Active OPEN Entries**: **6** (*3 Carried Over, 3 Newly Detected*)
- **Entries Moved from OPEN to CLOSED**: **2** (*Total Closed Rows: 2*)
- **OPEN Entries with Passed SLA Date**: **3** of **6**

## 1. Itemized OPEN POA&M Aging & SLA Status

| POAM ID | Weakness Name | Asset Identifier | Risk | Original Detection Date | Age (Days Old) | Scheduled Completion Date (SLA) | SLA Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `POAM-2026-0003` | TLS Version 1.0 and Sweet32 3DES Cipher Suites Supported | `10.42.10.14 (443/TCP)` | **Moderate** | `2026-06-15` | **127 days old** | `2026-09-13` | **PASSED SLA (37 days overdue)** |
| `POAM-2026-0001` | OpenSSH < 9.3p2 Remote Code Execution ( ssh-agent ) | `10.42.10.14 (22/TCP)` | **Critical** | `2026-08-05` | **76 days old** | `2026-09-04` | **PASSED SLA (46 days overdue)** |
| `POAM-2026-0002` | Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) | `10.42.10.18 (8443/TCP)` | **Critical** | `2026-08-25` | **56 days old** | `2026-09-24` | **PASSED SLA (26 days overdue)** |
| `POAM-2026-0007` | Apache Commons Text < 1.10.0 StringSubstitutor Interpolation RCE | `10.42.10.31 (8080/TCP)` | **Moderate** | `2026-09-10` | **40 days old** | `2026-12-09` | Within SLA (50 days left) |
| `POAM-2026-0008` | OpenSSH Information Disclosure Discrepancy (CVE-2020-14145) | `10.42.10.40 (22/TCP)` | **Low** | `2026-09-25` | **25 days old** | `2027-03-24` | Within SLA (155 days left) |
| `POAM-2026-0006` | OpenSSH RegreSSHion Unauthenticated Remote Code Execution (CVE-2024-6387) | `10.42.10.22 (22/TCP)` | **High** | `2026-10-05` | **15 days old** | `2026-11-04` | Within SLA (15 days left) |

## 2. Entries Moved from OPEN to CLOSED POA&M

| POAM ID | Weakness Name | Asset Identifier | Original Detection Date | Closure Date | Closure Note |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POAM-2026-0004` | SSH Weak Key Exchange Algorithms Enabled (diffie-hellman-group1-sha1) | `10.42.10.25 (22/TCP)` | `2026-08-18` | `2026-10-20` | Patched via Ansible hardening playbook in October. [Closed 2026-10-20: Verified remediated — finding no longer present in latest scan] |
| `POAM-2026-0005` | NGINX HTTP/2 Rapid Reset DoS Vulnerability (CVE-2023-44487) | `10.42.10.30 (443/TCP)` | `2026-09-02` | `2026-10-20` | Upgraded nginx package across ingress nodes. [Closed 2026-10-20: Verified remediated — finding no longer present in latest scan] |

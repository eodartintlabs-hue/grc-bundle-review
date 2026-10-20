# GRCx FedRAMP POA&M Scan Transformation & SLA Aging Report

- **Transformation Date**: `2026-10-20`
- **Generated OPEN FedRAMP POA&M**: `OPEN FedRAMP-POAM.xlsx`
- **Generated CLOSED FedRAMP POA&M**: `CLOSED FedRAMP-POAM.xlsx`
- **Total Active OPEN Entries**: **5** (*0 Carried Over, 5 Newly Detected*)
- **Entries Moved from OPEN to CLOSED**: **0** (*Total Closed Rows: 0*)
- **OPEN Entries with Passed SLA Date**: **3** of **5**

## 1. Itemized OPEN POA&M Aging & SLA Status

| POAM ID | Weakness Name | Asset Identifier | Risk | Original Detection Date | Age (Days Old) | Scheduled Completion Date (SLA) | SLA Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `POAM-2026-0004` | CVE-2024-2511 - OpenSSL Unbounded Memory Growth in TLSv1.3 Session Cache | `i-0a1b2c3d4e5f60003 (AWS_EC2_INSTANCE)` | **Moderate** | `2026-06-20` | **122 days old** | `2026-09-18` | **PASSED SLA (32 days overdue)** |
| `POAM-2026-0001` | ALAS2023-2026-412: openssh signal handler race condition (RegreSSHion) | `i-0a1b2c3d4e5f60001 (AWS_EC2_INSTANCE)` | **Critical** | `2026-08-10` | **71 days old** | `2026-09-09` | **PASSED SLA (41 days overdue)** |
| `POAM-2026-0002` | CVE-2024-45337 - golang.org/x/crypto/ssh ServerConfig PublicKeyCallback Authorization Bypass | `arn:aws:ecr:us-gov-west-1:123456789012:repository/grc-auth-proxy:v1.4.2 (AWS_ECR_CONTAINER_IMAGE)` | **High** | `2026-09-01` | **49 days old** | `2026-10-01` | **PASSED SLA (19 days overdue)** |
| `POAM-2026-0005` | CVE-2025-21502 - Minor CPython urllib URL parsing edge case | `arn:aws:ecr:us-gov-west-1:123456789012:repository/grc-worker:v1.1.0 (AWS_ECR_CONTAINER_IMAGE)` | **Low** | `2026-09-18` | **32 days old** | `2027-03-17` | Within SLA (148 days left) |
| `POAM-2026-0003` | CVE-2023-44487 - HTTP/2 Rapid Reset Attack (nginx) | `i-0a1b2c3d4e5f60002 (AWS_EC2_INSTANCE)` | **High** | `2026-10-02` | **18 days old** | `2026-11-01` | Within SLA (12 days left) |

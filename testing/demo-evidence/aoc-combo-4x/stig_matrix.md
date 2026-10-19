# DISA STIG & SRG Applicability Matrix
> **Generated**: 2026-10-19 14:29:47 UTC  
> **Source SBOM**: `sbom.cdx.json`  
> **Classification / Use**: Internal Compliance & Security Audit Deliverable (SCR/SCN / FedRAMP / DoD)

---

## 1. Executive Summary

* **Total SBOM Components Evaluated**: `5`
* **Applicable DISA STIGs / SRGs Identified**: `1`
* **CAT I Critical Requirements Surface**: `5` components
* **CAT II Medium Requirements Surface**: `0` components

### 1.1 STIG Applicability Catalog

| Benchmark ID | STIG / SRG Title | Version | Max Severity | Mapped Components |
| :--- | :--- | :--- | :---: | :---: |
| `U_ASD_V5R1_STIG` | **Application Security and Development (ASD) STIG** | Version 5, Release 1 | `CAT I` | **5** |

---

## 2. NIST SP 800-53 Control Coverage
The mapped STIG baselines mandate compliance checks against the following NIST SP 800-53 controls:

> `AC-3`, `IA-2`, `SC-12`, `SC-13`, `SC-8`, `SI-10`, `SI-16`, `SI-2`, `SI-4`, `SI-7`

---

## 3. Component-to-STIG Traceability Matrix

| Component Name | Version | Type | Mapped DISA STIG / SRG | Severity | NIST Controls | Resolution Rationale |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| **/workspace** | `Unknown` | `file` | Application Security and Development (ASD) STIG | `CAT I` | SI-2, SI-4, SI-7, SI-10, ... | Application dependency governed by General Application Security and Development (ASD) STIG |
| **/workspace/requirements.txt** | `Unknown` | `file` | Application Security and Development (ASD) STIG | `CAT I` | SI-2, SI-4, SI-7, SI-10, ... | Application dependency governed by General Application Security and Development (ASD) STIG |
| **cryptography** | `38.0.1` | `library` | Application Security and Development (ASD) STIG | `CAT I` | SI-2, SI-4, SI-7, SI-10, ... | Resolved via PURL ecosystem (pypi): Python application dependency (PyPI) |
| **pycrypto** | `2.6.1` | `library` | Application Security and Development (ASD) STIG | `CAT I` | SI-2, SI-4, SI-7, SI-10, ... | Resolved via PURL ecosystem (pypi): Python application dependency (PyPI) |
| **requests** | `2.31.0` | `library` | Application Security and Development (ASD) STIG | `CAT I` | SI-2, SI-4, SI-7, SI-10, ... | Resolved via PURL ecosystem (pypi): Python application dependency (PyPI) |

---
*Artifact produced by GRC Bundle Review Pipeline (`sbom_analyzer.py`)*
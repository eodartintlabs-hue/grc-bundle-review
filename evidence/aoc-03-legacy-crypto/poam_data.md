# Plan of Action and Milestones (POA&M) Datapoints

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD CC SRG / SCR-SCN)  
> **Audit Target Identifier**: `aoc-03-legacy-crypto`  
> **Source Subject**: `Local Audit Evidence`  
> **Cryptographic Hash (SHA-256)**: `N/A`  
> **Review Session ID**: `N/A`  
> **Evaluation Timestamp**: `2026-10-15 22:50:32 UTC`  
> **Overall Audit Posture**: **NON-COMPLIANT (Remediation Gating Enforced)**  

---

## 1. Executive Vulnerability & Risk Summary

The following risk rollup aggregates all findings detected across static AST analysis (Semgrep), dependency scanning (Grype/Trivy), secret scanning (Gitleaks), Infrastructure-as-Code policy validation (Checkov), and cryptographic library audits:

| Severity Level | DISA STIG Impact Category | Active Findings Count | Mandatory Remediation SLA | Compliance Status |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | **Category I (CAT I)** | **0** | **30 Calendar Days** | ✅ Clear |
| **HIGH** | **Category II (CAT II)** | **7** | **60 Calendar Days** | ❌ Non-Compliant |
| **MEDIUM** | **Category III (CAT III)** | **10** | **90 Calendar Days** | ⚠️ Warning |
| **LOW / INFO** | Informational | **0** | 180 Calendar Days | ✅ Monitored |
| **TOTAL** | — | **17** | — | **NON-COMPLIANT (Remediation Gating Enforced)** |

---

## 2. Standardized POA&M Itemization Table

All line items below are structured for automated ingestion into formal Enterprise POA&M tracking systems (eMASS, Archer, ServiceNow GRC, Jira Security):

| POAM ID | Primary NIST Control | Weakness / Finding Name | Severity / CAT | Source Engine | Affected Asset / File | Target Completion | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **POAM-001** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **MEDIUM / CAT II** | `Semgrep` | `src/LegacyEncryption.java:14` | `2027-01-13` | Open |
| **POAM-002** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **MEDIUM / CAT II** | `Semgrep` | `src/LegacyEncryption.java:15` | `2027-01-13` | Open |
| **POAM-003** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **HIGH / CAT II** | `Semgrep` | `src/LegacyEncryption.java:17` | `2026-12-14` | Open |
| **POAM-004** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **HIGH / CAT II** | `Semgrep` | `src/LegacyEncryption.java:18` | `2026-12-14` | Open |
| **POAM-005** | `SI-7` | AOC-09 [NIST SP 800-53 SI-7] | **MEDIUM / CAT II** | `Semgrep` | `src/cipher.go:3` | `2027-01-13` | Open |
| **POAM-006** | `SI-7` | AOC-09 [NIST SP 800-53 SI-7] | **MEDIUM / CAT II** | `Semgrep` | `src/cipher.go:3` | `2027-01-13` | Open |
| **POAM-007** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **MEDIUM / CAT II** | `Semgrep` | `src/cipher.go:13` | `2027-01-13` | Open |
| **POAM-008** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **MEDIUM / CAT II** | `Semgrep` | `src/cipher.go:17` | `2027-01-13` | Open |
| **POAM-009** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **HIGH / CAT II** | `Semgrep` | `src/cipher.go:24` | `2026-12-14` | Open |
| **POAM-010** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **HIGH / CAT II** | `Semgrep` | `src/cipher.go:29` | `2026-12-14` | Open |
| **POAM-011** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **MEDIUM / CAT II** | `Semgrep` | `src/crypto_service.py:12` | `2027-01-13` | Open |
| **POAM-012** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **MEDIUM / CAT II** | `Semgrep` | `src/crypto_service.py:13` | `2027-01-13` | Open |
| **POAM-013** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **HIGH / CAT II** | `Semgrep` | `src/crypto_service.py:19` | `2026-12-14` | Open |
| **POAM-014** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **HIGH / CAT II** | `Semgrep` | `src/crypto_service.py:24` | `2026-12-14` | Open |
| **POAM-015** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **MEDIUM / CAT II** | `Semgrep` | `src/hashing.js:5` | `2027-01-13` | Open |
| **POAM-016** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **MEDIUM / CAT II** | `Semgrep` | `src/hashing.js:6` | `2027-01-13` | Open |
| **POAM-017** | `SI-16` | AOC-03 [NIST SP 800-53 SI-16] | **HIGH / CAT II** | `Semgrep` | `src/hashing.js:12` | `2026-12-14` | Open |

---

## 3. Remediation & Corrective Action Plans

### 3.001 [POAM-001] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/LegacyEncryption.java:14`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-java-weak-hashing` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Weak digest algorithm (MD5 or SHA-1) in Java. Upgrade to SHA-256 or SHA-512.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.002 [POAM-002] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/LegacyEncryption.java:15`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-java-weak-hashing` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Weak digest algorithm (MD5 or SHA-1) in Java. Upgrade to SHA-256 or SHA-512.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.003 [POAM-003] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/LegacyEncryption.java:17`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-java-weak-ciphers` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Insecure cipher transformation (DES, RC4, or ECB mode) detected in Java. Use AES/GCM/NoPadding.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.004 [POAM-004] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/LegacyEncryption.java:18`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-java-weak-ciphers` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Insecure cipher transformation (DES, RC4, or ECB mode) detected in Java. Use AES/GCM/NoPadding.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.005 [POAM-005] AOC-09 [NIST SP 800-53 SI-7]
* **Affected Asset**: `src/cipher.go:3`
* **Governing Controls**: `SI-7` | **Area of Concern**: `AOC-09: Crypto Dependencies on Unsupported Libraries`
* **Detection Identifier**: `rules.grc-aoc09-go-deprecated-crypto-module` (Semgrep)
* **Detailed Finding**: AOC-09 [NIST SP 800-53 SI-7]: Deprecated crypto algorithm package imported in Go. Migrate to standard crypto/sha256 or crypto/aes.
* **Prescribed Action / Fix**: Remediate source code according to the secure coding baseline; eliminate static credentials, legacy ciphers, or shell execution.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.006 [POAM-006] AOC-09 [NIST SP 800-53 SI-7]
* **Affected Asset**: `src/cipher.go:3`
* **Governing Controls**: `SI-7` | **Area of Concern**: `AOC-09: Crypto Dependencies on Unsupported Libraries`
* **Detection Identifier**: `rules.grc-aoc09-go-deprecated-crypto-module` (Semgrep)
* **Detailed Finding**: AOC-09 [NIST SP 800-53 SI-7]: Deprecated crypto algorithm package imported in Go. Migrate to standard crypto/sha256 or crypto/aes.
* **Prescribed Action / Fix**: Remediate source code according to the secure coding baseline; eliminate static credentials, legacy ciphers, or shell execution.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.007 [POAM-007] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/cipher.go:13`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-go-weak-hashing` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Insecure MD5/SHA-1 hash algorithm detected in Go. Use crypto/sha256 or crypto/sha512.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.008 [POAM-008] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/cipher.go:17`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-go-weak-hashing` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Insecure MD5/SHA-1 hash algorithm detected in Go. Use crypto/sha256 or crypto/sha512.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.009 [POAM-009] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/cipher.go:24`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-go-weak-ciphers` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Deprecated cipher (DES or RC4) instantiated in Go. Migrate to AES-GCM (crypto/aes and crypto/cipher).
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.010 [POAM-010] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/cipher.go:29`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-go-weak-ciphers` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Deprecated cipher (DES or RC4) instantiated in Go. Migrate to AES-GCM (crypto/aes and crypto/cipher).
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.011 [POAM-011] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/crypto_service.py:12`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-python-weak-hashing` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Insecure cryptographic hash function (MD5/SHA-1) detected in Python. Use SHA-256 or SHA-3 for integrity.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.012 [POAM-012] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/crypto_service.py:13`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-python-weak-hashing` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Insecure cryptographic hash function (MD5/SHA-1) detected in Python. Use SHA-256 or SHA-3 for integrity.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.013 [POAM-013] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/crypto_service.py:19`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-python-weak-ciphers` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Insecure cipher (DES, 3DES, RC4, or Blowfish) detected in Python. Upgrade to AES-GCM with >= 256-bit keys.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.014 [POAM-014] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/crypto_service.py:24`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-python-weak-ciphers` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Insecure cipher (DES, 3DES, RC4, or Blowfish) detected in Python. Upgrade to AES-GCM with >= 256-bit keys.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.015 [POAM-015] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/hashing.js:5`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-javascript-weak-hashing` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Weak digest algorithm (MD5/SHA-1) in Node.js crypto. Use sha256 or sha512.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.016 [POAM-016] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/hashing.js:6`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-javascript-weak-hashing` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Weak digest algorithm (MD5/SHA-1) in Node.js crypto. Use sha256 or sha512.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2027-01-13` (90 days)

### 3.017 [POAM-017] AOC-03 [NIST SP 800-53 SI-16]
* **Affected Asset**: `src/hashing.js:12`
* **Governing Controls**: `SI-16` | **Area of Concern**: `AOC-03: Weak Encryption Check`
* **Detection Identifier**: `rules.grc-aoc03-javascript-weak-ciphers` (Semgrep)
* **Detailed Finding**: AOC-03 [NIST SP 800-53 SI-16]: Legacy cipher or deprecated createCipher API detected in JavaScript. Use crypto.createCipheriv with aes-256-gcm.
* **Prescribed Action / Fix**: Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)


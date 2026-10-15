# Plan of Action and Milestones (POA&M) Datapoints

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD CC SRG / SCR-SCN)  
> **Audit Target Identifier**: `aoc-02-weak-passwords`  
> **Source Subject**: `Local Audit Evidence`  
> **Cryptographic Hash (SHA-256)**: `N/A`  
> **Review Session ID**: `N/A`  
> **Evaluation Timestamp**: `2026-10-15 22:50:23 UTC`  
> **Overall Audit Posture**: **NON-COMPLIANT (Remediation Gating Enforced)**  

---

## 1. Executive Vulnerability & Risk Summary

The following risk rollup aggregates all findings detected across static AST analysis (Semgrep), dependency scanning (Grype/Trivy), secret scanning (Gitleaks), Infrastructure-as-Code policy validation (Checkov), and cryptographic library audits:

| Severity Level | DISA STIG Impact Category | Active Findings Count | Mandatory Remediation SLA | Compliance Status |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | **Category I (CAT I)** | **0** | **30 Calendar Days** | ✅ Clear |
| **HIGH** | **Category II (CAT II)** | **16** | **60 Calendar Days** | ❌ Non-Compliant |
| **MEDIUM** | **Category III (CAT III)** | **0** | **90 Calendar Days** | ✅ Clear |
| **LOW / INFO** | Informational | **0** | 180 Calendar Days | ✅ Monitored |
| **TOTAL** | — | **16** | — | **NON-COMPLIANT (Remediation Gating Enforced)** |

---

## 2. Standardized POA&M Itemization Table

All line items below are structured for automated ingestion into formal Enterprise POA&M tracking systems (eMASS, Archer, ServiceNow GRC, Jira Security):

| POAM ID | Primary NIST Control | Weakness / Finding Name | Severity / CAT | Source Engine | Affected Asset / File | Target Completion | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **POAM-001** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/ApplicationConfig.java:10` | `2026-12-14` | Open |
| **POAM-002** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/ApplicationConfig.java:11` | `2026-12-14` | Open |
| **POAM-003** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/ApplicationConfig.java:12` | `2026-12-14` | Open |
| **POAM-004** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/ApplicationConfig.java:13` | `2026-12-14` | Open |
| **POAM-005** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/auth_service.py:11` | `2026-12-14` | Open |
| **POAM-006** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/auth_service.py:12` | `2026-12-14` | Open |
| **POAM-007** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/auth_service.py:13` | `2026-12-14` | Open |
| **POAM-008** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/auth_service.py:14` | `2026-12-14` | Open |
| **POAM-009** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/client.js:7` | `2026-12-14` | Open |
| **POAM-010** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/client.js:8` | `2026-12-14` | Open |
| **POAM-011** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/client.js:9` | `2026-12-14` | Open |
| **POAM-012** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/client.js:11` | `2026-12-14` | Open |
| **POAM-013** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/database.go:9` | `2026-12-14` | Open |
| **POAM-014** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/database.go:10` | `2026-12-14` | Open |
| **POAM-015** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/database.go:13` | `2026-12-14` | Open |
| **POAM-016** | `IA-2` | AOC-02 [NIST SP 800-53 IA-2] | **HIGH / CAT II** | `Semgrep` | `src/database.go:14` | `2026-12-14` | Open |

---

## 3. Remediation & Corrective Action Plans

### 3.001 [POAM-001] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/ApplicationConfig.java:10`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-java-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded password literal in Java source code. Inject credentials via external configuration or vault.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.002 [POAM-002] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/ApplicationConfig.java:11`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-java-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded password literal in Java source code. Inject credentials via external configuration or vault.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.003 [POAM-003] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/ApplicationConfig.java:12`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-java-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded password literal in Java source code. Inject credentials via external configuration or vault.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.004 [POAM-004] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/ApplicationConfig.java:13`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-java-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded password literal in Java source code. Inject credentials via external configuration or vault.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.005 [POAM-005] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/auth_service.py:11`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-python-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.006 [POAM-006] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/auth_service.py:12`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-python-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.007 [POAM-007] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/auth_service.py:13`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-python-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.008 [POAM-008] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/auth_service.py:14`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-python-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.009 [POAM-009] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/client.js:7`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-javascript-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credentials in JavaScript/TypeScript code. Use process.env or a secure key store.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.010 [POAM-010] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/client.js:8`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-javascript-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credentials in JavaScript/TypeScript code. Use process.env or a secure key store.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.011 [POAM-011] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/client.js:9`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-javascript-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credentials in JavaScript/TypeScript code. Use process.env or a secure key store.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.012 [POAM-012] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/client.js:11`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-javascript-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credentials in JavaScript/TypeScript code. Use process.env or a secure key store.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.013 [POAM-013] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/database.go:9`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-go-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Go source code. Store credentials securely outside the repository.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.014 [POAM-014] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/database.go:10`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-go-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Go source code. Store credentials securely outside the repository.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.015 [POAM-015] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/database.go:13`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-go-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Go source code. Store credentials securely outside the repository.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)

### 3.016 [POAM-016] AOC-02 [NIST SP 800-53 IA-2]
* **Affected Asset**: `src/database.go:14`
* **Governing Controls**: `IA-2` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `rules.grc-aoc02-go-hardcoded-credentials` (Semgrep)
* **Detailed Finding**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Go source code. Store credentials securely outside the repository.
* **Prescribed Action / Fix**: Externalize credentials into a secret management vault or protected environment variable.
* **Scheduled Completion SLA**: `2026-12-14` (60 days)


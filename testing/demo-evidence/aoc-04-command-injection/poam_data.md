# Plan of Action and Milestones (POA&M) Datapoints

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD CC SRG / SCR-SCN)  
> **Audit Target Identifier**: `6dec88c8940840c0ee7bcea50a24226c50ddffd2be92ad8b107831996f9f67a2`  
> **Source Subject**: `/Users/byronturner-pro/Desktop/GRC-Test-Dummies/bundles/aoc-04-command-injection.bundle`  
> **Cryptographic Hash (SHA-256)**: `6dec88c8940840c0ee7bcea50a24226c50ddffd2be92ad8b107831996f9f67a2`  
> **Review Session ID**: `872c1eef-7d6a-46ce-aec9-72fc4b2a6d30`  
> **Evaluation Timestamp**: `2026-10-16 19:15:35 UTC`  
> **Overall Audit Posture**: **NON-COMPLIANT (Remediation Gating Enforced)**  

---

## 1. Executive Vulnerability & Risk Summary

The following risk rollup aggregates all findings detected across static AST analysis (Semgrep), dependency scanning (Grype/Trivy), secret scanning (Gitleaks), Infrastructure-as-Code policy validation (Checkov), and cryptographic library audits:

| Severity Level | DISA STIG Impact Category | Active Findings Count | Mandatory Remediation SLA | Compliance Status |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | **Category I (CAT I)** | **9** | **30 Calendar Days** | ❌ Non-Compliant |
| **HIGH** | **Category II (CAT II)** | **0** | **60 Calendar Days** | ✅ Clear |
| **MEDIUM** | **Category III (CAT III)** | **0** | **90 Calendar Days** | ✅ Clear |
| **LOW / INFO** | Informational | **0** | 180 Calendar Days | ✅ Monitored |
| **TOTAL** | — | **9** | — | **NON-COMPLIANT (Remediation Gating Enforced)** |

---

## 2. Standardized POA&M Itemization Table

All line items below are structured for automated ingestion into formal Enterprise POA&M tracking systems (eMASS, Archer, ServiceNow GRC, Jira Security):

| POAM ID | Primary NIST Control | Weakness / Finding Name | Severity / CAT | Source Engine | Affected Asset / File | Target Completion | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **POAM-001** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `src/CommandExecutor.java:11` | `2026-11-15` | Open |
| **POAM-002** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `src/CommandExecutor.java:15` | `2026-11-15` | Open |
| **POAM-003** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `src/executor.go:10` | `2026-11-15` | Open |
| **POAM-004** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `src/executor.go:15` | `2026-11-15` | Open |
| **POAM-005** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `src/runner.py:14` | `2026-11-15` | Open |
| **POAM-006** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `src/runner.py:20` | `2026-11-15` | Open |
| **POAM-007** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `src/runner.py:28` | `2026-11-15` | Open |
| **POAM-008** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `src/system.js:5` | `2026-11-15` | Open |
| **POAM-009** | `SI-4` | AOC-04 [NIST SP 800-53 SI-4] | **CRITICAL / CAT I** | `Semgrep` | `src/system.js:15` | `2026-11-15` | Open |

---

## 3. Remediation & Corrective Action Plans

### 3.001 [POAM-001] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `src/CommandExecutor.java:11`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-java-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution in Java via Runtime or ProcessBuilder. Sanitize input and pass arguments as discrete array elements.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-15` (30 days)

### 3.002 [POAM-002] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `src/CommandExecutor.java:15`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-java-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution in Java via Runtime or ProcessBuilder. Sanitize input and pass arguments as discrete array elements.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-15` (30 days)

### 3.003 [POAM-003] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `src/executor.go:10`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-go-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Arbitrary shell execution invocation detected in Go. Execute binaries directly with separate arguments.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-15` (30 days)

### 3.004 [POAM-004] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `src/executor.go:15`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-go-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Arbitrary shell execution invocation detected in Go. Execute binaries directly with separate arguments.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-15` (30 days)

### 3.005 [POAM-005] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `src/runner.py:14`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-python-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution via shell invocation in Python. Use subprocess.run with arguments list and shell=False.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-15` (30 days)

### 3.006 [POAM-006] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `src/runner.py:20`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-python-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution via shell invocation in Python. Use subprocess.run with arguments list and shell=False.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-15` (30 days)

### 3.007 [POAM-007] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `src/runner.py:28`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-python-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution via shell invocation in Python. Use subprocess.run with arguments list and shell=False.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-15` (30 days)

### 3.008 [POAM-008] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `src/system.js:5`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-javascript-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Potential command injection in Node.js child_process.exec. Prefer child_process.execFile with parameter arrays.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-15` (30 days)

### 3.009 [POAM-009] AOC-04 [NIST SP 800-53 SI-4]
* **Affected Asset**: `src/system.js:15`
* **Governing Controls**: `SI-4` | **Area of Concern**: `AOC-04: Command Injection`
* **Detection Identifier**: `rules.grc-aoc04-javascript-command-injection` (Semgrep)
* **Detailed Finding**: AOC-04 [NIST SP 800-53 SI-4]: Potential command injection in Node.js child_process.exec. Prefer child_process.execFile with parameter arrays.
* **Prescribed Action / Fix**: Replace shell execution with parameterized runtime APIs; avoid shell=True.
* **Scheduled Completion SLA**: `2026-11-15` (30 days)


# Custom Baseline Ruleset Validation Audit Log

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (Ruleset Verification Log)  
> **Audit Target Identifier**: `aoc-02-weak-passwords`  
> **Ruleset File**: `rules/custom-baseline-ruleset.yaml`  
> **Evaluation Timestamp**: `2026-10-15 22:50:23 UTC`  

---

## 1. Execution Summary

The custom Semgrep baseline defines **37 high-assurance security rules** spanning password hygiene, cryptography, command injection, TLS validation, and infrastructure hardening across Go, Java, Python, and JavaScript.

| Metric | Value | Audit Significance |
| :--- | :--- | :--- |
| **Total Evaluated Rules** | **37** | Complete baseline coverage |
| **Triggered Rules (Violations Detected)** | **4** | Active findings requiring engineering triage |
| **Clean Rules (Passed Checks)** | **33** | Controls verified without violation |
| **Total Discovered Code Defects** | **16** | Raw AST match instances |

---

## 2. Itemized Rule Evaluation Audit Trail

| Rule Identifier | Target AOC | Governing NIST Control | Severity | Audit Status | Triggered Matches |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `grc-aoc02-python-hardcoded-credentials` | AOC-02: Password Hygiene | `IA-2` | `ERROR` | ❌ **TRIGGERED** | **4** |
| `grc-aoc02-go-hardcoded-credentials` | AOC-02: Password Hygiene | `IA-2` | `ERROR` | ❌ **TRIGGERED** | **4** |
| `grc-aoc02-java-hardcoded-credentials` | AOC-02: Password Hygiene | `IA-2` | `ERROR` | ❌ **TRIGGERED** | **4** |
| `grc-aoc02-javascript-hardcoded-credentials` | AOC-02: Password Hygiene | `IA-2` | `ERROR` | ❌ **TRIGGERED** | **4** |
| `grc-aoc03-python-weak-hashing` | AOC-03: Weak Encryption Check | `SI-16` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-python-weak-ciphers` | AOC-03: Weak Encryption Check | `SI-16` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-go-weak-hashing` | AOC-03: Weak Encryption Check | `SI-16` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-go-weak-ciphers` | AOC-03: Weak Encryption Check | `SI-16` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-java-weak-hashing` | AOC-03: Weak Encryption Check | `SI-16` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-java-weak-ciphers` | AOC-03: Weak Encryption Check | `SI-16` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-javascript-weak-hashing` | AOC-03: Weak Encryption Check | `SI-16` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-javascript-weak-ciphers` | AOC-03: Weak Encryption Check | `SI-16` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc04-python-command-injection` | AOC-04: Command Injection | `SI-4` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc04-go-command-injection` | AOC-04: Command Injection | `SI-4` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc04-java-command-injection` | AOC-04: Command Injection | `SI-4` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc04-javascript-command-injection` | AOC-04: Command Injection | `SI-4` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc05-python-disabled-tls-verification` | AOC-05: Improper TLS | `SI-17` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc05-go-insecure-tls` | AOC-05: Improper TLS | `SI-17` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc05-java-insecure-trust-manager` | AOC-05: Improper TLS | `SI-17` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc05-javascript-disabled-tls-check` | AOC-05: Improper TLS | `SI-17` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc06-generic-embedded-private-keys` | AOC-06: Secrets Management | `SC-12` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc09-python-deprecated-crypto-module` | AOC-09: Crypto Dependencies on Unsupported Libraries | `SI-7` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc09-go-deprecated-crypto-module` | AOC-09: Crypto Dependencies on Unsupported Libraries | `SI-7` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc09-java-deprecated-crypto-provider` | AOC-09: Crypto Dependencies on Unsupported Libraries | `SI-7` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc09-javascript-deprecated-crypto-package` | AOC-09: Crypto Dependencies on Unsupported Libraries | `SI-7` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc10-python-unsafe-deserialization` | AOC-10: CRITICAL Severity Findings | `RA-5` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc10-java-unsafe-deserialization` | AOC-10: CRITICAL Severity Findings | `RA-5` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc10-javascript-dangerous-eval` | AOC-10: CRITICAL Severity Findings | `RA-5` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc10-go-unsafe-pointer` | AOC-10: CRITICAL Severity Findings | `RA-5` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc11-python-debug-exposed` | AOC-11: Violation of Category I STIGs | `SI-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc11-go-plaintext-http-listener` | AOC-11: Violation of Category I STIGs | `SI-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc11-java-xxe-processing` | AOC-11: Violation of Category I STIGs | `SI-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc11-javascript-insecure-cookie-attributes` | AOC-11: Violation of Category I STIGs | `SI-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc140-python-stdout-credential-leak` | AOC-140: Organization Specific Controls | `CM-6` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc140-go-stdout-credential-leak` | AOC-140: Organization Specific Controls | `CM-6` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc140-java-stdout-credential-leak` | AOC-140: Organization Specific Controls | `CM-6` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc140-javascript-console-credential-leak` | AOC-140: Organization Specific Controls | `CM-6` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |

---

## 3. Discovered Violation Code Locations

* **Rule**: `rules.grc-aoc02-java-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/ApplicationConfig.java:10`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded password literal in Java source code. Inject credentials via external configuration or vault.
* **Rule**: `rules.grc-aoc02-java-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/ApplicationConfig.java:11`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded password literal in Java source code. Inject credentials via external configuration or vault.
* **Rule**: `rules.grc-aoc02-java-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/ApplicationConfig.java:12`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded password literal in Java source code. Inject credentials via external configuration or vault.
* **Rule**: `rules.grc-aoc02-java-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/ApplicationConfig.java:13`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded password literal in Java source code. Inject credentials via external configuration or vault.
* **Rule**: `rules.grc-aoc02-python-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/auth_service.py:11`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Rule**: `rules.grc-aoc02-python-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/auth_service.py:12`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Rule**: `rules.grc-aoc02-python-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/auth_service.py:13`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Rule**: `rules.grc-aoc02-python-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/auth_service.py:14`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Python source code. Use environment variables or a secrets manager.
* **Rule**: `rules.grc-aoc02-javascript-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/client.js:7`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credentials in JavaScript/TypeScript code. Use process.env or a secure key store.
* **Rule**: `rules.grc-aoc02-javascript-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/client.js:8`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credentials in JavaScript/TypeScript code. Use process.env or a secure key store.
* **Rule**: `rules.grc-aoc02-javascript-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/client.js:9`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credentials in JavaScript/TypeScript code. Use process.env or a secure key store.
* **Rule**: `rules.grc-aoc02-javascript-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/client.js:11`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credentials in JavaScript/TypeScript code. Use process.env or a secure key store.
* **Rule**: `rules.grc-aoc02-go-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/database.go:9`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Go source code. Store credentials securely outside the repository.
* **Rule**: `rules.grc-aoc02-go-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/database.go:10`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Go source code. Store credentials securely outside the repository.
* **Rule**: `rules.grc-aoc02-go-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/database.go:13`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Go source code. Store credentials securely outside the repository.
* **Rule**: `rules.grc-aoc02-go-hardcoded-credentials` (AOC-02: Password Hygiene)
  * **Location**: `src/database.go:14`
  * **Message**: AOC-02 [NIST SP 800-53 IA-2]: Detected hardcoded credential assignment in Go source code. Store credentials securely outside the repository.

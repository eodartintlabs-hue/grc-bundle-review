# DevSecOps Engineering & Compliance Workspace Layout

> **Classification / Use**: Internal Engineering & Compliance Specification  
> **Target Frameworks**: DISA STIG, NIST SP 800-53 / FedRAMP, OWASP Top 10  
> **Environment Status**: Active Workstation Baseline

---
## 1. System Architecture & Host Environment

### 1.1 Hardware Baseline
| Specification | Component / Version | Notes |
| :--- | :--- | :--- |
| **Platform** | MacBook Pro | Host Developer Machine |
| **Architecture** | Apple Silicon (M5 Pro) | ARM64 Native Execution |

### 1.2 Infrastructure & Runtimes
* **Container Runtime**: Docker for macOS (isolated scanner execution)
* **Version Control**: Git
* **CI/CD Orchestration**: GitHub Actions
* **Scripting Engine**: Python 3.x

### 1.3 Developer Applications & Utilities
* **Repository Platform**: GitHub
* **Development Environment**: Google Antigravity IDE
* **Integrity & Hashing**: `shasum` (artifact checksum generation and verification)

---

## 2. Containerized Security Scanning Suite

All automated static analysis and vulnerability tools execute inside isolated Docker containers:

| Tool | Scanning Domain | Coverage / Purpose |
| :--- | :--- | :--- |
| **Semgrep** | SAST | AST-based static source code analysis |
| **Gitleaks** | Secret Detection | Detection of hardcoded API keys, tokens, and credentials |
| **Checkov** | IaC Security | Static analysis for Terraform, CloudFormation, and Dockerfiles |
| **Syft** | SBOM Generation | Generation of SPDX / CycloneDX software bill of materials |
| **Grype** | Vulnerability Scanner | Dependency and container CVE scanning |
| **Trivy** | Vulnerability Scanner | Multi-target security scanner (OS packages, dependencies, misconfigs) |

---

## 3. Custom Automation & Rule Engines

### 3.1 Custom Baseline YAML Engine
A specialized policy configuration containing **48 rules** to identify security and configuration gaps within Git bundles:
* **Key Rotation**: Enforce validity windows and lifecycle rotation requirements. *(Note: Deprecated / no longer enforced as of December 2025)*
* **Password Hygiene**: Flag default, static, or weak password structures.
* **Weak Encryption Check**: Detect legacy ciphers (e.g., DES, RC4, MD5, SHA-1).
* **Command Injection**: Detect unsanitized runtime shell execution vectors.
* **Improper TLS**: Identify deprecated protocols (TLS 1.0/1.1) and disabled certificate checks.
* **Lack of FIPS Mode**: Detect unvalidated cryptographic modules and missing FIPS mode flags.
* **Custom AOCs**: Organization-specific security checks and guardrails.

### 3.2 Python Utilities & Git Integration
* **SBOM Analyzer (`sbom_analyzer.py`)**: Parses generated SBOM components and maps them directly against applicable DISA STIG baselines.
* **GitHub Rulesets (`ruleset_checker.py`)**: Custom pre-commit and commit-validation rulesets that intercept commits violating Areas of Concern (AOCs).
* **Cryptographic Provider Scanner (`crypto_lib_scan.py`)**: Static inspection script to enumerate cryptographic libraries and security providers in application dependencies.

---

## 4. Work Products & Compliance Deliverables

The workspace generates standardized audit and authorization artifacts:

| Deliverable | Format | Purpose / Recipient |
| :--- | :--- | :--- |
| **Bundle Identifier** | String / Hash | Unique build/bundle provenance identifier |
| **Software Bill of Materials (SBOM)** | JSON (SPDX/CycloneDX) | Supply chain inventory and transparency |
| **Unified Scan Reports** | JSON / HTML / PDF | Aggregated SAST, Secret, IaC, and CVE vulnerability results |
| **Ruleset Checks Summary** | Log / Text | Verification logs for commit-level AOC policy compliance |
| **STIG Applicability Matrix** | Table / List | Bundle-specific catalog of relevant DISA STIG requirements |
| **POAM Datapoints** | Markdown (`poam_data.md`) | Structured risk and vulnerability inputs for POA&M ingestion |
| **Control Mapping File** | Markdown (`controls.md`) | Direct traceability matrix mapping findings to compliance controls |
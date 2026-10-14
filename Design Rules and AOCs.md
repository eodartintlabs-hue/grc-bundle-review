# Design Rules and AOCs

## Design Rules for GRC Bundle Review Process
- **Never halt main build pipeline.** GRC analysis is out-of-band (OOB), read-only, and fail-open. It is not a build gating process.
- **GRC owns the OOB pipeline.** The workspace exists solely for the purpose of GRC analysis. This includes the design, maintenance and ownership of the tools and processes used in the pipeline. Bundles are manually copied into the workspace by dev teams upon GRC request.
- **Ephemeral execution environment.** The workspace is ephemeral and is only used for GRC analysis. Once the analysis is complete, the workspace is destroyed and the bundle is deleted. 
- **Work products serve GRC deliverables only**. No engineering products are produced by the GRC pipeline.  
- **GRC advisory is asynchronous with build process.** GRC does not provide real-time feedback or block deployments. The objective is post-validation analysis and reporting to satisfy the requirements listed below:
    

## Areas of Concern (AOCs)

| # | Area of Concern (AOC) | Description | Policy Reference |
| :--- | :--- | :--- | :--- |
| **01** | **Key Rotation** | Enforce validity windows and lifecycle rotation requirements for cryptographic keys, tokens, and secrets. **Note:** *This AOC is no longer enforced as of December 2025.* | NIST SP 800-53-SI-16 |
| **02** | **Password Hygiene** | Flag default, static, or weak password structures. | NIST SP 800-53-IA-2 |
| **03** | **Weak Encryption Check** | Detect legacy ciphers (e.g., DES, RC4, MD5, SHA-1) and insecure cryptographic implementations. | NIST SP 800-53-SI-16 |
| **04** | **Command Injection** | Detect unsanitized runtime shell execution vectors in code. | NIST SP 800-53-SI-4 |
| **05** | **Improper TLS** | Identify deprecated protocols (TLS 1.0/1.1) and disabled certificate checks. | NIST SP 800-53-SI-17 |
| **06** | **Secrets Management** | Review key and cert management practices. | NIST SP 800-53-SC-12 |
| **07** | **IaC Misconfigurations & Policy Violations** | Detect IaC misconfigurations and policy violations. | NIST SP 800-53-AC-6 | 
| **08** | **Component Inventory & SBOM Accuracy** | Verify organization specific component inventory and SBOM requirements. | NIST SP 800-53-SI-7 |
| **09** | **Crypto Dependencies on Unsupported Libraries** | Identify end-of-life and unsupported libraries found in the application dependencies (e.g. OpenSSL 1.1.1).  | NIST SP 800-53-SI-7 |
| **10** | **CRITICAL Severity Findings** | Critical vulnerabilities identified by automated tools that pose an immediate risk to the system. | NIST SP 800-53-RA-5 |
| **11** | **Violation of Category I STIGs** | Detect configurations that violate Category I STIG requirements. Category I STIGs are considered critical and must be remediated immediately. | NIST SP 800-53-SI-2 |
| **140** | **Organization Specific Controls** | Custom organization-specific security checks and guardrails. These rules are not standardized and may vary depending on the organization's specific security requirements and compliance obligations. | Organization-specific |



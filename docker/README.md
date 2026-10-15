# GRC Containerized Scanner Suite (`grc-scanner:local`)

> **Classification**: Internal DevSecOps & Security Compliance Specification  
> **Target Frameworks**: DISA STIG, NIST SP 800-53 Rev. 5, FedRAMP High  
> **Execution Model**: 100% Local Docker Container, Zero Cloud Cost, Zero Host Pollution  

---

## 1. Overview

This directory defines the **authoritative, unified container image** used to execute all third-party security scanners in the **GRC Bundle Review Pipeline**.

Instead of installing dozens of tools, Python virtual environments, and Go runtimes directly onto your host machine (which could interfere with local MCP servers, agents, and other developer projects), all tools are built into an isolated, local Docker image: **`grc-scanner:local`**.

### Included Security Scanning Tools

| Tool | Scanning Domain | Primary Coverage / Ruleset |
| :--- | :--- | :--- |
| **Semgrep** | Static Application Security Testing (SAST) | AST-based scanning against 37 custom AOC baseline rules (`rules/custom-baseline-ruleset.yaml`). |
| **Checkov** | Infrastructure-as-Code (IaC) | Static analysis for Terraform, CloudFormation, Kubernetes, and Ansible playbooks (AOC 07). |
| **Gitleaks** | Secret & Credential Detection | Detection of hardcoded API keys, private keys, and tokens (AOC 02, AOC 06). |
| **Syft** | Software Bill of Materials (SBOM) | Automated cataloging of all OS packages and language dependencies into CycloneDX/SPDX. |
| **Grype** | Vulnerability Scanner | Vulnerability and CVE matching against generated SBOMs (AOC 10). |
| **Trivy** | Multi-Target Vulnerability Scanner | Comprehensive CVE and misconfiguration scanner for filesystems and packages. |
| **OpenSCAP** | OS-Level STIG Evaluation | Offline evaluation of DISA STIG benchmarks (`oscap xccdf eval`) for cold-mounted AMIs. |

---

## 2. Quickstart: Building the Local Image

Run the build command once from the repository root:

```bash
cd /Users/byronturner-pro/Desktop/GRC-Bundle-Review_Pipeline

# Build the local Docker image (takes ~2 minutes)
docker build -t grc-scanner:local -f docker/Dockerfile.scanner .
```

* **Cost**: \$0.00 (builds locally on your machine).
* **Isolation**: Nothing is installed onto your macOS system.
* **Compatibility**: Native ARM64 build on Apple Silicon.

---

## 3. Running Scans Against an Ephemeral Workspace

### Automated Scan (All Tools)
Mount your restored ephemeral workspace as **read-only (`:ro`)** and run the built-in orchestrator:

```bash
docker run --rm \
  --network none \
  -v "$(pwd)/ephemeral_workspace:/workspace:ro" \
  -v "$(pwd)/rules:/rules:ro" \
  -v "$(pwd)/evidence:/evidence:rw" \
  grc-scanner:local \
  /usr/local/bin/scan_orchestrator.sh
```

### Running an Individual Tool
You can also run any specific tool directly inside the container:

```bash
# Example: Run Semgrep SAST
docker run --rm \
  -v "$(pwd)/ephemeral_workspace:/workspace:ro" \
  -v "$(pwd)/rules:/rules:ro" \
  grc-scanner:local \
  semgrep scan --config=/rules/custom-baseline-ruleset.yaml /workspace

# Example: Run Gitleaks Secret Scan
docker run --rm \
  -v "$(pwd)/ephemeral_workspace:/workspace:ro" \
  grc-scanner:local \
  gitleaks dir /workspace

# Example: Run Checkov IaC Scan
docker run --rm \
  -v "$(pwd)/ephemeral_workspace:/workspace:ro" \
  grc-scanner:local \
  checkov -d /workspace
```

---

## 4. Key Security Controls

1. **Read-Only Workspace Mount (`:ro`)**: The container cannot modify, corrupt, or alter any files inside the bundle workspace.
2. **Network Isolation (`--network none`)**: Blocks all incoming and outgoing network traffic, preventing untrusted test code from executing network calls or sending data externally.
3. **Reproducibility**: The exact same Dockerfile can be executed in GitHub Actions CI/CD to produce 100% identical results.

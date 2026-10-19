# Product Roadmap (`hygiene/ROADMAP.md`)

<p align="center">
  <a href="../README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/DATAFLOW.md"><b>🔄 Data Flow</b></a> &nbsp;·&nbsp;
  <a href="../SECURITY.md"><b>🛡️ Security Policy</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/GOVERNANCE.md"><b>⚖️ Governance & Mandates</b></a> &nbsp;·&nbsp;
  <a href="../testing/TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="../testing/live-demo.md"><b>🎬 Live Demo</b></a> &nbsp;·&nbsp;
  <a href="RELEASE_NOTES.md"><b>🚀 Release Notes</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG.md"><b>🩹 v1 Patch Log</b></a> &nbsp;·&nbsp;
  <a href="ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc-bundle-use-case.md"><b>📑 Use Case Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="../docs/test-dummies-guide.md"><b>🎯 Test Dummies Guide</b></a>
</p>

> **Project**: GRC Bundle & AMI Review Pipeline (`grc-bundle-review`)  
> **Active Series**: `v1.0.x — Yokosuka` *(Restricted Beta — Local Workstation Baseline)*  
> **Upcoming `v1.x` Minor Releases (🇯🇵 Japan Series)**: `v1.2.0 — Sasebo` *(Universal Workstation Portability)* $\rightarrow$ `v1.3.0 — Misawa` *(Tenable & AWS Inspector CSV Ingest)*  
> **Upcoming `v2.x` GA Releases (🌺 Hawaiian Series)**: `v2.0.0 — Pearl Harbor` *(Cloud Lift, Helm Auditing & Local LLM Baseline)* $\rightarrow$ `v2.1.0+` *(RAM-Adaptive LLM Scaling & OSCAL)*  
> **Companion Release History**: See **[`hygiene/RELEASE_NOTES.md`](RELEASE_NOTES.md)** and **[`hygiene/PATCH_LOG.md`](PATCH_LOG.md)**.

---

## 1. Executive Release Progression: Japan Beta (`v1.x`) $\rightarrow$ Hawaii GA (`v2.x`)

The **GRC Bundle & AMI Review Pipeline** follows a structured maturity progression from a single-workstation Beta prototype into an enterprise-grade, cloud-hosted, AI-enriched compliance platform:

1. **🇯🇵 `v1.0.x — Yokosuka` (Active Beta Baseline)**: Establishes the 5-phase out-of-band (`.bundle` & `AMI` cold-mount) workflow, 9-engine air-gapped Docker scanner suite, 37 AST rules, and Phase 4 Markdown/JSON synthesis.
2. **🇯🇵 `v1.2.0 — Sasebo` (Universal Workstation Portability & Plug-and-Play Compatibility)**: Eliminates single-machine assumptions so any engineer or assessor pulling the repo from GitHub on **macOS (Apple Silicon / Intel)**, **Linux (`amd64` / `arm64`)**, or **Windows WSL2** can run `./grc` out-of-the-box with zero permission errors, UID/GID volume conflicts, or unpinned image build failures.
3. **🇯🇵 `v1.3.0 — Misawa` (External Telemetry Ingestion — Tenable & AWS Inspector CSVs $\rightarrow$ Official FedRAMP POA&M `.xlsx`)**: Expands the pipeline to ingest external vulnerability CSV exports from **Tenable** and **AWS Inspector**, deduplicating findings and directly populating the **official FedRAMP POA&M spreadsheet (`.xlsx`)**.
4. **🌺 `v2.0.0 — Pearl Harbor` (Full Production GA — Cloud Lift, Helm Chart Auditing & Local LLM Baseline)**: Launches the **Hawaiian Military Base Cities** GA series by lifting execution from local workstations into **AWS EC2 & Bottlerocket** cloud enclaves, introducing offline **Helm Chart compliance auditing**, and integrating an initial air-gapped local LLM (`Gemma` / `GPT-OSS`) synthesis tier.
5. **🌺 `v2.1.0+ — Subsequent Hawaiian Series (`Kaneohe`, `Wahiawa`)**: Introduces **dynamic endpoint RAM-adaptive LLM tier selection**, NIST OSCAL 1.1.x export, and cryptographic bundle signature attestation.

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'darkMode': true,
    'background': '#070a12',
    'primaryColor': '#0f172a',
    'primaryTextColor': '#f8fafc',
    'primaryBorderColor': '#38bdf8',
    'lineColor': '#38bdf8',
    'secondaryColor': '#1e1b4b',
    'tertiaryColor': '#0c4a6e',
    'mainBkg': '#0f172a',
    'nodeBorder': '#38bdf8',
    'clusterBkg': '#0b0f19',
    'clusterBorder': '#1e293b',
    'defaultLinkColor': '#38bdf8',
    'fontFamily': 'system-ui, -apple-system, sans-serif'
  }
}}%%
flowchart LR
    classDef yokosuka fill:#0c192e,stroke:#0284c7,stroke-width:1.5px,color:#f0f9ff;
    classDef sasebo fill:#0d1c38,stroke:#3b82f6,stroke-width:1.8px,color:#ffffff;
    classDef misawa fill:#1e1b4b,stroke:#6366f1,stroke-width:1.8px,color:#e0e7ff;
    classDef pearl fill:#042f2e,stroke:#14b8a6,stroke-width:2px,color:#ffffff;
    classDef kaneohe fill:#1a0f37,stroke:#a855f7,stroke-width:1.5px,color:#f3e8ff;

    subgraph JPN["<b>🇯🇵 v1.x — Japan Military Installation Series (Beta &amp; Hardening)</b>"]
        direction LR
        Y["<b>v1.0.x — Yokosuka</b><br/><i>Active Baseline</i><br/>• 5-Phase Bundle &amp; AMI Flow<br/>• 9-Engine Air-Gapped Suite<br/>• Markdown POA&amp;M &amp; JSON"]:::yokosuka
        S["<b>v1.2.0 — Sasebo</b><br/><i>Workstation Portability</i><br/>• Multi-OS (macOS/Linux/WSL2)<br/>• Rootless/UID Volume Fix<br/>• ./grc doctor Pre-Flight<br/>• Pinned Deterministic Docker"]:::sasebo
        M["<b>v1.3.0 — Misawa</b><br/><i>External Telemetry Ingest</i><br/>• Tenable CSV Parser<br/>• AWS Inspector CSV Parser<br/>• Cross-Scanner Deduplication<br/>• Official FedRAMP POA&amp;M .xlsx"]:::misawa
        Y --> S --> M
    end

    subgraph HWI["<b>🌺 v2.x — Hawaiian Military Base Cities Series (Full Production GA)</b>"]
        direction LR
        P["<b>v2.0.0 — Pearl Harbor</b><br/><i>Production GA Launch</i><br/>• Cloud Lift (AWS EC2 &amp; Bottlerocket)<br/>• Helm Chart Compliance Engine<br/>• Air-Gapped Local LLM Baseline<br/>  (Gemma / GPT-OSS Synthesis)"]:::pearl
        K["<b>v2.1.0+ — Kaneohe / Wahiawa</b><br/><i>Adaptive Scale &amp; OSCAL</i><br/>• Dynamic Endpoint RAM Profiler<br/>  for Multi-Tier LLM Sizing<br/>• NIST OSCAL 1.1.x API Export<br/>• Cosign / SLSA Attestation"]:::kaneohe
        P --> K
    end

    M ==>|"GA Graduation"| P

    style JPN fill:#051326,stroke:#0284c7,stroke-width:1.5px,color:#38bdf8
    style HWI fill:#041c16,stroke:#10b981,stroke-width:2px,color:#34d399
```

---

## 2. Near-Term `v1.x` Minor Releases (🇯🇵 Japan Series)

### ⚓ `v1.2.0 — Sasebo`: Universal Workstation Portability & Clone-and-Run Hardening

* **Operational Problem**: Currently, the pipeline includes workstation-specific assumptions (e.g., Apple Silicon `Darwin ARM64` defaults, Docker Desktop for Mac volume ownership translation, root-owned container outputs on Linux hosts, and unpinned `curl | sh` installer scripts in `Dockerfile.scanner`). When another engineer or assessor clones the repository from GitHub onto an Intel Mac, Ubuntu/RHEL workstation, Fedora with Podman, or Windows WSL2, these differences can cause immediate build or runtime failures.
* **Planned Code & Architecture Changes in `v1.2.0 — Sasebo`**:
  1. **Container UID/GID Ownership Synchronization (`--user $(id -u):$(id -g)`)**: On native Linux hosts, containers running as `root` write `evidence/` files owned by `root:root`, locking out the host user during `grc report` or cleanup. `Sasebo` passes host UID/GID context and configures writable scratch caches (`/tmp/.cache`) so `semgrep`, `checkov`, `syft`, `grype`, and `trivy` run cleanly as non-root across Linux, macOS, and WSL2.
  2. **Deterministic, Version-Pinned `Dockerfile.scanner`**: Replaces floating `main/install.sh` downloads for Syft, Grype, Trivy, Semgrep, and Checkov with version-pinned, SHA-256-verified multi-arch (`linux/amd64` and `linux/arm64`) binary releases—preventing upstream breaking changes when a new user runs `./grc docker-build`.
  3. **Container Runtime Agnosticism (Docker Desktop, Colima, Rancher Desktop, Podman & Linux Engine)**: Replaces macOS-specific Docker daemon checks in `./grc` with a portable runtime detector supporting standard `docker` and rootless `podman`.
  4. **SELinux / AppArmor Volume Mount Compatibility (`:ro,Z`)**: Detects SELinux-enforcing Linux hosts (RHEL, Fedora, Rocky Linux) and automatically applies proper mount labels so container scanners are not blocked with `Permission denied` when reading `/workspace` or writing `/evidence`.
  5. **Pre-Flight Environment Diagnostic (`./grc doctor`) & Dynamic Host Detection**: Adds a `./grc doctor` command that verifies `git`, `python3` ($\ge 3.9$), container daemon status, disk space, and architecture, while dynamically detecting host OS/CPU in `./grc fetch` instead of hardcoding `Darwin ARM64`.

---

### 🛩️ `v1.3.0 — Misawa`: Tenable & AWS Inspector CSV Ingestion $\rightarrow$ Official FedRAMP POA&M Spreadsheet

* **Operational Problem**: Beyond static Git bundle and cold-mounted AMI analysis, security teams and 3PAOs rely on continuous vulnerability exports from **Tenable (Nessus / Tenable.sc / Tenable.io)** and **Amazon Inspector**. Manually merging these CSV exports with static scan findings into the rigid **official FedRAMP Plan of Action and Milestones (POA&M) Excel workbook (`.xlsx`)** is slow and error-prone.
* **Planned Capabilities in `v1.3.0 — Misawa`**:
  1. **Multi-Source CSV Ingestion Engine (`scripts/grc_ingest.py` / `./grc ingest`)**:
     * Parses standard **Tenable CSV** exports (Plugin ID, CVE, CVSS v3, Severity, Host/Asset, Plugin Output, Solution) and **AWS Inspector CSV** exports (Finding ARN, Vulnerability ID, ECR/EC2 Resource ID, Package Manager, Fix Available).
  2. **Cross-Scanner Normalization & Deduplication**:
     * Correlates external CSV findings with internal Phase 3 outputs (`grype_findings.json`, `trivy_findings.json`, `semgrep_findings.json`, `oscap_results.xml`) so shared CVEs are consolidated into single POA&M weaknesses with an aggregated affected-asset inventory.
  3. **Official FedRAMP POA&M `.xlsx` Workbook Generator**:
     * Populates the official FedRAMP POA&M spreadsheet layout (Weakness Name, Original Detection Date, Source Identifier, Asset Identifier, Scheduled Completion Date based on 30/60/90-day FedRAMP SLAs, Milestone with Completion Dates, and Vendor Dependency tracking) alongside `poam_data.md` and `scr_scn_package.json`.
* **Target CLI Interface**:
  ```bash
  ./grc ingest \
    --tenable /path/to/tenable_vulnerabilities.csv \
    --inspector /path/to/aws_inspector_export.csv \
    --evidence ./evidence/release-v1.3.0 \
    --export-fedramp-xlsx
  ```

---

## 3. Full Production GA Launch: `v2.0.0 — Pearl Harbor` (🌺 Hawaiian Series)

Following the portability hardening of `Sasebo` (`v1.2.0`) and the external CSV/FedRAMP `.xlsx` pipeline in `Misawa` (`v1.3.0`), **`v2.0.0 — Pearl Harbor`** marks the pipeline's graduation to **Full Production General Availability (GA)**.

### Pillar 1: Cloud-Hosted Enclave Execution (`AWS EC2` & `AWS Bottlerocket`)

* **Operational Goal**: Lift the pipeline from a strictly local auditor workstation tool to an automated, cloud-hosted compliance worker running inside **AWS Commercial** and **AWS GovCloud (IL4–IL6)** enclaves.
* **Planned Implementation**:
  * **Hardened AWS EC2 Worker Blueprint**: Terraform and CloudFormation deployment modules provisioning a STIG-hardened EC2 scanner worker with least-privilege IAM instance profiles (`ec2:CreateVolume`, `ec2:AttachVolume`, `ec2:DetachVolume`, `ec2:DeleteVolume`, and scoped KMS decrypt permissions) to perform real-time, in-region EBS snapshot cold-mounts (`./grc ami`).
  * **AWS Bottlerocket Immutable Host Support**: Native container orchestration profile for **AWS Bottlerocket**—running the `grc-scanner` suite atop an immutable, minimal, SELinux-enforcing OS purpose-built for hosting containers with transactional updates and no SSH/shell attack surface.
  * **Zero-Internet VPC Endpoint Operation**: Executes inside private VPC subnets using S3 and EC2 VPC Endpoints, preserving the pipeline's `--network none` air-gap posture during Phase 3 scanning.

---

### Pillar 2: Helm Chart Compliance Engine (`./grc scan --engine helm`)

* **Operational Goal**: Extend Phase 3 Infrastructure-as-Code compliance auditing (`AOC-07`, `AOC-11`, `AOC-140`) to natively render and audit **Kubernetes Helm charts** before cluster deployment.
* **Planned Implementation**:
  * **Offline Helm Template Rendering**: Automatically discovers `Chart.yaml` hierarchies inside restored Git bundles, renders effective Kubernetes manifests offline (`helm template`) across default `values.yaml` and environment override files (`values-prod.yaml`), and audits both raw templates and rendered manifests.
  * **DISA Kubernetes STIG & NSA/CISA Hardening Checks**:
    * Flags privileged pods (`privileged: true`), root container execution (`runAsNonRoot: false`), and missing `seccompProfile` / `readOnlyRootFilesystem` security contexts.
    * Detects unpinned container image tags (`:latest` vs. immutable `@sha256:` digests), missing CPU/memory resource limits (`SC-6`), missing `NetworkPolicy` isolation (`SC-7`), and plaintext secrets in `values.yaml` (`SC-12`, `SC-28`).

---

### Pillar 3: Air-Gapped Local LLM Compliance Synthesis (`Gemma` / `GPT-OSS` Baseline)

* **Operational Goal**: Eliminate manual analyst bottlenecks when drafting FedRAMP POA&M weakness descriptions, code-context remediation steps, and milestone schedules—while strictly maintaining a **100% offline, air-gapped (`--network none`)** security posture where zero CUI or vulnerability data ever leaves the host or cloud enclave.
* **Planned Implementation in `v2.0.0 — Pearl Harbor`**:
  * **Bundled Offline Open-Weights Inference (`./grc report --ai-enrich`)**: Integrates an air-gapped local inference runtime running a baseline quantized **Google `Gemma`** or **`GPT-OSS`** model directly inside the compliance worker environment.
  * **Automated Narrative & Remediation Generation**: Translates normalized scanner JSON and ingested Tenable/Inspector CSV rows into 3PAO-ready FedRAMP POA&M weakness narratives, remediation steps, and false-positive justification drafts.
  * *(Note: Dynamic endpoint RAM profiling to automatically scale between 2B, 9B, and 27B+ model quantizations based on available host memory is slated for **`v2.1.0 — Kaneohe`**).*

---

## 4. Post-GA `v2.x` Roadmap (`Kaneohe` & `Wahiawa`)

### 🌺 `v2.1.0 — Kaneohe`: Dynamic Endpoint RAM-Adaptive LLM Scaling & NIST OSCAL

* **Hardware-Aware RAM Profiler for Local LLMs (`Gemma` / `GPT-OSS`)**:
  * Introduces automatic host memory & accelerator inspection (`sysctl hw.memsize` on macOS, `/proc/meminfo` on Linux/EC2/Bottlerocket) so `./grc` dynamically selects the optimal quantized model tier based on the endpoint's RAM configuration:
    * **`< 8 GB RAM`**: Deterministic rule-based template fallback (zero LLM memory overhead).
    * **`8 GB – 16 GB RAM`**: Lightweight quantized tier (`Gemma-2B` / `Gemma-4B Q4_K_M`) for laptops and small EC2 workers.
    * **`16 GB – 32 GB RAM`**: Balanced tier (`Gemma-9B` / `GPT-OSS-8B Q5_K_M`) for pro workstations and standard cloud workers.
    * **`32 GB – 64 GB+ RAM`**: Deep-reasoning tier (`Gemma-27B` / `GPT-OSS-20B+ Q8_0`) for high-memory EC2 instances, generating comprehensive 3PAO deviation requests and multi-control impact analyses.
* **NIST OSCAL 1.1.x Machine Export**: Emits standardized OSCAL Assessment Results (`assessment-results.json`) and OSCAL POA&M (`poam.json`) payloads alongside `scr_scn_package.json` for direct eMASS API ingestion.

---

## 5. Master Release Milestone Schedule

| Release Version | Codename | Series Theme | Primary Focus & Key Deliverables | Status |
| :--- | :--- | :--- | :--- | :--- |
| **`v1.0.0` – `v1.0.4`** | **`Yokosuka`** | 🇯🇵 Japan *(Beta)* | • 5-phase Out-of-Band Git `.bundle` and AWS AMI cold-mount lifecycle<br/>• 9-engine air-gapped scanner suite & 37 custom Semgrep AST rules<br/>• Phase 4 Markdown & JSON synthesis (`poam_data.md`, `controls.md`, `scr_scn_package.json`) | ✅ **Active Baseline** |
| **`v1.2.0`** | **`Sasebo`** | 🇯🇵 Japan *(Beta)* | • **Universal Workstation Portability**: Out-of-the-box compatibility across macOS (`arm64`/`amd64`), Linux, and Windows WSL2<br/>• Non-root UID/GID container volume mapping & SELinux/Podman compatibility<br/>• Deterministic version-pinned `Dockerfile.scanner` & `./grc doctor` pre-flight check | 🎯 **Next Up (`v1.2`)** |
| **`v1.3.0`** | **`Misawa`** | 🇯🇵 Japan *(Beta)* | • **Tenable & AWS Inspector CSV Ingest (`./grc ingest`)**<br/>• Cross-scanner CVE deduplication & asset correlation<br/>• Automated generation of the **official FedRAMP POA&M Excel spreadsheet (`.xlsx`)** | 🗓️ **Planned (`v1.3`)** |
| **`v2.0.0`** | **`Pearl Harbor`** | 🌺 Hawaii *(GA)* | • **Full Production GA Launch**<br/>• **Cloud-Hosted Execution** on **AWS EC2** and **AWS Bottlerocket** container hosts<br/>• **Helm Chart Compliance Engine (`./grc scan --engine helm`)** with offline template rendering<br/>• **Air-Gapped Local LLM Baseline (`Gemma` / `GPT-OSS`)** for POA&M narrative synthesis | 🚧 **Planned (`v2.0` GA)** |
| **`v2.1.0`** | **`Kaneohe`** | 🌺 Hawaii *(GA)* | • **RAM-Adaptive Local LLM Profiler**: Dynamic `Gemma` / `GPT-OSS` model selection (`2B` $\rightarrow$ `27B+`) dictated by endpoint RAM configuration<br/>• **NIST OSCAL 1.1.x Export** & release-to-release delta comparison (`./grc diff`) | 🗓️ **Post-GA Backlog** |
| **`v2.2.0`** | **`Wahiawa`** | 🌺 Hawaii *(GA)* | • **Cosign / Sigstore & SLSA v1.0 Provenance Gate** in Phase 1<br/>• Direct OCI container image tarball auditing (`./grc image`) | 🗓️ **Post-GA Backlog** |

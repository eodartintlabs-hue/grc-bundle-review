#!/usr/bin/env bash
# scan_orchestrator.sh - Automated Container Scan Orchestrator
# Executes all containerized security scanners against /workspace and saves reports in /evidence.
# ==============================================================================================

set -euo pipefail

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
RULES_DIR="${RULES_DIR:-/rules}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"

mkdir -p "${EVIDENCE_DIR}"

echo "=========================================================="
echo "  GRC Bundle Review: Containerized Security Scan Suite"
echo "=========================================================="
echo "Target Workspace:  ${WORKSPACE_DIR}"
echo "Evidence Output:   ${EVIDENCE_DIR}"
echo "=========================================================="

# ------------------------------------------------------------------------------
# 1. Semgrep SAST Analysis (AOC 02–140)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [1/6] Running Semgrep SAST against custom baseline ruleset..."
if [[ -f "${RULES_DIR}/custom-baseline-ruleset.yaml" ]]; then
    semgrep scan \
        --config="${RULES_DIR}/custom-baseline-ruleset.yaml" \
        --json \
        --output="${EVIDENCE_DIR}/semgrep_findings.json" \
        "${WORKSPACE_DIR}" || true
    echo "    -> Semgrep findings saved to: ${EVIDENCE_DIR}/semgrep_findings.json"
else
    echo "[WARN] Semgrep custom baseline ruleset not found in ${RULES_DIR}."
fi

# ------------------------------------------------------------------------------
# 2. Gitleaks Secret & Token Detection (AOC 02, AOC 06)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [2/6] Running Gitleaks secret detection..."
gitleaks dir "${WORKSPACE_DIR}" \
    --report-format json \
    --report-path "${EVIDENCE_DIR}/gitleaks_findings.json" \
    --exit-code 0 || true
echo "    -> Gitleaks findings saved to: ${EVIDENCE_DIR}/gitleaks_findings.json"

# ------------------------------------------------------------------------------
# 3. Checkov Infrastructure-as-Code (IaC) Scanning (AOC 07)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [3/6] Running Checkov IaC security analysis..."
checkov -d "${WORKSPACE_DIR}" \
    --output json \
    --output-file-path "${EVIDENCE_DIR}" \
    --soft-fail || true
if [[ -f "${EVIDENCE_DIR}/results_json.json" ]]; then
    mv "${EVIDENCE_DIR}/results_json.json" "${EVIDENCE_DIR}/checkov_findings.json"
fi
echo "    -> Checkov findings saved to: ${EVIDENCE_DIR}/checkov_findings.json"

# ------------------------------------------------------------------------------
# 4. Syft Software Bill of Materials (SBOM) Generation (AOC 08)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [4/6] Generating CycloneDX SBOM via Syft..."
syft dir:"${WORKSPACE_DIR}" \
    -o cyclonedx-json="${EVIDENCE_DIR}/sbom.cdx.json" || true
echo "    -> CycloneDX SBOM generated at: ${EVIDENCE_DIR}/sbom.cdx.json"

# ------------------------------------------------------------------------------
# 5. Grype Dependency Vulnerability Analysis (AOC 10)
# ------------------------------------------------------------------------------
echo ""
echo "[*] [5/6] Scanning SBOM for CVE vulnerabilities via Grype..."
if [[ -f "${EVIDENCE_DIR}/sbom.cdx.json" ]]; then
    grype sbom:"${EVIDENCE_DIR}/sbom.cdx.json" \
        -o json > "${EVIDENCE_DIR}/grype_findings.json" || true
    echo "    -> Grype CVE findings saved to: ${EVIDENCE_DIR}/grype_findings.json"
fi

# ------------------------------------------------------------------------------
# 6. Trivy Misconfiguration & Vulnerability Scan
# ------------------------------------------------------------------------------
echo ""
echo "[*] [6/6] Executing Trivy filesystem evaluation..."
trivy fs "${WORKSPACE_DIR}" \
    --format json \
    --output "${EVIDENCE_DIR}/trivy_findings.json" \
    --quiet || true
echo "    -> Trivy findings saved to: ${EVIDENCE_DIR}/trivy_findings.json"

echo ""
echo "[*] Formatting JSON evidence deliverables with indentation..."
for JSON_FILE in "${EVIDENCE_DIR}"/*.json; do
    if [[ -f "${JSON_FILE}" && -s "${JSON_FILE}" ]]; then
        python3 -m json.tool "${JSON_FILE}" "${JSON_FILE}.pretty" 2>/dev/null && mv "${JSON_FILE}.pretty" "${JSON_FILE}" || true
    fi
done

echo ""
echo "=========================================================="
echo "[SUCCESS] Containerized security scanning complete."
echo "All evidence files written to: ${EVIDENCE_DIR}"
echo "=========================================================="

#!/usr/bin/env bash
# scan_orchestrator.sh - Automated Container Scan Orchestrator
# Executes containerized security scanners against /workspace and saves reports in /evidence.
# Supports running the full suite (all) or any individual engine on demand.
# ==============================================================================================

set -euo pipefail

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
RULES_DIR="${RULES_DIR:-/rules}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
TARGET_ENGINE="${1:-${SCAN_ENGINE:-all}}"

mkdir -p "${EVIDENCE_DIR}"

echo "=========================================================="
echo "  GRC Bundle Review: Containerized Security Scan Suite"
echo "=========================================================="
echo "Target Workspace:  ${WORKSPACE_DIR}"
echo "Evidence Output:   ${EVIDENCE_DIR}"
echo "Selected Engine:   ${TARGET_ENGINE}"
echo "Network Posture:   AIR-GAPPED (--network none)"
echo "=========================================================="

# Copy provenance manifest into evidence directory if present
if [[ -f "${WORKSPACE_DIR}/bundle_provenance.json" ]]; then
    cp -f "${WORKSPACE_DIR}/bundle_provenance.json" "${EVIDENCE_DIR}/bundle_provenance.json" || true
fi
if [[ -f "${WORKSPACE_DIR}/ami_provenance.json" ]]; then
    cp -f "${WORKSPACE_DIR}/ami_provenance.json" "${EVIDENCE_DIR}/ami_provenance.json" || true
fi

run_semgrep() {
    echo ""
    echo "[*] [Engine: semgrep] Running Semgrep SAST against custom baseline ruleset..."
    if [[ -f "${RULES_DIR}/custom-baseline-ruleset.yaml" ]]; then
        SEMGREP_SEND_METRICS=off semgrep scan \
            --config="${RULES_DIR}/custom-baseline-ruleset.yaml" \
            --metrics=off \
            --json \
            --output="${EVIDENCE_DIR}/semgrep_findings.json" \
            "${WORKSPACE_DIR}" || true
        echo "    -> Semgrep findings saved to: ${EVIDENCE_DIR}/semgrep_findings.json"
    else
        echo "[WARN] Semgrep custom baseline ruleset not found in ${RULES_DIR}."
    fi
}

run_gitleaks() {
    echo ""
    echo "[*] [Engine: gitleaks] Running Gitleaks secret & credential detection..."
    gitleaks dir "${WORKSPACE_DIR}" \
        --report-format json \
        --report-path "${EVIDENCE_DIR}/gitleaks_findings.json" \
        --exit-code 0 || true
    echo "    -> Gitleaks findings saved to: ${EVIDENCE_DIR}/gitleaks_findings.json"
}

run_checkov() {
    echo ""
    echo "[*] [Engine: checkov] Running Checkov IaC security analysis..."
    BC_SKIP_MAPPING=TRUE checkov -d "${WORKSPACE_DIR}" \
        --skip-download \
        --output json \
        --output-file-path "${EVIDENCE_DIR}" \
        --soft-fail || true
    if [[ -f "${EVIDENCE_DIR}/results_json.json" ]]; then
        mv "${EVIDENCE_DIR}/results_json.json" "${EVIDENCE_DIR}/checkov_findings.json"
    fi
    echo "    -> Checkov findings saved to: ${EVIDENCE_DIR}/checkov_findings.json"
}

run_syft() {
    echo ""
    echo "[*] [Engine: syft] Generating CycloneDX SBOM via Syft..."
    SYFT_CHECK_FOR_APP_UPDATE=false syft dir:"${WORKSPACE_DIR}" \
        -o cyclonedx-json="${EVIDENCE_DIR}/sbom.cdx.json" || true
    echo "    -> CycloneDX SBOM generated at: ${EVIDENCE_DIR}/sbom.cdx.json"
}

run_grype() {
    echo ""
    if [[ ! -f "${EVIDENCE_DIR}/sbom.cdx.json" ]]; then
        echo "[*] [Engine: grype] Prerequisite sbom.cdx.json not found; generating via Syft first..."
        run_syft
    fi
    echo "[*] [Engine: grype] Scanning SBOM for CVE vulnerabilities via Grype..."
    if [[ -f "${EVIDENCE_DIR}/sbom.cdx.json" ]]; then
        GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false grype sbom:"${EVIDENCE_DIR}/sbom.cdx.json" \
            -o json > "${EVIDENCE_DIR}/grype_findings.json" || true
        echo "    -> Grype CVE findings saved to: ${EVIDENCE_DIR}/grype_findings.json"
    fi
}

run_trivy() {
    echo ""
    echo "[*] [Engine: trivy] Executing Trivy filesystem evaluation..."
    trivy fs "${WORKSPACE_DIR}" \
        --offline-scan \
        --skip-db-update \
        --format json \
        --output "${EVIDENCE_DIR}/trivy_findings.json" \
        --quiet || true
    echo "    -> Trivy findings saved to: ${EVIDENCE_DIR}/trivy_findings.json"
}

run_oscap() {
    echo ""
    echo "[*] [Engine: oscap] Checking OpenSCAP XCCDF/OVAL evaluation readiness..."
    if command -v oscap >/dev/null 2>&1; then
        oscap --version | head -n 3 > "${EVIDENCE_DIR}/oscap_engine_info.txt" || true
        echo "    -> OpenSCAP engine verified. Ready for XCCDF profile evaluation."
    else
        echo "[WARN] oscap CLI binary not present in container."
    fi
}

case "${TARGET_ENGINE}" in
    all)
        run_semgrep
        run_gitleaks
        run_checkov
        run_syft
        run_grype
        run_trivy
        ;;
    semgrep)
        run_semgrep
        ;;
    gitleaks)
        run_gitleaks
        ;;
    checkov)
        run_checkov
        ;;
    syft)
        run_syft
        ;;
    grype)
        run_grype
        ;;
    trivy)
        run_trivy
        ;;
    oscap|openscap)
        run_oscap
        ;;
    *)
        echo "[ERROR] Unknown containerized engine: ${TARGET_ENGINE}"
        echo "Supported container engines: all, semgrep, gitleaks, checkov, syft, grype, trivy, oscap"
        exit 1
        ;;
esac

echo ""
echo "[*] Formatting JSON evidence deliverables with indentation..."
for JSON_FILE in "${EVIDENCE_DIR}"/*.json; do
    if [[ -f "${JSON_FILE}" && -s "${JSON_FILE}" ]]; then
        python3 -m json.tool "${JSON_FILE}" "${JSON_FILE}.pretty" 2>/dev/null && mv "${JSON_FILE}.pretty" "${JSON_FILE}" || true
    fi
done

echo ""
echo "=========================================================="
echo "[SUCCESS] Containerized security scanning complete (${TARGET_ENGINE})."
echo "All evidence files written to: ${EVIDENCE_DIR}"
echo "=========================================================="


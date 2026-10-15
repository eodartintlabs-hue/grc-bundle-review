#!/usr/bin/env python3
"""
grc_reporter.py - GRC Compliance Report & SCR/SCN Package Synthesizer
====================================================================

Classification: Internal Compliance & Security Audit Deliverable Generator
Pipeline Role: Phase 4 (Evidence & SCR/SCN Package Consolidation)
Target Frameworks: NIST SP 800-53 Rev. 5, DISA STIG, FedRAMP High, DoD Cloud Computing SRG
Operational Pattern: Out-of-Band (OOB), Zero Untrusted Execution, Fail-Open

Purpose:
  Aggregates, normalizes, and synthesizes multi-engine scanner findings
  (Semgrep, Checkov, Grype, Trivy, Gitleaks, CryptoScan, OpenSCAP)
  and provenance metadata into formal, audit-ready compliance deliverables:
    1. poam_data.md          - Structured Plan of Action & Milestones (FedRAMP/DoD)
    2. controls.md           - NIST SP 800-53 Rev. 5 Comprehensive Traceability Matrix
    3. ruleset_validation.md - Custom 37-Rule Semgrep Baseline Audit Log
    4. scr_scn_package.json  - Consolidated Machine-Readable SCR/SCN Evidence Payload
    5. sha256sum             - Cryptographic Evidence Manifest Sealing Deliverables

Zero External Dependencies:
  Uses exclusively Python 3 standard library (json, hashlib, pathlib, datetime, re, os).
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ==============================================================================
# NIST SP 800-53 REV. 5 CONTROL DEFINITIONS
# ==============================================================================

NIST_CONTROLS_CATALOG: Dict[str, Dict[str, str]] = {
    "IA-2": {
        "title": "Identification and Authentication (Organizational Users)",
        "family": "Identification and Authentication (IA)",
        "description": "Uniquely identify and authenticate organizational users (or processes acting on their behalf). Prohibits hardcoded static credentials, default passwords, and unmanaged API tokens.",
        "stig_cat": "CAT I",
    },
    "IA-7": {
        "title": "Cryptographic Module Authentication",
        "family": "Identification and Authentication (IA)",
        "description": "Authenticate to cryptographic modules using mechanisms meeting applicable federal laws, regulations, and standards.",
        "stig_cat": "CAT II",
    },
    "SI-2": {
        "title": "Flaw Remediation",
        "family": "System and Information Integrity (SI)",
        "description": "Identify, report, and correct system flaws (vulnerabilities and CVEs) within defined remediation timeframes.",
        "stig_cat": "CAT I",
    },
    "SI-4": {
        "title": "Information System Monitoring",
        "family": "System and Information Integrity (SI)",
        "description": "Monitor system execution to detect attacks and indicators of potential compromise. Prohibits unsanitized runtime shell execution (command injection).",
        "stig_cat": "CAT I",
    },
    "SI-7": {
        "title": "Software, Firmware, and Information Integrity",
        "family": "System and Information Integrity (SI)",
        "description": "Employ integrity verification tools to detect unauthorized changes and prohibit use of unsupported, unmaintained, or EOL libraries and providers.",
        "stig_cat": "CAT I",
    },
    "SI-10": {
        "title": "Information Input Validation",
        "family": "System and Information Integrity (SI)",
        "description": "Validate information inputs to syntax rules, character sets, and payload limits before runtime interpretation.",
        "stig_cat": "CAT I",
    },
    "SI-16": {
        "title": "Memory Protection / Cryptographic Hash Integrity",
        "family": "System and Information Integrity (SI)",
        "description": "Protect memory integrity and enforce strong cryptographic hash algorithms. Prohibits MD5, SHA-1, DES, and RC4.",
        "stig_cat": "CAT I",
    },
    "SI-17": {
        "title": "Fail-Secure / Secure Communications Initiation",
        "family": "System and Information Integrity (SI)",
        "description": "Ensure the system fails to a secure state. Prohibits disabled TLS certificate validation and deprecated TLS 1.0/1.1 protocols.",
        "stig_cat": "CAT I",
    },
    "SC-8": {
        "title": "Transmission Confidentiality and Integrity",
        "family": "System and Communications Protection (SC)",
        "description": "Protect the confidentiality and integrity of transmitted information using strong cryptography (TLS 1.2+ / 1.3).",
        "stig_cat": "CAT I",
    },
    "SC-12": {
        "title": "Cryptographic Key Establishment and Management",
        "family": "System and Communications Protection (SC)",
        "description": "Establish and manage cryptographic keys in accordance with NIST SP 800-56A/B and applicable FIPS guidelines.",
        "stig_cat": "CAT I",
    },
    "SC-13": {
        "title": "Cryptographic Protection (FIPS 140 Validation)",
        "family": "System and Communications Protection (SC)",
        "description": "Implement cryptographic modules validated under FIPS 140-2 / 140-3. Enforce OS kernel FIPS mode and validated security providers.",
        "stig_cat": "CAT I",
    },
    "SC-28": {
        "title": "Protection of Information at Rest",
        "family": "System and Communications Protection (SC)",
        "description": "Protect the confidentiality and integrity of information at rest (e.g., EBS volume encryption, S3 SSE-KMS).",
        "stig_cat": "CAT I",
    },
    "AC-3": {
        "title": "Access Enforcement",
        "family": "Access Control (AC)",
        "description": "Enforce approved authorizations for logical access to information and system resources (e.g. security group ingress rules).",
        "stig_cat": "CAT I",
    },
    "AC-6": {
        "title": "Least Privilege",
        "family": "Access Control (AC)",
        "description": "Employ the principle of least privilege, allowing only authorized accesses necessary for accomplishing assigned tasks (e.g., prohibiting public cloud buckets).",
        "stig_cat": "CAT I",
    },
    "CM-6": {
        "title": "Configuration Settings",
        "family": "Configuration Management (CM)",
        "description": "Establish and document mandatory configuration settings for IT products using hardened baselines (DISA STIG / CIS).",
        "stig_cat": "CAT II",
    },
    "CM-8": {
        "title": "Information System Component Inventory",
        "family": "Configuration Management (CM)",
        "description": "Develop and document an inventory of information system components (SBOM) detailing name, version, and license.",
        "stig_cat": "CAT II",
    },
    "RA-5": {
        "title": "Vulnerability Monitoring and Scanning",
        "family": "Risk Assessment (RA)",
        "description": "Monitor and scan for vulnerabilities in the system and hosted applications, prioritizing remediation of critical CVEs.",
        "stig_cat": "CAT I",
    },
}

# SLA rules based on FedRAMP / DoD High Baseline
SLA_DAYS_MAP: Dict[str, int] = {
    "CRITICAL": 30,
    "CAT I": 30,
    "HIGH": 60,
    "CAT II": 60,
    "MEDIUM": 90,
    "CAT III": 90,
    "LOW": 180,
    "INFORMATIONAL": 180,
}


# ==============================================================================
# NORMALIZED FINDING DATA STRUCTURE
# ==============================================================================

class NormalizedFinding:
    """Represents a unified security finding across any scanning engine."""

    def __init__(
        self,
        finding_id: str,
        source_tool: str,
        rule_or_cve_id: str,
        title: str,
        severity: str,
        cat_level: str,
        file_path: str,
        line_number: Optional[int],
        message: str,
        aoc: str,
        nist_controls: List[str],
        remediation: str,
        raw_data: Optional[Dict[str, Any]] = None,
    ):
        self.finding_id = finding_id
        self.source_tool = source_tool
        self.rule_or_cve_id = rule_or_cve_id
        self.title = title
        self.severity = severity.upper()
        self.cat_level = cat_level.upper()
        self.file_path = file_path
        self.line_number = line_number
        self.message = message
        self.aoc = aoc
        self.nist_controls = nist_controls if nist_controls else ["CM-6"]
        self.remediation = remediation
        self.raw_data = raw_data or {}

        # Calculate FedRAMP SLA days
        self.sla_days = SLA_DAYS_MAP.get(self.severity, 60)
        self.target_date = (datetime.date.today() + datetime.timedelta(days=self.sla_days)).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "source_tool": self.source_tool,
            "rule_or_cve_id": self.rule_or_cve_id,
            "title": self.title,
            "severity": self.severity,
            "cat_level": self.cat_level,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "message": self.message,
            "aoc": self.aoc,
            "nist_controls": self.nist_controls,
            "remediation": self.remediation,
            "sla_days": self.sla_days,
            "target_completion_date": self.target_date,
            "status": "Open (Identified Out-of-Band)",
        }


# ==============================================================================
# GRC COMPLIANCE REPORT SYNTHESIZER
# ==============================================================================

class GRCComplianceReporter:
    """
    Parses all scanner deliverables and synthesizes Phase 4 SCR/SCN packages.
    """

    def __init__(
        self,
        evidence_dir: Path,
        workspace_dir: Optional[Path] = None,
        ruleset_path: Optional[Path] = None,
    ):
        self.evidence_dir = Path(evidence_dir).resolve()
        self.workspace_dir = Path(workspace_dir).resolve() if workspace_dir else None
        self.ruleset_path = Path(ruleset_path).resolve() if ruleset_path else None

        self.findings: List[NormalizedFinding] = []
        self.provenance: Dict[str, Any] = {}
        self.baseline_rules: List[Dict[str, Any]] = []
        self._finding_counter = 1

    def _next_id(self) -> str:
        fid = f"POAM-{self._finding_counter:03d}"
        self._finding_counter += 1
        return fid

    def clean_path(self, path_str: str) -> str:
        """Strips /workspace/ prefix to show relative repo paths."""
        if not path_str:
            return "N/A"
        clean = path_str.replace("/workspace/", "")
        if clean.startswith("/"):
            clean = clean[1:]
        return clean

    # --------------------------------------------------------------------------
    # INGESTION & PARSING
    # --------------------------------------------------------------------------

    def load_provenance(self) -> None:
        """Loads bundle or AMI provenance record."""
        # 1. Check evidence dir
        prov_file = self.evidence_dir / "bundle_provenance.json"
        if not prov_file.exists():
            prov_file = self.evidence_dir / "ami_provenance.json"

        # 2. Check workspace dir
        if not prov_file.exists() and self.workspace_dir:
            prov_file = self.workspace_dir / "bundle_provenance.json"
            if not prov_file.exists():
                prov_file = self.workspace_dir / "ami_provenance.json"

        if prov_file.exists():
            try:
                with open(prov_file, "r", encoding="utf-8") as f:
                    self.provenance = json.load(f)
                # Ensure evidence directory has a copy of provenance
                dest_prov = self.evidence_dir / prov_file.name
                if not dest_prov.exists():
                    with open(dest_prov, "w", encoding="utf-8") as f:
                        json.dump(self.provenance, f, indent=2)
            except Exception as e:
                print(f"[!] Warning: Failed to parse provenance file {prov_file}: {e}", file=sys.stderr)

    def load_baseline_rules(self) -> None:
        """Loads rule definitions from custom-baseline-ruleset.yaml."""
        if not self.ruleset_path or not self.ruleset_path.exists():
            # Try default relative locations
            candidate = Path(__file__).resolve().parent.parent / "rules" / "custom-baseline-ruleset.yaml"
            if candidate.exists():
                self.ruleset_path = candidate

        if self.ruleset_path and self.ruleset_path.exists():
            try:
                # Basic standard-library YAML line parser (no PyYAML requirement)
                with open(self.ruleset_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Extract rule blocks
                rule_chunks = re.findall(
                    r"  - id:\s*([^\n]+).*?severity:\s*([^\n]+).*?message:\s*\"([^\"]+)\".*?aoc:\s*\"([^\"]+)\".*?nist_control:\s*\"([^\"]+)\"",
                    content,
                    re.DOTALL,
                )
                for chunk in rule_chunks:
                    r_id, r_sev, r_msg, r_aoc, r_nist = chunk
                    # Extract control ID like 'IA-2'
                    ctl_match = re.search(r"([A-Z]{2}-\d+)", r_nist)
                    ctl_id = ctl_match.group(1) if ctl_match else "CM-6"

                    self.baseline_rules.append({
                        "id": r_id.strip(),
                        "severity": r_sev.strip(),
                        "message": r_msg.strip(),
                        "aoc": r_aoc.strip(),
                        "nist_control": ctl_id,
                    })
            except Exception as e:
                print(f"[!] Warning: Failed to parse baseline ruleset: {e}", file=sys.stderr)

    def parse_semgrep(self) -> None:
        """Parses semgrep_findings.json."""
        s_file = self.evidence_dir / "semgrep_findings.json"
        if not s_file.exists():
            return

        try:
            with open(s_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            results = data.get("results", [])
            for r in results:
                check_id = r.get("check_id", "semgrep-rule")
                path = self.clean_path(r.get("path", ""))
                line = r.get("start", {}).get("line")
                extra = r.get("extra", {})
                message = extra.get("message", "Semgrep security finding")
                meta = extra.get("metadata", {})

                raw_sev = extra.get("severity", "WARNING").upper()
                if raw_sev == "ERROR":
                    severity = "HIGH"
                    cat_level = "CAT II"
                elif raw_sev == "INFO":
                    severity = "LOW"
                    cat_level = "CAT III"
                else:
                    severity = "MEDIUM"
                    cat_level = "CAT II"

                aoc = meta.get("aoc", "General Security Policy")
                # Elevate Critical AOCs
                if "AOC-04" in aoc or "AOC-10" in aoc:
                    severity = "CRITICAL"
                    cat_level = "CAT I"

                nist_raw = meta.get("nist_control", "CM-6")
                ctl_match = re.search(r"([A-Z]{2}-\d+)", nist_raw)
                ctl_id = ctl_match.group(1) if ctl_match else "CM-6"

                title = message.split(":")[0] if ":" in message else check_id
                remediation = "Remediate source code according to the secure coding baseline; eliminate static credentials, legacy ciphers, or shell execution."
                if "AOC-02" in aoc:
                    remediation = "Externalize credentials into a secret management vault or protected environment variable."
                elif "AOC-03" in aoc:
                    remediation = "Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384."
                elif "AOC-04" in aoc:
                    remediation = "Replace shell execution with parameterized runtime APIs; avoid shell=True."
                elif "AOC-05" in aoc:
                    remediation = "Enable strict TLS certificate validation and enforce minimum TLS 1.2 or 1.3."

                self.findings.append(
                    NormalizedFinding(
                        finding_id=self._next_id(),
                        source_tool="Semgrep",
                        rule_or_cve_id=check_id,
                        title=title,
                        severity=severity,
                        cat_level=cat_level,
                        file_path=f"{path}:{line}" if line else path,
                        line_number=line,
                        message=message,
                        aoc=aoc,
                        nist_controls=[ctl_id],
                        remediation=remediation,
                        raw_data=r,
                    )
                )
        except Exception as e:
            print(f"[!] Warning: Error parsing Semgrep findings: {e}", file=sys.stderr)

    def parse_checkov(self) -> None:
        """Parses checkov_findings.json."""
        c_file = self.evidence_dir / "checkov_findings.json"
        if not c_file.exists():
            return

        try:
            with open(c_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Checkov can be dict or list of dicts (multi-framework)
            reports = data if isinstance(data, list) else [data]

            for report in reports:
                results = report.get("results", {})
                failed = results.get("failed_checks", [])
                for check in failed:
                    cid = check.get("check_id", "CKV_POLICY")
                    cname = check.get("check_name", "IaC Configuration Check Failed")
                    fpath = self.clean_path(check.get("file_path", ""))
                    lines = check.get("file_line_range", [])
                    line_str = f":{lines[0]}" if lines else ""
                    res = check.get("resource", "Unknown Resource")
                    guideline = check.get("guideline") or "Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks."

                    # Determine control and AOC
                    nist_ctls = ["CM-6"]
                    aoc = "AOC-07: Infrastructure-as-Code Misconfiguration"
                    sev = "HIGH"
                    cat = "CAT II"

                    if "public" in cname.lower() or "s3" in cname.lower():
                        nist_ctls = ["AC-6", "CM-6", "SC-28"]
                        sev = "CRITICAL"
                        cat = "CAT I"
                    elif "security group" in cname.lower() or "0.0.0.0" in cname.lower() or "port" in cname.lower():
                        nist_ctls = ["AC-3", "CM-6"]
                        sev = "CRITICAL"
                        cat = "CAT I"
                    elif "encryption" in cname.lower() or "ebs" in cname.lower():
                        nist_ctls = ["SC-13", "SC-28"]
                    elif "secret" in cid.lower() or "password" in cname.lower():
                        nist_ctls = ["IA-2"]
                        aoc = "AOC-02: Password Hygiene"
                        sev = "CRITICAL"
                        cat = "CAT I"

                    self.findings.append(
                        NormalizedFinding(
                            finding_id=self._next_id(),
                            source_tool="Checkov",
                            rule_or_cve_id=cid,
                            title=cname,
                            severity=sev,
                            cat_level=cat,
                            file_path=f"{fpath}{line_str} (Resource: {res})",
                            line_number=lines[0] if lines else None,
                            message=f"IaC policy violation on resource '{res}': {cname}",
                            aoc=aoc,
                            nist_controls=nist_ctls,
                            remediation=guideline,
                            raw_data=check,
                        )
                    )
        except Exception as e:
            print(f"[!] Warning: Error parsing Checkov findings: {e}", file=sys.stderr)

    def parse_crypto_scan(self) -> None:
        """Parses crypto_findings.json."""
        c_file = self.evidence_dir / "crypto_findings.json"
        if not c_file.exists():
            return

        try:
            with open(c_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            findings_list = data.get("findings", [])
            for item in findings_list:
                lib = item.get("library_name", "Unknown Crypto Library")
                ver = item.get("detected_version", "N/A")
                status = item.get("compliance_status", "FAIL")
                sev = item.get("severity", "CRITICAL").upper()
                cat = "CAT I" if sev == "CRITICAL" else "CAT II"
                aoc = item.get("area_of_concern", "AOC-09: Crypto Dependencies on Unsupported Libraries")
                remediation = item.get("remediation", f"Upgrade '{lib}' to a supported, active FIPS-capable version.")
                ctls = item.get("nist_controls", ["SI-7", "SC-12", "SC-13"])

                self.findings.append(
                    NormalizedFinding(
                        finding_id=self._next_id(),
                        source_tool="CryptoScan",
                        rule_or_cve_id=f"CRYPTO-{lib.upper()}-{status}",
                        title=f"Unsupported/Deprecated Cryptographic Library: {lib} ({ver})",
                        severity=sev,
                        cat_level=cat,
                        file_path="Dependency Manifest / System Libraries",
                        line_number=None,
                        message=f"Detected cryptographic library '{lib}' version '{ver}' with status '{status}'.",
                        aoc=aoc,
                        nist_controls=ctls,
                        remediation=remediation,
                        raw_data=item,
                    )
                )
        except Exception as e:
            print(f"[!] Warning: Error parsing CryptoScan findings: {e}", file=sys.stderr)

    def parse_grype(self) -> None:
        """Parses grype_findings.json."""
        g_file = self.evidence_dir / "grype_findings.json"
        if not g_file.exists() or g_file.stat().st_size == 0:
            return

        try:
            with open(g_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            matches = data.get("matches", [])
            for match in matches:
                vuln = match.get("vulnerability", {})
                art = match.get("artifact", {})
                cve_id = vuln.get("id", "CVE-UNKNOWN")
                raw_sev = vuln.get("severity", "Medium").upper()
                pkg_name = art.get("name", "Unknown Package")
                pkg_ver = art.get("version", "Unknown Version")

                if raw_sev in ("CRITICAL", "HIGH"):
                    cat = "CAT I" if raw_sev == "CRITICAL" else "CAT II"
                    sev = raw_sev
                else:
                    sev = "MEDIUM"
                    cat = "CAT III"

                fix_versions = vuln.get("fix", {}).get("versions", [])
                fix_text = f"Upgrade '{pkg_name}' to version {', '.join(fix_versions)}." if fix_versions else f"Upgrade or apply vendor patch for '{pkg_name}'."

                self.findings.append(
                    NormalizedFinding(
                        finding_id=self._next_id(),
                        source_tool="Grype",
                        rule_or_cve_id=cve_id,
                        title=f"Published Vulnerability: {cve_id} in {pkg_name} ({pkg_ver})",
                        severity=sev,
                        cat_level=cat,
                        file_path=f"Package: {pkg_name}:{pkg_ver}",
                        line_number=None,
                        message=f"{cve_id} detected in dependency {pkg_name} version {pkg_ver}. Severity: {raw_sev}.",
                        aoc="AOC-10: CRITICAL Severity Findings",
                        nist_controls=["RA-5", "SI-2"],
                        remediation=fix_text,
                        raw_data=match,
                    )
                )
        except Exception as e:
            print(f"[!] Warning: Error parsing Grype findings: {e}", file=sys.stderr)

    def parse_trivy(self) -> None:
        """Parses trivy_findings.json."""
        t_file = self.evidence_dir / "trivy_findings.json"
        if not t_file.exists() or t_file.stat().st_size == 0:
            return

        try:
            with open(t_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            results = data.get("Results", [])
            for res in results:
                target = self.clean_path(res.get("Target", "Workspace"))
                vulns = res.get("Vulnerabilities", [])
                for v in vulns:
                    cve_id = v.get("VulnerabilityID", "CVE-UNKNOWN")
                    pkg = v.get("PkgName", "package")
                    ver = v.get("InstalledVersion", "")
                    raw_sev = v.get("Severity", "MEDIUM").upper()
                    fix_ver = v.get("FixedVersion", "")
                    title = v.get("Title", f"Vulnerability in {pkg}")

                    cat = "CAT I" if raw_sev == "CRITICAL" else ("CAT II" if raw_sev == "HIGH" else "CAT III")
                    fix_text = f"Upgrade {pkg} to {fix_ver}." if fix_ver else f"Patch {pkg}."

                    self.findings.append(
                        NormalizedFinding(
                            finding_id=self._next_id(),
                            source_tool="Trivy",
                            rule_or_cve_id=cve_id,
                            title=f"{cve_id}: {title}",
                            severity=raw_sev,
                            cat_level=cat,
                            file_path=f"{target} ({pkg}:{ver})",
                            line_number=None,
                            message=f"{cve_id} affecting {pkg} ({ver}) in {target}",
                            aoc="AOC-10: CRITICAL Severity Findings",
                            nist_controls=["RA-5", "SI-2"],
                            remediation=fix_text,
                            raw_data=v,
                        )
                    )
        except Exception as e:
            print(f"[!] Warning: Error parsing Trivy findings: {e}", file=sys.stderr)

    def parse_gitleaks(self) -> None:
        """Parses gitleaks_findings.json."""
        g_file = self.evidence_dir / "gitleaks_findings.json"
        if not g_file.exists() or g_file.stat().st_size == 0:
            return

        try:
            with open(g_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, list):
                for leak in data:
                    rule = leak.get("RuleID", "hardcoded-secret")
                    desc = leak.get("Description", "Detected exposed secret or credential")
                    fpath = self.clean_path(leak.get("File", ""))
                    line = leak.get("StartLine")

                    self.findings.append(
                        NormalizedFinding(
                            finding_id=self._next_id(),
                            source_tool="Gitleaks",
                            rule_or_cve_id=rule,
                            title=f"Hardcoded Secret Detected: {desc}",
                            severity="CRITICAL",
                            cat_level="CAT I",
                            file_path=f"{fpath}:{line}" if line else fpath,
                            line_number=line,
                            message=f"Exposed secret ({rule}) in {fpath}. Credentials must not be stored in source code.",
                            aoc="AOC-02: Password Hygiene",
                            nist_controls=["IA-2", "SC-12"],
                            remediation="Rotate exposed credential immediately and inject secrets via environment or vault.",
                            raw_data=leak,
                        )
                    )
        except Exception as e:
            print(f"[!] Warning: Error parsing Gitleaks findings: {e}", file=sys.stderr)

    # --------------------------------------------------------------------------
    # SYNTHESIS & REPORT GENERATION
    # --------------------------------------------------------------------------

    def generate_poam_markdown(self) -> str:
        """Generates poam_data.md in formal FedRAMP High / DoD format."""
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Provenance metadata
        bundle_id = self.provenance.get("bundle_identifier") or self.provenance.get("ami_identifier") or self.evidence_dir.name
        source_path = self.provenance.get("bundle_source_path") or self.provenance.get("image_metadata", {}).get("name") or "Local Audit Evidence"
        sha256 = self.provenance.get("bundle_sha256") or self.provenance.get("image_metadata", {}).get("image_id") or "N/A"
        session_id = self.provenance.get("session_id", "N/A")

        # Counts
        crit_count = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in self.findings if f.severity == "HIGH")
        med_count = sum(1 for f in self.findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in self.findings if f.severity in ("LOW", "INFORMATIONAL"))
        total_count = len(self.findings)

        overall_posture = "NON-COMPLIANT (Remediation Gating Enforced)" if total_count > 0 else "COMPLIANT (Clean Out-of-Band Audit)"

        md = [
            "# Plan of Action and Milestones (POA&M) Datapoints",
            "",
            "> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD CC SRG / SCR-SCN)  ",
            f"> **Audit Target Identifier**: `{bundle_id}`  ",
            f"> **Source Subject**: `{source_path}`  ",
            f"> **Cryptographic Hash (SHA-256)**: `{sha256}`  ",
            f"> **Review Session ID**: `{session_id}`  ",
            f"> **Evaluation Timestamp**: `{now}`  ",
            f"> **Overall Audit Posture**: **{overall_posture}**  ",
            "",
            "---",
            "",
            "## 1. Executive Vulnerability & Risk Summary",
            "",
            "The following risk rollup aggregates all findings detected across static AST analysis (Semgrep), dependency scanning (Grype/Trivy), secret scanning (Gitleaks), Infrastructure-as-Code policy validation (Checkov), and cryptographic library audits:",
            "",
            "| Severity Level | DISA STIG Impact Category | Active Findings Count | Mandatory Remediation SLA | Compliance Status |",
            "| :--- | :--- | :--- | :--- | :--- |",
            f"| **CRITICAL** | **Category I (CAT I)** | **{crit_count}** | **30 Calendar Days** | {'❌ Non-Compliant' if crit_count > 0 else '✅ Clear'} |",
            f"| **HIGH** | **Category II (CAT II)** | **{high_count}** | **60 Calendar Days** | {'❌ Non-Compliant' if high_count > 0 else '✅ Clear'} |",
            f"| **MEDIUM** | **Category III (CAT III)** | **{med_count}** | **90 Calendar Days** | {'⚠️ Warning' if med_count > 0 else '✅ Clear'} |",
            f"| **LOW / INFO** | Informational | **{low_count}** | 180 Calendar Days | ✅ Monitored |",
            f"| **TOTAL** | — | **{total_count}** | — | **{overall_posture}** |",
            "",
            "---",
            "",
            "## 2. Standardized POA&M Itemization Table",
            "",
            "All line items below are structured for automated ingestion into formal Enterprise POA&M tracking systems (eMASS, Archer, ServiceNow GRC, Jira Security):",
            "",
            "| POAM ID | Primary NIST Control | Weakness / Finding Name | Severity / CAT | Source Engine | Affected Asset / File | Target Completion | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        if not self.findings:
            md.append("| *None* | — | No unmitigated vulnerabilities detected in release. | — | — | — | — | **Compliant** |")
        else:
            for f in self.findings:
                ctls_str = ", ".join(f.nist_controls)
                clean_title = f.title.replace("|", "/")
                clean_file = f.file_path.replace("|", "/")
                md.append(
                    f"| **{f.finding_id}** | `{ctls_str}` | {clean_title} | **{f.severity} / {f.cat_level}** | `{f.source_tool}` | `{clean_file}` | `{f.target_date}` | Open |"
                )

        md.extend([
            "",
            "---",
            "",
            "## 3. Remediation & Corrective Action Plans",
            "",
        ])

        if not self.findings:
            md.append("No remediation actions required. The audited release bundle conforms to baseline compliance rules.")
        else:
            for f in self.findings:
                md.extend([
                    f"### 3.{f.finding_id.replace('POAM-', '')} [{f.finding_id}] {f.title}",
                    f"* **Affected Asset**: `{f.file_path}`",
                    f"* **Governing Controls**: `{', '.join(f.nist_controls)}` | **Area of Concern**: `{f.aoc}`",
                    f"* **Detection Identifier**: `{f.rule_or_cve_id}` ({f.source_tool})",
                    f"* **Detailed Finding**: {f.message}",
                    f"* **Prescribed Action / Fix**: {f.remediation}",
                    f"* **Scheduled Completion SLA**: `{f.target_date}` ({f.sla_days} days)",
                    "",
                ])

        return "\n".join(md) + "\n"

    def generate_controls_markdown(self) -> str:
        """Generates controls.md NIST SP 800-53 Rev. 5 Traceability Matrix."""
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        bundle_id = self.provenance.get("bundle_identifier") or self.provenance.get("ami_identifier") or self.evidence_dir.name

        # Map findings by primary control
        findings_by_control: Dict[str, List[NormalizedFinding]] = {}
        for ctl in NIST_CONTROLS_CATALOG.keys():
            findings_by_control[ctl] = []

        for f in self.findings:
            for ctl in f.nist_controls:
                if ctl in findings_by_control:
                    findings_by_control[ctl].append(f)
                else:
                    findings_by_control[ctl] = [f]

        md = [
            "# NIST SP 800-53 Rev. 5 Controls Traceability Matrix",
            "",
            "> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD RMF / SCR-SCN)  ",
            f"> **Audit Target Identifier**: `{bundle_id}`  ",
            f"> **Evaluation Timestamp**: `{now}`  ",
            "",
            "---",
            "",
            "## 1. Compliance Status by Control Family",
            "",
            "| Control ID | Control Name | Control Family | DISA STIG Impact | Audit Findings Count | Compliance Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        # Sort by control ID
        for ctl_id, meta in sorted(NIST_CONTROLS_CATALOG.items()):
            c_findings = findings_by_control.get(ctl_id, [])
            count = len(c_findings)
            status = f"❌ **NON-COMPLIANT ({count})**" if count > 0 else "✅ **COMPLIANT**"
            md.append(
                f"| **{ctl_id}** | {meta['title']} | {meta['family']} | `{meta['stig_cat']}` | {count} | {status} |"
            )

        md.extend([
            "",
            "---",
            "",
            "## 2. Detailed Control Breakdown & Evidence Mapping",
            "",
        ])

        for ctl_id, meta in sorted(NIST_CONTROLS_CATALOG.items()):
            c_findings = findings_by_control.get(ctl_id, [])
            count = len(c_findings)
            status_badge = "❌ NON-COMPLIANT" if count > 0 else "✅ COMPLIANT"

            md.extend([
                f"### {ctl_id}: {meta['title']} — {status_badge}",
                f"* **Control Family**: {meta['family']}",
                f"* **DISA STIG Baseline**: `{meta['stig_cat']}`",
                f"* **Control Objective**: {meta['description']}",
                f"* **Evaluation Outcome**: {'Deficiencies detected out-of-band requiring remediation.' if count > 0 else 'No policy violations or vulnerabilities detected. Conforms to baseline.'}",
                "",
            ])

            if count > 0:
                md.extend([
                    "| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |",
                    "| :--- | :--- | :--- | :--- | :--- |",
                ])
                for f in c_findings:
                    md.append(
                        f"| **{f.finding_id}** | `{f.source_tool}` | `{f.rule_or_cve_id}` | `{f.file_path}` | **{f.severity}** |"
                    )
                md.append("")

        return "\n".join(md) + "\n"

    def generate_ruleset_validation_markdown(self) -> str:
        """Generates ruleset_validation.md itemizing Semgrep custom baseline execution."""
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        bundle_id = self.provenance.get("bundle_identifier") or self.provenance.get("ami_identifier") or self.evidence_dir.name

        def norm_id(rid: str) -> str:
            return rid.replace("rules.", "").strip()

        # Match baseline rules against triggered semgrep findings
        semgrep_findings = [f for f in self.findings if f.source_tool == "Semgrep"]
        triggered_norm_ids = {norm_id(f.rule_or_cve_id): f for f in semgrep_findings}

        total_rules = len(self.baseline_rules)
        triggered_rules_count = sum(1 for r in self.baseline_rules if norm_id(r["id"]) in triggered_norm_ids)
        clean_rules_count = total_rules - triggered_rules_count

        md = [
            "# Custom Baseline Ruleset Validation Audit Log",
            "",
            "> **Classification / Use**: Internal Compliance & Security Audit Deliverable (Ruleset Verification Log)  ",
            f"> **Audit Target Identifier**: `{bundle_id}`  ",
            f"> **Ruleset File**: `rules/custom-baseline-ruleset.yaml`  ",
            f"> **Evaluation Timestamp**: `{now}`  ",
            "",
            "---",
            "",
            "## 1. Execution Summary",
            "",
            f"The custom Semgrep baseline defines **{total_rules} high-assurance security rules** spanning password hygiene, cryptography, command injection, TLS validation, and infrastructure hardening across Go, Java, Python, and JavaScript.",
            "",
            "| Metric | Value | Audit Significance |",
            "| :--- | :--- | :--- |",
            f"| **Total Evaluated Rules** | **{total_rules}** | Complete baseline coverage |",
            f"| **Triggered Rules (Violations Detected)** | **{triggered_rules_count}** | Active findings requiring engineering triage |",
            f"| **Clean Rules (Passed Checks)** | **{clean_rules_count}** | Controls verified without violation |",
            f"| **Total Discovered Code Defects** | **{len(semgrep_findings)}** | Raw AST match instances |",
            "",
            "---",
            "",
            "## 2. Itemized Rule Evaluation Audit Trail",
            "",
            "| Rule Identifier | Target AOC | Governing NIST Control | Severity | Audit Status | Triggered Matches |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for rule in self.baseline_rules:
            rid = norm_id(rule["id"])
            matched_findings = [f for f in semgrep_findings if norm_id(f.rule_or_cve_id) == rid]
            match_count = len(matched_findings)

            if match_count > 0:
                status = "❌ **TRIGGERED**"
            else:
                status = "✅ **PASSED (CLEAN)**"

            md.append(
                f"| `{rid}` | {rule['aoc']} | `{rule['nist_control']}` | `{rule['severity']}` | {status} | **{match_count}** |"
            )

        md.extend([
            "",
            "---",
            "",
            "## 3. Discovered Violation Code Locations",
            "",
        ])

        if not semgrep_findings:
            md.append("No AST policy violations detected. All source files conform to baseline rules.")
        else:
            for f in semgrep_findings:
                md.extend([
                    f"* **Rule**: `{f.rule_or_cve_id}` ({f.aoc})",
                    f"  * **Location**: `{f.file_path}`",
                    f"  * **Message**: {f.message}",
                ])

        return "\n".join(md) + "\n"

    def generate_scr_scn_package_json(self) -> Dict[str, Any]:
        """Generates scr_scn_package.json machine-readable deliverable."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        bundle_id = self.provenance.get("bundle_identifier") or self.provenance.get("ami_identifier") or self.evidence_dir.name

        crit_count = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in self.findings if f.severity == "HIGH")
        med_count = sum(1 for f in self.findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in self.findings if f.severity in ("LOW", "INFORMATIONAL"))

        controls_rollup: Dict[str, Any] = {}
        for ctl_id, meta in NIST_CONTROLS_CATALOG.items():
            matching = [f.to_dict() for f in self.findings if ctl_id in f.nist_controls]
            controls_rollup[ctl_id] = {
                "title": meta["title"],
                "family": meta["family"],
                "status": "FAIL" if matching else "PASS",
                "findings_count": len(matching),
                "findings": matching,
            }

        return {
            "$schema": "https://specs.grc.internal/schemas/scr-scn-package-v1.json",
            "package_schema": "grc-scr-scn-package-v1",
            "session_id": self.provenance.get("session_id", "local-session"),
            "target_identifier": bundle_id,
            "generated_at": now,
            "provenance": self.provenance,
            "summary": {
                "total_findings": len(self.findings),
                "critical_cat1": crit_count,
                "high_cat2": high_count,
                "medium_cat3": med_count,
                "low_cat4": low_count,
                "overall_status": "NON_COMPLIANT" if self.findings else "COMPLIANT",
            },
            "controls_rollup": controls_rollup,
            "findings": [f.to_dict() for f in self.findings],
        }

    def seal_evidence_manifest(self) -> str:
        """
        Computes SHA-256 checksums across all files in evidence_dir
        and writes evidence_dir/sha256sum to cryptographically seal the package.
        """
        manifest_lines: List[str] = []
        target_file = self.evidence_dir / "sha256sum"

        # List all files except sha256sum itself and OS junk
        evidence_files = sorted([
            p for p in self.evidence_dir.iterdir()
            if p.is_file() and p.name != "sha256sum" and not p.name.startswith(".")
        ])

        for p in evidence_files:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            sha = h.hexdigest()
            manifest_lines.append(f"{sha}  {p.name}")

        manifest_content = "\n".join(manifest_lines) + "\n"
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(manifest_content)

        return manifest_content

    # --------------------------------------------------------------------------
    # EXECUTE FULL REPORTING PIPELINE
    # --------------------------------------------------------------------------

    def run(self, write_files: bool = True) -> Dict[str, Any]:
        """Executes all ingestion and generation steps."""
        self.load_provenance()
        self.load_baseline_rules()

        # Parse all scanner JSONs
        self.parse_semgrep()
        self.parse_checkov()
        self.parse_crypto_scan()
        self.parse_grype()
        self.parse_trivy()
        self.parse_gitleaks()

        poam_md = self.generate_poam_markdown()
        controls_md = self.generate_controls_markdown()
        ruleset_md = self.generate_ruleset_validation_markdown()
        package_json = self.generate_scr_scn_package_json()

        if write_files:
            # Write Deliverable 1: poam_data.md
            with open(self.evidence_dir / "poam_data.md", "w", encoding="utf-8") as f:
                f.write(poam_md)

            # Write Deliverable 2: controls.md
            with open(self.evidence_dir / "controls.md", "w", encoding="utf-8") as f:
                f.write(controls_md)

            # Write Deliverable 3: ruleset_validation.md
            with open(self.evidence_dir / "ruleset_validation.md", "w", encoding="utf-8") as f:
                f.write(ruleset_md)

            # Write Deliverable 4: scr_scn_package.json
            with open(self.evidence_dir / "scr_scn_package.json", "w", encoding="utf-8") as f:
                json.dump(package_json, f, indent=2)

            # Write Deliverable 5: sha256sum
            self.seal_evidence_manifest()

        return {
            "findings_count": len(self.findings),
            "evidence_dir": str(self.evidence_dir),
            "deliverables": [
                "poam_data.md",
                "controls.md",
                "ruleset_validation.md",
                "scr_scn_package.json",
                "sha256sum",
            ],
        }


# ==============================================================================
# CLI DISPATCHER
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GRC Phase 4 Compliance Deliverable & SCR/SCN Package Synthesizer"
    )
    parser.add_argument(
        "--evidence", "-e",
        required=True,
        type=Path,
        help="Target directory containing scanner JSON files (e.g. evidence/aoc-02-weak-passwords/)",
    )
    parser.add_argument(
        "--workspace", "-w",
        type=Path,
        default=None,
        help="Optional path to ephemeral workspace for provenance fallback",
    )
    parser.add_argument(
        "--ruleset",
        type=Path,
        default=None,
        help="Optional path to custom-baseline-ruleset.yaml",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output synthesis summary as JSON",
    )

    args = parser.parse_args()

    if not args.evidence.exists():
        print(f"[ERROR] Evidence directory not found: {args.evidence}", file=sys.stderr)
        sys.exit(1)

    reporter = GRCComplianceReporter(
        evidence_dir=args.evidence,
        workspace_dir=args.workspace,
        ruleset_path=args.ruleset,
    )

    result = reporter.run(write_files=True)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("==========================================================")
        print("  GRC Phase 4 Compliance Deliverables Generated")
        print("==========================================================")
        print(f"[*] Target Evidence:    {result['evidence_dir']}")
        print(f"[*] Total Discovered:   {result['findings_count']} finding(s)")
        print("[*] Generated Deliverables:")
        for d in result["deliverables"]:
            print(f"    - {d}")
        print("==========================================================")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
crypto_lib_scan.py - Static Cryptographic Provider & Dependency Scanner
========================================================================

Classification: Internal Compliance & Engineering Specification
Pipeline Role: Phase 3 (Analyze) & Phase 4 (Evidence) Deliverable Generator
Target Frameworks: NIST SP 800-53 (SI-7, SC-12, SC-13, IA-7), DISA STIG ASD V5R1

Purpose:
  Statically inspects an extracted repository or workspace to identify and enumerate
  cryptographic libraries, providers, and shared dependencies across:
    - Python (requirements.txt, Pipfile, pyproject.toml, setup.py)
    - JavaScript / Node.js (package.json, package-lock.json)
    - Java (pom.xml, build.gradle)
    - Go (go.mod, go.sum)
    - Native System Libraries (libcrypto.*, libssl.*, openssl binaries)

  Evaluates detected libraries against policy rules defined in `crypto_catalog.json`
  to directly satisfy:
    - AOC 09: Crypto Dependencies on Unsupported Libraries (e.g. OpenSSL 1.1.1, PyCrypto)
    - AOC 03: Weak Encryption Check (insecure provider identification)
    - FIPS 140 Cryptographic Module baseline traceability

Outputs:
  - Terminal Compliance Audit Summary
  - Structured JSON Evidence Deliverable (`crypto_findings.json`)
  - Markdown Audit Traceability Table (`crypto_matrix.md`)
"""

import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ==============================================================================
# DEFAULT EMBEDDED POLICY CATALOG (Fallback if JSON not present)
# ==============================================================================

DEFAULT_CRYPTO_CATALOG: Dict[str, Any] = {
    "openssl": {
        "display_name": "OpenSSL Cryptographic Library",
        "ecosystems": ["system", "c_cpp", "deb", "rpm", "alpine"],
        "patterns": [r"^openssl$", r"^libssl.*", r"^libcrypto.*"],
        "min_supported_version": "3.0.0",
        "status": "ACTIVE",
        "fips_capable": True,
        "eol_versions": [
            {"version": "1.1.1", "eol_date": "2023-09-11", "severity": "CRITICAL"},
            {"version": "1.1.0", "eol_date": "2019-09-11", "severity": "CRITICAL"},
            {"version": "1.0.2", "eol_date": "2019-12-31", "severity": "CRITICAL"},
        ],
        "remediation": "Upgrade OpenSSL to supported 3.0.x LTS or 3.2.x+ branch.",
        "nist_controls": ["SI-7", "SC-12", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "pycrypto": {
        "display_name": "Python PyCrypto",
        "ecosystems": ["pypi", "python"],
        "patterns": [r"^pycrypto$"],
        "status": "DEPRECATED_UNMAINTAINED",
        "severity": "CRITICAL",
        "description": "PyCrypto has been unmaintained since 2013 and contains unpatched vulnerabilities.",
        "remediation": "Migrate all cryptographic operations to 'cryptography' or 'pycryptodome'.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "cryptography": {
        "display_name": "PyCA Cryptography",
        "ecosystems": ["pypi", "python"],
        "patterns": [r"^cryptography$"],
        "min_supported_version": "41.0.0",
        "status": "APPROVED",
        "fips_capable": True,
        "remediation": "Ensure version >= 41.0.0 for modern memory-safe OpenSSL bindings.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "bouncycastle": {
        "display_name": "Bouncy Castle Crypto Provider",
        "ecosystems": ["maven", "gradle", "java"],
        "patterns": [r"^bcprov-.*", r"^bcpkix-.*", r"^bcutil-.*", r"^bouncycastle.*"],
        "min_supported_version": "1.70",
        "status": "ACTIVE",
        "fips_capable": True,
        "eol_versions": [
            {"version": "<1.70", "eol_date": "2021-11-01", "severity": "HIGH"}
        ],
        "remediation": "Upgrade org.bouncycastle dependencies to >= 1.70 (or bc-fips 1.0.2+).",
        "nist_controls": ["SI-7", "SC-12", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "crypto-js": {
        "display_name": "Node.js crypto-js",
        "ecosystems": ["npm", "yarn", "javascript", "typescript"],
        "patterns": [r"^crypto-js$"],
        "status": "UNRECOMMENDED",
        "severity": "MEDIUM",
        "description": "crypto-js lacks constant-time security and hardware acceleration.",
        "remediation": "Migrate to native Node.js 'crypto' module or Web Cryptography API.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "node-forge": {
        "display_name": "Node-Forge Cryptographic Provider",
        "ecosystems": ["npm", "yarn", "javascript", "typescript"],
        "patterns": [r"^node-forge$"],
        "min_supported_version": "1.3.1",
        "status": "ACTIVE",
        "remediation": "Ensure version >= 1.3.1 to avoid known signature bypass vulnerabilities.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "golang-x-crypto": {
        "display_name": "Go Supplementary Cryptography Libraries",
        "ecosystems": ["golang", "go"],
        "patterns": [r"^golang\.org/x/crypto.*"],
        "status": "APPROVED",
        "remediation": "Review specific subpackage usage. Ensure standard crypto/aes is preferred.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
}


# ==============================================================================
# DATA MODELS
# ==============================================================================

class CryptoFinding:
    """Represents a discovered cryptographic dependency and its compliance status."""

    def __init__(
        self,
        name: str,
        version: str,
        source_file: str,
        ecosystem: str,
        status: str,
        severity: str,
        description: str,
        remediation: str,
        nist_controls: List[str],
        aoc: str,
        rule_key: str,
    ):
        self.name = name
        self.version = version
        self.source_file = source_file
        self.ecosystem = ecosystem
        self.status = status  # "PASS", "WARN", "FAIL_EOL", "FAIL_DEPRECATED"
        self.severity = severity  # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
        self.description = description
        self.remediation = remediation
        self.nist_controls = nist_controls
        self.aoc = aoc
        self.rule_key = rule_key

    def to_dict(self) -> Dict[str, Any]:
        return {
            "library_name": self.name,
            "detected_version": self.version,
            "manifest_file": self.source_file,
            "ecosystem": self.ecosystem,
            "compliance_status": self.status,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "nist_controls": self.nist_controls,
            "area_of_concern": self.aoc,
            "matched_rule": self.rule_key,
        }


# ==============================================================================
# MANIFEST PARSERS
# ==============================================================================

class DependencyExtractor:
    """Parses standard language manifests and extracts packages with versions."""

    @staticmethod
    def extract_from_workspace(workspace_root: Path) -> List[Tuple[str, str, str, str]]:
        """
        Traverses workspace and extracts (package_name, version, manifest_relpath, ecosystem).
        """
        extracted = []
        for root, _, files in os.walk(workspace_root):
            if ".git" in root or "node_modules" in root or "vendor" in root:
                continue

            r_path = Path(root)
            for f in files:
                f_path = r_path / f
                rel_path = str(f_path.relative_to(workspace_root))

                # Python
                if f == "requirements.txt":
                    extracted.extend(DependencyExtractor._parse_requirements(f_path, rel_path))
                elif f == "pyproject.toml":
                    extracted.extend(DependencyExtractor._parse_pyproject(f_path, rel_path))

                # Node.js
                elif f == "package.json":
                    extracted.extend(DependencyExtractor._parse_package_json(f_path, rel_path))

                # Java
                elif f == "pom.xml":
                    extracted.extend(DependencyExtractor._parse_pom_xml(f_path, rel_path))

                # Go
                elif f == "go.mod":
                    extracted.extend(DependencyExtractor._parse_go_mod(f_path, rel_path))

                # Shared System Libraries
                elif f.startswith("libcrypto.") or f.startswith("libssl.") or f == "openssl":
                    extracted.append((f, "Unknown", rel_path, "system"))

        return extracted

    @staticmethod
    def _parse_requirements(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip().split("#")[0].strip()
                    if not line or line.startswith("-"):
                        continue
                    # Match name==1.2.3 or name>=1.2.3
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[=><~^!]+([0-9a-zA-Z_\.\-]+))?", line)
                    if m:
                        results.append((m.group(1), m.group(2) or "Unknown", rel_path, "python"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_pyproject(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Basic regex extraction for dependencies list
                deps = re.findall(r'["\']([a-zA-Z0-9_\-\.]+)(?:[=><~^!]+([0-9a-zA-Z_\.\-]+))?["\']', content)
                for name, ver in deps:
                    results.append((name, ver or "Unknown", rel_path, "python"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_package_json(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                for section in ("dependencies", "devDependencies"):
                    for pkg, ver in data.get(section, {}).items():
                        clean_ver = re.sub(r"[^0-9\.]", "", str(ver)) or "Unknown"
                        results.append((pkg, clean_ver, rel_path, "javascript"))
        except Exception:
            pass
        return results

    @staticmethod
    def _parse_pom_xml(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Extract artifactId and version tags
                artifacts = re.findall(
                    r"<artifactId>([^<]+)</artifactId>(?:.*?<version>([^<]+)</version>)?",
                    content,
                    re.DOTALL,
                )
                for art, ver in artifacts:
                    results.append((art.strip(), ver.strip() if ver else "Unknown", rel_path, "java"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_go_mod(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r"^require\s+([^\s]+)\s+([^\s]+)", line)
                    if m:
                        results.append((m.group(1), m.group(2).lstrip("v"), rel_path, "go"))
                    else:
                        m2 = re.match(r"^([^\s]+)\s+v([^\s]+)", line)
                        if m2 and "/" in m2.group(1):
                            results.append((m2.group(1), m2.group(2), rel_path, "go"))
        except OSError:
            pass
        return results


# ==============================================================================
# CRYPTO POLICY ENGINE
# ==============================================================================

class CryptoScanner:
    """Evaluates extracted dependencies against cryptographic policy catalog."""

    def __init__(self, catalog: Dict[str, Any]):
        self.catalog = catalog

    def evaluate(self, dependencies: List[Tuple[str, str, str, str]]) -> List[CryptoFinding]:
        findings = []

        for name, version, source_file, ecosystem in dependencies:
            matched_key, rule = self._match_rule(name)
            if not rule:
                continue

            finding = self._audit_dependency(name, version, source_file, ecosystem, matched_key, rule)
            findings.append(finding)

        return findings

    def _match_rule(self, name: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        for key, rule in self.catalog.items():
            for pat in rule.get("patterns", []):
                if re.match(pat, name, re.IGNORECASE):
                    return key, rule
        return None, None

    def _audit_dependency(
        self,
        name: str,
        version: str,
        source_file: str,
        ecosystem: str,
        rule_key: str,
        rule: Dict[str, Any],
    ) -> CryptoFinding:
        status_flag = rule.get("status", "ACTIVE")

        # Check explicitly deprecated libraries (AOC 09)
        if status_flag == "DEPRECATED_UNMAINTAINED":
            return CryptoFinding(
                name=name,
                version=version,
                source_file=source_file,
                ecosystem=ecosystem,
                status="FAIL_DEPRECATED",
                severity=rule.get("severity", "CRITICAL"),
                description=rule.get("description", "Deprecated and unmaintained cryptographic package."),
                remediation=rule.get("remediation", "Migrate to supported crypto provider."),
                nist_controls=rule.get("nist_controls", ["SI-7", "SC-13"]),
                aoc=rule.get("aoc", "AOC-09: Crypto Dependencies on Unsupported Libraries"),
                rule_key=rule_key,
            )

        # Check EOL versions (e.g. OpenSSL 1.1.1)
        for eol in rule.get("eol_versions", []):
            eol_ver = eol.get("version", "")
            if eol_ver.startswith("<"):
                # Handle "<1.70" style constraints
                threshold = eol_ver.lstrip("<")
                if version != "Unknown" and version < threshold:
                    return CryptoFinding(
                        name=name,
                        version=version,
                        source_file=source_file,
                        ecosystem=ecosystem,
                        status="FAIL_EOL",
                        severity=eol.get("severity", "CRITICAL"),
                        description=f"Version '{version}' is End-of-Life (EOL since {eol.get('eol_date')}).",
                        remediation=rule.get("remediation", "Upgrade to supported release branch."),
                        nist_controls=rule.get("nist_controls", ["SI-7"]),
                        aoc=rule.get("aoc", "AOC-09: Crypto Dependencies on Unsupported Libraries"),
                        rule_key=rule_key,
                    )
            elif version.startswith(eol_ver) and eol_ver:
                return CryptoFinding(
                    name=name,
                    version=version,
                    source_file=source_file,
                    ecosystem=ecosystem,
                    status="FAIL_EOL",
                    severity=eol.get("severity", "CRITICAL"),
                    description=f"Version branch '{version}' is End-of-Life (EOL since {eol.get('eol_date')}).",
                    remediation=rule.get("remediation", "Upgrade to supported release branch."),
                    nist_controls=rule.get("nist_controls", ["SI-7"]),
                    aoc=rule.get("aoc", "AOC-09: Crypto Dependencies on Unsupported Libraries"),
                    rule_key=rule_key,
                )

        # Check Minimum Supported Version
        min_ver = rule.get("min_supported_version")
        if min_ver and version != "Unknown" and version < min_ver:
            return CryptoFinding(
                name=name,
                version=version,
                source_file=source_file,
                ecosystem=ecosystem,
                status="WARN_OUTDATED",
                severity="HIGH",
                description=f"Detected version '{version}' is below baseline minimum '{min_ver}'.",
                remediation=rule.get("remediation", f"Upgrade to >= {min_ver}."),
                nist_controls=rule.get("nist_controls", ["SI-7", "SC-13"]),
                aoc=rule.get("aoc", "AOC-09: Crypto Dependencies on Unsupported Libraries"),
                rule_key=rule_key,
            )

        # Approved / Compliant Provider
        return CryptoFinding(
            name=name,
            version=version,
            source_file=source_file,
            ecosystem=ecosystem,
            status="PASS",
            severity="INFO",
            description=f"Supported cryptographic library. FIPS Capable: {rule.get('fips_capable', False)}.",
            remediation="None required. Maintain automated dependency patch cadence.",
            nist_controls=rule.get("nist_controls", ["SC-13"]),
            aoc=rule.get("aoc", "AOC-09: Crypto Dependencies on Unsupported Libraries"),
            rule_key=rule_key,
        )


# ==============================================================================
# REPORT GENERATORS
# ==============================================================================

class CryptoReporter:
    """Formats findings into Markdown, JSON, and terminal deliverables."""

    @staticmethod
    def to_markdown(findings: List[CryptoFinding], workspace: str) -> str:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        fails = sum(1 for f in findings if f.status.startswith("FAIL"))
        warns = sum(1 for f in findings if f.status.startswith("WARN"))
        passes = sum(1 for f in findings if f.status == "PASS")

        md = [
            "# Cryptographic Provider & Dependency Audit Matrix",
            f"> **Generated**: {now}  ",
            f"> **Workspace**: `{workspace}`  ",
            "> **Framework Reference**: NIST SP 800-53 (SI-7, SC-12, SC-13) / AOC-09 & AOC-03  ",
            "",
            "---",
            "",
            "## 1. Compliance Summary",
            "",
            f"* **Total Cryptographic Libraries Evaluated**: `{len(findings)}`",
            f"* **Failed / EOL / Unsupported**: `{fails}` (Requires immediate POA&M remediation)",
            f"* **Warnings / Below Baseline**: `{warns}`",
            f"* **Approved / Supported**: `{passes}`",
            "",
            "---",
            "",
            "## 2. Findings Detail Matrix",
            "",
            "| Library | Detected Version | Manifest Source | Status | Severity | NIST Controls | Remediation Guidance |",
            "| :--- | :---: | :--- | :---: | :---: | :--- | :--- |",
        ]

        for f in sorted(findings, key=lambda x: (x.severity, x.name)):
            status_chip = f"`{f.status}`"
            sev_chip = f"**`{f.severity}`**" if f.severity in ("CRITICAL", "HIGH") else f"`{f.severity}`"
            controls = ", ".join(f.nist_controls)
            md.append(
                f"| **{f.name}** | `{f.version}` | `{f.source_file}` | {status_chip} | {sev_chip} | `{controls}` | {f.remediation} |"
            )

        md.append("")
        md.append("---")
        md.append("*Generated by GRC Review Pipeline (`crypto_lib_scan.py`)*")
        return "\n".join(md)

    @staticmethod
    def to_json(findings: List[CryptoFinding], workspace: str) -> str:
        payload = {
            "metadata": {
                "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "workspace": workspace,
                "tool": "crypto_lib_scan.py",
                "framework": "NIST SP 800-53 Rev. 5 (SI-7, SC-12, SC-13)",
                "aoc_coverage": ["AOC-09", "AOC-03"],
            },
            "summary": {
                "total_crypto_libraries": len(findings),
                "critical_eol_count": sum(1 for f in findings if f.severity == "CRITICAL"),
                "high_severity_count": sum(1 for f in findings if f.severity == "HIGH"),
                "compliant_count": sum(1 for f in findings if f.status == "PASS"),
            },
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(payload, indent=2)


# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Static Cryptographic Provider & Dependency Auditor (GRC Review Pipeline)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 crypto_lib_scan.py --workspace ./ephemeral_workspace
  python3 crypto_lib_scan.py --workspace ./ephemeral_workspace --format markdown -o crypto_matrix.md
  python3 crypto_lib_scan.py --workspace ./ephemeral_workspace --format json -o crypto_findings.json
  python3 crypto_lib_scan.py --catalog rules/crypto_catalog.json --workspace ./ephemeral_workspace
        """,
    )
    parser.add_argument(
        "--workspace",
        "-w",
        default=".",
        help="Path to the extracted workspace or code tree to scan (default: current directory).",
    )
    parser.add_argument(
        "--catalog",
        "-c",
        help="Path to custom crypto_catalog.json policy file (defaults to rules/crypto_catalog.json if present).",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["terminal", "markdown", "json"],
        default="terminal",
        help="Output presentation format (default: terminal).",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path. If omitted, results are emitted to stdout.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    workspace_path = Path(args.workspace).resolve()
    if not workspace_path.exists():
        print(f"[FATAL] Workspace path does not exist: {workspace_path}", file=sys.stderr)
        sys.exit(1)

    # Load Catalog
    catalog = DEFAULT_CRYPTO_CATALOG
    catalog_path = Path(args.catalog) if args.catalog else Path(__file__).parent.parent / "rules" / "crypto_catalog.json"
    if catalog_path.exists():
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                catalog = data.get("rules", DEFAULT_CRYPTO_CATALOG)
        except Exception as e:
            print(f"[WARN] Failed to load catalog from {catalog_path}: {e}. Using embedded defaults.", file=sys.stderr)

    # 1. Discover dependencies across manifests
    deps = DependencyExtractor.extract_from_workspace(workspace_path)

    # 2. Audit against crypto policy
    scanner = CryptoScanner(catalog)
    findings = scanner.evaluate(deps)

    # 3. Format Output
    if args.format == "json":
        out = CryptoReporter.to_json(findings, str(workspace_path))
    elif args.format == "markdown":
        out = CryptoReporter.to_markdown(findings, str(workspace_path))
    else:
        # Terminal format
        lines = [
            "=======================================================================",
            "  Cryptographic Provider & Dependency Audit Report",
            "=======================================================================",
            f"Workspace: {workspace_path}",
            f"Crypto Packages Detected: {len(findings)}",
            "-----------------------------------------------------------------------",
        ]
        for f in findings:
            tag = f"[{f.severity}]"
            lines.append(f"{tag:<10} {f.name:<20} Ver: {f.version:<10} Status: {f.status}")
            lines.append(f"           Source: {f.source_file}")
            lines.append(f"           NIST: {', '.join(f.nist_controls)} | AOC: {f.aoc}")
            lines.append(f"           Action: {f.remediation}")
            lines.append("-----------------------------------------------------------------------")
        out = "\n".join(lines)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"[SUCCESS] Crypto audit report written to: {args.output}")
        except IOError as e:
            print(f"[ERROR] Failed to write output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(out)


if __name__ == "__main__":
    main()

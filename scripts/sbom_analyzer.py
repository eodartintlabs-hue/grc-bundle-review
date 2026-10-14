#!/usr/bin/env python3
"""
sbom_analyzer.py - Software Bill of Materials (SBOM) to DISA STIG/SRG Mapping Engine
====================================================================================

Classification: Internal Compliance & Engineering Specification
Target Frameworks: DISA STIG, DoD SRG, NIST SP 800-53 Rev. 4/5, FedRAMP
Pipeline Role: Phase 3 (Analyze) & Phase 4 (Evidence) Deliverable Generator

Purpose:
  Parses Software Bill of Materials (SBOM) files in CycloneDX (JSON) or SPDX (JSON)
  formats, identifies software components, runtimes, dependencies, and OS packages,
  and maps them directly to applicable Defense Information Systems Agency (DISA)
  Security Technical Implementation Guides (STIGs) and Security Requirements Guides (SRGs).

Key Outputs:
  - STIG Applicability Matrix (Markdown / JSON / CSV)
  - CAT I / CAT II / CAT III Risk Surface Assessment
  - NIST SP 800-53 Traceability Matrix for POA&M / SCR-SCN Ingestion
"""

import argparse
import csv
import datetime
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


# ==============================================================================
# DISA STIG & SRG KNOWLEDGE BASE CATALOG
# ==============================================================================

DISA_STIG_CATALOG: Dict[str, Dict[str, Any]] = {
    # --------------------------------------------------------------------------
    # General Application & Development
    # --------------------------------------------------------------------------
    "ASD_STIG": {
        "id": "U_ASD_V5R1_STIG",
        "title": "Application Security and Development (ASD) STIG",
        "benchmark_id": "Application_Security_and_Development_STIG",
        "version": "Version 5, Release 1",
        "type": "STIG",
        "target_domain": "Application Software, Custom Code, Libraries & Frameworks",
        "nist_controls": ["SI-2", "SI-4", "SI-7", "SI-10", "SI-16", "SC-8", "SC-12", "SC-13", "IA-2", "AC-3"],
        "max_severity": "CAT I",
        "description": "Applies to custom developed applications, software frameworks, and application-level open source libraries.",
    },
    "GENERIC_APP_SRG": {
        "id": "U_Application_SRG_V3R1",
        "title": "Application Security Requirements Guide (SRG)",
        "benchmark_id": "Application_SRG",
        "version": "Version 3, Release 1",
        "type": "SRG",
        "target_domain": "Generic Software Applications",
        "nist_controls": ["AC-2", "AC-3", "AC-6", "AU-2", "IA-5", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Baseline security requirements for software applications where a technology-specific STIG does not exist.",
    },

    # --------------------------------------------------------------------------
    # Runtimes, Languages & Execution Environments
    # --------------------------------------------------------------------------
    "JAVA_JRE_STIG": {
        "id": "U_Java_Runtime_Environment_STIG",
        "title": "Java Runtime Environment (JRE) STIG",
        "benchmark_id": "Java_Runtime_Environment_STIG",
        "version": "Version 1, Release 4",
        "type": "STIG",
        "target_domain": "Java Virtual Machine, OpenJDK, Oracle JRE",
        "nist_controls": ["SC-13", "SI-2", "SI-7", "AC-3"],
        "max_severity": "CAT I",
        "description": "Applies to systems hosting Java runtimes, JVM instances, and Java application servers.",
    },
    "NODEJS_SRG": {
        "id": "U_NodeJS_Application_SRG",
        "title": "Node.js Application Platform SRG",
        "benchmark_id": "NodeJS_Platform_SRG",
        "version": "Version 1, Release 1",
        "type": "SRG",
        "target_domain": "Node.js Runtimes & Server-Side JavaScript",
        "nist_controls": ["SI-2", "SI-4", "SC-8", "AC-6"],
        "max_severity": "CAT I",
        "description": "Security guidance for Node.js execution environments and asynchronous runtime modules.",
    },
    "PYTHON_SRG": {
        "id": "U_Python_Runtime_SRG",
        "title": "Python Runtime and Interpreter Security Requirements",
        "benchmark_id": "Python_Interpreter_SRG",
        "version": "Version 1, Release 2",
        "type": "SRG",
        "target_domain": "Python 3 Interpreter, PyPI Ecosystem",
        "nist_controls": ["SI-2", "SI-7", "SC-12", "AU-3"],
        "max_severity": "CAT I",
        "description": "Security baselines governing Python interpreter deployments, virtual environments, and package managers.",
    },
    "DOTNET_STIG": {
        "id": "U_Microsoft_NET_Framework_STIG",
        "title": "Microsoft .NET Framework STIG",
        "benchmark_id": "Microsoft_NET_Framework_STIG",
        "version": "Version 2, Release 2",
        "type": "STIG",
        "target_domain": ".NET Core / .NET Framework Runtimes",
        "nist_controls": ["SI-2", "SI-7", "SC-13"],
        "max_severity": "CAT II",
        "description": "Guidance for deployments utilizing .NET Core and CLR runtimes.",
    },

    # --------------------------------------------------------------------------
    # Web, Proxy & Application Servers
    # --------------------------------------------------------------------------
    "APACHE_HTTP_STIG": {
        "id": "U_Apache_Server_2.4_Unix_STIG",
        "title": "Apache Server 2.4 UNIX STIG",
        "benchmark_id": "Apache_Server_2_4_Unix_STIG",
        "version": "Version 2, Release 4",
        "type": "STIG",
        "target_domain": "Apache HTTP Server (httpd)",
        "nist_controls": ["AC-3", "AC-17", "SC-8", "SI-2", "SI-17"],
        "max_severity": "CAT I",
        "description": "Security configuration standards for Apache HTTPD web servers.",
    },
    "NGINX_STIG": {
        "id": "U_NGINX_Web_Server_STIG",
        "title": "NGINX Web Server / Reverse Proxy STIG",
        "benchmark_id": "NGINX_Web_Server_STIG",
        "version": "Version 1, Release 1",
        "type": "STIG",
        "target_domain": "NGINX Ingress, Reverse Proxy, Web Server",
        "nist_controls": ["AC-3", "AC-17", "SC-8", "SI-2", "SI-17"],
        "max_severity": "CAT I",
        "description": "Security requirements for NGINX HTTP servers, reverse proxies, and ingress controllers.",
    },
    "TOMCAT_STIG": {
        "id": "U_Apache_Tomcat_Application_Server_STIG",
        "title": "Apache Tomcat Application Server 9 STIG",
        "benchmark_id": "Apache_Tomcat_9_STIG",
        "version": "Version 2, Release 2",
        "type": "STIG",
        "target_domain": "Tomcat Servlet Container",
        "nist_controls": ["AC-3", "IA-2", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Applies to Tomcat servlet engines and Java EE web applications.",
    },
    "WEB_SERVER_SRG": {
        "id": "U_Web_Server_SRG_V3R1",
        "title": "Web Server Security Requirements Guide (SRG)",
        "benchmark_id": "Web_Server_SRG",
        "version": "Version 3, Release 1",
        "type": "SRG",
        "target_domain": "Generic Web Servers & Ingress Proxies",
        "nist_controls": ["SC-8", "SC-13", "SI-2", "AC-17"],
        "max_severity": "CAT I",
        "description": "Baseline requirements for web service engines (Caddy, Traefik, Envoy, Lighttpd).",
    },

    # --------------------------------------------------------------------------
    # Database & Storage Systems
    # --------------------------------------------------------------------------
    "POSTGRESQL_STIG": {
        "id": "U_PostgreSQL_9.x_STIG",
        "title": "PostgreSQL Database STIG",
        "benchmark_id": "PostgreSQL_Database_STIG",
        "version": "Version 2, Release 3",
        "type": "STIG",
        "target_domain": "PostgreSQL RDBMS Engine & Client Libraries",
        "nist_controls": ["AC-3", "AU-2", "AU-12", "IA-2", "SC-8", "SC-13", "SI-2"],
        "max_severity": "CAT I",
        "description": "Covers PostgreSQL relational database instances and client connectivity drivers.",
    },
    "MYSQL_STIG": {
        "id": "U_MySQL_Server_STIG",
        "title": "MySQL 8.0 Database Server STIG",
        "benchmark_id": "MySQL_Database_STIG",
        "version": "Version 2, Release 1",
        "type": "STIG",
        "target_domain": "MySQL / MariaDB RDBMS",
        "nist_controls": ["AC-3", "AU-2", "IA-2", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Applies to MySQL and MariaDB database deployments.",
    },
    "MONGODB_STIG": {
        "id": "U_MongoDB_Enterprise_Advanced_STIG",
        "title": "MongoDB Enterprise Advanced STIG",
        "benchmark_id": "MongoDB_STIG",
        "version": "Version 1, Release 2",
        "type": "STIG",
        "target_domain": "MongoDB Document Database",
        "nist_controls": ["AC-3", "AU-2", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Security guidance for NoSQL document stores utilizing MongoDB.",
    },
    "DATABASE_SRG": {
        "id": "U_Database_SRG_V3R1",
        "title": "Database Security Requirements Guide (SRG)",
        "benchmark_id": "Database_SRG",
        "version": "Version 3, Release 1",
        "type": "SRG",
        "target_domain": "Generic RDBMS, In-Memory Stores (Redis, Memcached), SQLite",
        "nist_controls": ["AC-3", "AU-2", "SC-8", "SC-13", "SI-2"],
        "max_severity": "CAT I",
        "description": "Baseline requirements for data stores lacking a dedicated technology STIG.",
    },

    # --------------------------------------------------------------------------
    # Operating Systems & Container Runtimes
    # --------------------------------------------------------------------------
    "RHEL_9_STIG": {
        "id": "U_RHEL_9_STIG",
        "title": "Red Hat Enterprise Linux 9 STIG",
        "benchmark_id": "RHEL_9_STIG",
        "version": "Version 1, Release 2",
        "type": "STIG",
        "target_domain": "RHEL 9, CentOS Stream 9, AlmaLinux 9, Rocky Linux 9",
        "nist_controls": ["AC-2", "AC-3", "AU-2", "CM-6", "IA-2", "SC-8", "SC-13", "SI-2", "SI-7"],
        "max_severity": "CAT I",
        "description": "Operating system security baseline for Red Hat Enterprise Linux 9 family.",
    },
    "RHEL_8_STIG": {
        "id": "U_RHEL_8_STIG",
        "title": "Red Hat Enterprise Linux 8 STIG",
        "benchmark_id": "RHEL_8_STIG",
        "version": "Version 1, Release 12",
        "type": "STIG",
        "target_domain": "RHEL 8, CentOS 8, AlmaLinux 8, Rocky Linux 8",
        "nist_controls": ["AC-2", "AC-3", "AU-2", "CM-6", "IA-2", "SC-8", "SC-13", "SI-2", "SI-7"],
        "max_severity": "CAT I",
        "description": "Operating system security baseline for Red Hat Enterprise Linux 8 family.",
    },
    "UBUNTU_22_STIG": {
        "id": "U_Canonical_Ubuntu_22.04_LTS_STIG",
        "title": "Canonical Ubuntu 22.04 LTS STIG",
        "benchmark_id": "Ubuntu_22_04_LTS_STIG",
        "version": "Version 1, Release 1",
        "type": "STIG",
        "target_domain": "Ubuntu 22.04 LTS Operating System Base",
        "nist_controls": ["AC-2", "AC-3", "AU-2", "CM-6", "IA-2", "SC-8", "SC-13", "SI-2"],
        "max_severity": "CAT I",
        "description": "Security baseline for Canonical Ubuntu 22.04 LTS distributions.",
    },
    "CONTAINER_PLATFORM_SRG": {
        "id": "U_Container_Platform_SRG_V1R1",
        "title": "Container Platform Security Requirements Guide (SRG)",
        "benchmark_id": "Container_Platform_SRG",
        "version": "Version 1, Release 1",
        "type": "SRG",
        "target_domain": "Docker, containerd, Podman, Container Images (Alpine, Distroless)",
        "nist_controls": ["AC-3", "AC-6", "CM-2", "CM-6", "SC-8", "SI-2", "SI-4", "SI-7"],
        "max_severity": "CAT I",
        "description": "Security standards for container images, runtime isolation, and microservices hosts.",
    },
    "KUBERNETES_STIG": {
        "id": "U_Kubernetes_STIG",
        "title": "Kubernetes STIG",
        "benchmark_id": "Kubernetes_STIG",
        "version": "Version 1, Release 3",
        "type": "STIG",
        "target_domain": "Kubernetes Clusters, CoreDNS, Kubelet, Helm",
        "nist_controls": ["AC-2", "AC-3", "AU-2", "CM-6", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Security standards for Kubernetes container orchestration environments.",
    },

    # --------------------------------------------------------------------------
    # Cryptographic & Network Security Infrastructure
    # --------------------------------------------------------------------------
    "OPENSSL_CRYPTO_SRG": {
        "id": "U_FIPS_Cryptographic_Module_SRG",
        "title": "Cryptographic Module and Protocol Security SRG",
        "benchmark_id": "Crypto_Module_SRG",
        "version": "Version 2, Release 1",
        "type": "SRG",
        "target_domain": "OpenSSL, LibreSSL, BoringSSL, Cryptographic Providers",
        "nist_controls": ["SC-12", "SC-13", "SI-7", "IA-7"],
        "max_severity": "CAT I",
        "description": "Requirements for cryptographic libraries, FIPS 140 compliance, and key management.",
    },
    "OPENSSH_STIG": {
        "id": "U_OpenSSH_Server_and_Client_STIG",
        "title": "OpenSSH Server and Client STIG",
        "benchmark_id": "OpenSSH_STIG",
        "version": "Version 1, Release 1",
        "type": "STIG",
        "target_domain": "OpenSSH Client, Server, SFTP",
        "nist_controls": ["AC-17", "IA-2", "SC-8", "SC-13", "SI-2"],
        "max_severity": "CAT I",
        "description": "Applies to SSH remote access utilities and secure transport implementations.",
    },
}


# ==============================================================================
# COMPONENT TO STIG RESOLUTION RULES
# ==============================================================================

# Regex patterns mapping component names or prefixes to STIG keys
COMPONENT_NAME_MAP: List[Tuple[re.Pattern, str, str]] = [
    # Web & Application Servers
    (re.compile(r"^(nginx|nginx-core|nginx-full|openresty)$", re.I), "NGINX_STIG", "Reverse proxy and web server engine"),
    (re.compile(r"^(apache2|httpd|apache-http-server)$", re.I), "APACHE_HTTP_STIG", "Apache web server core service"),
    (re.compile(r"^(tomcat|apache-tomcat|tomcat-embed-.*)$", re.I), "TOMCAT_STIG", "Tomcat servlet and JSP execution engine"),
    (re.compile(r"^(caddy|traefik|envoy|haproxy)$", re.I), "WEB_SERVER_SRG", "Web ingress and edge routing proxy"),

    # Runtimes & Interpreters
    (re.compile(r"^(python|python3|cpython|pypy.*)$", re.I), "PYTHON_SRG", "Python runtime interpreter environment"),
    (re.compile(r"^(nodejs|node|node-js)$", re.I), "NODEJS_SRG", "Node.js JavaScript server runtime engine"),
    (re.compile(r"^(openjdk.*|java.*|jdk|jre|adoptium.*)$", re.I), "JAVA_JRE_STIG", "Java Virtual Machine (JVM) runtime"),
    (re.compile(r"^(dotnet.*|microsoft\.net.*)$", re.I), "DOTNET_STIG", ".NET runtime and core libraries"),

    # Databases & Caches
    (re.compile(r"^(postgresql.*|postgres.*|libpq.*)$", re.I), "POSTGRESQL_STIG", "PostgreSQL database engine and connection stack"),
    (re.compile(r"^(mysql.*|mariadb.*)$", re.I), "MYSQL_STIG", "MySQL/MariaDB relational database service"),
    (re.compile(r"^(mongodb.*|mongo)$", re.I), "MONGODB_STIG", "MongoDB document database engine"),
    (re.compile(r"^(redis.*|memcached|sqlite.*)$", re.I), "DATABASE_SRG", "In-memory cache or embedded database engine"),

    # Security & Cryptography Infrastructure
    (re.compile(r"^(openssl.*|libcrypto.*|libssl.*|boringssl.*|libressl.*)$", re.I), "OPENSSL_CRYPTO_SRG", "Cryptographic communications provider"),
    (re.compile(r"^(openssh.*|ssh)$", re.I), "OPENSSH_STIG", "SSH cryptographic terminal and transport tool"),

    # Container & Orchestration
    (re.compile(r"^(docker.*|containerd.*|podman|moby.*)$", re.I), "CONTAINER_PLATFORM_SRG", "Container virtualization and runtime service"),
    (re.compile(r"^(kubernetes.*|k8s.*|coredns|kubelet|helm)$", re.I), "KUBERNETES_STIG", "Kubernetes cluster orchestration component"),

    # OS Distros & Base Images
    (re.compile(r"^(rhel|redhat-release|centos.*|rocky.*|almalinux.*)$", re.I), "RHEL_9_STIG", "RHEL-derivative enterprise operating system base"),
    (re.compile(r"^(ubuntu.*|debian.*)$", re.I), "UBUNTU_22_STIG", "Debian/Ubuntu Linux operating system baseline"),
    (re.compile(r"^(alpine.*|distroless.*|busybox)$", re.I), "CONTAINER_PLATFORM_SRG", "Lightweight container operating system base image"),
]

# PURL (Package URL) ecosystem mappings
PURL_ECOSYSTEM_MAP: Dict[str, Tuple[str, str]] = {
    "pypi": ("ASD_STIG", "Python application dependency (PyPI)"),
    "npm": ("ASD_STIG", "JavaScript/TypeScript application dependency (npm)"),
    "maven": ("ASD_STIG", "Java ecosystem application dependency (Maven)"),
    "golang": ("ASD_STIG", "Go language application dependency (Go Modules)"),
    "nuget": ("ASD_STIG", ".NET ecosystem application dependency (NuGet)"),
    "cargo": ("ASD_STIG", "Rust language application dependency (Crates)"),
    "gem": ("ASD_STIG", "Ruby ecosystem application dependency (RubyGems)"),
    "deb": ("UBUNTU_22_STIG", "Debian/Ubuntu system package (dpkg)"),
    "rpm": ("RHEL_9_STIG", "RHEL/CentOS system package (RPM)"),
    "alpine": ("CONTAINER_PLATFORM_SRG", "Alpine Linux container package (apk)"),
}


# ==============================================================================
# DATA MODELS
# ==============================================================================

class Component:
    """Normalized representation of an SBOM component/package."""

    def __init__(
        self,
        name: str,
        version: str = "Unknown",
        purl: str = "",
        component_type: str = "library",
        supplier: str = "",
        license_str: str = "",
        description: str = "",
    ):
        self.name = name.strip()
        self.version = version.strip() if version else "Unknown"
        self.purl = purl.strip()
        self.component_type = component_type.strip().lower()
        self.supplier = supplier.strip()
        self.license_str = license_str.strip()
        self.description = description.strip()

    def get_ecosystem(self) -> Optional[str]:
        """Extracts the ecosystem/package manager from a PURL string."""
        if self.purl.startswith("pkg:"):
            parts = self.purl[4:].split("/")
            if parts:
                return parts[0].lower()
        return None

    def __repr__(self) -> str:
        return f"<Component {self.name}@{self.version} ({self.purl or self.component_type})>"


class STIGMapping:
    """Association between an SBOM component and an applicable DISA STIG/SRG."""

    def __init__(
        self,
        component: Component,
        stig_key: str,
        match_reason: str,
        match_type: str,
    ):
        self.component = component
        self.stig_key = stig_key
        self.stig_info = DISA_STIG_CATALOG.get(stig_key, {})
        self.match_reason = match_reason
        self.match_type = match_type  # "EXACT_NAME", "REGEX_NAME", "PURL_ECOSYSTEM", "FALLBACK"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_name": self.component.name,
            "component_version": self.component.version,
            "component_type": self.component.component_type,
            "purl": self.component.purl,
            "stig_id": self.stig_info.get("id", "UNKNOWN"),
            "stig_title": self.stig_info.get("title", "UNKNOWN"),
            "benchmark_id": self.stig_info.get("benchmark_id", "UNKNOWN"),
            "version": self.stig_info.get("version", "UNKNOWN"),
            "max_severity": self.stig_info.get("max_severity", "UNKNOWN"),
            "nist_controls": self.stig_info.get("nist_controls", []),
            "match_reason": self.match_reason,
            "match_type": self.match_type,
        }


# ==============================================================================
# SBOM PARSERS (CYCLONEDX & SPDX)
# ==============================================================================

class SBOMParser:
    """Parses CycloneDX and SPDX JSON SBOM documents into normalized Component objects."""

    @staticmethod
    def parse_file(file_path: str) -> List[Component]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"SBOM file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse SBOM JSON: {e}")

        # Detect format
        if "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
            return SBOMParser._parse_cyclonedx(data)
        elif "spdxVersion" in data:
            return SBOMParser._parse_spdx(data)
        elif "components" in data and isinstance(data["components"], list):
            # Fallback CycloneDX variant
            return SBOMParser._parse_cyclonedx(data)
        elif "packages" in data and isinstance(data["packages"], list):
            # Fallback SPDX variant
            return SBOMParser._parse_spdx(data)
        else:
            raise ValueError(
                "Unrecognized SBOM schema. File does not appear to be valid CycloneDX or SPDX JSON."
            )

    @staticmethod
    def _parse_cyclonedx(data: Dict[str, Any]) -> List[Component]:
        components: List[Component] = []

        # Top-level metadata component (if present)
        meta_component = data.get("metadata", {}).get("component")
        if meta_component and "name" in meta_component:
            components.append(
                Component(
                    name=meta_component.get("name", ""),
                    version=meta_component.get("version", ""),
                    purl=meta_component.get("purl", ""),
                    component_type=meta_component.get("type", "application"),
                    supplier=meta_component.get("supplier", {}).get("name", "")
                    if isinstance(meta_component.get("supplier"), dict)
                    else "",
                    description=meta_component.get("description", ""),
                )
            )

        # Child components
        for comp in data.get("components", []):
            name = comp.get("name", "").strip()
            if not name:
                continue

            licenses = []
            for lic in comp.get("licenses", []):
                if isinstance(lic, dict):
                    if "license" in lic and isinstance(lic["license"], dict):
                        licenses.append(lic["license"].get("name") or lic["license"].get("id", ""))
                    elif "expression" in lic:
                        licenses.append(lic["expression"])

            components.append(
                Component(
                    name=name,
                    version=comp.get("version", "Unknown"),
                    purl=comp.get("purl", ""),
                    component_type=comp.get("type", "library"),
                    supplier=comp.get("supplier", {}).get("name", "")
                    if isinstance(comp.get("supplier"), dict)
                    else "",
                    license_str=", ".join(filter(None, licenses)),
                    description=comp.get("description", ""),
                )
            )

        return components

    @staticmethod
    def _parse_spdx(data: Dict[str, Any]) -> List[Component]:
        components: List[Component] = []

        for pkg in data.get("packages", []):
            name = pkg.get("name", "").strip()
            if not name:
                continue

            # Extract PURL from externalRefs
            purl = ""
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator", "")
                    break

            supplier = pkg.get("supplier", "")
            if supplier.lower().startswith("person:") or supplier.lower().startswith("organization:"):
                supplier = supplier.split(":", 1)[1].strip()

            components.append(
                Component(
                    name=name,
                    version=pkg.get("versionInfo", "Unknown"),
                    purl=purl,
                    component_type="package",
                    supplier=supplier,
                    license_str=pkg.get("licenseConcluded", "") or pkg.get("licenseDeclared", ""),
                    description=pkg.get("description", "") or pkg.get("summary", ""),
                )
            )

        return components


# ==============================================================================
# DISA STIG ANALYZER & RESOLUTION ENGINE
# ==============================================================================

class STIGAnalyzer:
    """Maps analyzed SBOM components to the authoritative DISA STIG and SRG catalog."""

    def __init__(self, components: List[Component]):
        self.components = components
        self.mappings: List[STIGMapping] = []

    def analyze(self) -> List[STIGMapping]:
        self.mappings = []
        for comp in self.components:
            mapping = self._resolve_component(comp)
            self.mappings.append(mapping)
        return self.mappings

    def _resolve_component(self, comp: Component) -> STIGMapping:
        name_clean = comp.name.strip().lower()

        # Step 1: Match against specific component regular expressions
        for pattern, stig_key, reason in COMPONENT_NAME_MAP:
            if pattern.search(name_clean):
                return STIGMapping(
                    component=comp,
                    stig_key=stig_key,
                    match_reason=f"Direct component technology match: {reason}",
                    match_type="REGEX_NAME",
                )

        # Step 2: Match against PURL ecosystem
        ecosystem = comp.get_ecosystem()
        if ecosystem and ecosystem in PURL_ECOSYSTEM_MAP:
            stig_key, reason = PURL_ECOSYSTEM_MAP[ecosystem]
            return STIGMapping(
                component=comp,
                stig_key=stig_key,
                match_reason=f"Resolved via PURL ecosystem ({ecosystem}): {reason}",
                match_type="PURL_ECOSYSTEM",
            )

        # Step 3: Operating system indicators in component type
        if comp.component_type in ("operating-system", "os"):
            return STIGMapping(
                component=comp,
                stig_key="RHEL_9_STIG",
                match_reason="Operating system baseline requirement",
                match_type="TYPE_INFERENCE",
            )

        # Step 4: Container image indicators
        if comp.component_type in ("container", "container-image"):
            return STIGMapping(
                component=comp,
                stig_key="CONTAINER_PLATFORM_SRG",
                match_reason="Container image platform requirement",
                match_type="TYPE_INFERENCE",
            )

        # Step 5: Default Fallback to Application Security and Development STIG
        return STIGMapping(
            component=comp,
            stig_key="ASD_STIG",
            match_reason="Application dependency governed by General Application Security and Development (ASD) STIG",
            match_type="FALLBACK",
        )

    def generate_summary(self) -> Dict[str, Any]:
        stig_counts: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)
        nist_control_set: Set[str] = set()

        for m in self.mappings:
            stig_id = m.stig_info.get("id", "UNKNOWN")
            stig_counts[stig_id] += 1
            sev = m.stig_info.get("max_severity", "UNKNOWN")
            severity_counts[sev] += 1
            for c in m.stig_info.get("nist_controls", []):
                nist_control_set.add(c)

        return {
            "total_components": len(self.components),
            "unique_stigs_mapped": len(stig_counts),
            "stig_distribution": dict(sorted(stig_counts.items(), key=lambda x: x[1], reverse=True)),
            "severity_distribution": dict(severity_counts),
            "mapped_nist_controls": sorted(list(nist_control_set)),
        }


# ==============================================================================
# REPORT & DELIVERABLE GENERATORS
# ==============================================================================

class ReportGenerator:
    """Formats STIG applicability analyses into Markdown, JSON, Table, or CSV deliverables."""

    @staticmethod
    def to_markdown(
        mappings: List[STIGMapping],
        summary: Dict[str, Any],
        sbom_filename: str = "SBOM",
    ) -> str:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        md = []
        md.append("# DISA STIG & SRG Applicability Matrix")
        md.append(f"> **Generated**: {now}  ")
        md.append(f"> **Source SBOM**: `{os.path.basename(sbom_filename)}`  ")
        md.append("> **Classification / Use**: Internal Compliance & Security Audit Deliverable (SCR/SCN / FedRAMP / DoD)")
        md.append("")
        md.append("---")
        md.append("")

        # Executive Summary
        md.append("## 1. Executive Summary")
        md.append("")
        md.append(f"* **Total SBOM Components Evaluated**: `{summary['total_components']}`")
        md.append(f"* **Applicable DISA STIGs / SRGs Identified**: `{summary['unique_stigs_mapped']}`")
        md.append(f"* **CAT I Critical Requirements Surface**: `{summary['severity_distribution'].get('CAT I', 0)}` components")
        md.append(f"* **CAT II Medium Requirements Surface**: `{summary['severity_distribution'].get('CAT II', 0)}` components")
        md.append("")

        # STIG Distribution Table
        md.append("### 1.1 STIG Applicability Catalog")
        md.append("")
        md.append("| Benchmark ID | STIG / SRG Title | Version | Max Severity | Mapped Components |")
        md.append("| :--- | :--- | :--- | :---: | :---: |")

        for stig_id, count in summary["stig_distribution"].items():
            # Find matching catalog info
            info = next((v for v in DISA_STIG_CATALOG.values() if v["id"] == stig_id), {})
            title = info.get("title", stig_id)
            ver = info.get("version", "N/A")
            sev = info.get("max_severity", "N/A")
            md.append(f"| `{stig_id}` | **{title}** | {ver} | `{sev}` | **{count}** |")

        md.append("")
        md.append("---")
        md.append("")

        # NIST Control Traceability
        md.append("## 2. NIST SP 800-53 Control Coverage")
        md.append("The mapped STIG baselines mandate compliance checks against the following NIST SP 800-53 controls:")
        md.append("")
        controls_formatted = ", ".join([f"`{c}`" for c in summary["mapped_nist_controls"]])
        md.append(f"> {controls_formatted}")
        md.append("")
        md.append("---")
        md.append("")

        # Detailed Matrix Table
        md.append("## 3. Component-to-STIG Traceability Matrix")
        md.append("")
        md.append("| Component Name | Version | Type | Mapped DISA STIG / SRG | Severity | NIST Controls | Resolution Rationale |")
        md.append("| :--- | :--- | :--- | :--- | :---: | :--- | :--- |")

        for m in sorted(mappings, key=lambda x: (x.stig_info.get("max_severity", ""), x.component.name)):
            c = m.component
            info = m.stig_info
            stig_title = info.get("title", m.stig_key)
            sev = info.get("max_severity", "N/A")
            controls_abbr = ", ".join(info.get("nist_controls", [])[:4])
            if len(info.get("nist_controls", [])) > 4:
                controls_abbr += ", ..."

            md.append(
                f"| **{c.name}** | `{c.version}` | `{c.component_type}` | {stig_title} | `{sev}` | {controls_abbr} | {m.match_reason} |"
            )

        md.append("")
        md.append("---")
        md.append("*Artifact produced by GRC Bundle Review Pipeline (`sbom_analyzer.py`)*")
        return "\n".join(md)

    @staticmethod
    def to_json(
        mappings: List[STIGMapping],
        summary: Dict[str, Any],
        sbom_filename: str = "SBOM",
    ) -> str:
        payload = {
            "metadata": {
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source_sbom": os.path.basename(sbom_filename),
                "analyzer": "sbom_analyzer.py (GRC Bundle Review Pipeline)",
            },
            "summary": summary,
            "mappings": [m.to_dict() for m in mappings],
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def to_csv(mappings: List[STIGMapping]) -> str:
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Component Name",
            "Version",
            "Type",
            "PURL",
            "DISA STIG ID",
            "DISA STIG Title",
            "Benchmark ID",
            "STIG Version",
            "Max Severity",
            "NIST SP 800-53 Controls",
            "Match Rationale",
        ])
        for m in mappings:
            c = m.component
            info = m.stig_info
            writer.writerow([
                c.name,
                c.version,
                c.component_type,
                c.purl,
                info.get("id", ""),
                info.get("title", ""),
                info.get("benchmark_id", ""),
                info.get("version", ""),
                info.get("max_severity", ""),
                "; ".join(info.get("nist_controls", [])),
                m.match_reason,
            ])
        return output.getvalue()


# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================

def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DISA STIG & SRG SBOM Applicability Analyzer (GRC Bundle Review Pipeline)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sbom_analyzer.py --sbom /path/to/sbom.json --format markdown -o stig_matrix.md
  python3 sbom_analyzer.py --sbom cyclonedx.json --format json -o stig_applicability.json
  python3 sbom_analyzer.py --sbom spdx.json --format csv -o stig_export.csv
        """,
    )
    parser.add_argument(
        "--sbom",
        "-s",
        required=True,
        help="Path to the input SBOM file (CycloneDX or SPDX JSON format).",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path. If omitted, results are written to stdout.",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["markdown", "json", "csv", "summary"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    parser.add_argument(
        "--catalog-dump",
        action="store_true",
        help="Print the internal DISA STIG / SRG reference catalog and exit.",
    )
    return parser


def main() -> None:
    parser = build_cli()
    args = parser.parse_args()

    if args.catalog_dump:
        print(json.dumps(DISA_STIG_CATALOG, indent=2))
        sys.exit(0)

    try:
        components = SBOMParser.parse_file(args.sbom)
    except Exception as e:
        print(f"[ERROR] Failed to load SBOM file: {e}", file=sys.stderr)
        sys.exit(1)

    analyzer = STIGAnalyzer(components)
    mappings = analyzer.analyze()
    summary = analyzer.generate_summary()

    if args.format == "markdown":
        output_data = ReportGenerator.to_markdown(mappings, summary, sbom_filename=args.sbom)
    elif args.format == "json":
        output_data = ReportGenerator.to_json(mappings, summary, sbom_filename=args.sbom)
    elif args.format == "csv":
        output_data = ReportGenerator.to_csv(mappings)
    elif args.format == "summary":
        output_data = json.dumps(summary, indent=2)
    else:
        output_data = ReportGenerator.to_markdown(mappings, summary, sbom_filename=args.sbom)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_data)
            print(f"[SUCCESS] STIG Applicability Matrix written to: {args.output}")
        except IOError as e:
            print(f"[ERROR] Failed to write output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_data)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
GRCx (The GRC eXperience) — Standalone Scan-to-POA&M Transformation Engine
Engine: scripts/transform_scans.py (v1.2.0 — Misawa)

Purpose:
  Standalone Continuous Monitoring (ConMon) engine for GRC analysts.
  Ingests Tenable (Nessus / Tenable.sc / Tenable.io) or AWS Inspector scan
  results in .csv or .xlsx format and populates the official OPEN and CLOSED
  FedRAMP POA&M Excel templates (.xlsx) using 100% Python 3 Standard Library.

Key Capabilities:
  1. Multi-Format Ingestion (.csv & .xlsx): Auto-detects Tenable vs. AWS Inspector
     exports and maps every finding (1 row per Vulnerability + Asset pair) into
     the 27 official FedRAMP POA&M columns.
  2. Open -> Closed POA&M Delta Reconciliation: Requests the previously filled-out
     OPEN FedRAMP POA&M (.xlsx). Findings still present carry over with their
     immutable Original Detection Date; findings no longer present in the new scan
     (or marked False Positive = Yes) automatically move to the CLOSED FedRAMP
     POA&M template (.xlsx).
  3. Interactive Remediation Plan Drafter ([y/n]): Detects any POA&M entries
     missing a Remediation Plan (Column K) and asks if the analyst wants GRCx to
     auto-draft missing plans with official Tenable or AWS remediation URLs.
  4. SLA Breach & Finding Age Analysis: Reports the exact count of finished POA&M
     entries whose Scheduled Completion Date (SLA) has passed and calculates how
     many days old each entry is from its Original Detection Date.
"""

import argparse
import csv
import datetime
import os
import re
import shutil
import sys
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants & FedRAMP Column Definitions
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_OPEN_TEMPLATE = os.path.join(REPO_ROOT, "templates", "OPEN FedRAMP-POAM-Template.xlsx")
DEFAULT_CLOSED_TEMPLATE = os.path.join(REPO_ROOT, "templates", "CLOSED LEGACY FedRAMP-POAM-Template.xlsx")

EXCEL_EPOCH = datetime.date(1899, 12, 30)
MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

ET.register_namespace("", MAIN_NS)
ET.register_namespace("r", REL_NS)

# 27 logical FedRAMP POA&M fields in canonical order:
# In OPEN FedRAMP-POAM-Template.xlsx:   Columns B .. AB (Row 5+)
# In CLOSED FedRAMP-POAM-Template.xlsx: Columns A .. AA (Row 3+)
POAM_FIELDS = [
    "poam_id",                  # OPEN: B  | CLOSED: A  | POAM ID
    "controls",                 # OPEN: C  | CLOSED: B  | Controls
    "weakness_name",            # OPEN: D  | CLOSED: C  | Weakness Name
    "weakness_description",     # OPEN: E  | CLOSED: D  | Weakness Description
    "detector_source",          # OPEN: F  | CLOSED: E  | Weakness Detector Source
    "source_identifier",        # OPEN: G  | CLOSED: F  | Weakness Source Identifier
    "asset_identifier",         # OPEN: H  | CLOSED: G  | Asset Identifier
    "point_of_contact",         # OPEN: I  | CLOSED: H  | Point of Contact
    "resources_required",       # OPEN: J  | CLOSED: I  | Resources Required
    "remediation_plan",         # OPEN: K  | CLOSED: J  | Remediation Plan / Overall Remediation Plan
    "original_detection_date",  # OPEN: L  | CLOSED: K  | Original Detection Date
    "scheduled_completion_date",# OPEN: M  | CLOSED: L  | Scheduled Completion Date
    "status_date",              # OPEN: N  | CLOSED: M  | Status Date
    "vendor_dependency",        # OPEN: O  | CLOSED: N  | Vendor Dependency
    "last_vendor_checkin",      # OPEN: P  | CLOSED: O  | Last Vendor Check-in Date
    "vendor_product_name",      # OPEN: Q  | CLOSED: P  | Vendor Dependent Product Name
    "original_risk_rating",     # OPEN: R  | CLOSED: Q  | Original Risk Rating
    "adjusted_risk_rating",     # OPEN: S  | CLOSED: R  | Adjusted Risk Rating
    "risk_adjustment",          # OPEN: T  | CLOSED: S  | Risk Adjustment
    "false_positive",           # OPEN: U  | CLOSED: T  | False Positive
    "operational_requirement",  # OPEN: V  | CLOSED: U  | Operational Requirement
    "deviation_rationale",      # OPEN: W  | CLOSED: V  | Deviation Rationale
    "supporting_documents",     # OPEN: X  | CLOSED: W  | Supporting Documents
    "comments",                 # OPEN: Y  | CLOSED: X  | Comments
    "bod_22_01_tracking",       # OPEN: Z  | CLOSED: Y  | Binding Operational Directive 22-01 tracking
    "bod_22_01_due_date",       # OPEN: AA | CLOSED: Z  | Binding Operational Directive 22-01 Due Date
    "cve",                      # OPEN: AB | CLOSED: AA | CVE
]

OPEN_COL_LETTERS = [
    "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N",
    "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "AA", "AB"
]

CLOSED_COL_LETTERS = [
    "A", "B", "C", "D", "F" if False else "E", "F", "G", "H", "I", "J", "K", "L", "M",
    "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "AA"
]

DATE_FIELDS = {
    "original_detection_date",
    "scheduled_completion_date",
    "status_date",
    "last_vendor_checkin",
    "bod_22_01_due_date",
}

SLA_DAYS_BY_RISK = {
    "Critical": 30,
    "High": 30,
    "Moderate": 90,
    "Low": 180,
}

RISK_ORDER = {"Critical": 0, "High": 1, "Moderate": 2, "Low": 3}


# ---------------------------------------------------------------------------
# Date & Excel Helper Utilities
# ---------------------------------------------------------------------------

def col_to_idx(col_str: str) -> int:
    """Convert Excel column letters (e.g., 'A' -> 0, 'Z' -> 25, 'AA' -> 26)."""
    res = 0
    for ch in col_str:
        if "A" <= ch <= "Z":
            res = res * 26 + (ord(ch) - ord("A") + 1)
    return res - 1


def split_cell_ref(cell_ref: str) -> Tuple[str, int]:
    """Split 'AB12' into ('AB', 12)."""
    m = re.match(r"^([A-Z]+)(\d+)$", cell_ref.upper())
    if not m:
        return ("A", 1)
    return m.group(1), int(m.group(2))


def date_to_excel_serial(d: datetime.date) -> int:
    """Convert Python date to Excel serial integer (1900 date system)."""
    return (d - EXCEL_EPOCH).days


def excel_serial_to_date(serial_val: float) -> Optional[datetime.date]:
    """Convert Excel serial number to Python date."""
    try:
        days = int(round(float(serial_val)))
        if 10000 <= days <= 90000:
            return EXCEL_EPOCH + datetime.timedelta(days=days)
    except (ValueError, TypeError):
        pass
    return None


def parse_any_date(val: str, fallback: Optional[datetime.date] = None) -> Optional[datetime.date]:
    """Parse Excel serial dates, ISO timestamps, or common US/International date strings."""
    if val is None:
        return fallback
    s = str(val).strip()
    if not s or s.lower() in ("n/a", "none", "null", "-"):
        return fallback

    # Check if numeric Excel serial date
    if re.match(r"^\d+(\.\d+)?$", s):
        d = excel_serial_to_date(float(s))
        if d:
            return d

    # Strip trailing time / timezone component if ISO-like
    s_clean = re.sub(r"[T\s]\d{1,2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2}|\s*[A-Z]{2,4})?$", "", s).strip()

    date_formats = [
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%m/%d/%y",
        "%Y/%m/%d",
        "%d-%b-%Y",
        "%d-%b-%y",
        "%b %d, %Y",
        "%B %d, %Y",
        "%d/%m/%Y",
    ]
    for fmt in date_formats:
        try:
            return datetime.datetime.strptime(s_clean, fmt).date()
        except ValueError:
            continue

    # Try matching YYYY-MM-DD anywhere inside the string
    m_iso = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m_iso:
        try:
            return datetime.date(int(m_iso.group(1)), int(m_iso.group(2)), int(m_iso.group(3)))
        except ValueError:
            pass

    return fallback


def format_date_iso(d: Optional[datetime.date]) -> str:
    """Format date as YYYY-MM-DD or empty string."""
    return d.strftime("%Y-%m-%d") if d else ""


def normalize_risk(raw_risk: str) -> Optional[str]:
    """
    Normalize scanner severity strings into FedRAMP Risk Ratings:
    Critical, High, Moderate, Low (or None for Informational/None).
    """
    if not raw_risk:
        return None
    s = str(raw_risk).strip().lower()
    if s in ("critical", "crit", "4", "cat i", "cat 1", "very high"):
        return "Critical"
    if s in ("high", "3"):
        return "High"
    if s in ("moderate", "medium", "med", "2", "cat ii", "cat 2"):
        return "Moderate"
    if s in ("low", "1", "cat iii", "cat 3"):
        return "Low"
    if s in ("info", "informational", "none", "0", "passed", "open"):
        return None
    return None


def compute_sla_date(detection_date: datetime.date, risk_rating: str, adjusted_risk: str = "", risk_adj_approved: str = "") -> datetime.date:
    """Calculate FedRAMP Scheduled Completion Date from Original Detection Date and Risk Rating."""
    effective_risk = risk_rating
    if str(risk_adj_approved).strip().lower() == "yes" and adjusted_risk in SLA_DAYS_BY_RISK:
        effective_risk = adjusted_risk
    days = SLA_DAYS_BY_RISK.get(effective_risk, 90)
    return detection_date + datetime.timedelta(days=days)


# ---------------------------------------------------------------------------
# Pure-Python Standard Library .xlsx Reader
# ---------------------------------------------------------------------------

def read_xlsx_rows(xlsx_path: str, sheet_index: int = 0) -> List[Dict[str, str]]:
    """
    Read an .xlsx worksheet into a list of dicts keyed by column letter ('A', 'B', ..., 'AB').
    Each dict also includes '_row_num' (1-based Excel row index).
    """
    ns = {"main": MAIN_NS, "r": REL_NS}
    rows_out: List[Dict[str, str]] = []

    with zipfile.ZipFile(xlsx_path, "r") as z:
        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            ss_root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in ss_root.findall("main:si", ns):
                texts = [t.text or "" for t in si.findall(".//main:t", ns)]
                shared_strings.append("".join(texts))

        wb_root = ET.fromstring(z.read("xl/workbook.xml"))
        rels_root = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        rel_map = {rel.attrib["Id"]: rel.attrib["Target"] for rel in rels_root}

        sheets = wb_root.findall(".//main:sheet", ns)
        if not sheets:
            return []
        chosen_sheet = sheets[min(sheet_index, len(sheets) - 1)]
        rid = chosen_sheet.attrib[f"{{{REL_NS}}}id"]
        target = "xl/" + rel_map[rid].lstrip("/")
        if target not in z.namelist():
            target = "xl/worksheets/sheet1.xml"

        s_root = ET.fromstring(z.read(target))
        for r in s_root.findall(".//main:row", ns):
            r_num = int(r.attrib.get("r", "0"))
            row_dict: Dict[str, str] = {"_row_num": str(r_num)}
            for c in r.findall("main:c", ns):
                c_ref = c.attrib.get("r", "")
                col_let, _ = split_cell_ref(c_ref)
                c_type = c.attrib.get("t", "")
                v = c.find("main:v", ns)
                is_elem = c.find("main:is", ns)
                val = ""
                if v is not None and v.text is not None:
                    if c_type == "s":
                        idx = int(v.text)
                        val = shared_strings[idx] if 0 <= idx < len(shared_strings) else v.text
                    else:
                        val = v.text
                elif is_elem is not None:
                    val = "".join([t.text or "" for t in is_elem.findall(".//main:t", ns)])
                row_dict[col_let] = val.strip()
            rows_out.append(row_dict)

    return rows_out


# ---------------------------------------------------------------------------
# Generic Scan File Reader (.csv or .xlsx) & Scanner Auto-Detection
# ---------------------------------------------------------------------------

def load_scan_records(scan_path: str) -> List[Dict[str, str]]:
    """
    Load a Tenable or AWS Inspector scan export from either .csv or .xlsx
    into a list of column-header -> value dictionaries.
    """
    ext = os.path.splitext(scan_path)[1].lower()
    if ext in (".xlsx", ".xlsm"):
        raw_rows = read_xlsx_rows(scan_path)
        if not raw_rows:
            return []
        # Find header row (first non-empty row with >= 3 populated columns)
        header_row = None
        header_idx = 0
        for i, r in enumerate(raw_rows):
            non_empty = [k for k, v in r.items() if k != "_row_num" and v]
            if len(non_empty) >= 3:
                header_row = r
                header_idx = i
                break
        if not header_row:
            return []
        col_to_header = {
            col: val.strip()
            for col, val in header_row.items()
            if col != "_row_num" and val.strip()
        }
        records: List[Dict[str, str]] = []
        for r in raw_rows[header_idx + 1:]:
            rec = {}
            has_val = False
            for col, hdr in col_to_header.items():
                v = r.get(col, "").strip()
                if v:
                    has_val = True
                rec[hdr] = v
            if has_val:
                records.append(rec)
        return records
    else:
        # CSV reader (with UTF-8-SIG BOM handling)
        with open(scan_path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            out = []
            for row in reader:
                clean_row = {(k or "").strip(): (v or "").strip() for k, v in row.items() if k}
                if any(clean_row.values()):
                    out.append(clean_row)
            return out


def detect_scanner_type(records: List[Dict[str, str]], explicit_scanner: Optional[str] = None) -> str:
    """Detect whether the input scan is 'tenable' or 'inspector'."""
    if explicit_scanner and explicit_scanner.lower() in ("tenable", "inspector", "aws", "nessus"):
        return "tenable" if explicit_scanner.lower() in ("tenable", "nessus") else "inspector"
    if not records:
        return "tenable"
    headers_lower = {k.lower() for k in records[0].keys()}
    tenable_markers = {"plugin id", "plugin", "plugin name", "synopsis", "plugin output", "see also"}
    inspector_markers = {"finding arn", "arn", "vulnerability id", "resource id", "fix available", "inspector score", "package manager"}
    t_hits = len(headers_lower & tenable_markers)
    i_hits = len(headers_lower & inspector_markers)
    if i_hits > t_hits:
        return "inspector"
    return "tenable"


def get_first_field(row: Dict[str, str], candidates: List[str], default: str = "") -> str:
    """Case-insensitive lookup across candidate column names."""
    lower_map = {k.lower().strip(): v for k, v in row.items()}
    for cand in candidates:
        val = lower_map.get(cand.lower().strip(), "")
        if val != "":
            return val.strip()
    return default


def infer_nist_controls(weakness_name: str, description: str, cve: str) -> str:
    """Infer governing NIST SP 800-53 Rev 5 controls based on finding characteristics."""
    text = f"{weakness_name} {description}".lower()
    controls = ["RA-5", "SI-2"]
    if any(k in text for k in ("tls", "ssl", "certificate", "cipher", "rc4", "3des", "CBC")):
        controls.append("SC-8")
        controls.append("SC-13")
    elif any(k in text for k in ("fips", "openssl", "crypto", "md5", "sha-1", "sha1")):
        controls.append("SC-13")
    if any(k in text for k in ("ssh", "password", "authentication", "credential", "default account")):
        controls.append("IA-2")
        controls.append("AC-6")
    if any(k in text for k in ("cis ", "stig", "configuration", "permission", "world-writable", "unencrypted")):
        controls.append("CM-6")
    # Preserve order while deduplicating
    seen = set()
    dedup = []
    for c in controls:
        if c not in seen:
            seen.add(c)
            dedup.append(c)
    return ", ".join(dedup)


def extract_cves(raw_cve_text: str, fallback_text: str = "") -> str:
    """Extract and deduplicate CVE-YYYY-NNNN+ identifiers."""
    combined = f"{raw_cve_text} {fallback_text}"
    matches = re.findall(r"CVE-\d{4}-\d{4,7}", combined, flags=re.IGNORECASE)
    seen = set()
    out = []
    for m in matches:
        up = m.upper()
        if up not in seen:
            seen.add(up)
            out.append(up)
    return ", ".join(out)


def extract_urls(text: str) -> List[str]:
    """Extract HTTP/HTTPS URLs from scanner fields."""
    if not text:
        return []
    urls = re.findall(r"https?://[^\s,;\)\"'>]+", text)
    seen = set()
    out = []
    for u in urls:
        u_clean = u.rstrip(".")
        if u_clean not in seen:
            seen.add(u_clean)
            out.append(u_clean)
    return out


# ---------------------------------------------------------------------------
# Normalization of Tenable & AWS Inspector Rows -> Logical POA&M Entries
# ---------------------------------------------------------------------------

def normalize_scan_rows(
    records: List[Dict[str, str]],
    scanner_type: str,
    scan_filename: str,
    today: datetime.date,
    default_poc: str,
) -> List[Dict[str, object]]:
    """
    Convert raw Tenable or AWS Inspector rows into normalized POA&M entry dicts.
    Enforces 1 POA&M row per unique (Vulnerability + Asset) combination.
    """
    grouped: Dict[Tuple[str, str], Dict[str, object]] = {}

    for row in records:
        if scanner_type == "tenable":
            raw_risk = get_first_field(row, ["Risk", "Severity", "Risk Factor", "VPR Severity"])
            risk = normalize_risk(raw_risk)
            if not risk:
                continue

            plugin_id = get_first_field(row, ["Plugin ID", "Plugin", "PluginID"])
            if plugin_id.endswith(".0"):
                plugin_id = plugin_id[:-2]
            name = get_first_field(row, ["Name", "Plugin Name", "Title"], default=f"Tenable Plugin {plugin_id}")
            synopsis = get_first_field(row, ["Synopsis"])
            desc = get_first_field(row, ["Description", "Summary"])
            plugin_out = get_first_field(row, ["Plugin Output", "Output"])
            full_desc = desc or synopsis or name
            if synopsis and desc and synopsis not in desc:
                full_desc = f"{synopsis}\n\n{desc}"
            if plugin_out:
                snippet = plugin_out[:400] + ("..." if len(plugin_out) > 400 else "")
                full_desc = f"{full_desc}\n\n[Scanner Evidence]: {snippet}"

            host = get_first_field(row, ["Host", "IP Address", "DNS Name", "FQDN", "Asset", "NetBIOS Name"], default="unknown-host")
            port = get_first_field(row, ["Port"])
            proto = get_first_field(row, ["Protocol"])
            solution = get_first_field(row, ["Solution", "Remediation", "Recommendation"])
            see_also = get_first_field(row, ["See Also", "References", "URL"])
            raw_cve = get_first_field(row, ["CVE", "CVEs"])
            cves = extract_cves(raw_cve, f"{name} {desc}")

            first_seen_str = get_first_field(row, ["First Discovered", "First Seen", "Discovery Date", "Original Detection Date", "Plugin Publication Date"])
            last_seen_str = get_first_field(row, ["Last Observed", "Last Seen", "Status Date"])
            det_date = parse_any_date(first_seen_str, fallback=today) or today
            stat_date = parse_any_date(last_seen_str, fallback=today) or today

            kev_raw = get_first_field(row, ["CISA KEV", "KEV", "Exploit Available", "BOD 22-01"])
            is_kev = "Yes" if kev_raw.lower() in ("yes", "true", "1", "kev") else ""

            source_id = plugin_id or cves.split(",")[0].strip() or name
            asset_base = host
            asset_display = f"{host} ({port}/{proto.upper()})" if (port and port != "0" and proto) else host
            detector_source = "Tenable Nessus"
            vendor_dep = "No"
            vendor_prod = ""

        else:
            # AWS Inspector
            raw_risk = get_first_field(row, ["Severity", "Original Risk Rating", "Risk"])
            risk = normalize_risk(raw_risk)
            if not risk:
                continue

            vuln_id = get_first_field(row, ["Vulnerability ID", "CVE", "Plugin ID", "Finding ID"])
            finding_arn = get_first_field(row, ["Finding ARN", "ARN"])
            title = get_first_field(row, ["Title", "Finding Title", "Weakness Name"], default=vuln_id or "AWS Inspector Finding")
            desc = get_first_field(row, ["Description", "Weakness Description"], default=title)
            pkg = get_first_field(row, ["Affected Packages", "Package", "Package Name", "Vulnerable Package"])
            file_path = get_first_field(row, ["File Path", "Package Path"])
            full_desc = desc
            if pkg:
                full_desc += f"\n\nAffected Package(s): {pkg}"
            if file_path:
                full_desc += f" ({file_path})"

            resource_id = get_first_field(row, ["Resource ID", "Instance ID", "Asset Identifier", "Asset ID", "AWS Account ID"], default="aws-resource")
            resource_type = get_first_field(row, ["Resource Type"])
            asset_base = resource_id
            asset_display = f"{resource_id} ({resource_type})" if resource_type and resource_type not in resource_id else resource_id

            solution = get_first_field(row, ["Remediation", "Recommendation", "Remediation Plan", "Fixed Version"])
            fix_avail = get_first_field(row, ["Fix Available", "FixAvailable"])
            pkg_mgr = get_first_field(row, ["Package Manager", "Vendor", "Platform"])
            see_also = get_first_field(row, ["Vendor Advisory", "Reference URLs", "URL", "See Also"])
            raw_cve = get_first_field(row, ["CVE", "Vulnerability ID"])
            cves = extract_cves(raw_cve, f"{title} {desc}")

            first_seen_str = get_first_field(row, ["First Observed At", "First Seen", "Created At", "Original Detection Date"])
            last_seen_str = get_first_field(row, ["Last Observed At", "Last Seen", "Updated At", "Status Date"])
            det_date = parse_any_date(first_seen_str, fallback=today) or today
            stat_date = parse_any_date(last_seen_str, fallback=today) or today

            kev_raw = get_first_field(row, ["CISA KEV", "Exploit Available", "BOD 22-01"])
            is_kev = "Yes" if kev_raw.lower() in ("yes", "true", "1") else ""

            source_id = vuln_id or finding_arn or cves.split(",")[0].strip() or title
            name = title
            detector_source = "AWS Inspector"
            if fix_avail.lower() == "no":
                vendor_dep = "Yes"
                vendor_prod = pkg_mgr or "Upstream OS / Package Maintainer"
            else:
                vendor_dep = "No"
                vendor_prod = ""

        # Deduplication key: 1 row per (Vulnerability Source ID + Base Asset Identifier)
        dedup_key = (source_id.strip().lower(), asset_base.strip().lower())

        if dedup_key in grouped:
            existing = grouped[dedup_key]
            # Merge additional port/protocol on the same asset if different
            curr_asset = str(existing["asset_identifier"])
            if asset_display not in curr_asset.split("\n"):
                existing["asset_identifier"] = f"{curr_asset}\n{asset_display}"
            # Keep earliest detection date
            if det_date < existing["_det_date_obj"]:
                existing["_det_date_obj"] = det_date
                existing["original_detection_date"] = format_date_iso(det_date)
            # Keep highest severity if multiple records for same vuln+asset
            if RISK_ORDER.get(risk, 99) < RISK_ORDER.get(str(existing["original_risk_rating"]), 99):
                existing["original_risk_rating"] = risk
            continue

        sla_date = compute_sla_date(det_date, risk)
        controls = infer_nist_controls(name, full_desc, cves)

        grouped[dedup_key] = {
            "_dedup_key": dedup_key,
            "_scanner_type": scanner_type,
            "_raw_solution": solution,
            "_see_also": see_also,
            "_det_date_obj": det_date,
            "_sla_date_obj": sla_date,
            "_stat_date_obj": stat_date,
            "poam_id": "",
            "controls": controls,
            "weakness_name": name,
            "weakness_description": full_desc,
            "detector_source": detector_source,
            "source_identifier": source_id,
            "asset_identifier": asset_display,
            "point_of_contact": default_poc,
            "resources_required": "",
            "remediation_plan": solution,
            "original_detection_date": format_date_iso(det_date),
            "scheduled_completion_date": format_date_iso(sla_date),
            "status_date": format_date_iso(stat_date),
            "vendor_dependency": vendor_dep,
            "last_vendor_checkin": "",
            "vendor_product_name": vendor_prod,
            "original_risk_rating": risk,
            "adjusted_risk_rating": "",
            "risk_adjustment": "No",
            "false_positive": "No",
            "operational_requirement": "No",
            "deviation_rationale": "",
            "supporting_documents": scan_filename,
            "comments": "",
            "bod_22_01_tracking": is_kev,
            "bod_22_01_due_date": format_date_iso(det_date + datetime.timedelta(days=14)) if is_kev == "Yes" else "",
            "cve": cves,
        }

    return list(grouped.values())


# ---------------------------------------------------------------------------
# Reading Previous OPEN & CLOSED FedRAMP POA&M Workbooks
# ---------------------------------------------------------------------------

def extract_base_asset(asset_str: str) -> str:
    """Normalize asset identifier (strip port/protocol or resource type suffix) for matching."""
    if not asset_str:
        return ""
    first_line = asset_str.strip().splitlines()[0].strip()
    base = re.sub(r"\s*\([^\)]*\)\s*$", "", first_line).strip()
    return base.lower()


def load_existing_poam_workbook(xlsx_path: str, is_closed_template: bool = False) -> List[Dict[str, object]]:
    """
    Parse an existing OPEN or CLOSED FedRAMP POA&M .xlsx file and return its populated rows.
    """
    if not xlsx_path or not os.path.isfile(xlsx_path):
        return []

    rows = read_xlsx_rows(xlsx_path, sheet_index=0)
    col_letters = CLOSED_COL_LETTERS if is_closed_template else OPEN_COL_LETTERS
    min_data_row = 3 if is_closed_template else 5

    entries: List[Dict[str, object]] = []
    for r in rows:
        r_num = int(r.get("_row_num", "0"))
        if r_num < min_data_row:
            continue

        entry: Dict[str, object] = {}
        for field_name, col_let in zip(POAM_FIELDS, col_letters):
            val = r.get(col_let, "").strip()
            if field_name == "source_identifier" and val.endswith(".0"):
                val = val[:-2]
            entry[field_name] = val

        # Check if this row is actually populated with a POA&M entry
        if not any([
            entry.get("poam_id"),
            entry.get("weakness_name"),
            entry.get("source_identifier"),
            entry.get("asset_identifier"),
        ]):
            continue

        # Normalize date fields from Excel serial numbers into YYYY-MM-DD strings and date objects
        det_d = parse_any_date(str(entry.get("original_detection_date", "")))
        sla_d = parse_any_date(str(entry.get("scheduled_completion_date", "")))
        stat_d = parse_any_date(str(entry.get("status_date", "")))
        chk_d = parse_any_date(str(entry.get("last_vendor_checkin", "")))
        bod_d = parse_any_date(str(entry.get("bod_22_01_due_date", "")))

        risk = normalize_risk(str(entry.get("original_risk_rating", ""))) or str(entry.get("original_risk_rating", "Moderate"))
        entry["original_risk_rating"] = risk

        if det_d and not sla_d:
            sla_d = compute_sla_date(
                det_d,
                risk,
                str(entry.get("adjusted_risk_rating", "")),
                str(entry.get("risk_adjustment", "")),
            )

        entry["_det_date_obj"] = det_d
        entry["_sla_date_obj"] = sla_d
        entry["_stat_date_obj"] = stat_d
        entry["original_detection_date"] = format_date_iso(det_d) if det_d else str(entry.get("original_detection_date", ""))
        entry["scheduled_completion_date"] = format_date_iso(sla_d) if sla_d else str(entry.get("scheduled_completion_date", ""))
        entry["status_date"] = format_date_iso(stat_d) if stat_d else str(entry.get("status_date", ""))
        entry["last_vendor_checkin"] = format_date_iso(chk_d) if chk_d else ""
        entry["bod_22_01_due_date"] = format_date_iso(bod_d) if bod_d else ""

        src_key = str(entry.get("source_identifier") or entry.get("cve") or entry.get("weakness_name") or "").strip().lower()
        asset_key = extract_base_asset(str(entry.get("asset_identifier", "")))
        entry["_dedup_key"] = (src_key, asset_key)
        entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Delta Reconciliation: Previous OPEN POA&M vs. New Scan Results
# ---------------------------------------------------------------------------

def reconcile_poam_entries(
    prev_open_entries: List[Dict[str, object]],
    new_scan_entries: List[Dict[str, object]],
    today: datetime.date,
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], Dict[str, int]]:
    """
    Reconcile previous OPEN POA&M rows with new scan findings:
      - Carry-Over Open: In Previous OPEN and still present in New Scan (and not False Positive = Yes)
      - Newly Detected Open: In New Scan only
      - Moved to Closed: In Previous OPEN, absent from New Scan (or marked False Positive = Yes)
    """
    prev_by_key: Dict[Tuple[str, str], Dict[str, object]] = {}
    prev_by_alt_key: Dict[Tuple[str, str], Dict[str, object]] = {}

    max_poam_seq = 0
    for p in prev_open_entries:
        pid = str(p.get("poam_id", ""))
        m_seq = re.search(r"(\d+)$", pid)
        if m_seq:
            max_poam_seq = max(max_poam_seq, int(m_seq.group(1)))

        k = p["_dedup_key"]
        prev_by_key[k] = p
        wname = str(p.get("weakness_name", "")).strip().lower()
        asset_k = k[1]
        if wname:
            prev_by_alt_key[(wname, asset_k)] = p

    matched_prev_ids = set()
    final_open: List[Dict[str, object]] = []
    newly_closed: List[Dict[str, object]] = []

    carry_over_count = 0
    new_open_count = 0

    for scan_item in new_scan_entries:
        s_key = scan_item["_dedup_key"]
        s_wname_key = (str(scan_item.get("weakness_name", "")).strip().lower(), s_key[1])

        matched_prev = prev_by_key.get(s_key) or prev_by_alt_key.get(s_wname_key)

        if matched_prev is not None:
            matched_prev_ids.add(id(matched_prev))

            # If marked False Positive == Yes in previous POA&M, move to CLOSED
            if str(matched_prev.get("false_positive", "")).strip().lower() == "yes":
                closed_copy = dict(matched_prev)
                closed_copy["status_date"] = format_date_iso(today)
                closed_copy["_stat_date_obj"] = today
                prev_comment = str(closed_copy.get("comments", "")).strip()
                note = f"[Closed {format_date_iso(today)}: Approved False Positive moved to Closed POA&M]"
                closed_copy["comments"] = f"{prev_comment}\n{note}".strip() if prev_comment else note
                newly_closed.append(closed_copy)
                continue

            # Carry-over Open item: preserve immutable Original Detection Date, POAM ID, and analyst fields
            merged = dict(scan_item)
            merged["poam_id"] = matched_prev.get("poam_id") or merged["poam_id"]
            if matched_prev.get("controls"):
                merged["controls"] = matched_prev["controls"]
            if matched_prev.get("point_of_contact"):
                merged["point_of_contact"] = matched_prev["point_of_contact"]
            if matched_prev.get("resources_required"):
                merged["resources_required"] = matched_prev["resources_required"]
            # Preserve existing analyst Remediation Plan if present; if blank, leave blank so GRCx can offer to draft
            if matched_prev.get("remediation_plan"):
                merged["remediation_plan"] = matched_prev["remediation_plan"]
            else:
                merged["remediation_plan"] = ""

            # Original Detection Date never changes!
            orig_det_obj = matched_prev.get("_det_date_obj") or scan_item.get("_det_date_obj") or today
            merged["_det_date_obj"] = orig_det_obj
            merged["original_detection_date"] = format_date_iso(orig_det_obj)

            # Carry over Risk Adjustments / Deviations
            for carry_field in [
                "vendor_dependency",
                "last_vendor_checkin",
                "vendor_product_name",
                "adjusted_risk_rating",
                "risk_adjustment",
                "false_positive",
                "operational_requirement",
                "deviation_rationale",
                "supporting_documents",
                "comments",
                "bod_22_01_tracking",
                "bod_22_01_due_date",
            ]:
                if matched_prev.get(carry_field):
                    merged[carry_field] = matched_prev[carry_field]

            # Recalculate or preserve Scheduled Completion Date based on immutable Original Detection Date
            sla_obj = compute_sla_date(
                orig_det_obj,
                str(merged.get("original_risk_rating", "Moderate")),
                str(merged.get("adjusted_risk_rating", "")),
                str(merged.get("risk_adjustment", "")),
            )
            merged["_sla_date_obj"] = sla_obj
            merged["scheduled_completion_date"] = format_date_iso(sla_obj)
            merged["status_date"] = format_date_iso(today)
            merged["_stat_date_obj"] = today
            merged["_is_carry_over"] = True

            final_open.append(merged)
            carry_over_count += 1
        else:
            # Newly detected Open POA&M item
            max_poam_seq += 1
            new_item = dict(scan_item)
            new_item["poam_id"] = f"POAM-{today.year}-{max_poam_seq:04d}"
            new_item["_is_carry_over"] = False
            final_open.append(new_item)
            new_open_count += 1

    # Any entry in prev_open_entries that was NOT matched in the new scan is remediated -> move to CLOSED!
    for p in prev_open_entries:
        if id(p) not in matched_prev_ids:
            closed_item = dict(p)
            closed_item["status_date"] = format_date_iso(today)
            closed_item["_stat_date_obj"] = today
            prev_comment = str(closed_item.get("comments", "")).strip()
            note = f"[Closed {format_date_iso(today)}: Verified remediated — finding no longer present in latest scan]"
            closed_item["comments"] = f"{prev_comment}\n{note}".strip() if prev_comment else note
            newly_closed.append(closed_item)

    stats = {
        "carry_over_open": carry_over_count,
        "new_open": new_open_count,
        "total_open": len(final_open),
        "moved_to_closed": len(newly_closed),
    }
    return final_open, newly_closed, stats


# ---------------------------------------------------------------------------
# Remediation Plan URL Drafter (Tenable & AWS Inspector)
# ---------------------------------------------------------------------------

def build_remediation_plan_with_urls(entry: Dict[str, object]) -> str:
    """
    Construct a detailed FedRAMP Remediation Plan containing official Tenable or
    AWS remediation reference URLs for findings missing a remediation plan.
    """
    detector = str(entry.get("detector_source", "")).lower()
    scanner_type = str(entry.get("_scanner_type", "")).lower()
    is_tenable = "tenable" in detector or "nessus" in detector or scanner_type == "tenable"

    source_id = str(entry.get("source_identifier", "")).strip()
    cve_str = str(entry.get("cve", "")).strip()
    cves = [c.strip() for c in cve_str.split(",") if c.strip().startswith("CVE-")]
    raw_solution = str(entry.get("_raw_solution", "")).strip()
    see_also = str(entry.get("_see_also", "")).strip()
    weakness_name = str(entry.get("weakness_name", "identified vulnerability")).strip()

    urls: List[str] = []

    if is_tenable:
        # Official Tenable Nessus Plugin Remediation URL
        if source_id and re.match(r"^\d+$", source_id):
            urls.append(f"https://www.tenable.com/plugins/nessus/{source_id}")
        else:
            urls.append("https://www.tenable.com/plugins/search")
        for u in extract_urls(see_also):
            if u not in urls:
                urls.append(u)
        for c in cves[:2]:
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{c}"
            if nvd_url not in urls:
                urls.append(nvd_url)

        base_action = (
            raw_solution
            if raw_solution
            else f"Apply the vendor-supplied security update or configuration hardening to remediate '{weakness_name}' and verify closure via follow-on Tenable credentialed scan."
        )
        url_block = "\n".join(f"• {u}" for u in urls)
        return (
            f"Remediation Action: {base_action}\n\n"
            f"Official Tenable & Vendor Remediation References:\n{url_block}"
        )
    else:
        # Official AWS Inspector & ALAS / CVE Remediation URLs
        if source_id.upper().startswith("ALAS"):
            alas_id = source_id.upper().replace(" ", "")
            urls.append(f"https://explore.alas.aws.amazon.com/{alas_id}.html")
        for u in extract_urls(see_also):
            if u not in urls:
                urls.append(u)
        for c in cves[:2]:
            aws_cve_url = f"https://explore.alas.aws.amazon.com/CVE/{c}.html"
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{c}"
            if aws_cve_url not in urls:
                urls.append(aws_cve_url)
            if nvd_url not in urls:
                urls.append(nvd_url)
        inspector_doc_url = "https://docs.aws.amazon.com/inspector/latest/user/findings-understanding.html"
        if inspector_doc_url not in urls:
            urls.append(inspector_doc_url)

        base_action = (
            raw_solution
            if raw_solution
            else f"Update the affected package/image or apply the AWS-recommended security patch for '{weakness_name}', redeploy the hardened AMI/container, and verify closure in AWS Inspector."
        )
        url_block = "\n".join(f"• {u}" for u in urls)
        return (
            f"Remediation Action: {base_action}\n\n"
            f"Official AWS Inspector & Advisory Remediation References:\n{url_block}"
        )


# ---------------------------------------------------------------------------
# Pure-Python Standard Library .xlsx Template Writer
# ---------------------------------------------------------------------------

def write_poam_workbook(
    template_path: str,
    output_path: str,
    entries: List[Dict[str, object]],
    is_closed_template: bool = False,
) -> None:
    """
    Populate either the OPEN FedRAMP POA&M template (Row 5+, Cols B..AB) or the
    CLOSED LEGACY FedRAMP POA&M template (Row 3+, Cols A..AA) while preserving
    all native formatting, styles, drawings, and data validations.

    In the OPEN template, also extends the Risk Rating dropdown and Column M
    Scheduled Completion Date formula to support 'Critical' (30d), 'High' (30d),
    'Moderate' (90d), and 'Low' (180d).
    """
    ns = {"main": MAIN_NS, "r": REL_NS}
    col_letters = CLOSED_COL_LETTERS if is_closed_template else OPEN_COL_LETTERS
    start_row = 3 if is_closed_template else 5

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with zipfile.ZipFile(template_path, "r") as zin:
        # Load sharedStrings.xml
        shared_strings: List[str] = []
        ss_index_map: Dict[str, int] = {}
        if "xl/sharedStrings.xml" in zin.namelist():
            ss_root = ET.fromstring(zin.read("xl/sharedStrings.xml"))
            for si in ss_root.findall("main:si", ns):
                texts = [t.text or "" for t in si.findall(".//main:t", ns)]
                full_str = "".join(texts)
                if full_str not in ss_index_map:
                    ss_index_map[full_str] = len(shared_strings)
                shared_strings.append(full_str)
        else:
            ss_root = ET.Element(f"{{{MAIN_NS}}}sst", {"count": "0", "uniqueCount": "0"})

        def get_or_add_shared_string(s_val: str) -> int:
            if s_val in ss_index_map:
                return ss_index_map[s_val]
            idx = len(shared_strings)
            shared_strings.append(s_val)
            ss_index_map[s_val] = idx
            si_el = ET.SubElement(ss_root, f"{{{MAIN_NS}}}si")
            t_el = ET.SubElement(si_el, f"{{{MAIN_NS}}}t")
            if s_val.startswith(" ") or s_val.endswith(" ") or "\n" in s_val:
                t_el.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            t_el.text = s_val
            return idx

        # Parse sheet1.xml
        sheet_xml_bytes = zin.read("xl/worksheets/sheet1.xml")
        s_root = ET.fromstring(sheet_xml_bytes)
        sheet_data = s_root.find("main:sheetData", ns)

        # Keep header rows (< start_row) intact, remove existing blank/template rows >= start_row
        existing_rows = list(sheet_data.findall("main:row", ns))
        for r_el in existing_rows:
            r_num = int(r_el.attrib.get("r", "0"))
            if r_num >= start_row:
                sheet_data.remove(r_el)

        # Build populated rows + a buffer of clean blank formatted rows
        total_rows_to_write = max(len(entries) + 25, 100)
        for offset in range(total_rows_to_write):
            r_num = start_row + offset
            row_attribs = {"r": str(r_num), "ht": "15.75" if is_closed_template else "18.0", "customHeight": "1"}
            r_el = ET.SubElement(sheet_data, f"{{{MAIN_NS}}}row", row_attribs)

            entry = entries[offset] if offset < len(entries) else None

            if not is_closed_template:
                # Column A in OPEN template (blank cell with style s="2")
                ET.SubElement(r_el, f"{{{MAIN_NS}}}c", {"r": f"A{r_num}", "s": "2"})

            for field_name, col_let in zip(POAM_FIELDS, col_letters):
                cell_ref = f"{col_let}{r_num}"

                # Choose cell style
                if is_closed_template:
                    c_style = "2"
                else:
                    if field_name == "scheduled_completion_date":
                        c_style = "22"  # Date format + SLA formula column
                    elif field_name in DATE_FIELDS:
                        c_style = "21"  # Date format (numFmtId=14)
                    else:
                        c_style = "2"

                c_el = ET.SubElement(r_el, f"{{{MAIN_NS}}}c", {"r": cell_ref, "s": c_style})

                if not is_closed_template and field_name == "scheduled_completion_date":
                    # Write Excel SLA formula supporting Critical (30d), High (30d), Moderate (90d), Low (180d)
                    f_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}f")
                    f_el.text = (
                        f'IF(OR(S{r_num}="N/A",ISBLANK(S{r_num}),T{r_num}<>"Yes"),'
                        f'IF(OR(R{r_num}="Critical",R{r_num}="High"),L{r_num}+30,'
                        f'IF(R{r_num}="Moderate",L{r_num}+90,IF(R{r_num}="Low",L{r_num}+180,""))),'
                        f'IF(OR(S{r_num}="Critical",S{r_num}="High"),L{r_num}+30,'
                        f'IF(S{r_num}="Moderate",L{r_num}+90,IF(S{r_num}="Low",L{r_num}+180,""))))'
                    )
                    if entry is not None:
                        d_obj = parse_any_date(str(entry.get(field_name, "")))
                        if d_obj:
                            v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                            v_el.text = str(date_to_excel_serial(d_obj))
                    continue

                if entry is None:
                    continue

                raw_val = str(entry.get(field_name, "")).strip()
                if not raw_val:
                    continue

                if field_name in DATE_FIELDS:
                    d_obj = parse_any_date(raw_val)
                    if d_obj and not is_closed_template:
                        # Store as numeric Excel serial date so formulas & date formatting work natively
                        v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                        v_el.text = str(date_to_excel_serial(d_obj))
                    else:
                        # Store formatted YYYY-MM-DD string in CLOSED template (where s=2 has numFmtId=0)
                        str_val = format_date_iso(d_obj) if d_obj else raw_val
                        c_el.set("t", "s")
                        v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                        v_el.text = str(get_or_add_shared_string(str_val))
                elif field_name == "source_identifier" and re.match(r"^\d+$", raw_val):
                    # Numeric Plugin ID
                    v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                    v_el.text = raw_val
                else:
                    c_el.set("t", "s")
                    v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                    v_el.text = str(get_or_add_shared_string(raw_val))

        # In OPEN template, extend DataValidation dropdown for Column R and Column S to include Critical
        if not is_closed_template:
            dvs = s_root.find("main:dataValidations", ns)
            if dvs is not None:
                for dv in dvs.findall("main:dataValidation", ns):
                    sqref = dv.attrib.get("sqref", "")
                    f1 = dv.find("main:formula1", ns)
                    if f1 is not None and f1.text:
                        if "R5" in sqref:
                            dv.set("prompt", "Low, Moderate, High, Critical")
                            f1.text = '"Low,Moderate,High,Critical"'
                        elif "S5" in sqref:
                            dv.set("prompt", "Low, Moderate, High, Critical, N/A")
                            f1.text = '"Low,Moderate,High,Critical,N/A"'

        # Update sharedStrings count attributes
        ss_root.set("count", str(len(shared_strings)))
        ss_root.set("uniqueCount", str(len(shared_strings)))

        # Write updated archive
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == "xl/worksheets/sheet1.xml":
                    xml_bytes = ET.tostring(s_root, encoding="utf-8", xml_declaration=True)
                    zout.writestr(item, xml_bytes)
                elif item.filename == "xl/sharedStrings.xml":
                    ss_bytes = ET.tostring(ss_root, encoding="utf-8", xml_declaration=True)
                    zout.writestr(item, ss_bytes)
                elif item.filename == "xl/calcChain.xml":
                    # Omit stale calcChain.xml so Excel recalculates cleanly on open
                    continue
                else:
                    zout.writestr(item, zin.read(item.filename))


# ---------------------------------------------------------------------------
# SLA Breach & Age Analysis + Terminal & Markdown Reporting
# ---------------------------------------------------------------------------

def analyze_and_report_sla(
    open_entries: List[Dict[str, object]],
    closed_entries_moved: List[Dict[str, object]],
    all_closed_entries: List[Dict[str, object]],
    stats: Dict[str, int],
    today: datetime.date,
    open_out_path: str,
    closed_out_path: str,
    summary_md_path: Optional[str] = None,
) -> Dict[str, object]:
    """
    Calculate finding age (days from Original Detection Date) and SLA breach status
    (Scheduled Completion Date < Today) for all finished OPEN POA&M entries.
    """
    overdue_entries = []
    within_sla_entries = []

    for e in open_entries:
        det_d = e.get("_det_date_obj") or parse_any_date(str(e.get("original_detection_date", ""))) or today
        sla_d = e.get("_sla_date_obj") or parse_any_date(str(e.get("scheduled_completion_date", ""))) or today
        age_days = max(0, (today - det_d).days)
        days_past_sla = (today - sla_d).days  # Positive if overdue, negative if days remaining

        e["_age_days"] = age_days
        e["_days_past_sla"] = days_past_sla
        e["_is_overdue"] = sla_d < today

        if sla_d < today:
            overdue_entries.append(e)
        else:
            within_sla_entries.append(e)

    # Sort open entries by overdue status first, then age descending
    sorted_open = sorted(
        open_entries,
        key=lambda x: (0 if x.get("_is_overdue") else 1, -int(x.get("_age_days", 0))),
    )

    print("\n" + "=" * 96)
    print("  GRCx (v1.2.0 — Misawa) · FEDRAMP POA&M TRANSFORMATION & SLA AGING REPORT")
    print("=" * 96)
    print(f"  Analysis Reference Date : {format_date_iso(today)}")
    print(f"  Finished OPEN POA&M     : {open_out_path}")
    print(f"  Finished CLOSED POA&M   : {closed_out_path}")
    print("-" * 96)
    print(f"  • Total Active OPEN POA&M Entries   : {len(open_entries)}  "
          f"({stats['carry_over_open']} Carried Over, {stats['new_open']} Newly Detected)")
    print(f"  • Entries Moved OPEN -> CLOSED      : {len(closed_entries_moved)}  "
          f"(Total in Closed Workbook: {len(all_closed_entries)})")
    print(f"  • OPEN Entries w/ PASSED SLA Date   : {len(overdue_entries)} of {len(open_entries)} "
          f"({'ACTION REQUIRED — SLA BREACH' if overdue_entries else 'ALL WITHIN SLA'})")
    print("=" * 96)

    if sorted_open:
        print("\n  ITEMIZED OPEN POA&M AGING & SLA STATUS:")
        print(f"  {'POAM ID':<15} | {'Risk':<8} | {'Orig. Detected':<14} | {'Age (Days Old)':<16} | {'SLA Due Date':<12} | {'SLA Status'}")
        print("  " + "-" * 92)
        for e in sorted_open:
            pid = str(e.get("poam_id", ""))[:15]
            risk = str(e.get("original_risk_rating", ""))[:8]
            det_s = str(e.get("original_detection_date", ""))
            sla_s = str(e.get("scheduled_completion_date", ""))
            age_d = int(e.get("_age_days", 0))
            past_d = int(e.get("_days_past_sla", 0))
            if e.get("_is_overdue"):
                sla_status = f"🚨 PASSED SLA ({past_d} days overdue)"
            else:
                sla_status = f"✅ Within SLA ({abs(past_d)} days remaining)"
            print(f"  {pid:<15} | {risk:<8} | {det_s:<14} | {f'{age_d} days old':<16} | {sla_s:<12} | {sla_status}")
    else:
        print("\n  [✓] Zero Open POA&M findings remain in the workbook.")

    if closed_entries_moved:
        print("\n  ENTRIES MOVED FROM OPEN -> CLOSED FEDRAMP POA&M IN THIS CYCLE:")
        for c in closed_entries_moved:
            print(f"    • {c.get('poam_id', 'N/A')} | {c.get('weakness_name', '')[:45]} | Asset: {c.get('asset_identifier', '')} | Closed: {c.get('status_date', '')}")

    print("=" * 96 + "\n")

    if summary_md_path:
        os.makedirs(os.path.dirname(os.path.abspath(summary_md_path)), exist_ok=True)
        lines = [
            "# GRCx FedRAMP POA&M Scan Transformation & SLA Aging Report",
            "",
            f"- **Transformation Date**: `{format_date_iso(today)}`",
            f"- **Generated OPEN FedRAMP POA&M**: `{os.path.basename(open_out_path)}`",
            f"- **Generated CLOSED FedRAMP POA&M**: `{os.path.basename(closed_out_path)}`",
            f"- **Total Active OPEN Entries**: **{len(open_entries)}** (*{stats['carry_over_open']} Carried Over, {stats['new_open']} Newly Detected*)",
            f"- **Entries Moved from OPEN to CLOSED**: **{len(closed_entries_moved)}** (*Total Closed Rows: {len(all_closed_entries)}*)",
            f"- **OPEN Entries with Passed SLA Date**: **{len(overdue_entries)}** of **{len(open_entries)}**",
            "",
            "## 1. Itemized OPEN POA&M Aging & SLA Status",
            "",
            "| POAM ID | Weakness Name | Asset Identifier | Risk | Original Detection Date | Age (Days Old) | Scheduled Completion Date (SLA) | SLA Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for e in sorted_open:
            age_d = int(e.get("_age_days", 0))
            past_d = int(e.get("_days_past_sla", 0))
            status_str = f"**PASSED SLA ({past_d} days overdue)**" if e.get("_is_overdue") else f"Within SLA ({abs(past_d)} days left)"
            wname = str(e.get("weakness_name", "")).replace("|", "\\|").replace("\n", " ")
            asset = str(e.get("asset_identifier", "")).replace("|", "\\|").replace("\n", ", ")
            lines.append(
                f"| `{e.get('poam_id')}` | {wname} | `{asset}` | **{e.get('original_risk_rating')}** | "
                f"`{e.get('original_detection_date')}` | **{age_d} days old** | `{e.get('scheduled_completion_date')}` | {status_str} |"
            )

        if closed_entries_moved:
            lines.extend([
                "",
                "## 2. Entries Moved from OPEN to CLOSED POA&M",
                "",
                "| POAM ID | Weakness Name | Asset Identifier | Original Detection Date | Closure Date | Closure Note |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for c in closed_entries_moved:
                wname = str(c.get("weakness_name", "")).replace("|", "\\|").replace("\n", " ")
                asset = str(c.get("asset_identifier", "")).replace("|", "\\|").replace("\n", ", ")
                comm = str(c.get("comments", "")).replace("|", "\\|").replace("\n", " ")
                lines.append(
                    f"| `{c.get('poam_id')}` | {wname} | `{asset}` | `{c.get('original_detection_date')}` | `{c.get('status_date')}` | {comm} |"
                )

        with open(summary_md_path, "w", encoding="utf-8") as mf:
            mf.write("\n".join(lines) + "\n")

    return {
        "total_open": len(open_entries),
        "overdue_count": len(overdue_entries),
        "moved_to_closed": len(closed_entries_moved),
    }


# ---------------------------------------------------------------------------
# CLI & Interactive Orchestration
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="grc transform",
        description=(
            "GRCx Standalone Scan-to-POA&M Transformer (transform_scans.py): "
            "Ingests Tenable or AWS Inspector (.csv or .xlsx) scan results, reconciles "
            "against a previous OPEN FedRAMP POA&M, moves resolved items to the CLOSED "
            "FedRAMP POA&M template, drafts missing remediation plans with official "
            "Tenable/AWS URLs, and reports SLA breaches and finding age."
        ),
    )
    parser.add_argument(
        "--scan", "-s",
        help="Path to Tenable or AWS Inspector scan results file (.csv or .xlsx).",
    )
    parser.add_argument(
        "--scanner",
        choices=["auto", "tenable", "inspector"],
        default="auto",
        help="Scanner source type (default: auto-detect from column headers).",
    )
    parser.add_argument(
        "--previous-open", "-p",
        default=None,
        help="Path to previously filled-out OPEN FedRAMP POA&M (.xlsx) for Open->Closed delta reconciliation (or 'none' for initial baseline).",
    )
    parser.add_argument(
        "--no-previous",
        action="store_true",
        help="Skip prompting for a previously filled-out OPEN FedRAMP POA&M (treat run as an initial baseline).",
    )
    parser.add_argument(
        "--previous-closed",
        default=None,
        help="Optional path to existing CLOSED FedRAMP POA&M (.xlsx) to append newly closed entries.",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Directory where finished OPEN and CLOSED FedRAMP POA&M .xlsx files will be saved (default: evidence/poam-transform/).",
    )
    parser.add_argument(
        "--open-template",
        default=DEFAULT_OPEN_TEMPLATE,
        help="Path to base OPEN FedRAMP POA&M template (.xlsx).",
    )
    parser.add_argument(
        "--closed-template",
        default=DEFAULT_CLOSED_TEMPLATE,
        help="Path to base CLOSED LEGACY FedRAMP POA&M template (.xlsx).",
    )
    parser.add_argument(
        "--poc",
        default="Cloud Security / GRC Team",
        help="Default Point of Contact (Column I) for newly detected POA&M items.",
    )
    parser.add_argument(
        "--draft-remediations",
        choices=["ask", "y", "n"],
        default="ask",
        help="Whether to auto-draft missing Remediation Plans with Tenable/AWS URLs ('ask' prompts interactively).",
    )
    parser.add_argument(
        "--include-scanner-solutions",
        action="store_true",
        help="Pre-fill Column K directly from raw scanner Solution text before checking for missing remediation plans.",
    )
    parser.add_argument(
        "--reference-date",
        default=None,
        help="Override reference date (YYYY-MM-DD) for SLA and finding age calculation (default: today).",
    )

    args = parser.parse_args()

    today = parse_any_date(args.reference_date) if args.reference_date else datetime.date.today()
    if not today:
        today = datetime.date.today()

    # 1. Resolve Scan Input Path (interactive prompt if not passed via --scan)
    scan_path = args.scan
    if not scan_path:
        if sys.stdin.isatty():
            print("\n=== GRCx Standalone FedRAMP POA&M Scan Transformer ===")
            scan_path = input("[?] Enter path to Tenable or AWS Inspector scan file (.csv or .xlsx): ").strip().strip("'\"")
        if not scan_path:
            parser.error("A scan file (.csv or .xlsx) is required. Pass --scan <path> or enter it interactively.")

    if not os.path.isfile(scan_path):
        print(f"[ERROR] Scan file not found: {scan_path}", file=sys.stderr)
        return 1

    # 2. Request Previously Filled-Out OPEN FedRAMP POA&M Form (if not provided via flag)
    prev_open_path = args.previous_open
    if prev_open_path and prev_open_path.strip().lower() in ("none", "null", "false", "-"):
        prev_open_path = ""
    elif prev_open_path is None and not args.no_previous and sys.stdin.isatty():
        user_prev = input(
            "[?] Enter path to previously filled-out OPEN FedRAMP POA&M (.xlsx) to reconcile\n"
            "    Open -> Closed transitions (or press Enter if none / initial baseline): "
        ).strip().strip("'\"")
        if user_prev:
            prev_open_path = user_prev

    if prev_open_path and not os.path.isfile(prev_open_path):
        print(f"[ERROR] Previous OPEN POA&M file not found: {prev_open_path}", file=sys.stderr)
        return 1

    # 3. Load and Normalize Scan Findings
    records = load_scan_records(scan_path)
    scanner_type = detect_scanner_type(records, None if args.scanner == "auto" else args.scanner)
    print(f"[*] Loaded {len(records)} scan rows from '{os.path.basename(scan_path)}' (Detected source: {scanner_type.upper()})")

    scan_entries = normalize_scan_rows(
        records=records,
        scanner_type=scanner_type,
        scan_filename=os.path.basename(scan_path),
        today=today,
        default_poc=args.poc,
    )

    # Unless --include-scanner-solutions is explicitly passed, treat new scan entries without
    # an analyst-approved POA&M remediation plan (or with missing remediation URLs) as needing
    # a remediation plan check so the analyst is prompted whether GRCx should draft them with URLs.
    if not args.include_scanner_solutions:
        for se in scan_entries:
            se["remediation_plan"] = ""

    # 4. Load Previous OPEN & CLOSED POA&M Workbooks and Reconcile Open -> Closed
    prev_open_entries = load_existing_poam_workbook(prev_open_path, is_closed_template=False) if prev_open_path else []
    if prev_open_path:
        print(f"[*] Loaded {len(prev_open_entries)} existing entries from previous OPEN POA&M: {os.path.basename(prev_open_path)}")

    prev_closed_entries = (
        load_existing_poam_workbook(args.previous_closed, is_closed_template=True)
        if args.previous_closed and os.path.isfile(args.previous_closed)
        else []
    )

    final_open, newly_closed, stats = reconcile_poam_entries(
        prev_open_entries=prev_open_entries,
        new_scan_entries=scan_entries,
        today=today,
    )
    all_closed = prev_closed_entries + newly_closed

    # 5. Check for Missing Remediation Plans (Column K) and Prompt User [y/n]
    missing_remediation_entries = [
        e for e in final_open if not str(e.get("remediation_plan", "")).strip()
    ]

    if missing_remediation_entries:
        choice = args.draft_remediations
        if choice == "ask":
            if sys.stdin.isatty():
                ans = input(
                    f"\n[!] {len(missing_remediation_entries)} of {len(final_open)} OPEN POA&M entries are missing a Remediation Plan (Column K).\n"
                    f"    Would you like GRCx to draft missing remediation plans with official Tenable/AWS remediation links? (y/n): "
                ).strip().lower()
                choice = "y" if ans.startswith("y") else "n"
            else:
                choice = "y"

        if choice == "y":
            for e in missing_remediation_entries:
                e["remediation_plan"] = build_remediation_plan_with_urls(e)
            print(f"[+] Drafted {len(missing_remediation_entries)} Remediation Plans with official {scanner_type.upper()} remediation URLs.")
        else:
            print(f"[*] Left {len(missing_remediation_entries)} missing Remediation Plans blank per user selection.")

    # 6. Write Finished OPEN and CLOSED FedRAMP POA&M Workbooks
    scan_stem = os.path.splitext(os.path.basename(scan_path))[0]
    out_dir = args.output_dir or os.path.join(REPO_ROOT, "evidence", f"poam-{scan_stem}")
    os.makedirs(out_dir, exist_ok=True)

    open_out_path = os.path.join(out_dir, "OPEN FedRAMP-POAM.xlsx")
    closed_out_path = os.path.join(out_dir, "CLOSED FedRAMP-POAM.xlsx")
    summary_md_path = os.path.join(out_dir, "poam_transform_summary.md")

    write_poam_workbook(
        template_path=args.open_template,
        output_path=open_out_path,
        entries=final_open,
        is_closed_template=False,
    )
    write_poam_workbook(
        template_path=args.closed_template,
        output_path=closed_out_path,
        entries=all_closed,
        is_closed_template=True,
    )

    # 7. Run SLA Breach & Finding Age Analysis and Print Report
    analyze_and_report_sla(
        open_entries=final_open,
        closed_entries_moved=newly_closed,
        all_closed_entries=all_closed,
        stats=stats,
        today=today,
        open_out_path=open_out_path,
        closed_out_path=closed_out_path,
        summary_md_path=summary_md_path,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())

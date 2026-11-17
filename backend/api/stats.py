"""
Statistics, Device Inventory & Vulnerabilities API Router.
Provides aggregated telemetry for the Overview Dashboard, Asset Inventory,
and Vulnerability Center with resilient exception handling and logging.
"""

import json
import logging
import sqlite3
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException

from app.database.db import (
    DEFAULT_DB_PATH,
    get_db_connection,
    list_scans,
    list_assets,
    initialize_database,
)

logger = logging.getLogger("cctv_scanner.stats")
router = APIRouter(prefix="/api", tags=["Statistics & Vulnerabilities"])


def calculate_overview_statistics(db_path=None) -> Dict[str, Any]:
    """
    Compute comprehensive metrics for the Overview Dashboard.
    Resilient to empty databases, missing fields, or malformed result JSON.
    """
    if db_path is None:
        db_path = DEFAULT_DB_PATH

    initialize_database(db_path)

    # 1. Fetch assets and scans
    try:
        scans = list_scans(limit=100, db_path=db_path)
    except Exception as e:
        logger.warning("Could not load scans for overview stats: %s", e)
        scans = []

    try:
        assets = list_assets(limit=1000, db_path=db_path)
    except Exception as e:
        logger.warning("Could not load assets for overview stats: %s", e)
        assets = []

    # 2. Compute total unique discovered devices across assets & scans
    all_ip_set = {a.get("ip") for a in assets if a.get("ip")}
    for s in scans:
        tgt = s.get("target")
        if tgt:
            all_ip_set.add(tgt)
    total_discovered = len(all_ip_set)

    # 3. Count online devices
    online_count = sum(1 for a in assets if str(a.get("status", "")).lower() == "online")
    if online_count == 0 and scans:
        online_count = sum(1 for s in scans if str(s.get("scan_status", "")).lower() == "up")

    # 4. Track vulnerable devices, findings severity & vendor distribution
    vulnerable_targets = set()
    critical_count = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    vendor_counts: Dict[str, int] = {}
    risk_scores: List[int] = []
    risk_trend: List[Dict[str, Any]] = []

    # Check assets for vulnerable posture
    for a in assets:
        ip = a.get("ip")
        r_score = a.get("risk_score") or 0
        r_level = str(a.get("risk_level") or "INFO").upper()
        if (r_score > 0 or r_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")) and ip:
            vulnerable_targets.add(ip)

        v = a.get("vendor")
        if v and v != "Unknown":
            vendor_counts[v] = vendor_counts.get(v, 0) + 1

    # Fetch scan telemetry and parse result JSON
    try:
        with get_db_connection(db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT id, target, generated_at, scan_status, device_type, vendor, risk_score, risk_level, result_json "
                "FROM scans ORDER BY id ASC"
            ).fetchall()

            for row in rows:
                target = row["target"] or "Unknown"
                score = int(row["risk_score"] or 0)
                level = str(row["risk_level"] or "INFO").upper()
                vendor = row["vendor"] or "Unknown"

                risk_scores.append(score)
                if vendor and vendor != "Unknown":
                    vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

                if score > 0 or level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    if target != "Unknown":
                        vulnerable_targets.add(target)

                # Parse JSON findings payload safely
                raw_json = row["result_json"]
                parsed_counts = False
                if raw_json:
                    try:
                        payload = json.loads(raw_json)
                        if isinstance(payload, dict):
                            risk_meta = payload.get("risk", {})
                            if isinstance(risk_meta, dict):
                                counts = risk_meta.get("severity_counts", {})
                                if isinstance(counts, dict) and counts:
                                    for sev, cnt in counts.items():
                                        sev_upper = str(sev).upper()
                                        if sev_upper in severity_counts:
                                            try:
                                                severity_counts[sev_upper] += int(cnt or 0)
                                            except (ValueError, TypeError):
                                                pass
                                    try:
                                        critical_count += int(counts.get("CRITICAL", 0) or 0)
                                    except (ValueError, TypeError):
                                        pass
                                    parsed_counts = True

                            # If severity_counts was not present in risk, check findings lists
                            if not parsed_counts:
                                all_findings = []
                                if isinstance(payload.get("security_findings"), list):
                                    all_findings.extend(payload["security_findings"])
                                if isinstance(payload.get("http_findings"), list):
                                    all_findings.extend(payload["http_findings"])
                                if isinstance(payload.get("cve_candidates"), list):
                                    all_findings.extend(payload["cve_candidates"])

                                for f in all_findings:
                                    if isinstance(f, dict):
                                        f_sev = str(f.get("severity", "INFO")).upper()
                                        if f_sev in severity_counts:
                                            severity_counts[f_sev] += 1
                                        if f_sev == "CRITICAL":
                                            critical_count += 1
                                parsed_counts = bool(all_findings)
                    except Exception as json_err:
                        logger.debug("Failed parsing result_json for scan #%s: %s", row["id"], json_err)

                # Fallback if result_json was missing or empty
                if not parsed_counts:
                    if level == "CRITICAL":
                        critical_count += 1
                        severity_counts["CRITICAL"] += 1
                    elif level in severity_counts and score > 0:
                        severity_counts[level] += 1

                gen_at = str(row["generated_at"] or "")
                date_str = gen_at[:16].replace("T", " ") if gen_at else "Unknown"

                risk_trend.append({
                    "id": row["id"],
                    "target": target,
                    "date": date_str,
                    "score": score,
                    "level": level
                })
    except Exception as db_err:
        logger.error("Error querying scans for overview stats: %s", db_err, exc_info=True)

    # 5. Calculate overall security score (100 = flawless, lower = high aggregate risk)
    if risk_scores:
        avg_risk = sum(risk_scores) / len(risk_scores)
        overall_security_score = max(0, min(100, round(100 - avg_risk)))
    else:
        overall_security_score = 100

    # 6. Format vendor distribution for Recharts
    vendor_distribution = [
        {"name": v, "count": count} for v, count in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)
    ]
    if not vendor_distribution and assets:
        disc_vendors: Dict[str, int] = {}
        for a in assets:
            v = a.get("vendor") or "Unknown"
            disc_vendors[v] = disc_vendors.get(v, 0) + 1
        vendor_distribution = [
            {"name": v, "count": c} for v, c in sorted(disc_vendors.items(), key=lambda x: x[1], reverse=True)
        ]

    return {
        "total_discovered_devices": total_discovered,
        "online_devices": online_count,
        "vulnerable_devices": len(vulnerable_targets),
        "critical_vulnerabilities": critical_count,
        "overall_security_score": overall_security_score,
        "severity_breakdown": severity_counts,
        "vendor_distribution": vendor_distribution,
        "risk_trend": risk_trend[-15:],  # Most recent 15 data points
        "recent_scans": scans[:10]
    }


def get_all_vulnerabilities_data(db_path=None) -> Dict[str, Any]:
    """
    Retrieve all security findings & candidate CVEs across all scans,
    with clear candidate vs confirmed labels.
    """
    if db_path is None:
        db_path = DEFAULT_DB_PATH

    initialize_database(db_path)
    findings_list = []
    seen = set()

    try:
        with get_db_connection(db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT id, target, generated_at, result_json FROM scans ORDER BY id DESC"
            ).fetchall()

            for row in rows:
                scan_id = row["id"]
                target = row["target"] or "Unknown"
                date = row["generated_at"] or ""

                raw_json = row["result_json"]
                if not raw_json:
                    continue

                try:
                    payload = json.loads(raw_json)
                    if not isinstance(payload, dict):
                        continue
                except Exception as json_err:
                    logger.debug("Failed parsing result_json in vulnerabilities for scan #%s: %s", scan_id, json_err)
                    continue

                # 1. Static exposure findings
                for f in payload.get("security_findings", []):
                    if not isinstance(f, dict):
                        continue
                    key = (target, f.get("id"), f.get("title"))
                    if key in seen:
                        continue
                    seen.add(key)
                    findings_list.append({
                        "scan_id": scan_id,
                        "target": target,
                        "date": date,
                        "id": f.get("id", "SEC-001"),
                        "title": f.get("title", "Security Finding"),
                        "severity": str(f.get("severity", "MEDIUM")).upper(),
                        "category": "Exposure / Configuration",
                        "is_candidate": False,
                        "confirmed_vulnerability": bool(f.get("confirmed_vulnerability", False)),
                        "evidence": f.get("evidence", ""),
                        "description": f.get("description", ""),
                        "remediation": f.get("remediation", ""),
                        "port": f.get("port"),
                        "references": f.get("references") or []
                    })

                # 2. HTTP header findings
                for h in payload.get("http_findings", []):
                    if not isinstance(h, dict):
                        continue
                    key = (target, h.get("id"), h.get("port"))
                    if key in seen:
                        continue
                    seen.add(key)
                    findings_list.append({
                        "scan_id": scan_id,
                        "target": target,
                        "date": date,
                        "id": h.get("id", "HTTP-001"),
                        "title": h.get("title", "Missing Security Header"),
                        "severity": str(h.get("severity", "LOW")).upper(),
                        "category": "HTTP Security Header",
                        "is_candidate": False,
                        "confirmed_vulnerability": bool(h.get("confirmed_vulnerability", False)),
                        "evidence": h.get("evidence", ""),
                        "description": f"Audited response on {h.get('url', '')}." if h.get("url") else "Audited HTTP response headers.",
                        "remediation": h.get("remediation", ""),
                        "port": h.get("port"),
                        "references": h.get("references") or []
                    })

                # 3. CVE Candidates
                for c in payload.get("cve_candidates", []):
                    if not isinstance(c, dict):
                        continue
                    cve_id = c.get("cve_id", "CVE-CANDIDATE")
                    key = (target, cve_id, c.get("port"))
                    if key in seen:
                        continue
                    seen.add(key)
                    findings_list.append({
                        "scan_id": scan_id,
                        "target": target,
                        "date": date,
                        "id": cve_id,
                        "title": f"Candidate CVE: {cve_id}",
                        "severity": str(c.get("severity", "HIGH")).upper(),
                        "category": "Local CVE Intelligence",
                        "is_candidate": True,
                        "requires_manual_validation": bool(c.get("requires_manual_validation", True)),
                        "confirmed_vulnerability": bool(c.get("confirmed_vulnerability", False)),
                        "evidence": f"Detected {c.get('product_detected')} version {c.get('version_detected')} on port {c.get('port')}.",
                        "description": c.get("description", ""),
                        "remediation": "Verify firmware release notes against vendor advisory. Upgrade to a patched vendor firmware version if affected.",
                        "port": c.get("port"),
                        "references": c.get("references") or []
                    })
    except Exception as e:
        logger.error("Error retrieving vulnerabilities: %s", e, exc_info=True)

    # Sort: CRITICAL, HIGH, MEDIUM, LOW, INFO
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings_list.sort(key=lambda x: sev_rank.get(x["severity"], 5))

    return {
        "count": len(findings_list),
        "findings": findings_list
    }


# --- FASTAPI ENDPOINTS ---

@router.get("/stats/overview")
def get_overview_statistics():
    """Retrieve high-level metrics for the Overview Dashboard."""
    try:
        return calculate_overview_statistics()
    except Exception as e:
        logger.error("Unexpected error in get_overview_statistics: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to calculate overview statistics: {str(e)}")


@router.get("/inventory")
def get_device_inventory():
    """Consolidated table of devices from persistent SQLite assets."""
    try:
        devices = list_assets(limit=1000)
        return {
            "count": len(devices),
            "devices": devices
        }
    except Exception as e:
        logger.error("Error in get_device_inventory: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerabilities")
def get_all_vulnerabilities():
    """All security findings & candidate CVEs across all scans."""
    try:
        return get_all_vulnerabilities_data()
    except Exception as e:
        logger.error("Error in get_all_vulnerabilities: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

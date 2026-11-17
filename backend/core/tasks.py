import time
import uuid
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, Any, List

from app.discovery.network_discovery import discover_hosts
from app.discovery.nmap_scanner import scan_host
from app.pipeline import analyze_scan, save_report
from app.database.db import (
    save_scan,
    get_scan,
    list_scans,
    initialize_database,
    upsert_asset,
    list_assets,
    get_asset_by_ip
)

executor = ThreadPoolExecutor(max_workers=4)

# In-memory task tracker
scan_tasks: Dict[str, Dict[str, Any]] = {}
discovery_tasks: Dict[str, Dict[str, Any]] = {}

# In-memory cache for discovered hosts from latest discoveries (synced with SQLite assets)
discovered_inventory: Dict[str, Dict[str, Any]] = {}


def get_task_status(task_id: str) -> Dict[str, Any] | None:
    return scan_tasks.get(task_id)


def get_discovery_task_status(task_id: str) -> Dict[str, Any] | None:
    return discovery_tasks.get(task_id)


def get_all_discovered_hosts() -> List[Dict[str, Any]]:
    # Source directly from persistent SQLite assets
    return list_assets()


def run_discovery_worker(task_id: str, network: str):
    task = discovery_tasks[task_id]
    task["status"] = "running"
    task["stage"] = "discovering"
    task["progress"] = 20
    task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Validating CIDR: {network}")

    def log_callback(msg: str):
        task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    try:
        ipaddress.ip_network(network, strict=False)
        task["progress"] = 40

        hosts = discover_hosts(network, allow_fallback=True, log_callback=log_callback)

        task["progress"] = 80
        task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Discovery complete. Found {len(hosts)} active host(s).")

        # Persist discovered hosts to SQLite assets table and update memory cache
        for host in hosts:
            ip = host.get("ip")
            if ip:
                mac = host.get("mac") or "Unknown"
                vendor = host.get("vendor") or "Unknown"
                hostname = host.get("hostname")
                now_iso = datetime.now(timezone.utc).isoformat()
                upsert_asset({
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "status": "online",
                    "last_discovered": now_iso
                })
                discovered_inventory[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "discovered_at": now_iso,
                    "status": "online"
                }

        task["progress"] = 100
        task["status"] = "completed"
        task["stage"] = "completed"
        task["result"] = hosts

    except Exception as e:
        task["status"] = "failed"
        task["stage"] = "failed"
        task["progress"] = 100
        task["error"] = str(e)
        task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {str(e)}")


def start_discovery_task(network: str) -> str:
    task_id = f"disc_{uuid.uuid4().hex[:10]}"
    discovery_tasks[task_id] = {
        "task_id": task_id,
        "network": network,
        "status": "pending",
        "stage": "queued",
        "progress": 5,
        "message": f"Discovery task queued for network {network}",
        "logs": [f"[{datetime.now().strftime('%H:%M:%S')}] Discovery queued for {network}"],
        "result": [],
        "error": None
    }
    executor.submit(run_discovery_worker, task_id, network)
    return task_id


def run_scan_worker(task_id: str, target: str):
    task = scan_tasks[task_id]
    task["status"] = "running"
    task["stage"] = "service_scanning"
    task["progress"] = 20
    task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Initiating Nmap service & version scan (-sV) against {target}...")

    try:
        # Step 1: Nmap Scan
        scan_result = scan_host(target)
        open_ports_count = len([p for p in scan_result.get("ports", []) if p.get("state") == "open"])
        task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Port scan finished. Status: {scan_result.get('status')}. Detected {open_ports_count} open port(s).")
        task["progress"] = 50
        task["stage"] = "fingerprinting"

        # Step 2: Assessment & Fingerprinting Pipeline
        task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Running CCTV fingerprinting, HTTP checks, and local CVE matching...")
        task["progress"] = 75
        task["stage"] = "vulnerability_assessment"

        report = analyze_scan(scan_result)

        fp = report.get("fingerprint", {})
        risk = report.get("risk", {})
        task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Classification: {fp.get('device_type')} (Confidence: {fp.get('confidence')}%). Vendor: {fp.get('vendor')}.")
        task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Risk Score: {risk.get('risk_score')}/100 ({risk.get('risk_level')}). Unique findings: {risk.get('finding_count')}.")

        # Step 3: Database & File Persistence
        task["stage"] = "saving"
        task["progress"] = 90
        initialize_database()
        scan_id = save_scan(report)
        try:
            save_report(report)
        except Exception:
            pass

        # Update persistent asset inventory in SQLite
        open_ports_list = [p.get("port") for p in scan_result.get("ports", []) if p.get("state") == "open"]
        now_scanned_iso = datetime.now(timezone.utc).isoformat()
        status_val = "online" if scan_result.get("status") == "up" else "offline"

        upsert_asset({
            "ip": target,
            "vendor": fp.get("vendor", "Unknown"),
            "device_category": fp.get("device_type", "Unknown"),
            "confidence_level": "High" if fp.get("confidence", 0) >= 80 else ("Medium" if fp.get("confidence", 0) >= 40 else "Low"),
            "confidence_score": fp.get("confidence", 0),
            "risk_score": risk.get("risk_score", 0),
            "risk_level": risk.get("risk_level", "INFO"),
            "open_ports": open_ports_list,
            "last_scanned": now_scanned_iso,
            "status": status_val,
            "last_scan_id": scan_id
        })

        discovered_inventory[target] = {
            "ip": target,
            "mac": discovered_inventory.get(target, {}).get("mac", "Unknown"),
            "vendor": fp.get("vendor", "Unknown"),
            "device_type": fp.get("device_type", "Unknown"),
            "risk_score": risk.get("risk_score", 0),
            "risk_level": risk.get("risk_level", "INFO"),
            "open_ports": open_ports_list,
            "last_scanned": now_scanned_iso,
            "status": status_val,
            "last_scan_id": scan_id
        }

        task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Assessment saved with Database ID #{scan_id}.")
        task["progress"] = 100
        task["status"] = "completed"
        task["stage"] = "completed"
        task["scan_id"] = scan_id
        task["message"] = f"Scan completed successfully. Risk Level: {risk.get('risk_level')} ({risk.get('risk_score')}/100)."

    except Exception as e:
        task["status"] = "failed"
        task["stage"] = "failed"
        task["error"] = str(e)
        task["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Execution failed: {str(e)}")
        task["message"] = f"Scan failed: {str(e)}"


def start_scan_task(target: str) -> str:
    task_id = f"scan_{uuid.uuid4().hex[:10]}"
    scan_tasks[task_id] = {
        "task_id": task_id,
        "target": target,
        "status": "pending",
        "stage": "queued",
        "progress": 5,
        "message": f"Scan queued for target {target}",
        "logs": [f"[{datetime.now().strftime('%H:%M:%S')}] Scan registered for target {target}"],
        "scan_id": None,
        "error": None
    }
    executor.submit(run_scan_worker, task_id, target)
    return task_id

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from app.database.db import (
    list_assets,
    get_asset,
    get_scan,
    save_identification_result,
    update_asset_override,
    delete_asset
)
from app.discovery.network_telemetry import get_default_route_info
from app.fingerprint.device_identifier import classify_device, probe_device

router = APIRouter(prefix="/api/assets", tags=["Assets"])


class AssetOverrideRequest(BaseModel):
    category: str


def run_asset_identification(asset: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to gather multi-source evidence and execute the identification engine."""
    ip = asset["ip"]
    gateway, _ = get_default_route_info()

    # 1. Historical port/service data from previous scans if available
    scan_ports = []
    if asset.get("last_scan_id"):
        scan_record = get_scan(asset["last_scan_id"])
        if scan_record and "result" in scan_record:
            scan_ports = scan_record["result"].get("services", [])

    # 2. Safe, non-destructive probe for active ports, HTTP headers, and RTSP
    live_probe = probe_device(ip, gateway_ip=gateway)

    # 3. Merge ports from scan and live probe
    ports_map = {}
    for p in scan_ports:
        ports_map[p.get("port")] = p
    for p in live_probe.get("ports", []):
        port_num = p.get("port")
        if port_num not in ports_map:
            ports_map[port_num] = p

    evidence = {
        "ip": ip,
        "mac": asset.get("mac"),
        "vendor": asset.get("vendor"),
        "hostname": live_probe.get("hostname") or asset.get("hostname"),
        "ports": list(ports_map.values()),
        "http_banners": live_probe.get("http_banners", {}),
        "rtsp_banner": live_probe.get("rtsp_banner"),
        "gateway_ip": gateway,
        "is_gateway": (ip == gateway) if gateway else False
    }

    ident_res = classify_device(evidence)
    ident_dict = ident_res.to_dict()

    save_identification_result(asset["id"], ident_dict)
    return get_asset(asset["id"]) or asset


@router.get("")
def get_assets(
    category: Optional[str] = Query(None, description="Filter by device category e.g. 'IP CCTV Camera', 'Router'"),
    status: Optional[str] = Query(None, description="Filter by status e.g. 'online', 'offline'"),
    limit: int = Query(500, ge=1, le=1000)
):
    """
    List all discovered and assessed network assets persisted in SQLite.
    Survives application and system restarts.
    """
    try:
        items = list_assets(category_filter=category, status_filter=status, limit=limit)
        return {
            "count": len(items),
            "assets": items,
            "devices": items  # Compatibility alias for frontend inventory consumers
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/identify-all")
def identify_all_assets():
    """
    Run the Phase 3 multi-vendor identification engine on all discovered assets in SQLite.
    Preserves user overrides and persists evidence, model, and confidence scores.
    """
    try:
        assets = list_assets(limit=1000)
        identified_list = []
        for a in assets:
            updated = run_asset_identification(a)
            identified_list.append(updated)

        return {
            "count": len(identified_list),
            "message": f"Successfully identified {len(identified_list)} network asset(s)",
            "assets": identified_list
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{asset_id}")
def get_asset_by_id(asset_id: int):
    """Retrieve detailed asset profile by ID."""
    asset = get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.post("/{asset_id}/identify")
def identify_single_asset(asset_id: int):
    """
    Run the Phase 3 multi-vendor identification engine on a specific discovered asset.
    """
    asset = get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    updated = run_asset_identification(asset)
    return {
        "success": True,
        "message": f"Asset {asset.get('ip')} identified as {updated.get('effective_category')}",
        "asset": updated
    }


@router.get("/{asset_id}/identification")
def get_asset_identification_details(asset_id: int):
    """Retrieve granular identification evidence, signals, and confidence breakdown."""
    asset = get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return {
        "asset_id": asset["id"],
        "ip": asset["ip"],
        "mac": asset["mac"],
        "effective_category": asset["effective_category"],
        "detected_category": asset.get("device_category"),
        "manual_override_category": asset.get("manual_override_category"),
        "vendor": asset["vendor"],
        "model": asset.get("model"),
        "confidence_score": asset.get("confidence_score", 0),
        "confidence_level": asset.get("confidence_level", "Unknown"),
        "evidence": asset.get("evidence", []),
        "inconclusive_signals": asset.get("inconclusive_signals", []),
        "last_identified": asset.get("last_identified")
    }


@router.post("/{asset_id}/override-type")
def set_asset_manual_override(asset_id: int, request: AssetOverrideRequest):
    """Set or update user classification override for an asset."""
    category = request.category.strip()
    if not category:
        raise HTTPException(status_code=400, detail="Category cannot be empty")

    success = update_asset_override(asset_id, category)
    if not success:
        raise HTTPException(status_code=404, detail="Asset not found")

    updated = get_asset(asset_id)
    return {
        "success": True,
        "message": f"Asset classification updated to '{category}'",
        "asset": updated
    }


@router.delete("/{asset_id}")
def remove_asset(asset_id: int):
    """Remove an asset from the persistent inventory."""
    success = delete_asset(asset_id)
    if not success:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {
        "success": True,
        "message": f"Asset {asset_id} removed"
    }

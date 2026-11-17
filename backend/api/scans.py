import ipaddress
from fastapi import APIRouter, HTTPException
from backend.schemas.scan_models import ScanRequest
from backend.core.tasks import start_scan_task, get_task_status
from app.database.db import get_scan

router = APIRouter(prefix="/api/scans", tags=["Scans"])


@router.post("/start")
def start_scan(request: ScanRequest):
    target = request.target.strip()
    try:
        ipaddress.ip_address(target)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid target IP address format.")

    task_id = start_scan_task(target)
    return {
        "task_id": task_id,
        "target": target,
        "status": "pending",
        "message": f"Scan initiated for target {target}"
    }


@router.get("/tasks/{task_id}")
def check_scan_task(task_id: str):
    task = get_task_status(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    return task


@router.get("/{scan_id}")
def get_scan_details(scan_id: int):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found in database")
    return scan

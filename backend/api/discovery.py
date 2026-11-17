import ipaddress
from fastapi import APIRouter, HTTPException
from backend.schemas.scan_models import DiscoveryRequest
from backend.core.tasks import start_discovery_task, get_discovery_task_status, get_all_discovered_hosts
from app.discovery.network_telemetry import get_network_info

router = APIRouter(prefix="/api/discovery", tags=["Discovery"])


@router.post("/start")
def start_discovery(request: DiscoveryRequest):
    network = request.network.strip()
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid CIDR network format. Example: 192.168.1.0/24")

    task_id = start_discovery_task(network)
    return {
        "task_id": task_id,
        "network": network,
        "status": "pending",
        "message": f"Network discovery initiated for {network}"
    }


@router.get("/tasks/{task_id}")
def check_discovery_task(task_id: str):
    task = get_discovery_task_status(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Discovery task not found")
    return task


@router.get("/default-network")
def get_default_network():
    info = get_network_info()
    if info.get("cidr"):
        return {
            "network": info["cidr"],
            "local_ip": info.get("ip") or "127.0.0.1",
            "interface": info.get("active_interface"),
            "gateway": info.get("gateway"),
            "ssid": info.get("ssid")
        }
    return {"network": "192.168.0.0/24", "local_ip": "127.0.0.1"}


@router.get("/hosts")
def list_discovered_hosts():

    return {
        "hosts": get_all_discovered_hosts()
    }

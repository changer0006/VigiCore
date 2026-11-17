from fastapi import APIRouter
from app.discovery.network_telemetry import get_network_info, list_all_interfaces, get_nmap_info

router = APIRouter(prefix="/api/network", tags=["Network"])


@router.get("/info")
def get_system_network_info():
    """
    Dynamic telemetry for local macOS network environment.
    Returns default interface, IP, subnet mask, calculated CIDR, gateway, Wi-Fi SSID, and Nmap status.
    """
    return get_network_info()


@router.get("/interfaces")
def get_all_network_interfaces():
    """
    List all active network interfaces with IP configurations.
    """
    return {
        "interfaces": list_all_interfaces()
    }


@router.get("/nmap")
def check_nmap_readiness():
    """
    Verify Nmap binary availability and version.
    """
    return get_nmap_info()

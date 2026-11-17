import ipaddress
import os
import re
import socket
import subprocess
from app.discovery.network_discovery import (
    get_nmap_path,
    check_privileged_nmap,
    get_nmap_privilege_guidance,
)


def get_default_route_info() -> tuple[str | None, str | None]:
    """
    Dynamically discover the default gateway IP and egress network interface on macOS.
    Does not hardcode 'en0'.
    """
    gateway = None
    iface = None

    # Primary method on macOS: route -n get default
    try:
        proc = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            check=False
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.strip().split(":", 1)
                if len(parts) == 2:
                    k = parts[0].strip()
                    v = parts[1].strip()
                    if k == "gateway":
                        gateway = v
                    elif k == "interface":
                        iface = v
    except Exception:
        pass

    # Fallback method on macOS: netstat -rn -f inet
    if not gateway or not iface:
        try:
            proc = subprocess.run(
                ["netstat", "-rn", "-f", "inet"],
                capture_output=True,
                text=True,
                check=False
            )
            for line in proc.stdout.splitlines():
                tokens = line.split()
                if len(tokens) >= 4 and tokens[0] == "default":
                    gateway = tokens[1]
                    iface = tokens[3]
                    break
        except Exception:
            pass

    return gateway, iface


def get_interface_details(iface_name: str) -> dict:
    """Extract IPv4, netmask, CIDR, MAC, and status for a specific network interface."""
    details = {
        "interface": iface_name,
        "ip": None,
        "netmask": None,
        "cidr": None,
        "broadcast": None,
        "mac": None,
        "is_active": False
    }

    if not iface_name:
        return details

    try:
        proc = subprocess.run(
            ["ifconfig", iface_name],
            capture_output=True,
            text=True,
            check=False
        )
        if proc.returncode != 0:
            return details

        stdout = proc.stdout
        for line in stdout.splitlines():
            line_str = line.strip()

            if "status: active" in line_str:
                details["is_active"] = True

            elif line_str.startswith("ether "):
                parts = line_str.split()
                if len(parts) >= 2:
                    details["mac"] = parts[1].strip()

            elif line_str.startswith("inet "):
                # Example: inet 192.168.0.102 netmask 0xffffff00 broadcast 192.168.0.255
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)", line_str)
                if m:
                    ip_str = m.group(1)
                    hex_mask = int(m.group(2), 16)
                    netmask_str = str(ipaddress.IPv4Address(hex_mask))
                    try:
                        net_obj = ipaddress.IPv4Network(f"{ip_str}/{netmask_str}", strict=False)
                        details["ip"] = ip_str
                        details["netmask"] = netmask_str
                        details["cidr"] = str(net_obj)
                    except Exception:
                        pass

                b_match = re.search(r"broadcast\s+(\d+\.\d+\.\d+\.\d+)", line_str)
                if b_match:
                    details["broadcast"] = b_match.group(1)

    except Exception:
        pass

    return details


def get_wifi_ssid(iface_name: str = "en0") -> str | None:
    """Retrieve Wi-Fi SSID for the specified interface on macOS."""
    if not iface_name:
        return None

    # Method 1: ipconfig getsummary <iface>
    try:
        proc = subprocess.run(
            ["ipconfig", "getsummary", iface_name],
            capture_output=True,
            text=True,
            check=False
        )
        for line in proc.stdout.splitlines():
            line_str = line.strip()
            if line_str.startswith("SSID :"):
                ssid = line_str.split(":", 1)[1].strip()
                if ssid:
                    return ssid
    except Exception:
        pass

    # Method 2: networksetup -getairportnetwork <iface>
    try:
        proc = subprocess.run(
            ["networksetup", "-getairportnetwork", iface_name],
            capture_output=True,
            text=True,
            check=False
        )
        if "Current Wi-Fi Network:" in proc.stdout:
            return proc.stdout.split(":", 1)[1].strip()
    except Exception:
        pass

    return None


def get_nmap_info() -> dict:
    """Verify Nmap binary availability, extract version, and check privilege capabilities."""
    path = get_nmap_path()
    installed = False
    version = None
    is_privileged = False
    priv_mode = "unprivileged"

    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            installed = True
            m = re.search(r"Nmap\s+version\s+([^\s]+)", proc.stdout)
            version = m.group(1) if m else proc.stdout.splitlines()[0].strip()
            is_privileged, priv_mode = check_privileged_nmap()
    except Exception:
        pass

    guidance = get_nmap_privilege_guidance() if not is_privileged else None

    return {
        "installed": installed,
        "path": path if installed else None,
        "version": version,
        "privileged_available": is_privileged,
        "privilege_mode": priv_mode,
        "privilege_guidance": guidance
    }


def get_network_info() -> dict:
    """
    Consolidated dynamic telemetry for local macOS network.
    Dynamically resolves interface, gateway, IP, CIDR, SSID, and Nmap status.
    """
    gateway, iface = get_default_route_info()

    if not iface:
        # Fallback via UDP socket probe if route table is unusual
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                fallback_ip = s.getsockname()[0]
            parts = fallback_ip.split(".")
            return {
                "active_interface": "unknown",
                "ip": fallback_ip,
                "netmask": "255.255.255.0",
                "cidr": f"{parts[0]}.{parts[1]}.{parts[2]}.0/24",
                "gateway": gateway or f"{parts[0]}.{parts[1]}.{parts[2]}.1",
                "broadcast": None,
                "mac": None,
                "ssid": None,
                "nmap": get_nmap_info()
            }
        except Exception:
            pass

    details = get_interface_details(iface)
    ssid = get_wifi_ssid(iface)

    return {
        "active_interface": iface or "en0",
        "ip": details.get("ip"),
        "netmask": details.get("netmask"),
        "cidr": details.get("cidr"),
        "gateway": gateway,
        "broadcast": details.get("broadcast"),
        "mac": details.get("mac"),
        "ssid": ssid,
        "nmap": get_nmap_info()
    }


def list_all_interfaces() -> list[dict]:
    """Enumerate all network interfaces on the system."""
    gateway, default_iface = get_default_route_info()
    interfaces = []

    try:
        proc = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True, check=False)
        iface_names = proc.stdout.strip().split() if proc.returncode == 0 else []

        for name in iface_names:
            # Skip loopback and bridge members if no IP
            details = get_interface_details(name)
            if details.get("ip"):
                details["is_default"] = (name == default_iface)
                details["gateway"] = gateway if name == default_iface else None
                interfaces.append(details)
    except Exception:
        pass

    return interfaces

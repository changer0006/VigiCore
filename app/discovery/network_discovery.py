import os
import re
import shutil
import socket
import getpass
import ipaddress
import subprocess
import tempfile
import concurrent.futures
import xml.etree.ElementTree as ET


def get_nmap_path() -> str:
    """Find the Nmap executable binary path."""
    path = shutil.which("nmap")
    if path:
        return path
    for fallback in [
        "/opt/homebrew/bin/nmap",
        "/usr/local/bin/nmap",
        "/usr/bin/nmap",
    ]:
        if os.path.isfile(fallback) and os.access(fallback, os.X_OK):
            return fallback
    return "nmap"


def normalize_mac(mac: str | None) -> str | None:
    """Normalize MAC address to lowercase zero-padded format: aa:bb:cc:dd:ee:ff."""
    if not mac:
        return None
    clean = mac.strip().lower()
    if ":" in clean:
        parts = clean.split(":")
        if len(parts) == 6:
            try:
                return ":".join(f"{int(p, 16):02x}" for p in parts)
            except ValueError:
                pass
    elif "-" in clean:
        parts = clean.split("-")
        if len(parts) == 6:
            try:
                return ":".join(f"{int(p, 16):02x}" for p in parts)
            except ValueError:
                pass
    return clean


def is_valid_unicast_mac(mac: str | None) -> bool:
    """Validate that a MAC address is a real unicast hardware address (not broadcast or multicast)."""
    if not mac or mac == "(incomplete)":
        return False
    norm = normalize_mac(mac)
    if not norm or norm == "ff:ff:ff:ff:ff:ff" or norm == "00:00:00:00:00:00":
        return False
    # Multicast MAC addresses start with 01:00:5e (IPv4) or 33:33 (IPv6)
    if norm.startswith("01:00:5e") or norm.startswith("33:33"):
        return False
    return True


def get_local_arp_table() -> dict[str, str]:
    """
    Parse local system ARP table (arp -an on macOS/Linux).
    Extracts active IP -> normalized MAC mappings.
    Filters out (incomplete), broadcast, and multicast addresses.
    """
    arp_map = {}
    try:
        proc = subprocess.run(["arp", "-an"], capture_output=True, text=True, check=False)
        for line in proc.stdout.splitlines():
            # Example macOS line: ? (192.168.0.1) at a8:29:48:a9:3e:a0 on en0 ifscope [ethernet]
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "?" and parts[2] == "at":
                ip = parts[1].strip("()")
                raw_mac = parts[3].strip()
                if is_valid_unicast_mac(raw_mac):
                    norm_mac = normalize_mac(raw_mac)
                    if norm_mac:
                        arp_map[ip] = norm_mac
    except Exception:
        pass
    return arp_map


def lookup_oui_vendor(mac: str | None) -> str | None:
    """Look up MAC vendor in nmap-mac-prefixes if available."""
    if not mac:
        return None

    clean_prefix = re.sub(r"[^0-9a-fA-F]", "", mac)[:6].upper()
    if len(clean_prefix) < 6:
        return None

    prefix_paths = [
        "/opt/homebrew/share/nmap/nmap-mac-prefixes",
        "/usr/local/share/nmap/nmap-mac-prefixes",
        "/usr/share/nmap/nmap-mac-prefixes",
    ]

    for p in prefix_paths:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith(clean_prefix):
                            # Format: A82948 TP-Link Systems
                            return line[6:].strip()
            except Exception:
                pass
    return None


def get_local_ip() -> str | None:
    """Detect the local machine's primary IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


def check_privileged_nmap() -> tuple[bool, str]:
    """
    Detect whether privileged Nmap discovery is available.
    Returns (is_available, mode) where mode is:
      - 'root': Process running with effective UID 0.
      - 'sudo_nopasswd': Passwordless sudo available for nmap binary.
      - 'unprivileged': Running without raw packet capabilities.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True, "root"

    nmap_bin = get_nmap_path()
    try:
        # Check if sudo without password is configured for nmap (timeout prevents hanging)
        proc = subprocess.run(
            ["sudo", "-n", nmap_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False
        )
        if proc.returncode == 0:
            return True, "sudo_nopasswd"
    except Exception:
        pass

    return False, "unprivileged"


def get_nmap_privilege_guidance() -> dict:
    """
    Provide secure, narrowly-scoped administrator guidance for optional privileged ARP discovery.
    Never stores passwords or uses shell=True.
    """
    user = getpass.getuser()
    nmap_path = get_nmap_path()
    rule = f"{user} ALL=(ALL) NOPASSWD: {nmap_path}"
    return {
        "rule": rule,
        "sudoers_file": "/etc/sudoers.d/vigicore-nmap",
        "instructions": (
            "To enable Layer-2 raw ARP discovery without password prompts, "
            f"create '{rule}' in '/etc/sudoers.d/vigicore-nmap'. "
            "When running unprivileged, VigiCore automatically uses safe kernel-ARP table discovery."
        )
    }


def parse_discovery_xml(xml_source, enrich_arp: bool = True) -> list[dict]:
    """
    Parse Nmap XML output and extract live hosts with IP, MAC, and Vendor.
    Accepts an ElementTree, Element, or file path/string.
    """
    if isinstance(xml_source, ET.Element):
        root = xml_source
    elif isinstance(xml_source, ET.ElementTree):
        root = xml_source.getroot()
    elif isinstance(xml_source, str) and xml_source.strip().startswith("<"):
        root = ET.fromstring(xml_source)
    else:
        tree = ET.parse(xml_source)
        root = tree.getroot()

    hosts = []
    arp_table = None
    local_machine_ip = None

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        addresses = host.findall("address")

        ip_address = None
        mac_address = None
        vendor = None

        for address in addresses:
            address_type = address.get("addrtype")
            if address_type == "ipv4":
                ip_address = address.get("addr")
            elif address_type == "mac":
                mac_address = normalize_mac(address.get("addr"))
                vendor = address.get("vendor")

        # Extract hostname if available from Nmap XML
        hostname = None
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            first_h = hostnames_elem.find("hostname")
            if first_h is not None:
                hostname = first_h.get("name")

        if not vendor and hostname:
            vendor = hostname

        # Fallback ARP / vendor resolution for unprivileged scans
        if enrich_arp and ip_address:
            if not mac_address:
                if arp_table is None:
                    arp_table = get_local_arp_table()
                mac_address = arp_table.get(ip_address)

            if not vendor and mac_address:
                vendor = lookup_oui_vendor(mac_address)

            if not vendor:
                if local_machine_ip is None:
                    local_machine_ip = get_local_ip()
                if ip_address == local_machine_ip:
                    vendor = "Apple MacBook (Local Host)"

        hosts.append({
            "ip": ip_address,
            "mac": mac_address,
            "vendor": vendor,
            "discovery_method": "privileged_arp",
            "discovery_type": "Full ARP Discovery (Layer 2)"
        })

    return hosts


def trigger_subnet_arp_cache(net: ipaddress.IPv4Network, timeout: float = 0.08, max_workers: int = 64):
    """
    Trigger macOS kernel ARP resolution by issuing non-blocking UDP/TCP datagrams.
    Whenever the OS kernel attempts to transmit to an IP on the local subnet, the data link
    layer broadcasts an ARP who-has request. Live devices answer, populating the system ARP cache.
    Does not require raw socket or root privileges.
    """
    hosts_list = [str(ip) for ip in net.hosts()]
    target_ips = hosts_list[:512]

    def _probe_single(ip_str: str):
        # 1. Non-blocking UDP probe (DNS port 53 or WS-Discovery 3702)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(b"", (ip_str, 53))
        except Exception:
            pass

        # 2. Fast TCP connect probe to primary CCTV/Web ports
        for test_port in [80, 554, 8000]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((ip_str, test_port))
                    break
            except Exception:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(_probe_single, target_ips))


def unprivileged_discover_hosts(network: str, log_callback=None) -> list[dict]:
    """
    Safe unprivileged discovery engine for macOS / Linux.
    Does not require root or raw packet capabilities.
    1. Triggers kernel ARP queries for the subnet.
    2. Parses the system ARP table for resolved live devices.
    3. Normalizes MAC addresses and resolves OUI hardware vendors.
    4. Integrates local machine and gateway telemetry.
    """
    def _log(msg: str):
        if log_callback:
            log_callback(msg)

    _log(f"Initiating safe unprivileged kernel-ARP discovery for {network}")

    try:
        net = ipaddress.ip_network(network, strict=False)
    except Exception as e:
        raise RuntimeError(f"Invalid network CIDR '{network}': {str(e)}")

    # 1. Obtain local network telemetry for host & gateway enrichment
    from app.discovery.network_telemetry import get_network_info
    net_info = get_network_info()
    local_ip = net_info.get("ip")
    local_mac = normalize_mac(net_info.get("mac"))
    gateway_ip = net_info.get("gateway")

    # 2. Trigger kernel ARP queries across subnet hosts
    _log("Probing subnet addresses to populate local ARP cache...")
    trigger_subnet_arp_cache(net)

    # 3. Read and parse local system ARP table
    _log("Extracting resolved host entries from system ARP table...")
    arp_entries = get_local_arp_table()

    hosts_map = {}

    for ip_str, mac_str in arp_entries.items():
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            # Filter strictly to hosts within the requested CIDR
            if ip_obj in net and ip_str != str(net.network_address) and ip_str != str(net.broadcast_address):
                vendor = lookup_oui_vendor(mac_str)
                is_gateway = (ip_str == gateway_ip)
                if not vendor and is_gateway:
                    vendor = "Gateway Router"

                # Quick reverse DNS lookup
                hostname = None
                try:
                    hostname = socket.getfqdn(ip_str)
                    if hostname == ip_str:
                        hostname = None
                except Exception:
                    pass

                hosts_map[ip_str] = {
                    "ip": ip_str,
                    "mac": mac_str,
                    "vendor": vendor or ("Router / Network Device" if is_gateway else "Network Device"),
                    "hostname": hostname,
                    "discovery_method": "unprivileged_kernel_arp",
                    "discovery_type": "Unprivileged Kernel-ARP Discovery (Layer 2/3)"
                }
        except Exception:
            pass

    # 4. Include local host if inside target CIDR
    if local_ip:
        try:
            if ipaddress.ip_address(local_ip) in net:
                local_hostname = None
                try:
                    local_hostname = socket.gethostname()
                except Exception:
                    pass
                hosts_map[local_ip] = {
                    "ip": local_ip,
                    "mac": local_mac,
                    "vendor": "Apple MacBook (Local Host)",
                    "hostname": local_hostname,
                    "discovery_method": "local_telemetry",
                    "discovery_type": "Local Host Telemetry"
                }
        except Exception:
            pass

    # 5. Include gateway if detected and in CIDR, even if ARP was silent
    if gateway_ip and gateway_ip not in hosts_map:
        try:
            if ipaddress.ip_address(gateway_ip) in net:
                hosts_map[gateway_ip] = {
                    "ip": gateway_ip,
                    "mac": arp_entries.get(gateway_ip),
                    "vendor": "Gateway Router",
                    "hostname": None,
                    "discovery_method": "gateway_telemetry",
                    "discovery_type": "Default Gateway Telemetry"
                }
        except Exception:
            pass

    # Sort results by IP address for predictable display
    sorted_hosts = sorted(
        hosts_map.values(),
        key=lambda h: ipaddress.ip_address(h["ip"]) if h.get("ip") else ipaddress.ip_address("0.0.0.0")
    )

    _log(f"Unprivileged discovery complete. Found {len(sorted_hosts)} active host(s).")
    return sorted_hosts


def discover_hosts(network: str, allow_fallback: bool = True, log_callback=None) -> list[dict]:
    """
    Discover live hosts on an authorized network.
    Attempts privileged Nmap ARP discovery (-sn -PR) if available.
    Seamlessly falls back to safe unprivileged kernel-ARP discovery if permissions are restricted.
    """
    def _log(msg: str):
        if log_callback:
            log_callback(msg)

    nmap_bin = get_nmap_path()
    is_privileged, priv_mode = check_privileged_nmap()

    _log(f"Nmap privilege status: {priv_mode} (privileged={is_privileged})")

    with tempfile.TemporaryDirectory() as temp_dir:
        xml_path = os.path.join(temp_dir, "discovery.xml")
        cmd_prefix = ["sudo", "-n"] if priv_mode == "sudo_nopasswd" else []
        command = cmd_prefix + [
            nmap_bin,
            "-sn",
            "-oX",
            xml_path,
            network
        ]

        try:
            # When privileged, allow 30s; when unprivileged, use 5s so fallback activates quickly
            nmap_timeout = 30 if is_privileged else 5
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=nmap_timeout,
                check=False
            )
        except subprocess.TimeoutExpired:
            _log("Nmap scan timed out; activating safe unprivileged kernel-ARP discovery...")
            if allow_fallback:
                fallback_hosts = unprivileged_discover_hosts(network, log_callback=_log)
                if fallback_hosts:
                    return fallback_hosts
            raise RuntimeError(f"Nmap execution timed out after {nmap_timeout} seconds.")
        except FileNotFoundError:
            raise RuntimeError(
                f"Nmap executable not found at '{nmap_bin}'. Please ensure nmap is installed and added to PATH."
            )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() or f"Nmap exited with code {result.returncode}"
            raise RuntimeError(error_msg)

        # Check for permission or socket errors even if exit code was 0
        stderr_lower = (result.stderr or "").lower()
        has_perm_error = ("operation not permitted" in stderr_lower or "permission denied" in stderr_lower)

        hosts_up = []
        if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
            try:
                tree = ET.parse(xml_path)
                root = tree.getroot()
                hosts_up = [
                    h for h in root.findall("host")
                    if h.find("status") is not None and h.find("status").get("state") == "up"
                ]
            except Exception:
                pass

        if has_perm_error and len(hosts_up) == 0:
            if allow_fallback:
                _log("Nmap execution was restricted by permissions. Falling back to unprivileged discovery...")
                fallback_hosts = unprivileged_discover_hosts(network, log_callback=_log)
                if fallback_hosts:
                    return fallback_hosts
            raise RuntimeError(
                "Nmap execution was blocked by network permissions (Operation not permitted). "
                "Ensure the scanner is run with proper network privileges."
            )

        if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
            if allow_fallback:
                fallback_hosts = unprivileged_discover_hosts(network, log_callback=_log)
                if fallback_hosts:
                    return fallback_hosts
            raise RuntimeError("Nmap did not produce a valid XML scan result.")

        parsed_hosts = parse_discovery_xml(xml_path, enrich_arp=True)
        # If unprivileged Nmap missed devices (only found local host or 0), supplement with kernel ARP table
        if allow_fallback and (not parsed_hosts or len(parsed_hosts) <= 1):
            _log("Supplementing discovery results with unprivileged kernel-ARP telemetry...")
            fallback_hosts = unprivileged_discover_hosts(network, log_callback=_log)
            if fallback_hosts and len(fallback_hosts) > len(parsed_hosts):
                return fallback_hosts

        return parsed_hosts

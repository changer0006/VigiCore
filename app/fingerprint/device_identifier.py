import re
import socket
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple
from app.fingerprint.vendor_signatures import (
    SUPPORTED_CCTV_VENDORS,
    SUPPORTED_CATEGORIES,
    MAC_OUI_DATABASE,
    VENDOR_SIGNATURES,
    NON_CCTV_SIGNATURES
)


class IdentificationResult:
    def __init__(
        self,
        category: str,
        vendor: str,
        model: Optional[str],
        confidence_score: int,
        confidence_level: str,
        evidence: List[str],
        inconclusive_signals: List[str]
    ):
        self.category = category
        self.vendor = vendor
        self.model = model
        self.confidence_score = confidence_score
        self.confidence_level = confidence_level
        self.evidence = evidence
        self.inconclusive_signals = inconclusive_signals

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "vendor": self.vendor,
            "model": self.model,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level,
            "evidence": self.evidence,
            "inconclusive_signals": self.inconclusive_signals
        }


def get_confidence_level(score: int) -> str:
    """Return confidence level string based on score range."""
    if score >= 75:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 15:
        return "Low"
    return "Unknown"


def probe_single_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Fast, safe TCP connect probe."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def probe_rtsp_banner(ip: str, port: int = 554, timeout: float = 0.8) -> Optional[str]:
    """Safe, read-only RTSP OPTIONS probe to capture Server header."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            req = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CCTV-Scanner\r\n\r\n"
            s.sendall(req.encode())
            data = s.recv(1024).decode(errors="ignore")
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def probe_http_banner(ip: str, port: int, use_https: bool = False, timeout: float = 0.8) -> Dict[str, str]:
    """Safe, read-only HTTP GET probe to extract Server, WWW-Authenticate, and HTML title."""
    details = {"server": "", "auth_realm": "", "title": ""}
    proto = "https" if use_https else "http"
    url = f"{proto}://{ip}:{port}/"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) CCTV-Audit"}
    )
    try:
        ctx = None
        if use_https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            details["server"] = resp.headers.get("Server", "").strip()
            body = resp.read(2048).decode(errors="ignore")
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if m:
                details["title"] = m.group(1).strip()
    except urllib.error.HTTPError as e:
        details["server"] = e.headers.get("Server", "").strip()
        auth = e.headers.get("WWW-Authenticate", "")
        if "realm=" in auth.lower():
            m = re.search(r'realm=["\']?([^"\',]+)["\']?', auth, re.IGNORECASE)
            if m:
                details["auth_realm"] = m.group(1).strip()
    except Exception:
        pass
    return details


def probe_device(ip: str, gateway_ip: Optional[str] = None, timeout: float = 0.8) -> Dict[str, Any]:
    """Gather live network evidence for an IP without destructive actions."""
    hostname = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    target_ports = [53, 80, 443, 554, 631, 1756, 2020, 8000, 8080, 8088, 9000, 9100, 10554, 34567, 37777]
    open_ports = []
    for p in target_ports:
        if probe_single_port(ip, p, timeout=timeout):
            open_ports.append({"port": p, "state": "open"})

    http_banners = {}
    for p_info in open_ports:
        p = p_info["port"]
        if p in (80, 8080, 8088, 8000):
            banner = probe_http_banner(ip, p, use_https=False, timeout=timeout)
            if any(banner.values()):
                http_banners[p] = banner
        elif p == 443:
            banner = probe_http_banner(ip, p, use_https=True, timeout=timeout)
            if any(banner.values()):
                http_banners[p] = banner

    rtsp_banner = None
    if any(p["port"] == 554 for p in open_ports):
        rtsp_banner = probe_rtsp_banner(ip, port=554, timeout=timeout)

    return {
        "ip": ip,
        "hostname": hostname,
        "ports": open_ports,
        "http_banners": http_banners,
        "rtsp_banner": rtsp_banner,
        "gateway_ip": gateway_ip,
        "is_gateway": (ip == gateway_ip) if gateway_ip else False
    }


def classify_device(evidence: Dict[str, Any]) -> IdentificationResult:
    """
    Deterministic, transparent multi-signal device classification engine.
    Produces category, vendor, model, confidence score & level, evidence, and inconclusive signals.
    """
    ip = evidence.get("ip", "Unknown")
    mac = (evidence.get("mac") or "").lower().strip()
    mac_prefix = ":".join(mac.split(":")[:3]) if len(mac.split(":")) >= 3 else ""
    vendor_input = evidence.get("vendor") or ""
    hostname = (evidence.get("hostname") or "").lower()
    ports_data = evidence.get("ports", [])
    open_port_numbers = set()
    service_signatures: List[str] = []

    for p in ports_data:
        port_num = p.get("port")
        if port_num is not None:
            open_port_numbers.add(int(port_num))
        svc = (p.get("service") or "").lower()
        prod = (p.get("product") or "").lower()
        ver = (p.get("version") or "").lower()
        service_signatures.append(f"{svc} {prod} {ver}".strip())

    combined_service_str = " ".join(service_signatures).lower()
    http_banners: Dict[int, Dict[str, str]] = evidence.get("http_banners", {})
    rtsp_banner = (evidence.get("rtsp_banner") or "").lower()
    gateway_ip = evidence.get("gateway_ip")
    is_gateway = evidence.get("is_gateway", False) or (ip and gateway_ip and ip == gateway_ip)

    # Initialize tracking structures
    evidence_logs: List[str] = []
    inconclusive_logs: List[str] = []

    # Category candidate scores
    category_scores: Dict[str, int] = {c: 0 for c in SUPPORTED_CATEGORIES}
    identified_vendor = "Unknown"
    identified_model: Optional[str] = None

    # Step 1: MAC OUI resolution
    oui_vendor = MAC_OUI_DATABASE.get(mac_prefix)
    if oui_vendor:
        evidence_logs.append(f"Hardware MAC prefix ({mac_prefix}) matches manufacturer '{oui_vendor}' (+15 pts)")
        identified_vendor = oui_vendor
    elif vendor_input and vendor_input != "Unknown":
        for v in SUPPORTED_CCTV_VENDORS + ["TP-Link", "Apple", "HP", "Netgear", "Canon", "Brother"]:
            if v.lower() in vendor_input.lower():
                identified_vendor = v
                evidence_logs.append(f"ARP/OUI vendor metadata matches '{v}' (+15 pts)")
                break
        if identified_vendor == "Unknown":
            inconclusive_logs.append(f"MAC vendor '{vendor_input}' does not match known CCTV or enterprise signatures")
    else:
        inconclusive_logs.append("No hardware MAC OUI available for manufacturer lookup")

    # Step 2: Evaluate Router indicators
    router_score = 0
    if is_gateway:
        router_score += 45
        evidence_logs.append(f"IP {ip} matches network default gateway (+45 pts)")
    if 53 in open_port_numbers:
        router_score += 35
        evidence_logs.append("DNS service (port 53) active (+35 pts)")
    if 1900 in open_port_numbers:
        router_score += 15
        evidence_logs.append("UPnP service (port 1900) active (+15 pts)")

    # Router HTTP/hostname banners
    for p, b_info in http_banners.items():
        srv = b_info.get("server", "").lower()
        title = b_info.get("title", "").lower()
        for pat in NON_CCTV_SIGNATURES["Router"]["http_title_patterns"]:
            if re.search(pat, title) or re.search(pat, srv):
                router_score += 40
                evidence_logs.append(f"Router web banner detected on port {p}: '{title or srv}' (+40 pts)")
                break

    if identified_vendor in NON_CCTV_SIGNATURES["Router"]["vendors"] and identified_vendor != "TP-Link VIGI":
        if router_score > 0:
            router_score += 20
            evidence_logs.append(f"Networking hardware vendor '{identified_vendor}' corroborates router (+20 pts)")

    category_scores["Router"] = min(router_score, 100)

    # Step 3: Evaluate Computer / Workstation indicators
    comp_score = 0
    for pat in NON_CCTV_SIGNATURES["Computer"]["hostname_patterns"]:
        if re.search(pat, hostname):
            comp_score += 55
            evidence_logs.append(f"Hostname '{hostname}' matches personal workstation/computer (+55 pts)")
            break

    if any(p in open_port_numbers for p in [135, 139, 445]):
        comp_score += 40
        evidence_logs.append("Microsoft SMB / RPC networking services active (+40 pts)")
    if 3389 in open_port_numbers:
        comp_score += 40
        evidence_logs.append("Remote Desktop Protocol (port 3389) active (+40 pts)")
    if any(p in open_port_numbers for p in [5000, 7000]):
        comp_score += 30
        evidence_logs.append("Apple AirPlay streaming ports (5000/7000) active (+30 pts)")
    if identified_vendor in ["Apple", "Microsoft", "Dell", "Lenovo"] and not any(p in open_port_numbers for p in [554, 37777, 8000]):
        comp_score += 25
        evidence_logs.append(f"Hardware manufacturer '{identified_vendor}' without CCTV ports (+25 pts)")

    category_scores["Computer"] = min(comp_score, 100)

    # Step 4: Evaluate Printer indicators
    printer_score = 0
    if 9100 in open_port_numbers or 515 in open_port_numbers:
        printer_score += 50
        evidence_logs.append("RAW JetDirect / LPD printer port (9100/515) active (+50 pts)")
    if 631 in open_port_numbers:
        printer_score += 35
        evidence_logs.append("Internet Printing Protocol IPP (port 631) active (+35 pts)")
    if identified_vendor in NON_CCTV_SIGNATURES["Printer"]["vendors"]:
        if printer_score > 0:
            printer_score += 25
            evidence_logs.append(f"Printer manufacturer '{identified_vendor}' confirmed (+25 pts)")

    category_scores["Printer"] = min(printer_score, 100)

    # Step 5: Evaluate Multi-Vendor CCTV Identification
    cctv_score = 0
    cctv_vendor_detected = None
    cctv_category_candidate = "IP CCTV Camera"

    # Specific CCTV control ports
    if 37777 in open_port_numbers:
        cctv_score += 45
        cctv_vendor_detected = "Dahua" if identified_vendor != "CP Plus" else "CP Plus"
        evidence_logs.append(f"Dahua/CP Plus DVR/NVR proprietary management protocol active on TCP 37777 (+45 pts)")
    elif 34567 in open_port_numbers:
        cctv_score += 45
        cctv_vendor_detected = "CP Plus"
        evidence_logs.append(f"CP Plus / Xiongmai surveillance management port active on TCP 34567 (+45 pts)")
    elif 8000 in open_port_numbers and any(
        kw in combined_service_str for kw in ["hikvision", "ipcam", "camera"]
    ):
        cctv_score += 45
        cctv_vendor_detected = "Hikvision"
        evidence_logs.append(f"Hikvision IPCam / DVR SDK service active on TCP 8000 (+45 pts)")
    elif 1756 in open_port_numbers:
        cctv_score += 45
        cctv_vendor_detected = "Bosch"
        evidence_logs.append(f"Bosch Security Systems RCP+ protocol active on TCP 1756 (+45 pts)")
    elif 9000 in open_port_numbers and (identified_vendor == "Reolink" or "reolink" in hostname):
        cctv_score += 45
        cctv_vendor_detected = "Reolink"
        evidence_logs.append(f"Reolink media protocol active on TCP 9000 (+45 pts)")
    elif any(p in open_port_numbers for p in [4520, 4521, 4522, 4523, 4524]):
        cctv_score += 40
        cctv_vendor_detected = "Hanwha"
        evidence_logs.append(f"Hanwha / Samsung control port active (+40 pts)")
    elif 10554 in open_port_numbers or 2020 in open_port_numbers:
        if identified_vendor == "TP-Link" or "vigi" in hostname:
            cctv_score += 40
            cctv_vendor_detected = "TP-Link VIGI"
            evidence_logs.append(f"TP-Link VIGI IPC management service active (+40 pts)")

    # RTSP service check (port 554)
    if 554 in open_port_numbers or "rtsp" in combined_service_str:
        cctv_score += 15
        evidence_logs.append("Real-Time Streaming Protocol (RTSP port 554) active (+15 pts)")
        if rtsp_banner:
            evidence_logs.append(f"RTSP Server banner: '{rtsp_banner}' (+20 pts)")
            cctv_score += 20
            for v_name, v_data in VENDOR_SIGNATURES.items():
                if any(re.search(pat, rtsp_banner) for pat in v_data.get("rtsp_server_patterns", [])):
                    cctv_vendor_detected = v_name
                    evidence_logs.append(f"RTSP banner matches {v_name} streaming engine (+20 pts)")
                    cctv_score += 20
                    break
    else:
        inconclusive_logs.append("RTSP port 554 was not open")

    # HTTP/HTTPS Inspection for CCTV signatures
    http_cctv_found = False
    best_http_vendor = None
    best_http_model = None
    best_http_cat = None

    for p, b_info in http_banners.items():
        srv = b_info.get("server", "").lower()
        title = b_info.get("title", "").lower()
        realm = b_info.get("auth_realm", "").lower()
        combined_http = f"{srv} {title} {realm}".lower()

        # Prioritize identified_vendor if it is in VENDOR_SIGNATURES
        vendors_to_check = list(VENDOR_SIGNATURES.keys())
        if identified_vendor in vendors_to_check:
            vendors_to_check.remove(identified_vendor)
            vendors_to_check.insert(0, identified_vendor)

        for v_name in vendors_to_check:
            v_data = VENDOR_SIGNATURES[v_name]
            srv_match = any(re.search(pat, srv) for pat in v_data["http_server_patterns"])
            title_match = any(re.search(pat, title) for pat in v_data["http_title_patterns"])
            realm_match = any(re.search(pat, realm) for pat in v_data["http_auth_patterns"])

            if srv_match or title_match or realm_match:
                best_http_vendor = v_name
                http_cctv_found = True

                # Check model patterns
                for cat, pat_list in v_data["model_patterns"].items():
                    for pat in pat_list:
                        m = re.search(pat, combined_http, re.IGNORECASE)
                        if m:
                            best_http_model = m.group(0).upper()
                            best_http_cat = cat
                            break
                    if best_http_model:
                        break

                if best_http_model:
                    break

        if best_http_model:
            break

    if http_cctv_found and best_http_vendor:
        cctv_vendor_detected = best_http_vendor
        cctv_score += 40
        evidence_logs.append(f"Web interface matches {best_http_vendor} CCTV signature (+40 pts)")
        if best_http_model and best_http_cat:
            identified_model = best_http_model
            cctv_category_candidate = best_http_cat
            evidence_logs.append(f"Extracted hardware model: '{best_http_model}' ({best_http_cat}) (+20 pts)")
            cctv_score += 20

    if not http_cctv_found and (80 in open_port_numbers or 443 in open_port_numbers):
        inconclusive_logs.append("Web server headers/title on 80/443 did not match specific CCTV patterns")

    # Service signature scan results from Nmap
    for v_name, v_data in VENDOR_SIGNATURES.items():
        if v_name.lower() in combined_service_str:
            cctv_score += 35
            if not cctv_vendor_detected:
                cctv_vendor_detected = v_name
            evidence_logs.append(f"Nmap service banner explicitly identified {v_name} (+35 pts)")
            for cat, pat_list in v_data["model_patterns"].items():
                for pat in pat_list:
                    m = re.search(pat, combined_service_str, re.IGNORECASE)
                    if m:
                        identified_model = m.group(0).upper()
                        cctv_category_candidate = cat
                        evidence_logs.append(f"Hardware model detected in service metadata: '{identified_model}' ({cat}) (+20 pts)")
                        cctv_score += 20
                        break
                if identified_model:
                    break

    # If vendor OUI matches CCTV and CCTV signals exist
    if identified_vendor in SUPPORTED_CCTV_VENDORS or (identified_vendor == "TP-Link" and cctv_vendor_detected == "TP-Link VIGI"):
        if cctv_score > 0:
            cctv_score += 15
            evidence_logs.append(f"OUI manufacturer '{identified_vendor}' corroborates CCTV device (+15 pts)")
            if not cctv_vendor_detected:
                cctv_vendor_detected = identified_vendor

    # Camera vs NVR vs DVR fine-tuning
    if not identified_model:
        metadata_text = f"{hostname} " + " ".join(
            f"{b.get('server')} {b.get('title')}" for b in http_banners.values()
        )
        if "nvr" in metadata_text.lower():
            cctv_category_candidate = "NVR"
            evidence_logs.append("Network Video Recorder (NVR) designation found in device metadata")
        elif "dvr" in metadata_text.lower() or "xvr" in metadata_text.lower() or "hcvr" in metadata_text.lower():
            cctv_category_candidate = "DVR"
            evidence_logs.append("Digital Video Recorder (DVR/XVR) designation found in device metadata")
        elif "camera" in metadata_text.lower() or "ipcam" in metadata_text.lower():
            cctv_category_candidate = "IP CCTV Camera"
        else:
            cctv_category_candidate = "IP CCTV Camera"

    # Conflicting / Anti-CCTV demotions
    if router_score >= 50:
        # If strong router evidence exists, demote CCTV
        cctv_score = 0
        inconclusive_logs.append(f"Device displays authoritative router/gateway behavior; CCTV candidate discounted")
    elif comp_score >= 50:
        cctv_score = 0
        inconclusive_logs.append(f"Device displays operating system workstation behavior; CCTV candidate discounted")

    category_scores[cctv_category_candidate] = min(cctv_score, 100)

    # Step 6: Select Winner Category
    # Filter out categories that didn't meet minimum threshold
    sorted_candidates = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
    top_category, top_score = sorted_candidates[0]

    # Critical requirement:
    # "Do not classify a device as CCTV based only on port 554, MAC vendor, or one weak signal. Retain Unknown when evidence is insufficient."
    if top_category in ("IP CCTV Camera", "DVR", "NVR"):
        if top_score < 40 or not (cctv_vendor_detected or 37777 in open_port_numbers or 8000 in open_port_numbers or http_cctv_found or identified_model):
            # Insufficient evidence for CCTV!
            top_category = "Unknown"
            top_score = min(top_score, 25)
            inconclusive_logs.append("Weak or isolated RTSP/MAC signal was insufficient for CCTV classification without corroborating evidence")

    # If highest score is below 15, classify as Unknown
    if top_score < 15:
        top_category = "Unknown"
        final_level = "Unknown"
        final_vendor = identified_vendor if identified_vendor not in ("Unknown", "") else "Unknown"
    else:
        final_level = get_confidence_level(top_score)
        if top_category in ("IP CCTV Camera", "DVR", "NVR"):
            final_vendor = cctv_vendor_detected or identified_vendor
        else:
            final_vendor = identified_vendor

    return IdentificationResult(
        category=top_category,
        vendor=final_vendor if final_vendor else "Unknown",
        model=identified_model,
        confidence_score=top_score,
        confidence_level=final_level,
        evidence=evidence_logs,
        inconclusive_signals=inconclusive_logs
    )

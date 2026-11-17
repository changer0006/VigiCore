import re
from typing import Dict, Any, List

# Supported CCTV Vendors for Phase 3
SUPPORTED_CCTV_VENDORS = [
    "Hikvision",
    "Dahua",
    "CP Plus",
    "TP-Link VIGI",
    "Uniview",
    "Axis",
    "Reolink",
    "Bosch",
    "Hanwha"
]

# Supported Categories for Phase 3
SUPPORTED_CATEGORIES = [
    "IP CCTV Camera",
    "DVR",
    "NVR",
    "Router",
    "Computer",
    "Mobile",
    "Printer",
    "Other",
    "Unknown"
]

# Known MAC OUI prefixes (lower-case 6-hex without colons or with colons)
MAC_OUI_DATABASE: Dict[str, str] = {
    # Hikvision / EZVIZ
    "44:19:b6": "Hikvision",
    "44:47:cc": "Hikvision",
    "bc:ad:28": "Hikvision",
    "c0:56:e3": "Hikvision",
    "e0:50:8b": "Hikvision",
    "a4:14:37": "Hikvision",
    "18:68:cb": "Hikvision",
    "ec:71:db": "Hikvision",
    "00:40:48": "Hikvision",
    "04:cf:8c": "Hikvision",
    "40:b4:cd": "Hikvision",
    "10:a4:be": "EZVIZ",
    "54:c4:15": "EZVIZ",

    # Dahua / Amcrest
    "38:af:29": "Dahua",
    "4c:11:bf": "Dahua",
    "e4:24:6c": "Dahua",
    "90:02:a9": "Dahua",
    "bc:32:5f": "Dahua",
    "a0:bd:cd": "Dahua",
    "48:ea:63": "Dahua",
    "b0:c5:54": "Dahua",
    "9c:8e:cd": "Amcrest",

    # CP Plus (Aditya Infotech)
    "00:0b:3f": "CP Plus",
    "34:c9:f0": "CP Plus",
    "14:b4:84": "CP Plus",
    "d8:84:66": "CP Plus",

    # TP-Link (Requires service discrimination for VIGI vs Router)
    "a8:29:48": "TP-Link",
    "00:31:92": "TP-Link",
    "50:c7:bf": "TP-Link",
    "1c:3b:f3": "TP-Link",
    "30:de:4b": "TP-Link",
    "e8:48:b8": "TP-Link",
    "cc:32:e5": "TP-Link",

    # Uniview (Zhejiang Uniview Technologies)
    "00:0f:7c": "Uniview",
    "24:7f:20": "Uniview",

    # Axis Communications
    "00:40:8c": "Axis",
    "ac:cc:8e": "Axis",
    "b8:a4:4f": "Axis",
    "e8:27:25": "Axis",

    # Reolink
    "f4:b8:5e": "Reolink",

    # Bosch Security Systems
    "00:04:63": "Bosch",
    "00:07:5f": "Bosch",
    "00:1c:44": "Bosch",
    "40:11:15": "Bosch",

    # Hanwha Vision (Samsung Techwin / Hanwha Techwin)
    "00:09:18": "Hanwha",
    "00:16:6c": "Hanwha",
    "e4:30:22": "Hanwha",
    "f4:d9:fb": "Hanwha",
    "70:b3:d5": "Hanwha",

    # Printers
    "00:1e:0b": "HP",
    "00:25:b3": "HP",
    "00:00:85": "Canon",
    "00:26:ab": "Epson",
    "00:80:77": "Brother",

    # Computers
    "be:60:3a": "Apple",
    "f0:18:98": "Apple",
    "3c:22:fb": "Apple",
    "ac:de:48": "Apple",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox"
}

# Vendor-specific signature patterns and port definitions
VENDOR_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "Hikvision": {
        "ports": [8000, 554, 8200],
        "http_server_patterns": [r"dnvrs-webs", r"app-webs", r"hikvision-webs", r"hikvision", r"dvrdvs-webs"],
        "http_auth_patterns": [r"hikvision", r"dvrdvs", r"ip camera"],
        "http_title_patterns": [r"hikvision", r"ezviz", r"dvrdvs"],
        "http_paths": ["/doc/page/login.asp", "/ISAPI/System/deviceInfo"],
        "rtsp_server_patterns": [r"hikvision", r"dvr"],
        "hostname_patterns": [r"hikvision", r"ezviz", r"ds-\d{4}"],
        "model_patterns": {
            "NVR": [r"(?:ds|ids)-7[16789]\d{2}[a-z0-9\-/]*", r"(?:ds|ids)-8\d{3}[a-z0-9\-/]*", r"(?:ds|ids)-9\d{3}[a-z0-9\-/]*"],
            "DVR": [r"(?:ds|ids)-72\d{2}[a-z0-9\-/]*", r"(?:ds|ids)-7[0-3]\d{2}h[uqi]hi[a-z0-9\-/]*"],
            "IP CCTV Camera": [r"(?:ds|ids)-2cd\d{4}[a-z0-9\-/]*", r"(?:ds|ids)-2cv\d{4}[a-z0-9\-/]*", r"(?:ds|ids)-2de\d{4}[a-z0-9\-/]*", r"c[236][a-z0-9\-]+"]
        }
    },
    "Dahua": {
        "ports": [37777, 37778, 38800, 554],
        "http_server_patterns": [r"dh-web-server", r"dahua-web", r"amcrest-web"],
        "http_auth_patterns": [r"dahua", r"amcrest", r"login to dh"],
        "http_title_patterns": [r"web service", r"dahua", r"amcrest"],
        "http_paths": ["/RPC2", "/RPC2_Login", "/cgi-bin/magicBox.cgi"],
        "rtsp_server_patterns": [r"dahua", r"amcrest"],
        "hostname_patterns": [r"dahua", r"amcrest", r"dhi-"],
        "model_patterns": {
            "NVR": [r"dhi-nvr\d{4}[a-z0-9\-/]*", r"nvr[245]\d{3}[a-z0-9\-/]*", r"nv[45]\d{3}[a-z0-9\-/]*"],
            "DVR": [r"dhi-xvr\d{4}[a-z0-9\-/]*", r"xvr\d{4}[a-z0-9\-/]*", r"dhi-hcvr\d{4}[a-z0-9\-/]*", r"hcvr\d{4}[a-z0-9\-/]*"],
            "IP CCTV Camera": [r"ipc-hfw\d{4}[a-z0-9\-/]*", r"ipc-hdw\d{4}[a-z0-9\-/]*", r"ipc-hdbw\d{4}[a-z0-9\-/]*", r"ip[23458]m-[a-z0-9\-/]*", r"ad110|ad410"]
        }
    },
    "CP Plus": {
        "ports": [37777, 34567, 554],
        "http_server_patterns": [r"cp\s*plus"],
        "http_auth_patterns": [r"cp\s*plus", r"cp-plus"],
        "http_title_patterns": [r"cp\s*plus", r"e-zeeon", r"g-e-zee"],
        "http_paths": ["/RPC2", "/login.htm"],
        "rtsp_server_patterns": [r"cp\s*plus"],
        "hostname_patterns": [r"cp-plus", r"cp-uvr", r"cp-vnr", r"cp-unc"],
        "model_patterns": {
            "NVR": [r"cp-vnr-\d{4}[a-z0-9\-/]*", r"cp-unr-\d{4}[a-z0-9\-/]*"],
            "DVR": [r"cp-uvr-\d{4}[a-z0-9\-/]*", r"cp-dvr-\d{4}[a-z0-9\-/]*"],
            "IP CCTV Camera": [r"cp-unc-\d{4}[a-z0-9\-/]*", r"cp-vnc-\d{4}[a-z0-9\-/]*", r"cp-e\d{2}[a-z0-9\-/]*"]
        }
    },
    "TP-Link VIGI": {
        "ports": [10554, 2020, 554],
        "http_server_patterns": [r"vigi", r"tp-link\s+vigi"],
        "http_auth_patterns": [r"vigi", r"tp-link\s+vigi"],
        "http_title_patterns": [r"vigi", r"tp-link\s+vigi", r"vigi\s+security\s+manager"],
        "http_paths": ["/vigi/"],
        "rtsp_server_patterns": [r"vigi"],
        "hostname_patterns": [r"vigi", r"vigi-[a-z0-9]+"],
        "model_patterns": {
            "NVR": [r"vigi\s+nvr\d{4}[a-z0-9\-/]*", r"nvr10\d{2}[a-z0-9\-/]*"],
            "IP CCTV Camera": [r"vigi\s+c[2345]\d{2}[a-z0-9\-/]*", r"c[2345]\d{2}[a-z0-9\-/]*"]
        }
    },
    "Uniview": {
        "ports": [8088, 554, 82],
        "http_server_patterns": [r"uniview", r"unv-web"],
        "http_auth_patterns": [r"uniview", r"unv"],
        "http_title_patterns": [r"uniview", r"unv"],
        "http_paths": ["/LAPI/V1.0/System/DeviceInfo"],
        "rtsp_server_patterns": [r"unv", r"uniview"],
        "hostname_patterns": [r"unv", r"uniview", r"ipc[23]\d{3}"],
        "model_patterns": {
            "NVR": [r"nvr30[1-8]-[a-z0-9\-/]*", r"nvr5\d{2}[a-z0-9\-/]*"],
            "IP CCTV Camera": [r"ipc[23]\d{3}[a-z0-9\-/]*", r"ipc-b\d{3}[a-z0-9\-/]*", r"ipc-d\d{3}[a-z0-9\-/]*"]
        }
    },
    "Axis": {
        "ports": [554],
        "http_server_patterns": [r"boa/\d.*axis", r"axis"],
        "http_auth_patterns": [r"axis_"],
        "http_title_patterns": [r"axis\s+network\s+camera", r"axis\s+video\s+server", r"axis\s+companion", r"axis\s+[mpqv]\d{4}"],
        "http_paths": ["/axis-cgi/param.cgi", "/axis-cgi/jpg/image.cgi"],
        "rtsp_server_patterns": [r"axis"],
        "hostname_patterns": [r"axis-[a-z0-9]+"],
        "model_patterns": {
            "NVR": [r"axis\s+s[12]\d{3}[a-z0-9\-/]*"],
            "IP CCTV Camera": [r"axis\s+[mpqv]\d{4}[a-z0-9\-/]*", r"[mpqv]\d{4}-[a-z0-9\-/]*"]
        }
    },
    "Reolink": {
        "ports": [9000, 8000, 554],
        "http_server_patterns": [r"reolink"],
        "http_auth_patterns": [r"reolink"],
        "http_title_patterns": [r"reolink"],
        "http_paths": ["/api.cgi?cmd=Login", "/cgi-bin/api.cgi"],
        "rtsp_server_patterns": [r"reolink"],
        "hostname_patterns": [r"reolink"],
        "model_patterns": {
            "NVR": [r"rln[813]\d?-\d{3}[a-z0-9\-/]*"],
            "IP CCTV Camera": [r"rlc-\d{3}[a-z0-9\-/]*", r"e1\s+(?:pro|zoom)", r"argus\s+[23]?", r"trackmix", r"duo\s+[23]?"]
        }
    },
    "Bosch": {
        "ports": [1756, 554],
        "http_server_patterns": [r"bosch\s+security\s+systems", r"bvms", r"bosch-web"],
        "http_auth_patterns": [r"bosch", r"vip\s+x"],
        "http_title_patterns": [r"bosch", r"dinion", r"flexidome", r"autodome"],
        "http_paths": ["/rcp.xml"],
        "rtsp_server_patterns": [r"bosch"],
        "hostname_patterns": [r"bosch-", r"dinion", r"flexidome"],
        "model_patterns": {
            "NVR": [r"divar\s+ip\s+\d{4}", r"dip-\d{4}"],
            "IP CCTV Camera": [r"dinion\s+ip\s+\d{4}", r"flexidome\s+ip\s+\d{4}", r"autodome\s+ip\s+\d{4}"]
        }
    },
    "Hanwha": {
        "ports": [4520, 4521, 4522, 4523, 4524, 554],
        "http_server_patterns": [r"hanwha", r"samsung-web-server", r"hanwha-web", r"sunapi"],
        "http_auth_patterns": [r"hanwha", r"samsung\s+techwin", r"wisenet"],
        "http_title_patterns": [r"wisenet", r"hanwha\s+techwin", r"samsung\s+techwin"],
        "http_paths": ["/stw-cgi/system.cgi"],
        "rtsp_server_patterns": [r"hanwha", r"samsung"],
        "hostname_patterns": [r"wisenet", r"hanwha", r"samsung-"],
        "model_patterns": {
            "NVR": [r"[xqp]rn-\d{4}[a-z0-9\-/]*", r"srn-\d{4}[a-z0-9\-/]*"],
            "DVR": [r"hrx-\d{4}[a-z0-9\-/]*", r"srd-\d{4}[a-z0-9\-/]*"],
            "IP CCTV Camera": [r"[xqp]nd-\d{4}[a-z0-9\-/]*", r"[xqp]nv-\d{4}[a-z0-9\-/]*", r"snd-\d{4}[a-z0-9\-/]*"]
        }
    }
}

# Signatures for non-CCTV device categories
NON_CCTV_SIGNATURES = {
    "Router": {
        "ports": [53, 67, 1900],
        "vendors": ["TP-Link", "Netgear", "Asus", "Linksys", "Cisco", "MikroTik", "D-Link", "OpenWrt", "Ubiquiti"],
        "http_server_patterns": [r"openwrt", r"dd-wrt", r"routeros", r"boa(?!.*axis)", r"mini_httpd"],
        "http_title_patterns": [r"wireless\s+router", r"router", r"archer", r"openwrt", r"dd-wrt", r"asuswrt", r"gateway", r"broadband\s+router"],
        "hostname_patterns": [r"router", r"gateway", r"tplinkwifi", r"archer", r"modem", r"ap-"]
    },
    "Computer": {
        "ports": [135, 139, 445, 3389, 5000, 7000, 5900],
        "vendors": ["Apple", "Microsoft", "Dell", "Lenovo", "HP", "AsusTek"],
        "hostname_patterns": [r"macbook", r"imac", r"desktop-", r"laptop-", r"windows-pc", r"ubuntu", r"debian", r"fedora", r"mac-mini"],
        "http_title_patterns": [r"iis\s+windows", r"apache2\s+debian\s+default\s+page", r"ubuntu\s+default"]
    },
    "Mobile": {
        "hostname_patterns": [r"iphone", r"ipad", r"android", r"galaxy", r"pixel"],
        "vendors": ["Apple", "Samsung", "Google"]
    },
    "Printer": {
        "ports": [9100, 631, 515],
        "vendors": ["HP", "Canon", "Epson", "Brother", "Ricoh", "Xerox", "Lexmark"],
        "http_title_patterns": [r"laserjet", r"deskjet", r"epson\s+web\s+config", r"brother\s+web", r"cups", r"printer\s+status"]
    }
}

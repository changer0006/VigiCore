import unittest
from app.fingerprint.device_identifier import classify_device, IdentificationResult


class DeviceIdentifierTests(unittest.TestCase):

    def test_hikvision_camera_and_nvr(self):
        # Hikvision Camera
        cam_evidence = {
            "ip": "192.168.1.50",
            "mac": "44:19:b6:aa:bb:cc",
            "ports": [
                {"port": 80, "service": "http", "product": "DNVRS-Webs"},
                {"port": 554, "service": "rtsp", "product": "Hikvision RTSP Server"},
                {"port": 8000, "service": "ipcam", "product": "Hikvision IPCam control"}
            ],
            "http_banners": {
                80: {"server": "DNVRS-Webs", "title": "Hikvision DS-2CD2042WD-I", "auth_realm": "Hikvision"}
            },
            "rtsp_banner": "Hikvision RTSP Server"
        }
        res = classify_device(cam_evidence)
        self.assertEqual(res.category, "IP CCTV Camera")
        self.assertEqual(res.vendor, "Hikvision")
        self.assertIn("DS-2CD2042WD-I", res.model or "")
        self.assertEqual(res.confidence_level, "High")
        self.assertGreaterEqual(res.confidence_score, 75)
        self.assertGreaterEqual(len(res.evidence), 3)

        # Hikvision NVR
        nvr_evidence = {
            "ip": "192.168.1.51",
            "mac": "bc:ad:28:11:22:33",
            "ports": [
                {"port": 80, "service": "http"},
                {"port": 8000, "service": "ipcam"}
            ],
            "http_banners": {
                80: {"server": "App-webs/", "title": "Embedded Net NVR DS-7608NI-I2", "auth_realm": "DVRDVS"}
            }
        }
        res_nvr = classify_device(nvr_evidence)
        self.assertEqual(res_nvr.category, "NVR")
        self.assertEqual(res_nvr.vendor, "Hikvision")
        self.assertEqual(res_nvr.confidence_level, "High")

        # Hikvision DVR
        dvr_evidence = {
            "ip": "192.168.1.52",
            "mac": "44:47:cc:99:88:77",
            "ports": [{"port": 8000, "service": "ipcam"}],
            "http_banners": {
                80: {"server": "web-server", "title": "DVR DS-7208HQHI-K1", "auth_realm": "Hikvision"}
            }
        }
        res_dvr = classify_device(dvr_evidence)
        self.assertEqual(res_dvr.category, "DVR")
        self.assertEqual(res_dvr.vendor, "Hikvision")

    def test_dahua_and_amcrest(self):
        # Dahua Camera
        dahua_cam = {
            "ip": "192.168.1.60",
            "mac": "38:af:29:12:34:56",
            "ports": [
                {"port": 37777, "service": "dahua-dvr"},
                {"port": 554, "service": "rtsp"},
                {"port": 80, "service": "http"}
            ],
            "http_banners": {
                80: {"server": "DH-Web-Server", "title": "WEB SERVICE IPC-HFW4431R-Z", "auth_realm": "Dahua"}
            },
            "rtsp_banner": "Dahua RTSP Server"
        }
        res = classify_device(dahua_cam)
        self.assertEqual(res.category, "IP CCTV Camera")
        self.assertEqual(res.vendor, "Dahua")
        self.assertIn("IPC-HFW4431R-Z", res.model or "")
        self.assertEqual(res.confidence_level, "High")

        # Dahua XVR (DVR)
        dahua_xvr = {
            "ip": "192.168.1.61",
            "ports": [{"port": 37777, "service": "dahua-dvr"}],
            "http_banners": {
                80: {"server": "DH-Web-Server", "title": "DHI-XVR5108HS-4KL", "auth_realm": "Dahua"}
            }
        }
        res_xvr = classify_device(dahua_xvr)
        self.assertEqual(res_xvr.category, "DVR")
        self.assertEqual(res_xvr.vendor, "Dahua")

        # Amcrest Camera
        amcrest_cam = {
            "ip": "192.168.1.62",
            "mac": "9c:8e:cd:33:44:55",
            "ports": [
                {"port": 554, "service": "rtsp"},
                {"port": 80, "service": "http"}
            ],
            "http_banners": {
                80: {"server": "Amcrest-Web", "title": "Amcrest Technologies IP4M-1026W", "auth_realm": "Amcrest"}
            }
        }
        res_amcrest = classify_device(amcrest_cam)
        self.assertEqual(res_amcrest.category, "IP CCTV Camera")
        self.assertEqual(res_amcrest.vendor, "Dahua")  # Dahua/Amcrest OEM
        self.assertEqual(res_amcrest.confidence_level, "High")

    def test_cp_plus(self):
        # CP Plus IP Camera
        cp_cam = {
            "ip": "192.168.1.70",
            "mac": "00:0b:3f:11:22:33",
            "ports": [
                {"port": 37777, "service": "cpplus-dvr"},
                {"port": 554, "service": "rtsp"}
            ],
            "http_banners": {
                80: {"server": "CP PLUS", "title": "e-ZeeOn CP-UNC-TA21L3", "auth_realm": "CP PLUS"}
            }
        }
        res = classify_device(cp_cam)
        self.assertEqual(res.category, "IP CCTV Camera")
        self.assertEqual(res.vendor, "CP Plus")
        self.assertEqual(res.confidence_level, "High")

    def test_tplink_vigi_vs_tplink_router(self):
        # TP-Link VIGI Camera
        vigi_cam = {
            "ip": "192.168.1.80",
            "mac": "a8:29:48:11:22:33",
            "ports": [
                {"port": 10554, "service": "vigi"},
                {"port": 554, "service": "rtsp"}
            ],
            "http_banners": {
                80: {"server": "vigi", "title": "TP-Link VIGI C340", "auth_realm": "vigi"}
            }
        }
        res_vigi = classify_device(vigi_cam)
        self.assertEqual(res_vigi.category, "IP CCTV Camera")
        self.assertEqual(res_vigi.vendor, "TP-Link VIGI")
        self.assertEqual(res_vigi.confidence_level, "High")

        # TP-Link Standard Router (Archer C6) - MUST NOT BE CLASSIFIED AS CCTV
        router = {
            "ip": "192.168.0.1",
            "gateway_ip": "192.168.0.1",
            "is_gateway": True,
            "mac": "a8:29:48:a9:3e:a0",
            "vendor": "TP-Link Systems",
            "ports": [
                {"port": 53, "service": "domain", "product": "dnsmasq"},
                {"port": 80, "service": "http", "product": "mini_httpd"}
            ],
            "http_banners": {
                80: {"server": "mini_httpd", "title": "TP-Link Wireless Router Archer C6", "auth_realm": ""}
            }
        }
        res_router = classify_device(router)
        self.assertEqual(res_router.category, "Router")
        self.assertEqual(res_router.vendor, "TP-Link")
        self.assertEqual(res_router.confidence_level, "High")

    def test_uniview(self):
        evidence = {
            "ip": "192.168.1.90",
            "mac": "00:0f:7c:44:55:66",
            "ports": [
                {"port": 8088, "service": "http"},
                {"port": 554, "service": "rtsp"}
            ],
            "http_banners": {
                8088: {"server": "Uniview", "title": "UNV Network Camera IPC2122", "auth_realm": "Uniview"}
            },
            "rtsp_banner": "UNV RTSP Server"
        }
        res = classify_device(evidence)
        self.assertEqual(res.category, "IP CCTV Camera")
        self.assertEqual(res.vendor, "Uniview")
        self.assertEqual(res.confidence_level, "High")

    def test_axis(self):
        evidence = {
            "ip": "192.168.1.91",
            "mac": "00:40:8c:11:22:33",
            "ports": [
                {"port": 80, "service": "http"},
                {"port": 554, "service": "rtsp"}
            ],
            "http_banners": {
                80: {"server": "Boa/0.94.14rc21 (Axis)", "title": "AXIS M3007 Network Camera", "auth_realm": "AXIS_"}
            },
            "rtsp_banner": "Axis RTSP Server"
        }
        res = classify_device(evidence)
        self.assertEqual(res.category, "IP CCTV Camera")
        self.assertEqual(res.vendor, "Axis")
        self.assertEqual(res.confidence_level, "High")

    def test_reolink(self):
        evidence = {
            "ip": "192.168.1.92",
            "mac": "f4:b8:5e:66:77:88",
            "ports": [
                {"port": 9000, "service": "reolink"},
                {"port": 8000, "service": "http"},
                {"port": 554, "service": "rtsp"}
            ],
            "http_banners": {
                8000: {"server": "nginx", "title": "Reolink IP Camera RLC-810A", "auth_realm": "Reolink"}
            }
        }
        res = classify_device(evidence)
        self.assertEqual(res.category, "IP CCTV Camera")
        self.assertEqual(res.vendor, "Reolink")
        self.assertEqual(res.confidence_level, "High")

    def test_bosch(self):
        evidence = {
            "ip": "192.168.1.93",
            "mac": "00:04:63:77:88:99",
            "ports": [
                {"port": 1756, "service": "rcp+"},
                {"port": 554, "service": "rtsp"}
            ],
            "http_banners": {
                80: {"server": "Bosch Security Systems", "title": "FLEXIDOME IP 5000", "auth_realm": "Bosch"}
            }
        }
        res = classify_device(evidence)
        self.assertEqual(res.category, "IP CCTV Camera")
        self.assertEqual(res.vendor, "Bosch")
        self.assertEqual(res.confidence_level, "High")

    def test_hanwha(self):
        evidence = {
            "ip": "192.168.1.94",
            "mac": "00:09:18:11:22:33",
            "ports": [
                {"port": 4520, "service": "hanwha-control"},
                {"port": 554, "service": "rtsp"}
            ],
            "http_banners": {
                80: {"server": "Hanwha-Web", "title": "Wisenet XND-6080R", "auth_realm": "Hanwha"}
            }
        }
        res = classify_device(evidence)
        self.assertEqual(res.category, "IP CCTV Camera")
        self.assertEqual(res.vendor, "Hanwha")
        self.assertEqual(res.confidence_level, "High")

    def test_workstation_computer(self):
        # Apple MacBook
        mac_evidence = {
            "ip": "192.168.0.102",
            "mac": "be:60:3a:e6:3d:dd",
            "hostname": "Ram-MacBook-Air.local",
            "ports": [
                {"port": 5000, "service": "airplay"},
                {"port": 7000, "service": "airplay"}
            ]
        }
        res = classify_device(mac_evidence)
        self.assertEqual(res.category, "Computer")
        self.assertEqual(res.vendor, "Apple")
        self.assertEqual(res.confidence_level, "High")

        # Windows PC
        win_evidence = {
            "ip": "192.168.1.105",
            "hostname": "DESKTOP-8K3N19",
            "ports": [
                {"port": 135, "service": "msrpc"},
                {"port": 445, "service": "microsoft-ds"}
            ]
        }
        res_win = classify_device(win_evidence)
        self.assertEqual(res_win.category, "Computer")

    def test_printer(self):
        printer_evidence = {
            "ip": "192.168.1.200",
            "mac": "00:1e:0b:aa:bb:cc",
            "ports": [
                {"port": 9100, "service": "jetdirect"},
                {"port": 631, "service": "ipp"}
            ],
            "http_banners": {
                80: {"server": "HP-ChaiSOE", "title": "HP LaserJet Pro MFP M428"}
            }
        }
        res = classify_device(printer_evidence)
        self.assertEqual(res.category, "Printer")
        self.assertEqual(res.vendor, "HP")
        self.assertEqual(res.confidence_level, "High")

    def test_weak_signal_alone_retains_unknown(self):
        # Port 554 alone without any vendor or banner - MUST NOT be classified as CCTV
        sample_rtsp_only = {
            "ip": "192.168.1.250",
            "ports": [{"port": 554, "service": "rtsp"}]
        }
        res = classify_device(sample_rtsp_only)
        self.assertEqual(res.category, "Unknown")
        self.assertEqual(res.confidence_level, "Low")
        self.assertLess(res.confidence_score, 40)
        self.assertIn("Weak or isolated RTSP/MAC signal was insufficient", " ".join(res.inconclusive_signals))

        # MAC OUI alone without open ports
        sample_mac_only = {
            "ip": "192.168.1.251",
            "mac": "44:19:b6:00:11:22",
            "ports": []
        }
        res_mac = classify_device(sample_mac_only)
        self.assertEqual(res_mac.category, "Unknown")
        self.assertIn(res_mac.confidence_level, ["Unknown", "Low"])
        self.assertLess(res_mac.confidence_score, 40)

        # Completely empty / non-responsive host
        empty = {"ip": "192.168.1.252", "ports": []}
        res_empty = classify_device(empty)
        self.assertEqual(res_empty.category, "Unknown")
        self.assertEqual(res_empty.confidence_level, "Unknown")
        self.assertEqual(res_empty.confidence_score, 0)

    def test_conflicting_evidence_gateway_overrules_cctv(self):
        # A router that happens to have RTSP 554 enabled for UPnP/DLNA media sharing
        # Because it's the gateway and has DNS 53, Router must win over CCTV!
        conflicting = {
            "ip": "192.168.1.1",
            "is_gateway": True,
            "ports": [
                {"port": 53, "service": "domain"},
                {"port": 554, "service": "rtsp"},
                {"port": 80, "service": "http"}
            ],
            "http_banners": {
                80: {"server": "OpenWrt", "title": "OpenWrt LuCI Gateway"}
            }
        }
        res = classify_device(conflicting)
        self.assertEqual(res.category, "Router")
        self.assertNotEqual(res.category, "IP CCTV Camera")


if __name__ == "__main__":
    unittest.main()

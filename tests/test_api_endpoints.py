import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi import HTTPException

from backend.main import health_check
from backend.api.network import (
    get_system_network_info,
    get_all_network_interfaces,
    check_nmap_readiness
)
from backend.api.assets import (
    get_assets,
    get_asset_by_id,
    set_asset_manual_override,
    identify_single_asset,
    identify_all_assets,
    get_asset_identification_details,
    remove_asset,
    AssetOverrideRequest
)
from backend.api.discovery import get_default_network
from backend.api.stats import (
    get_overview_statistics,
    get_device_inventory,
    get_all_vulnerabilities
)
from app.database.db import upsert_asset, DEFAULT_DB_PATH


class ApiEndpointsTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_api.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("backend.main.check_db_connectivity")
    @patch("backend.main.get_nmap_info")
    @patch("backend.main.get_network_info")
    def test_health_check_endpoint(self, mock_net, mock_nmap, mock_db):
        mock_db.return_value = {"connected": True, "path": ":memory:", "scans_count": 0, "assets_count": 0}
        mock_nmap.return_value = {"installed": True, "path": "/opt/homebrew/bin/nmap", "version": "7.95"}
        mock_net.return_value = {
            "active_interface": "en0",
            "ip": "192.168.0.102",
            "cidr": "192.168.0.0/24",
            "gateway": "192.168.0.1",
            "ssid": "Test_WiFi"
        }

        res = health_check()
        self.assertEqual(res["status"], "healthy")
        self.assertEqual(res["version"], "1.0.0")
        self.assertTrue(res["database"]["connected"])
        self.assertTrue(res["nmap"]["installed"])
        self.assertEqual(res["network"]["cidr"], "192.168.0.0/24")

    @patch("backend.api.network.get_network_info")
    def test_network_info_endpoint(self, mock_info):
        mock_info.return_value = {
            "active_interface": "en0",
            "ip": "192.168.0.102",
            "netmask": "255.255.255.0",
            "cidr": "192.168.0.0/24",
            "gateway": "192.168.0.1",
            "broadcast": "192.168.0.255",
            "mac": "be:60:3a:e6:3d:dd",
            "ssid": "Test_SSID",
            "nmap": {"installed": True, "path": "/usr/bin/nmap", "version": "7.95"}
        }
        res = get_system_network_info()
        self.assertEqual(res["active_interface"], "en0")
        self.assertEqual(res["cidr"], "192.168.0.0/24")
        self.assertEqual(res["gateway"], "192.168.0.1")

    @patch("backend.api.network.list_all_interfaces")
    def test_network_interfaces_endpoint(self, mock_list):
        mock_list.return_value = [
            {"interface": "en0", "ip": "192.168.0.102", "is_default": True}
        ]
        res = get_all_network_interfaces()
        self.assertEqual(len(res["interfaces"]), 1)
        self.assertEqual(res["interfaces"][0]["interface"], "en0")

    @patch("backend.api.discovery.get_network_info")
    def test_default_network_endpoint(self, mock_info):
        mock_info.return_value = {
            "cidr": "192.168.10.0/24",
            "ip": "192.168.10.5",
            "active_interface": "en0",
            "gateway": "192.168.10.1",
            "ssid": "MyOffice"
        }
        res = get_default_network()
        self.assertEqual(res["network"], "192.168.10.0/24")
        self.assertEqual(res["local_ip"], "192.168.10.5")

    @patch("backend.api.assets.list_assets")
    def test_get_assets_endpoint(self, mock_list):
        mock_list.return_value = [
            {"id": 1, "ip": "192.168.0.1", "device_category": "Router", "effective_category": "Router"},
            {"id": 2, "ip": "192.168.0.50", "device_category": "CCTV Camera", "effective_category": "CCTV Camera"}
        ]
        res = get_assets(category=None, status=None, limit=100)
        self.assertEqual(res["count"], 2)
        self.assertEqual(len(res["assets"]), 2)
        self.assertEqual(len(res["devices"]), 2)

    @patch("backend.api.assets.get_asset")
    def test_get_asset_by_id_found_and_not_found(self, mock_get):
        mock_get.return_value = {"id": 1, "ip": "192.168.0.1"}
        res = get_asset_by_id(1)
        self.assertEqual(res["id"], 1)

        mock_get.return_value = None
        with self.assertRaises(HTTPException) as ctx:
            get_asset_by_id(999)
        self.assertEqual(ctx.exception.status_code, 404)

    @patch("backend.api.assets.update_asset_override")
    @patch("backend.api.assets.get_asset")
    def test_override_asset_type(self, mock_get, mock_update):
        mock_update.return_value = True
        mock_get.return_value = {
            "id": 1,
            "ip": "192.168.0.20",
            "device_category": "Unknown",
            "manual_override_category": "CCTV Camera",
            "effective_category": "CCTV Camera"
        }

        req = AssetOverrideRequest(category="CCTV Camera")
        res = set_asset_manual_override(1, req)
        self.assertTrue(res["success"])
        self.assertEqual(res["asset"]["effective_category"], "CCTV Camera")

        # Empty category rejection
        with self.assertRaises(HTTPException) as ctx:
            set_asset_manual_override(1, AssetOverrideRequest(category="  "))
        self.assertEqual(ctx.exception.status_code, 400)

    @patch("backend.api.assets.run_asset_identification")
    @patch("backend.api.assets.get_asset")
    def test_identify_single_asset_endpoint(self, mock_get, mock_run):
        mock_get.return_value = {"id": 1, "ip": "192.168.1.50"}
        mock_run.return_value = {
            "id": 1,
            "ip": "192.168.1.50",
            "effective_category": "IP CCTV Camera",
            "vendor": "Hikvision",
            "confidence_level": "High",
            "confidence_score": 90
        }
        res = identify_single_asset(1)
        self.assertTrue(res["success"])
        self.assertEqual(res["asset"]["effective_category"], "IP CCTV Camera")

    @patch("backend.api.assets.run_asset_identification")
    @patch("backend.api.assets.list_assets")
    def test_identify_all_assets_endpoint(self, mock_list, mock_run):
        mock_list.return_value = [
            {"id": 1, "ip": "192.168.0.1"},
            {"id": 2, "ip": "192.168.0.102"}
        ]
        mock_run.side_effect = [
            {"id": 1, "ip": "192.168.0.1", "effective_category": "Router"},
            {"id": 2, "ip": "192.168.0.102", "effective_category": "Computer"}
        ]
        res = identify_all_assets()
        self.assertEqual(res["count"], 2)
        self.assertEqual(res["assets"][0]["effective_category"], "Router")
        self.assertEqual(res["assets"][1]["effective_category"], "Computer")

    @patch("backend.api.assets.get_asset")
    def test_get_asset_identification_details_endpoint(self, mock_get):
        mock_get.return_value = {
            "id": 1,
            "ip": "192.168.1.50",
            "mac": "44:19:b6:aa:bb:cc",
            "effective_category": "IP CCTV Camera",
            "device_category": "IP CCTV Camera",
            "manual_override_category": None,
            "vendor": "Hikvision",
            "model": "DS-2CD2042WD-I",
            "confidence_score": 95,
            "confidence_level": "High",
            "evidence": ["Hardware MAC prefix matches Hikvision (+15 pts)"],
            "inconclusive_signals": [],
            "last_identified": "2026-11-16T10:00:00Z"
        }
        res = get_asset_identification_details(1)
        self.assertEqual(res["asset_id"], 1)
        self.assertEqual(res["effective_category"], "IP CCTV Camera")
        self.assertEqual(res["vendor"], "Hikvision")
        self.assertEqual(res["confidence_level"], "High")

    @patch("backend.api.stats.calculate_overview_statistics")
    def test_overview_stats_endpoint(self, mock_calc):
        mock_calc.return_value = {
            "total_discovered_devices": 5,
            "online_devices": 3,
            "vulnerable_devices": 2,
            "critical_vulnerabilities": 1,
            "overall_security_score": 75,
            "severity_breakdown": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1},
            "vendor_distribution": [{"name": "Hikvision", "count": 2}],
            "risk_trend": [],
            "recent_scans": []
        }
        res = get_overview_statistics()
        self.assertEqual(res["total_discovered_devices"], 5)
        self.assertEqual(res["overall_security_score"], 75)
        self.assertEqual(res["critical_vulnerabilities"], 1)

    @patch("backend.api.stats.get_all_vulnerabilities_data")
    def test_all_vulnerabilities_endpoint(self, mock_vulns):
        mock_vulns.return_value = {
            "count": 1,
            "findings": [{"id": "CAM-RTSP-001", "severity": "MEDIUM"}]
        }
        res = get_all_vulnerabilities()
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["findings"][0]["id"], "CAM-RTSP-001")


if __name__ == "__main__":
    unittest.main()

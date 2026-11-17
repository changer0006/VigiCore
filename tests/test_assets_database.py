import tempfile
import unittest
from pathlib import Path
from app.database.db import (
    initialize_database,
    check_db_connectivity,
    upsert_asset,
    get_asset,
    get_asset_by_ip,
    list_assets,
    update_asset_override,
    save_identification_result,
    delete_asset
)


class AssetsDatabaseTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_assets.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_db_connectivity_and_initialization(self):
        res = check_db_connectivity(self.db_path)
        self.assertTrue(res["connected"])
        self.assertEqual(res["assets_count"], 0)
        self.assertEqual(res["scans_count"], 0)

    def test_upsert_and_retrieve_asset(self):
        asset = {
            "ip": "192.168.0.50",
            "mac": "a8:29:48:a9:3e:a0",
            "vendor": "TP-Link Systems",
            "hostname": "tplink.wifi",
            "device_category": "Router",
            "confidence_level": "High",
            "confidence_score": 90,
            "status": "online",
            "open_ports": [80, 443]
        }
        asset_id = upsert_asset(asset, self.db_path)
        self.assertIsInstance(asset_id, int)

        retrieved = get_asset(asset_id, self.db_path)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["ip"], "192.168.0.50")
        self.assertEqual(retrieved["mac"], "a8:29:48:a9:3e:a0")
        self.assertEqual(retrieved["vendor"], "TP-Link Systems")
        self.assertEqual(retrieved["device_category"], "Router")
        self.assertEqual(retrieved["effective_category"], "Router")
        self.assertEqual(retrieved["open_ports"], [80, 443])

        # Test retrieve by IP
        by_ip = get_asset_by_ip("192.168.0.50", self.db_path)
        self.assertIsNotNone(by_ip)
        self.assertEqual(by_ip["id"], asset_id)

    def test_upsert_existing_asset_preserves_first_discovered(self):
        asset1 = {
            "ip": "192.168.0.100",
            "mac": "00:11:22:33:44:55",
            "vendor": "Unknown",
            "first_discovered": "2026-11-01T12:00:00Z",
            "last_discovered": "2026-11-01T12:00:00Z",
        }
        id1 = upsert_asset(asset1, self.db_path)

        asset2 = {
            "ip": "192.168.0.100",
            "mac": "00:11:22:33:44:55",
            "vendor": "Dahua Technology",
            "device_category": "CCTV Camera",
            "last_discovered": "2026-11-16T10:00:00Z",
            "risk_score": 85,
            "risk_level": "HIGH"
        }
        id2 = upsert_asset(asset2, self.db_path)
        self.assertEqual(id1, id2)

        saved = get_asset(id1, self.db_path)
        self.assertEqual(saved["first_discovered"], "2026-11-01T12:00:00Z")
        self.assertEqual(saved["last_discovered"], "2026-11-16T10:00:00Z")
        self.assertEqual(saved["vendor"], "Dahua Technology")
        self.assertEqual(saved["effective_category"], "CCTV Camera")
        self.assertEqual(saved["risk_score"], 85)
        self.assertEqual(saved["risk_level"], "HIGH")

    def test_manual_override_category(self):
        asset = {
            "ip": "192.168.0.102",
            "mac": "be:60:3a:e6:3d:dd",
            "vendor": "Apple",
            "device_category": "Workstation"
        }
        asset_id = upsert_asset(asset, self.db_path)
        initial = get_asset(asset_id, self.db_path)
        self.assertEqual(initial["effective_category"], "Workstation")

        # Set user override
        updated = update_asset_override(asset_id, "Security Console", self.db_path)
        self.assertTrue(updated)

        after = get_asset(asset_id, self.db_path)
        self.assertEqual(after["manual_override_category"], "Security Console")
        self.assertEqual(after["effective_category"], "Security Console")

    def test_list_and_delete_assets(self):
        upsert_asset({"ip": "10.0.0.1", "device_category": "Router"}, self.db_path)
        upsert_asset({"ip": "10.0.0.2", "device_category": "CCTV Camera"}, self.db_path)
        upsert_asset({"ip": "10.0.0.3", "device_category": "NVR"}, self.db_path)

        all_assets = list_assets(db_path=self.db_path)
        self.assertEqual(len(all_assets), 3)

        cctv_only = list_assets(category_filter="CCTV Camera", db_path=self.db_path)
        self.assertEqual(len(cctv_only), 1)
        self.assertEqual(cctv_only[0]["ip"], "10.0.0.2")

        # Delete asset
        deleted = delete_asset(cctv_only[0]["id"], self.db_path)
        self.assertTrue(deleted)
        self.assertEqual(len(list_assets(db_path=self.db_path)), 2)

    def test_save_identification_and_preserve_manual_override(self):
        asset_id = upsert_asset({
            "ip": "192.168.1.50",
            "device_category": "Unknown",
            "manual_override_category": "Guard Post Camera"
        }, self.db_path)

        # Run identification persistence
        ident = {
            "category": "IP CCTV Camera",
            "vendor": "Hikvision",
            "model": "DS-2CD2042WD-I",
            "confidence_score": 95,
            "confidence_level": "High",
            "evidence": ["Hikvision OUI matched", "RTSP 554 active"],
            "inconclusive_signals": []
        }
        saved = save_identification_result(asset_id, ident, self.db_path)
        self.assertTrue(saved)

        # Retrieve asset
        after = get_asset(asset_id, self.db_path)
        self.assertIsNotNone(after)
        # Automatic detection is updated
        self.assertEqual(after["device_category"], "IP CCTV Camera")
        self.assertEqual(after["vendor"], "Hikvision")
        self.assertEqual(after["model"], "DS-2CD2042WD-I")
        self.assertEqual(after["confidence_level"], "High")
        self.assertEqual(after["confidence_score"], 95)
        self.assertEqual(len(after["evidence"]), 2)
        # User manual override is strictly preserved!
        self.assertEqual(after["manual_override_category"], "Guard Post Camera")
        self.assertEqual(after["effective_category"], "Guard Post Camera")

    def test_persistence_across_restart(self):
        # Create records in db
        id1 = upsert_asset({"ip": "192.168.10.1", "device_category": "Router", "vendor": "Cisco"}, self.db_path)
        save_identification_result(id1, {
            "category": "Router",
            "vendor": "Cisco",
            "model": "RV340",
            "confidence_score": 85,
            "confidence_level": "High",
            "evidence": ["Gateway match"],
            "inconclusive_signals": []
        }, self.db_path)

        # Close and reopen db to simulate process restart
        reopened_asset = get_asset(id1, self.db_path)
        self.assertIsNotNone(reopened_asset)
        self.assertEqual(reopened_asset["ip"], "192.168.10.1")
        self.assertEqual(reopened_asset["model"], "RV340")
        self.assertEqual(reopened_asset["confidence_level"], "High")


if __name__ == "__main__":
    unittest.main()

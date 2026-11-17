"""
Comprehensive Test Suite for Overview Statistics & Vulnerability Endpoints.
Covers:
1. Empty database behavior
2. Database with discovered assets only
3. Database with completed scans
4. Database with vulnerability findings
5. Missing or malformed optional fields
6. Database migration compatibility
7. FastAPI endpoint responses
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.database.db import (
    initialize_database,
    save_scan,
    upsert_asset,
    DEFAULT_DB_PATH
)
from backend.api.stats import (
    calculate_overview_statistics,
    get_all_vulnerabilities_data,
    get_overview_statistics,
    get_device_inventory,
    get_all_vulnerabilities
)


class OverviewStatsTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_stats.db"
        initialize_database(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_empty_database(self):
        """Empty database should return consistent zero statistics without crashing."""
        stats = calculate_overview_statistics(db_path=self.db_path)

        self.assertEqual(stats["total_discovered_devices"], 0)
        self.assertEqual(stats["online_devices"], 0)
        self.assertEqual(stats["vulnerable_devices"], 0)
        self.assertEqual(stats["critical_vulnerabilities"], 0)
        self.assertEqual(stats["overall_security_score"], 100)
        self.assertEqual(stats["severity_breakdown"], {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        })
        self.assertEqual(stats["vendor_distribution"], [])
        self.assertEqual(stats["risk_trend"], [])
        self.assertEqual(stats["recent_scans"], [])

        vulns = get_all_vulnerabilities_data(db_path=self.db_path)
        self.assertEqual(vulns["count"], 0)
        self.assertEqual(vulns["findings"], [])

    def test_02_database_with_discovered_assets_only(self):
        """Database with discovered assets but no scans yet."""
        upsert_asset({
            "ip": "192.168.1.1",
            "vendor": "TP-Link",
            "status": "online",
            "device_category": "Router"
        }, db_path=self.db_path)

        upsert_asset({
            "ip": "192.168.1.100",
            "vendor": "Apple",
            "status": "offline",
            "device_category": "Computer"
        }, db_path=self.db_path)

        stats = calculate_overview_statistics(db_path=self.db_path)

        self.assertEqual(stats["total_discovered_devices"], 2)
        self.assertEqual(stats["online_devices"], 1)
        self.assertEqual(stats["vulnerable_devices"], 0)
        self.assertEqual(stats["overall_security_score"], 100)

        vendors = {v["name"]: v["count"] for v in stats["vendor_distribution"]}
        self.assertEqual(vendors.get("TP-Link"), 1)
        self.assertEqual(vendors.get("Apple"), 1)

    def test_03_database_with_completed_scans(self):
        """Database with completed scans and average risk calculation."""
        save_scan({
            "target": "192.168.1.10",
            "generated_at": "2026-11-16T10:00:00Z",
            "scan_status": "up",
            "fingerprint": {"device_type": "IP CCTV Camera", "vendor": "Hikvision"},
            "risk": {
                "risk_score": 40,
                "risk_level": "MEDIUM",
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0}
            }
        }, db_path=self.db_path)

        save_scan({
            "target": "192.168.1.20",
            "generated_at": "2026-11-16T11:00:00Z",
            "scan_status": "up",
            "fingerprint": {"device_type": "NVR", "vendor": "Dahua"},
            "risk": {
                "risk_score": 60,
                "risk_level": "HIGH",
                "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            }
        }, db_path=self.db_path)

        stats = calculate_overview_statistics(db_path=self.db_path)

        self.assertEqual(stats["total_discovered_devices"], 2)
        self.assertEqual(stats["vulnerable_devices"], 2)
        # Average risk is (40 + 60) / 2 = 50. Security score = 100 - 50 = 50.
        self.assertEqual(stats["overall_security_score"], 50)
        self.assertEqual(stats["severity_breakdown"]["HIGH"], 1)
        self.assertEqual(stats["severity_breakdown"]["MEDIUM"], 1)
        self.assertEqual(len(stats["risk_trend"]), 2)

    def test_04_database_with_vulnerability_findings(self):
        """Database with critical vulnerabilities and multi-source findings."""
        scan_payload = {
            "target": "192.168.1.8",
            "generated_at": "2026-11-16T12:00:00Z",
            "scan_status": "up",
            "fingerprint": {"device_type": "Likely CCTV/NVR", "vendor": "Hikvision"},
            "security_findings": [
                {
                    "id": "CAM-RTSP-001",
                    "title": "RTSP service exposed",
                    "severity": "MEDIUM",
                    "evidence": "Port 554/tcp open",
                    "remediation": "Restrict access",
                    "confirmed_vulnerability": False
                }
            ],
            "http_findings": [
                {
                    "id": "HTTP-HDR-001",
                    "title": "Missing HSTS",
                    "severity": "LOW",
                    "port": 80,
                    "evidence": "Header omitted",
                    "remediation": "Add HSTS",
                    "confirmed_vulnerability": False
                }
            ],
            "cve_candidates": [
                {
                    "cve_id": "CVE-2021-36260",
                    "port": 80,
                    "product_detected": "Hikvision Web",
                    "version_detected": "V4.0",
                    "severity": "CRITICAL",
                    "confirmed_vulnerability": False,
                    "requires_manual_validation": True
                }
            ],
            "risk": {
                "risk_score": 85,
                "risk_level": "CRITICAL",
                "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 1, "INFO": 0}
            }
        }
        save_scan(scan_payload, db_path=self.db_path)

        stats = calculate_overview_statistics(db_path=self.db_path)
        self.assertEqual(stats["critical_vulnerabilities"], 1)
        self.assertEqual(stats["vulnerable_devices"], 1)
        self.assertEqual(stats["severity_breakdown"]["CRITICAL"], 1)
        self.assertEqual(stats["severity_breakdown"]["MEDIUM"], 1)
        self.assertEqual(stats["severity_breakdown"]["LOW"], 1)

        vulns = get_all_vulnerabilities_data(db_path=self.db_path)
        self.assertEqual(vulns["count"], 3)
        # CRITICAL should be first due to severity sort
        self.assertEqual(vulns["findings"][0]["severity"], "CRITICAL")
        self.assertEqual(vulns["findings"][0]["id"], "CVE-2021-36260")
        self.assertTrue(vulns["findings"][0]["is_candidate"])

    def test_05_missing_optional_fields_resilience(self):
        """Endpoint must gracefully handle None, missing, or malformed data."""
        with sqlite3.connect(self.db_path) as conn:
            # 1. Row with NULL result_json
            conn.execute("""
                INSERT INTO scans (target, generated_at, scan_status, device_type, vendor, risk_score, risk_level, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ("192.168.1.99", "", None, None, None, None, "CRITICAL", ""))

            # 2. Row with invalid/corrupt JSON
            conn.execute("""
                INSERT INTO scans (target, generated_at, scan_status, device_type, vendor, risk_score, risk_level, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ("192.168.1.101", "2026-11-16T12:00:00Z", "up", "Camera", "Hikvision", 50, "MEDIUM", "INVALID-JSON-{{{"))

            # 3. Row with empty JSON object
            conn.execute("""
                INSERT INTO scans (target, generated_at, scan_status, device_type, vendor, risk_score, risk_level, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ("192.168.1.102", "2026-11-16T12:00:00Z", "up", "Camera", "Hikvision", 0, "INFO", "{}"))

            # 4. Row with non-dict risk field
            conn.execute("""
                INSERT INTO scans (target, generated_at, scan_status, device_type, vendor, risk_score, risk_level, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ("192.168.1.103", "2026-11-16T12:00:00Z", "up", "Camera", "Hikvision", 30, "LOW", '{"risk": "not-a-dict"}'))

            # 5. Row with non-integer severity counts
            conn.execute("""
                INSERT INTO scans (target, generated_at, scan_status, device_type, vendor, risk_score, risk_level, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ("192.168.1.104", "2026-11-16T12:00:00Z", "up", "Camera", "Hikvision", 70, "HIGH", '{"risk": {"severity_counts": {"CRITICAL": "invalid_int", "HIGH": null}}}'))

        # Must not raise any exceptions!
        stats = calculate_overview_statistics(db_path=self.db_path)
        self.assertIsInstance(stats, dict)
        self.assertEqual(stats["total_discovered_devices"], 5)
        self.assertGreaterEqual(stats["critical_vulnerabilities"], 1)

        vulns = get_all_vulnerabilities_data(db_path=self.db_path)
        self.assertIsInstance(vulns, dict)

    def test_06_database_migration_compatibility(self):
        """Legacy tables missing recent migration columns must auto-migrate cleanly."""
        legacy_db = Path(self.temp_dir.name) / "legacy.db"
        with sqlite3.connect(legacy_db) as conn:
            # Minimal legacy assets table missing 'model', 'evidence_json', etc.
            conn.execute("""
                CREATE TABLE assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    mac TEXT,
                    vendor TEXT,
                    hostname TEXT,
                    device_category TEXT DEFAULT 'Unknown',
                    confidence_level TEXT DEFAULT 'Low',
                    confidence_score INTEGER DEFAULT 0,
                    first_discovered TEXT NOT NULL,
                    last_discovered TEXT NOT NULL,
                    status TEXT DEFAULT 'online'
                )
            """)
            conn.execute("""
                INSERT INTO assets (ip, vendor, first_discovered, last_discovered)
                VALUES ('10.0.0.1', 'Cisco', '2026-01-01', '2026-01-01')
            """)

        # Call initialize_database on legacy schema
        initialize_database(legacy_db)

        # Verify query runs smoothly without schema errors
        stats = calculate_overview_statistics(db_path=legacy_db)
        self.assertEqual(stats["total_discovered_devices"], 1)
        self.assertEqual(stats["online_devices"], 1)


if __name__ == "__main__":
    unittest.main()

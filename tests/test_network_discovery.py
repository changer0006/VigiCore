import unittest
from unittest.mock import patch, MagicMock
from app.discovery.network_discovery import (
    parse_discovery_xml,
    discover_hosts,
    unprivileged_discover_hosts,
    check_privileged_nmap,
    get_nmap_privilege_guidance,
    normalize_mac,
    is_valid_unicast_mac,
)


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="sudo nmap -sn -PR 192.168.0.0/24" start="1700000000" version="7.99">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <address addr="a8:29:48:a9:3e:a0" addrtype="mac" vendor="TP-Link router"/>
    <hostnames>
      <hostname name="router.local" type="PTR"/>
    </hostnames>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.0.50" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="conn-refused"/>
    <address addr="192.168.0.102" addrtype="ipv4"/>
    <hostnames>
      <hostname name="MacBook" type="PTR"/>
    </hostnames>
  </host>
  <runstats>
    <finished time="1700000020" summary="Nmap done; 256 IP addresses (2 hosts up) scanned"/>
    <hosts up="2" down="254" total="256"/>
  </runstats>
</nmaprun>
"""


class NetworkDiscoveryTests(unittest.TestCase):

    def test_parse_sample_nmap_xml_with_two_discovered_hosts(self):
        hosts = parse_discovery_xml(SAMPLE_NMAP_XML, enrich_arp=False)

        self.assertEqual(len(hosts), 2)

        # Host 1: TP-Link Router
        self.assertEqual(hosts[0]["ip"], "192.168.0.1")
        self.assertEqual(hosts[0]["mac"], "a8:29:48:a9:3e:a0")
        self.assertEqual(hosts[0]["vendor"], "TP-Link router")
        self.assertEqual(hosts[0]["discovery_method"], "privileged_arp")

        # Host 2: MacBook
        self.assertEqual(hosts[1]["ip"], "192.168.0.102")
        self.assertIn("MacBook", hosts[1]["vendor"])

    @patch("subprocess.run")
    def test_permission_blocked_scan_raises_runtime_error_when_no_fallback_hosts(self, mock_run):
        # Nmap exited with code 0 but stderr had 'Operation not permitted'
        # And fallback is disabled
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = "Strange read error from 192.168.0.1 (1 - 'Operation not permitted')"
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        with self.assertRaises(RuntimeError) as ctx:
            discover_hosts("192.168.0.0/24", allow_fallback=False)

        self.assertIn("permissions", str(ctx.exception).lower())

    @patch("subprocess.run")
    def test_nmap_failure_exit_code_raises_error(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed to resolve target network"
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        with self.assertRaises(RuntimeError) as ctx:
            discover_hosts("invalid_network")

        self.assertIn("Failed to resolve target network", str(ctx.exception))

    @patch("app.discovery.network_discovery.get_local_arp_table")
    @patch("app.discovery.network_telemetry.get_network_info")
    @patch("subprocess.run")
    def test_unprivileged_fallback_activates_on_nmap_permission_error(self, mock_run, mock_net_info, mock_arp):
        # Nmap fails with permission error
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stderr = "Operation not permitted"
        mock_res.stdout = ""
        mock_run.return_value = mock_res

        mock_net_info.return_value = {
            "ip": "192.168.1.100",
            "mac": "a0:9a:8e:3a:7f:68",
            "gateway": "192.168.1.1"
        }
        mock_arp.return_value = {
            "192.168.1.1": "a8:29:48:a9:3e:a0",
            "192.168.1.55": "bc:ba:e1:12:34:56"
        }

        hosts = discover_hosts("192.168.1.0/24", allow_fallback=True)

        self.assertGreaterEqual(len(hosts), 2)
        ips = [h["ip"] for h in hosts]
        self.assertIn("192.168.1.1", ips)
        self.assertIn("192.168.1.100", ips)

    def test_normalize_mac(self):
        self.assertEqual(normalize_mac("32:a0:46:6f:1:34"), "32:a0:46:6f:01:34")
        self.assertEqual(normalize_mac("A8:29:48:A9:3E:A0"), "a8:29:48:a9:3e:a0")
        self.assertIsNone(normalize_mac(None))

    def test_is_valid_unicast_mac(self):
        self.assertTrue(is_valid_unicast_mac("a8:29:48:a9:3e:a0"))
        self.assertFalse(is_valid_unicast_mac("(incomplete)"))
        self.assertFalse(is_valid_unicast_mac("ff:ff:ff:ff:ff:ff"))
        self.assertFalse(is_valid_unicast_mac("01:00:5e:00:00:fb"))
        self.assertFalse(is_valid_unicast_mac(None))

    @patch("subprocess.run")
    def test_check_privileged_nmap(self, mock_run):
        # When sudo -n returns 0
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        avail, mode = check_privileged_nmap()
        self.assertTrue(avail)
        self.assertEqual(mode, "sudo_nopasswd")

        # When sudo -n returns non-zero
        mock_proc.returncode = 1
        with patch("os.geteuid", return_value=501):
            avail, mode = check_privileged_nmap()
            self.assertFalse(avail)
            self.assertEqual(mode, "unprivileged")

    def test_get_nmap_privilege_guidance(self):
        guidance = get_nmap_privilege_guidance()
        self.assertIn("rule", guidance)
        self.assertIn("NOPASSWD", guidance["rule"])
        self.assertIn("/etc/sudoers.d/vigicore-nmap", guidance["sudoers_file"])


if __name__ == "__main__":
    unittest.main()

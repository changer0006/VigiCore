import subprocess
import unittest
from unittest.mock import patch, MagicMock

from app.discovery.network_telemetry import (
    get_default_route_info,
    get_interface_details,
    get_wifi_ssid,
    get_nmap_info,
    get_network_info,
    list_all_interfaces
)


class NetworkTelemetryTests(unittest.TestCase):

    @patch("subprocess.run")
    def test_get_default_route_info_success(self, mock_run):
        mock_output = """   route to: default
destination: default
       mask: default
    gateway: 192.168.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
        0         0         0         0         0         0      1500         0
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_output)
        gateway, iface = get_default_route_info()
        self.assertEqual(gateway, "192.168.0.1")
        self.assertEqual(iface, "en0")

    @patch("subprocess.run")
    def test_get_default_route_info_netstat_fallback(self, mock_run):
        # First call (route) fails, second call (netstat) succeeds
        def side_effect(cmd, *args, **kwargs):
            if cmd[0] == "route":
                return MagicMock(returncode=1, stdout="", stderr="route: not found")
            elif cmd[0] == "netstat":
                output = """Routing tables
Internet:
Destination        Gateway            Flags        Netif Expire
default            10.0.0.1           UGScg          en1
10.0.0/24          link#6             UCSc           en1
"""
                return MagicMock(returncode=0, stdout=output)
            return MagicMock(returncode=1, stdout="")

        mock_run.side_effect = side_effect
        gateway, iface = get_default_route_info()
        self.assertEqual(gateway, "10.0.0.1")
        self.assertEqual(iface, "en1")

    @patch("subprocess.run")
    def test_get_interface_details(self, mock_run):
        mock_ifconfig = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether be:60:3a:e6:3d:dd
	inet6 fe80::1091:780f:94e0:6dfa%en0 prefixlen 64 secured scopeid 0x6
	inet 192.168.0.102 netmask 0xffffff00 broadcast 192.168.0.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_ifconfig)
        details = get_interface_details("en0")

        self.assertEqual(details["interface"], "en0")
        self.assertEqual(details["ip"], "192.168.0.102")
        self.assertEqual(details["netmask"], "255.255.255.0")
        self.assertEqual(details["cidr"], "192.168.0.0/24")
        self.assertEqual(details["broadcast"], "192.168.0.255")
        self.assertEqual(details["mac"], "be:60:3a:e6:3d:dd")
        self.assertTrue(details["is_active"])

    @patch("subprocess.run")
    def test_get_wifi_ssid(self, mock_run):
        mock_summary = """Wireless Network:
  SSID : Test_CCTV_WiFi
  BSSID : 00:11:22:33:44:55
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_summary)
        ssid = get_wifi_ssid("en0")
        self.assertEqual(ssid, "Test_CCTV_WiFi")

    @patch("subprocess.run")
    def test_get_nmap_info(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Nmap version 7.95 ( https://nmap.org )\nPlatform: arm-apple-darwin"
        )
        info = get_nmap_info()
        self.assertTrue(info["installed"])
        self.assertEqual(info["version"], "7.95")


if __name__ == "__main__":
    unittest.main()

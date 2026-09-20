"""
Unit tests for network resolution, target parsing, and port parsing.
"""

import unittest
from port_scanner.utils.network import resolve_host, parse_targets, parse_ports


class TestNetworkUtils(unittest.TestCase):
    """Test suite for network address and port parsing logic."""

    def test_resolve_ip(self):
        """Valid IP string should return the IP directly."""
        ip, original = resolve_host("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(original, "127.0.0.1")

    def test_resolve_localhost(self):
        """'localhost' should resolve to 127.0.0.1 or standard loopback."""
        ip, original = resolve_host("localhost")
        self.assertTrue(ip.startswith("127.") or ip == "::1")
        self.assertEqual(original, "localhost")

    def test_resolve_invalid_host(self):
        """Invalid domain should raise ValueError."""
        with self.assertRaises(ValueError):
            resolve_host("this-domain-definitely-does-not-exist-12345abcdef.local")

    def test_parse_targets_single_ip(self):
        """Parsing a single IP address."""
        targets = parse_targets("192.168.1.1")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0][0], "192.168.1.1")

    def test_parse_targets_cidr(self):
        """Parsing CIDR notation /30 should yield 2 usable host IPs."""
        targets = parse_targets("192.168.1.0/30")
        ips = [t[0] for t in targets]
        self.assertEqual(ips, ["192.168.1.1", "192.168.1.2"])

    def test_parse_targets_range(self):
        """Parsing IP range 192.168.1.1-192.168.1.3."""
        targets = parse_targets("192.168.1.1-192.168.1.3")
        ips = [t[0] for t in targets]
        self.assertEqual(ips, ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_parse_targets_short_range(self):
        """Parsing short range 10.0.0.1-3."""
        targets = parse_targets("10.0.0.1-3")
        ips = [t[0] for t in targets]
        self.assertEqual(ips, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_parse_ports_single(self):
        """Parsing single port."""
        ports = parse_ports("80")
        self.assertEqual(ports, [80])

    def test_parse_ports_list(self):
        """Parsing comma-separated list of ports."""
        ports = parse_ports("80,443,8080")
        self.assertEqual(ports, [80, 443, 8080])

    def test_parse_ports_range(self):
        """Parsing range of ports."""
        ports = parse_ports("20-25")
        self.assertEqual(ports, [20, 21, 22, 23, 24, 25])

    def test_parse_ports_mixed(self):
        """Parsing mixed comma and range."""
        ports = parse_ports("22,80-82,443")
        self.assertEqual(ports, [22, 80, 81, 82, 443])

    def test_parse_ports_top(self):
        """Parsing top ports preset."""
        top20 = parse_ports(top_count=20)
        self.assertEqual(len(top20), 20)
        self.assertIn(80, top20)
        self.assertIn(443, top20)

    def test_parse_ports_invalid_number(self):
        """Out of bounds port should raise ValueError."""
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_parse_ports_invalid_string(self):
        """Non-numeric port string should raise ValueError."""
        with self.assertRaises(ValueError):
            parse_ports("abc")


if __name__ == "__main__":
    unittest.main()

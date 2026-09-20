"""
Unit tests for scanner engine, banner sanitization, and concurrency.
Uses mocked sockets for reliable, network-independent test runs.
"""

import unittest
from unittest.mock import MagicMock, patch
import socket

from port_scanner.core.scanner import PortScanner, PortResult, ScanResult
from port_scanner.core.banner import sanitize_banner


class TestScanner(unittest.TestCase):
    """Test cases for PortScanner and associated data structures."""

    def test_port_result_to_dict(self):
        """Verify dictionary serialization of PortResult."""
        res = PortResult(port=80, state="OPEN", service="HTTP", banner="Apache/2.4", latency_ms=12.345)
        d = res.to_dict()
        self.assertEqual(d["port"], 80)
        self.assertEqual(d["state"], "OPEN")
        self.assertEqual(d["service"], "HTTP")
        self.assertEqual(d["banner"], "Apache/2.4")
        self.assertEqual(d["latency_ms"], 12.35)

    def test_scan_result_scan_rate(self):
        """Verify scan throughput rate calculation."""
        res = ScanResult(
            target_ip="127.0.0.1",
            target_host="localhost",
            ports_scanned=100,
            duration=2.0
        )
        self.assertEqual(res.scan_rate, 50.0)

    def test_sanitize_banner_http_server(self):
        """Verify extraction of HTTP Server header."""
        raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n"
        banner = sanitize_banner(raw)
        self.assertEqual(banner, "HTTP (Server: nginx/1.18.0)")

    def test_sanitize_banner_generic(self):
        """Verify extraction of generic first line greeting."""
        raw = b"220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [127.0.0.1]\r\n"
        banner = sanitize_banner(raw)
        self.assertTrue(banner.startswith("220 ProFTPD"))

    def test_sanitize_banner_empty(self):
        """Verify handling of empty raw bytes."""
        self.assertEqual(sanitize_banner(b""), "")

    @patch("socket.socket")
    def test_scan_single_port_open(self, mock_socket_cls):
        """Test scanning an open port with a mock socket."""
        mock_sock_instance = MagicMock()
        mock_socket_cls.return_value = mock_sock_instance
        # connect does not raise exception -> successful connection
        mock_sock_instance.connect.return_value = None

        scanner = PortScanner(timeout=0.5, threads=2, grab_banners=False)
        result = scanner.scan_single_port("127.0.0.1", 80)

        self.assertIsNotNone(result)
        self.assertEqual(result.port, 80)
        self.assertEqual(result.state, "OPEN")
        self.assertEqual(result.service, "HTTP")

    @patch("socket.socket")
    def test_scan_single_port_closed(self, mock_socket_cls):
        """Test scanning a closed port raising ConnectionRefusedError."""
        mock_sock_instance = MagicMock()
        mock_socket_cls.return_value = mock_sock_instance
        mock_sock_instance.connect.side_effect = ConnectionRefusedError("Connection refused")

        scanner = PortScanner(timeout=0.5, threads=2, grab_banners=False)
        result = scanner.scan_single_port("127.0.0.1", 9999)

        self.assertIsNone(result)

    @patch("socket.socket")
    def test_scan_single_port_timeout(self, mock_socket_cls):
        """Test scanning a filtered port raising socket.timeout."""
        mock_sock_instance = MagicMock()
        mock_socket_cls.return_value = mock_sock_instance
        mock_sock_instance.connect.side_effect = socket.timeout("Timed out")

        scanner = PortScanner(timeout=0.5, threads=2, grab_banners=False)
        result = scanner.scan_single_port("127.0.0.1", 8888)

        self.assertIsNone(result)

    @patch.object(PortScanner, "scan_single_port")
    def test_scan_target_aggregation(self, mock_scan_single):
        """Test multi-port scan aggregation and progress callback."""
        def fake_scan(ip, p, host="target"):
            if p in (80, 443):
                return PortResult(port=p, state="OPEN", service="Web")
            return None

        mock_scan_single.side_effect = fake_scan

        progress_calls = []
        def callback(scanned, total):
            progress_calls.append((scanned, total))

        scanner = PortScanner(threads=4, progress_callback=callback)
        result = scanner.scan_target("127.0.0.1", [22, 80, 443, 8080])

        self.assertEqual(result.ports_scanned, 4)
        self.assertEqual(len(result.open_ports), 2)
        self.assertEqual(result.open_ports[0].port, 80)
        self.assertEqual(result.open_ports[1].port, 443)
        self.assertEqual(len(progress_calls), 4)


if __name__ == "__main__":
    unittest.main()

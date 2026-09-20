"""
Unit tests for JSON, CSV, and Console reporters.
"""

import json
import csv
import os
import tempfile
import unittest

from port_scanner.core.scanner import PortResult, ScanResult
from port_scanner.reporters.json_reporter import export_json
from port_scanner.reporters.csv_reporter import export_csv
from port_scanner.reporters.console_reporter import print_banner, print_scan_results


class TestReporters(unittest.TestCase):
    """Test suite for report generation modules."""

    def setUp(self):
        self.sample_port = PortResult(
            port=443,
            state="OPEN",
            service="HTTPS",
            banner="HTTP (Server: cloudflare)",
            latency_ms=25.4,
        )
        self.sample_result = ScanResult(
            target_ip="1.1.1.1",
            target_host="cloudflare-dns.com",
            ports_scanned=10,
            open_ports=[self.sample_port],
            duration=0.5,
        )

    def test_export_json(self):
        """Test exporting scan results to JSON file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            filepath = tf.name

        try:
            export_json(self.sample_result, filepath)
            self.assertTrue(os.path.exists(filepath))

            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("generator", data)
            self.assertIn("scans", data)
            self.assertEqual(len(data["scans"]), 1)
            scan = data["scans"][0]
            self.assertEqual(scan["target_ip"], "1.1.1.1")
            self.assertEqual(scan["open_ports_count"], 1)
            self.assertEqual(scan["open_ports"][0]["port"], 443)
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    def test_export_csv(self):
        """Test exporting scan results to CSV file."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
            filepath = tf.name

        try:
            export_csv(self.sample_result, filepath)
            self.assertTrue(os.path.exists(filepath))

            with open(filepath, "r", encoding="utf-8") as f:
                reader = list(csv.reader(f))

            self.assertGreaterEqual(len(reader), 2)  # Header + 1 row
            self.assertEqual(reader[0][0], "Target IP")
            self.assertEqual(reader[1][0], "1.1.1.1")
            self.assertEqual(reader[1][2], "443")
            self.assertEqual(reader[1][5], "HTTPS")
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    def test_console_reporter_renders_cleanly(self):
        """Verify console print functions execute without errors."""
        try:
            print_banner()
            print_scan_results(self.sample_result)
        except Exception as e:
            self.fail(f"Console reporter raised an exception: {e}")


if __name__ == "__main__":
    unittest.main()

"""
CSV export reporter for spreadsheet auditing and vulnerability triage.
"""

import csv
from typing import List, Union
from port_scanner.core.scanner import ScanResult


def export_csv(results: Union[ScanResult, List[ScanResult]], filepath: str) -> None:
    """
    Export scan results to a comma-separated values (CSV) file.
    """
    if isinstance(results, ScanResult):
        results_list = [results]
    else:
        results_list = results

    fieldnames = [
        "Target IP",
        "Target Host",
        "Port",
        "Protocol",
        "State",
        "Service",
        "Latency (ms)",
        "Banner",
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)

        for scan in results_list:
            for port in scan.open_ports:
                writer.writerow([
                    scan.target_ip,
                    scan.target_host,
                    port.port,
                    "TCP",
                    port.state,
                    port.service,
                    f"{port.latency_ms:.2f}",
                    port.banner,
                ])

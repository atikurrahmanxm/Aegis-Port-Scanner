"""
JSON export reporter for SIEM, security pipeline, or automated consumption.
"""

import json
from datetime import datetime
from typing import List, Union
from port_scanner.core.scanner import ScanResult


def export_json(results: Union[ScanResult, List[ScanResult]], filepath: str) -> None:
    """
    Export one or multiple scan results to a formatted JSON file.
    """
    if isinstance(results, ScanResult):
        results_list = [results]
    else:
        results_list = results

    data = {
        "generator": "AegisScan v1.0.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "scans": [r.to_dict() for r in results_list],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

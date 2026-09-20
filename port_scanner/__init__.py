"""
AegisScan: Advanced Multithreaded Network Port Scanner & Service Fingerprinter.
Author: Atikur Rahman
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Atikur Rahman"
__description__ = "High-performance multithreaded network port scanner with banner grabbing and service detection"

from port_scanner.core.scanner import PortScanner, ScanResult, PortResult
from port_scanner.utils.network import parse_targets, parse_ports

__all__ = [
    "PortScanner",
    "ScanResult",
    "PortResult",
    "parse_targets",
    "parse_ports",
    "__version__",
]

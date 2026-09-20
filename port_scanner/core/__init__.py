"""Core scanner and service detection package."""
from port_scanner.core.scanner import PortScanner, ScanResult, PortResult
from port_scanner.core.services import (
    COMMON_SERVICES,
    TOP_20_PORTS,
    TOP_100_PORTS,
    TOP_1000_PORTS,
    get_service_name,
    get_top_ports,
)
from port_scanner.core.banner import grab_banner, sanitize_banner

__all__ = [
    "PortScanner",
    "ScanResult",
    "PortResult",
    "COMMON_SERVICES",
    "TOP_20_PORTS",
    "TOP_100_PORTS",
    "TOP_1000_PORTS",
    "get_service_name",
    "get_top_ports",
    "grab_banner",
    "sanitize_banner",
]

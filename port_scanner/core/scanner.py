"""
High-performance multithreaded TCP Port Scanner engine.
Coordinates socket connections, latency measurement, banner grabbing,
and concurrent worker pools.
"""

import socket
import time
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Callable, Dict, Any

from port_scanner.core.services import get_service_name
from port_scanner.core.banner import grab_banner


@dataclass
class PortResult:
    """Represents the scan outcome for a single network port."""
    port: int
    state: str = "OPEN"
    service: str = "Unknown"
    banner: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "latency_ms": round(self.latency_ms, 2),
        }


@dataclass
class ScanResult:
    """Aggregated scan outcome for a specific target host."""
    target_ip: str
    target_host: str
    ports_scanned: int
    open_ports: List[PortResult] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0

    @property
    def scan_rate(self) -> float:
        """Scan throughput in ports per second."""
        if self.duration > 0:
            return round(self.ports_scanned / self.duration, 1)
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "target_host": self.target_host,
            "ports_scanned": self.ports_scanned,
            "open_ports_count": len(self.open_ports),
            "duration_seconds": round(self.duration, 2),
            "scan_rate_pps": self.scan_rate,
            "open_ports": [p.to_dict() for p in self.open_ports],
        }


class PortScanner:
    """
    Multithreaded TCP Connect Port Scanner.
    """

    def __init__(
        self,
        timeout: float = 1.0,
        threads: int = 50,
        grab_banners: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ):
        """
        Initialize the scanner with configurable parameters.

        Args:
            timeout: Socket connection timeout in seconds.
            threads: Maximum number of worker threads for parallel scanning.
            grab_banners: If True, probes open ports for service banners.
            progress_callback: Optional callback invoked as (scanned_count, total_count).
        """
        self.timeout = timeout
        self.threads = max(1, min(threads, 500))  # Sanity clamp 1 - 500 threads
        self.grab_banners = grab_banners
        self.progress_callback = progress_callback

    def scan_single_port(
        self,
        target_ip: str,
        port: int,
        target_host: str = "target"
    ) -> Optional[PortResult]:
        """
        Scan an individual port via TCP 3-way handshake.

        Returns:
            PortResult if open, or None if closed/filtered.
        """
        start_t = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((target_ip, port))
            latency = (time.perf_counter() - start_t) * 1000.0  # ms
            sock.close()

            service = get_service_name(port)
            banner = ""
            if self.grab_banners:
                banner = grab_banner(target_ip, port, timeout=self.timeout, host=target_host)

            return PortResult(
                port=port,
                state="OPEN",
                service=service,
                banner=banner,
                latency_ms=latency,
            )
        except (socket.timeout, ConnectionRefusedError, OSError):
            # Port is closed or filtered
            try:
                sock.close()
            except Exception:
                pass
            return None
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return None

    def scan_target(
        self,
        target_ip: str,
        ports: List[int],
        target_host: str = "target"
    ) -> ScanResult:
        """
        Scan a list of ports on a target IP concurrently using thread pooling.

        Args:
            target_ip: Target IPv4 address.
            ports: List of integer port numbers to scan.
            target_host: Original hostname or identifier.

        Returns:
            ScanResult containing all discovered open ports and metrics.
        """
        start_time = time.time()
        total_ports = len(ports)
        scanned_count = 0
        open_ports: List[PortResult] = []

        # Use ThreadPoolExecutor for I/O bound socket concurrency
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self.scan_single_port, target_ip, p, target_host): p
                for p in ports
            }

            for future in as_completed(future_to_port):
                scanned_count += 1
                if self.progress_callback:
                    self.progress_callback(scanned_count, total_ports)

                try:
                    res = future.result()
                    if res is not None:
                        open_ports.append(res)
                except Exception:
                    pass

        end_time = time.time()
        duration = max(0.001, end_time - start_time)

        # Sort ports in ascending numerical order
        open_ports.sort(key=lambda r: r.port)

        return ScanResult(
            target_ip=target_ip,
            target_host=target_host,
            ports_scanned=total_ports,
            open_ports=open_ports,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
        )

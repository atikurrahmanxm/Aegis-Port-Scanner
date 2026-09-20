"""
Network validation and target resolution helpers.
Handles IP addresses, hostnames, CIDR ranges, and port specifications.
"""

import ipaddress
import socket
from typing import List, Tuple, Optional


def resolve_host(target: str) -> Tuple[str, str]:
    """
    Resolve a hostname or IP address to an IP.

    Returns:
        Tuple of (resolved_ip, hostname_or_ip)
    
    Raises:
        ValueError: If the target cannot be resolved or is invalid.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target specification cannot be empty.")

    # Check if target is already an IP address
    try:
        ip_obj = ipaddress.ip_address(target)
        return str(ip_obj), target
    except ValueError:
        pass

    # Resolve hostname
    try:
        resolved_ip = socket.gethostbyname(target)
        return resolved_ip, target
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host '{target}': {e}")
    except Exception as e:
        raise ValueError(f"Failed to resolve target '{target}': {e}")


def parse_targets(target_spec: str) -> List[Tuple[str, str]]:
    """
    Parse a target string which can be:
    - Single IP: '192.168.1.1'
    - Single hostname: 'example.com'
    - CIDR notation: '192.168.1.0/30'
    - Comma-separated list: '192.168.1.1,example.com'
    - IP range: '192.168.1.10-192.168.1.15' or '192.168.1.10-15'

    Returns:
        List of tuples: [(resolved_ip, original_spec), ...]
    """
    targets = []
    items = [item.strip() for item in target_spec.split(",") if item.strip()]

    for item in items:
        # Check CIDR
        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
                for ip in network.hosts():
                    targets.append((str(ip), str(ip)))
                # If network has no hosts (e.g. /32), take the single address
                if not list(network.hosts()):
                    targets.append((str(network.network_address), str(network.network_address)))
                continue
            except ValueError:
                pass

        # Check IP range e.g. 192.168.1.1-192.168.1.5 or 192.168.1.1-5
        if "-" in item and not item.startswith("-"):
            parts = item.split("-")
            if len(parts) == 2:
                start_str, end_str = parts[0].strip(), parts[1].strip()
                try:
                    start_ip = ipaddress.ip_address(start_str)
                    if "." in end_str:
                        end_ip = ipaddress.ip_address(end_str)
                    else:
                        # e.g., 192.168.1.1-5
                        octets = start_str.split(".")
                        octets[-1] = end_str
                        end_ip = ipaddress.ip_address(".".join(octets))
                    
                    if int(start_ip) > int(end_ip):
                        raise ValueError(f"Start IP {start_ip} is greater than End IP {end_ip}")
                    
                    # Limit range expansion to prevent accidental massive memory bloat (max 1024 hosts)
                    if int(end_ip) - int(start_ip) > 1024:
                        raise ValueError(f"Range {item} too large (max 1024 hosts allowed per range)")

                    curr = int(start_ip)
                    while curr <= int(end_ip):
                        ip_str = str(ipaddress.ip_address(curr))
                        targets.append((ip_str, ip_str))
                        curr += 1
                    continue
                except ValueError as ve:
                    # If not valid IP range, treat as host resolution fallback
                    pass

        # Standard single host or IP
        resolved_ip, original = resolve_host(item)
        targets.append((resolved_ip, original))

    if not targets:
        raise ValueError(f"No valid targets found in specification: '{target_spec}'")

    return targets


def parse_ports(port_spec: Optional[str] = None, top_count: Optional[int] = None) -> List[int]:
    """
    Parse port specification string or return top ports.

    Supported formats:
    - '80'
    - '80,443,8080'
    - '1-1024'
    - '22,80-90,443'
    - top_count: 20, 100, 1000

    Returns:
        Sorted list of unique integer port numbers (1 - 65535)
    """
    from port_scanner.core.services import get_top_ports

    if top_count is not None:
        return get_top_ports(top_count)

    if not port_spec:
        # Default to top 100 ports if nothing specified
        return get_top_ports(100)

    ports = set()
    parts = [p.strip() for p in port_spec.split(",") if p.strip()]

    for part in parts:
        if "-" in part:
            range_parts = part.split("-")
            if len(range_parts) != 2:
                raise ValueError(f"Invalid port range format: '{part}'")
            try:
                start_p = int(range_parts[0].strip())
                end_p = int(range_parts[1].strip())
            except ValueError:
                raise ValueError(f"Port range must contain numbers: '{part}'")
            
            if start_p > end_p:
                raise ValueError(f"Start port {start_p} cannot be greater than end port {end_p}")
            if start_p < 1 or end_p > 65535:
                raise ValueError(f"Port range {part} out of bounds (1-65535)")
            
            ports.update(range(start_p, end_p + 1))
        else:
            try:
                p = int(part)
                if p < 1 or p > 65535:
                    raise ValueError(f"Port {p} is outside valid range (1-65535)")
                ports.add(p)
            except ValueError:
                raise ValueError(f"Invalid port number: '{part}'")

    if not ports:
        raise ValueError("No valid ports specified.")

    return sorted(list(ports))

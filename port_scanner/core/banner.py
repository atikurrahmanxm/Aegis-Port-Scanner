"""
Banner grabbing engine for service identification and version extraction.
Supports raw TCP banners and SSL/TLS wrapped banners.
"""

import re
import socket
import ssl
from typing import Optional
from port_scanner.core.services import get_probe_payload


def sanitize_banner(raw_data: bytes) -> str:
    """
    Sanitize raw banner bytes into a clean, human-readable single-line string.
    Removes binary garbage, ANSI codes, and excessive whitespace.
    """
    if not raw_data:
        return ""

    # Decode with fallback to replace bad characters
    text = raw_data.decode("utf-8", errors="replace")
    
    # Filter printable characters and common whitespace
    printable = "".join(ch if (ch.isprintable() or ch in " \t\r\n") else " " for ch in text)
    
    # Check for HTTP Server header or status line
    http_server_match = re.search(r"Server:\s*([^\r\n]+)", printable, re.IGNORECASE)
    if http_server_match:
        return f"HTTP (Server: {http_server_match.group(1).strip()})"
    
    # If HTTP status line exists
    http_status_match = re.match(r"(HTTP/\d\.\d\s+\d{3}\s+[^\r\n]*)", printable)
    if http_status_match:
        return http_status_match.group(1).strip()

    # Extract first informative line
    lines = [line.strip() for line in printable.splitlines() if line.strip()]
    if lines:
        banner = lines[0]
        # Cap length for clean terminal display
        if len(banner) > 80:
            banner = banner[:77] + "..."
        return banner

    return ""


def grab_banner(
    ip: str, 
    port: int, 
    timeout: float = 1.5,
    host: str = "target"
) -> str:
    """
    Attempt to grab service banner from open port.
    
    Tries:
    1. Read initial banner greeting (SSH, FTP, SMTP).
    2. Send tailored probe payload if no greeting.
    3. TLS wrap for HTTPS / SSL ports (443, 8443, etc.).
    """
    banner = ""
    is_tls = port in {443, 8443, 9443, 993, 995, 465, 636}

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        sock = raw_sock
        if is_tls:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=host if host != "target" else None)
            except Exception:
                # Fallback to plain socket if TLS wrap fails
                sock = raw_sock

        # First, try to receive initial greeting without sending anything
        # (common for SSH, FTP, Telnet, SMTP)
        try:
            sock.settimeout(0.6)
            data = sock.recv(1024)
            if data:
                banner = sanitize_banner(data)
                sock.close()
                return banner
        except (socket.timeout, BlockingIOError):
            pass

        # If no immediate greeting, send probe payload
        probe = get_probe_payload(port, host=host)
        if probe:
            sock.settimeout(timeout)
            sock.sendall(probe)
            try:
                data = sock.recv(1024)
                if data:
                    banner = sanitize_banner(data)
            except (socket.timeout, BlockingIOError):
                pass

        sock.close()
    except Exception:
        pass

    return banner

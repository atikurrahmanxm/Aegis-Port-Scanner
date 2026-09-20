"""
Console output formatting and colorized terminal table renderer.
"""

import sys
from datetime import datetime
from typing import List
from port_scanner.core.scanner import ScanResult
from port_scanner.utils.logger import Colors


def print_banner() -> None:
    """Print the startup dynamic ASCII banner with system metadata."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    banner_lines = [
        ("    ___    ___________  _________   ______________   _   __", Colors.BRIGHT_CYAN),
        ("   /   |  / ____/ ____//  _/ ___/  / ___/ ____/   | / | / /", Colors.BRIGHT_CYAN),
        ("  / /| | / __/ / / __  / / \\__ \\   \\__ \\/ /   / /| |/  |/ / ", Colors.CYAN),
        (" / ___ |/ /___/ /_/ /_/ / ___/ /  ___/ / /___/ ___ / /|  /  ", Colors.BRIGHT_BLUE),
        ("/_/  |_/_____/\\____/___//____/  /____/\\____/_/  |_/_/ |_/   ", Colors.BRIGHT_BLUE),
    ]
    print()
    for text, color in banner_lines:
        print(f"{Colors.BOLD}{color}{text}{Colors.RESET}")
    
    border = "=" * 65
    print(f"{Colors.DIM}{border}{Colors.RESET}")
    print(f" {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}AegisScan{Colors.RESET} {Colors.DIM}v1.0.0{Colors.RESET} | {Colors.WHITE}Advanced Network Reconnaissance{Colors.RESET}")
    print(f" {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}Author:{Colors.RESET}    {Colors.BRIGHT_YELLOW}Atikur Rahman{Colors.RESET} | {Colors.DIM}Engine: Multithreaded TCP (RFC 793){Colors.RESET}")
    print(f" {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}Active @:{Colors.RESET}  {Colors.WHITE}{now_str}{Colors.RESET}")
    print(f"{Colors.DIM}{border}{Colors.RESET}\n")


def print_scan_header(
    target_host: str,
    target_ip: str,
    port_count: int,
    threads: int,
    timeout: float,
    banner_grab: bool,
) -> None:
    """Print target configuration summary before starting scan."""
    print(f"{Colors.BOLD}{Colors.WHITE}[*] Target Configuration:{Colors.RESET}")
    print(f"    - Target:       {Colors.BRIGHT_YELLOW}{target_host}{Colors.RESET} ({target_ip})")
    print(f"    - Ports Queued: {port_count} ports")
    print(f"    - Concurrency:  {threads} worker threads")
    print(f"    - Socket Mode:  Timeout {timeout}s | Banner Grabbing: {'Enabled' if banner_grab else 'Disabled'}")
    print(f"{Colors.DIM}{'-' * 65}{Colors.RESET}\n")


def print_progress(scanned: int, total: int) -> None:
    """Render a compact terminal progress bar."""
    if total == 0:
        return
    pct = (scanned / total) * 100
    bar_width = 30
    filled = int(bar_width * scanned // total)
    bar = "=" * filled + (">" if filled < bar_width else "") + " " * (bar_width - filled - (1 if filled < bar_width else 0))
    sys.stdout.write(f"\r{Colors.BRIGHT_BLUE}[*]{Colors.RESET} Scanning: [{Colors.BRIGHT_CYAN}{bar}{Colors.RESET}] {pct:5.1f}% ({scanned}/{total})")
    sys.stdout.flush()


def print_scan_results(result: ScanResult) -> None:
    """Print formatted result table and scan summary statistics."""
    # Clear progress line
    sys.stdout.write("\r" + " " * 75 + "\r")
    sys.stdout.flush()

    if not result.open_ports:
        print(f"\n{Colors.BRIGHT_YELLOW}[!] No open ports discovered on {result.target_ip}.{Colors.RESET}")
    else:
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Discovered {len(result.open_ports)} open port(s) on {result.target_ip}:{Colors.RESET}\n")
        
        # Table Header
        col_port = 12
        col_state = 10
        col_service = 24
        col_latency = 14

        header = (
            f"{Colors.BOLD}"
            f"{'PORT':<{col_port}}"
            f"{'STATE':<{col_state}}"
            f"{'SERVICE':<{col_service}}"
            f"{'LATENCY':<{col_latency}}"
            f"{'BANNER / VERSION'}"
            f"{Colors.RESET}"
        )
        print(header)
        print(f"{Colors.DIM}{'-' * 85}{Colors.RESET}")

        for port_res in result.open_ports:
            port_str = f"{port_res.port}/tcp"
            state_str = f"{Colors.BRIGHT_GREEN}{port_res.state}{Colors.RESET}"
            service_str = port_res.service[:22]  # Cap service name length
            lat_str = f"{port_res.latency_ms:.1f} ms"
            banner_str = port_res.banner if port_res.banner else f"{Colors.DIM}N/A{Colors.RESET}"

            row = (
                f"{port_str:<{col_port}}"
                f"{state_str:<{col_state + (len(state_str) - len(port_res.state))}}"
                f"{service_str:<{col_service}}"
                f"{lat_str:<{col_latency}}"
                f"{banner_str}"
            )
            print(row)

        print(f"{Colors.DIM}{'-' * 85}{Colors.RESET}")

    # Summary footer
    print(f"\n{Colors.BOLD}--- Scan Summary ---{Colors.RESET}")
    print(f" Total Ports Scanned: {result.ports_scanned}")
    print(f" Open Ports Found:    {len(result.open_ports)}")
    print(f" Scan Duration:       {result.duration:.2f} seconds")
    print(f" Scan Speed:          {result.scan_rate:.1f} ports/second\n")

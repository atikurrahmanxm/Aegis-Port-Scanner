"""
Command Line Interface (CLI) entrypoint for AegisScan.
Handles argument parsing, target dispatch, signal handling, and execution flow.
"""

import sys
import argparse
from typing import List

from port_scanner import __version__
from port_scanner.core.scanner import PortScanner, ScanResult
from port_scanner.utils.network import parse_targets, parse_ports
from port_scanner.utils.logger import log_info, log_success, log_warning, log_error, log_debug
from port_scanner.reporters.console_reporter import (
    print_banner,
    print_scan_header,
    print_progress,
    print_scan_results,
)
from port_scanner.reporters.json_reporter import export_json
from port_scanner.reporters.csv_reporter import export_csv


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="aegisscan",
        description="AegisScan: High-Performance Multithreaded TCP Port Scanner & Service Fingerprinter",
        epilog="Examples:\n"
               "  python run.py -t 127.0.0.1 -p 80,443,8080\n"
               "  python run.py -t scanme.nmap.org --top-ports 20 -b\n"
               "  python run.py -t 192.168.1.0/29 -p 1-1024 -T 100\n"
               "  python run.py -t 10.0.0.1 -p 20-100 -b -o report.json -f json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target specification (IP, hostname, CIDR like 192.168.1.0/28, or comma-separated list)",
    )

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p", "--ports",
        help="Ports to scan (e.g., '80', '22,80,443', or range '1-1024'). Default: top 100 ports",
    )
    port_group.add_argument(
        "--top-ports",
        type=int,
        choices=[20, 100, 1000],
        help="Scan the top N most frequent ports (20, 100, or 1000)",
    )

    parser.add_argument(
        "-b", "--banner",
        action="store_true",
        help="Enable active banner grabbing and service version probing",
    )

    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=50,
        help="Number of concurrent worker threads (default: 50, max: 500)",
    )

    parser.add_argument(
        "-w", "--timeout",
        type=float,
        default=1.0,
        help="Socket connection timeout in seconds (default: 1.0s)",
    )

    parser.add_argument(
        "-o", "--output",
        help="Save scan report to specified file path",
    )

    parser.add_argument(
        "-f", "--format",
        choices=["json", "csv"],
        default="json",
        help="Output file format (json or csv, default: json)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose / debug diagnostic messages",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def main(args: List[str] = None) -> int:
    """Main CLI execution routine."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    print_banner()

    # 1. Parse and validate target(s)
    try:
        targets = parse_targets(parsed_args.target)
    except ValueError as e:
        log_error(f"Target error: {e}")
        return 1

    # 2. Parse and validate ports
    try:
        ports = parse_ports(
            port_spec=parsed_args.ports,
            top_count=parsed_args.top_ports,
        )
    except ValueError as e:
        log_error(f"Port specification error: {e}")
        return 1

    log_debug(f"Target count: {len(targets)}, Port count: {len(ports)}", parsed_args.verbose)

    # 3. Setup scanner instance
    scanner = PortScanner(
        timeout=parsed_args.timeout,
        threads=parsed_args.threads,
        grab_banners=parsed_args.banner,
        progress_callback=print_progress,
    )

    all_results: List[ScanResult] = []

    # 4. Execute scan per target
    try:
        for idx, (target_ip, target_host) in enumerate(targets, 1):
            if len(targets) > 1:
                log_info(f"Target [{idx}/{len(targets)}]: {target_host} ({target_ip})")

            print_scan_header(
                target_host=target_host,
                target_ip=target_ip,
                port_count=len(ports),
                threads=parsed_args.threads,
                timeout=parsed_args.timeout,
                banner_grab=parsed_args.banner,
            )

            result = scanner.scan_target(
                target_ip=target_ip,
                ports=ports,
                target_host=target_host,
            )
            print_scan_results(result)
            all_results.append(result)

    except KeyboardInterrupt:
        print("\n")
        log_warning("Scan interrupted by user (Ctrl+C). Partial results retained.")
        if not all_results:
            return 130

    # 5. Export results if requested
    if parsed_args.output and all_results:
        out_path = parsed_args.output
        try:
            if parsed_args.format.lower() == "csv":
                export_csv(all_results, out_path)
            else:
                export_json(all_results, out_path)
            log_success(f"Report exported successfully to {out_path} ({parsed_args.format.upper()})")
        except Exception as e:
            log_error(f"Failed to export report to {out_path}: {e}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

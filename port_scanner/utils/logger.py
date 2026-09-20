"""
Structured and colored logging utility for terminal output.
Supports Windows terminal ANSI escape sequences.
"""

import os
import sys
import logging

# Check if colors are supported
def _init_colors() -> bool:
    if os.name == 'nt':
        # Enable ANSI support in Windows console
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
                return True
        except Exception:
            return False
    return sys.stdout.isatty()


USE_COLOR = _init_colors()


class Colors:
    """ANSI color codes for stylish terminal outputs."""
    RESET = "\033[0m" if USE_COLOR else ""
    BOLD = "\033[1m" if USE_COLOR else ""
    DIM = "\033[2m" if USE_COLOR else ""
    
    # Standard colors
    RED = "\033[31m" if USE_COLOR else ""
    GREEN = "\033[32m" if USE_COLOR else ""
    YELLOW = "\033[33m" if USE_COLOR else ""
    BLUE = "\033[34m" if USE_COLOR else ""
    MAGENTA = "\033[35m" if USE_COLOR else ""
    CYAN = "\033[36m" if USE_COLOR else ""
    WHITE = "\033[37m" if USE_COLOR else ""
    
    # Bright colors
    BRIGHT_GREEN = "\033[92m" if USE_COLOR else ""
    BRIGHT_CYAN = "\033[96m" if USE_COLOR else ""
    BRIGHT_YELLOW = "\033[93m" if USE_COLOR else ""
    BRIGHT_RED = "\033[91m" if USE_COLOR else ""
    BRIGHT_BLUE = "\033[94m" if USE_COLOR else ""


def log_info(msg: str) -> None:
    """Log an informative message."""
    print(f"{Colors.BRIGHT_BLUE}[*]{Colors.RESET} {msg}")


def log_success(msg: str) -> None:
    """Log a success message."""
    print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} {msg}")


def log_warning(msg: str) -> None:
    """Log a warning message."""
    print(f"{Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {msg}")


def log_error(msg: str) -> None:
    """Log an error message."""
    print(f"{Colors.BRIGHT_RED}[-]{Colors.RESET} {msg}", file=sys.stderr)


def log_debug(msg: str, verbose: bool = False) -> None:
    """Log a debug message if verbose is enabled."""
    if verbose:
        print(f"{Colors.DIM}[DEBUG] {msg}{Colors.RESET}")

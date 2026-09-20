#!/usr/bin/env python3
"""
AegisScan: Root execution script.
Run directly via: python run.py -t <target> [options]
"""

import sys
from port_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())

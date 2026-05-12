#!/usr/bin/env python3
"""Legacy wrapper for result analysis."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quic_scanner_ipv4.result_analysis import main


if __name__ == "__main__":
    raise SystemExit(main())

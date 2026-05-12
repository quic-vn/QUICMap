#!/usr/bin/env python3
"""Legacy wrapper for SQLite domain enrichment."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quic_scanner_ipv4.domain_enrichment import main


if __name__ == "__main__":
    raise SystemExit(main())

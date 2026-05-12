#!/usr/bin/env python3
"""Build per-country IPv6 hitlists from APNIC and the world responsive hitlist."""

from quic_scanner_ipv6.country_hitlists import main


if __name__ == "__main__":
    raise SystemExit(main())

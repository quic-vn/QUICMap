#!/usr/bin/env python3
"""Legacy wrapper for the domain/IP SQLite DB builder."""

import os
import runpy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
runpy.run_path(os.path.join(ROOT, "build_domain_ip_db.py"), run_name="__main__")

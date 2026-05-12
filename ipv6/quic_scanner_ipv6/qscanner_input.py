#!/usr/bin/env python3
"""Generate QScanner input CSV from IPv6 targets and zDNS PTR results."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
from typing import Dict, Iterator, List, Set


def iter_zdns_records(path: str) -> Iterator[dict]:
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                yield record


def first_ptr_answer(record: dict) -> str:
    try:
        answers = record["results"]["PTR"]["data"].get("answers", [])
    except Exception:
        return ""
    if not answers:
        return ""
    return (answers[0].get("answer") or answers[0].get("rdata") or "").strip().rstrip(".")


def load_ptr_map(path: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for record in iter_zdns_records(path):
        ip = (record.get("name") or "").strip()
        hostname = first_ptr_answer(record)
        if not ip or not hostname:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        result[ip] = hostname
    return result


def load_ip_list(path: str) -> List[str]:
    ips: List[str] = []
    seen: Set[str] = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            ip = line.strip().strip('"')
            if not ip or ip in seen:
                continue
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if parsed.version != 6:
                continue
            seen.add(ip)
            ips.append(ip)
    return ips


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate IPv6 QScanner CSV from IP list and zDNS JSONL.")
    parser.add_argument("--ip-list", required=True, help="Path to IPv6 ip_list.txt")
    parser.add_argument("--zdns-json", required=True, help="zDNS JSON lines file")
    parser.add_argument("--out-csv", required=True, help="Output CSV path")
    parser.add_argument("--port", default="443", help="Port column value")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ips = load_ip_list(args.ip_list)
    ptr_map = load_ptr_map(args.zdns_json)

    out_dir = os.path.dirname(args.out_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(args.out_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "hostname", "port", "scid", "dcid"])
        for ip in ips:
            writer.writerow([ip, ptr_map.get(ip, ""), args.port, "", ""])

    missing_count = sum(1 for ip in ips if ip not in ptr_map)
    print(f"[OK] Wrote {len(ips)} rows to {args.out_csv} (PTR hit: {len(ptr_map)}, missing: {missing_count})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


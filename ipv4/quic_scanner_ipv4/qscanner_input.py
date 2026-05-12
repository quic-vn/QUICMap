#!/usr/bin/env python3
"""Generate a QScanner input CSV from IP targets and zDNS PTR results."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import threading
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


def get_status_and_data(record: dict) -> tuple[str | None, dict | None]:
    if "status" in record or "data" in record:
        return record.get("status"), record.get("data")
    ptr_result = (record.get("results") or {}).get("PTR") or {}
    return ptr_result.get("status"), ptr_result.get("data")


def first_answer(data: dict | None) -> str:
    answers = (data or {}).get("answers") or []
    if not answers:
        return ""
    value = (answers[0].get("answer") or answers[0].get("rdata") or "").strip()
    return value.rstrip(".")


def load_ptr_map(zdns_jsonl: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for record in iter_zdns_records(zdns_jsonl):
        try:
            status, data = get_status_and_data(record)
            if status != "NOERROR":
                continue
            hostname = first_answer(data)
            ip = (record.get("name") or "").strip()
            if not hostname:
                continue
            ipaddress.ip_address(ip)
            result[ip] = hostname
        except Exception:
            continue
    return result


def search_file_for_ips(file_path: str, wanted: Set[str]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                ip = parts[0].strip().strip('"')
                if ip in wanted and ip not in found:
                    hostname = parts[1].strip().rstrip(".")
                    if hostname:
                        found[ip] = hostname
                        if len(found) == len(wanted):
                            break
    except Exception:
        pass
    return found


def fallback_lookup_selective_parallel(source_dir: str, wanted_ips: Set[str], workers: int = 8) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not source_dir or not os.path.isdir(source_dir) or not wanted_ips:
        return result

    files = sorted(
        os.path.join(source_dir, file_name)
        for file_name in os.listdir(source_dir)
        if os.path.isfile(os.path.join(source_dir, file_name))
    )
    remaining = set(wanted_ips)
    lock = threading.Lock()

    def worker(file_path: str) -> Dict[str, str]:
        nonlocal remaining
        with lock:
            snapshot = set(remaining)
        if not snapshot:
            return {}

        found = search_file_for_ips(file_path, snapshot)
        if not found:
            return {}

        with lock:
            for ip, hostname in found.items():
                if ip not in result:
                    result[ip] = hostname
                    remaining.discard(ip)
        return found

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(worker, file_path) for file_path in files]
        for future in concurrent.futures.as_completed(futures):
            future.result()
            with lock:
                if not remaining:
                    for pending in futures:
                        if not pending.done():
                            pending.cancel()
                    break

    return result


def load_ip_list(ip_list_path: str) -> List[str]:
    ips: List[str] = []
    seen: Set[str] = set()
    with open(ip_list_path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            ip = line.strip().strip('"')
            if not ip or ip in seen:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            seen.add(ip)
            ips.append(ip)
    return ips


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate QScanner CSV from zDNS JSONL results.")
    parser.add_argument("--ip-list", required=True, help="Path to ip_list.txt")
    parser.add_argument("--zdns-json", required=True, help="zDNS JSON lines file")
    parser.add_argument("--out-csv", required=True, help="Output CSV path")
    parser.add_argument("--port", default="443", help="Port column value")
    parser.add_argument("--fallback-dir", default="", help="Optional directory with domain/IP mappings")
    parser.add_argument("--workers", type=int, default=8, help="Number of fallback worker threads")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ips = load_ip_list(args.ip_list)
    ptr_map = load_ptr_map(args.zdns_json)

    missing_ips = {ip for ip in ips if not ptr_map.get(ip)}
    fallback_map = {}
    if missing_ips and args.fallback_dir:
        fallback_map = fallback_lookup_selective_parallel(args.fallback_dir, missing_ips, workers=args.workers)

    out_dir = os.path.dirname(args.out_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(args.out_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "hostname", "port", "scid", "dcid"])
        for ip in ips:
            writer.writerow([ip, ptr_map.get(ip) or fallback_map.get(ip) or "", args.port, "", ""])

    missing_count = sum(1 for ip in ips if ip not in ptr_map and ip not in fallback_map)
    print(
        f"[OK] Wrote {len(ips)} rows to {args.out_csv} "
        f"(zDNS hit: {len(ptr_map)}, fallback hit: {len(fallback_map)}, missing: {missing_count})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


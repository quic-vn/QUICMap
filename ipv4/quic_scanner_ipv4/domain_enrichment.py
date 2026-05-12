#!/usr/bin/env python3
"""Expand `test_input.csv` by filling hostnames from the SQLite domain/IP database."""

from __future__ import annotations

import argparse
import csv
import os
import sqlite3
import sys
import time
from collections import OrderedDict
from typing import Iterable, Optional, Tuple


MAX_DOMAINS_PER_IP = 300
CACHE_MAX_IPS = 20000
PROGRESS_EVERY = 1000
DB_TIMEOUT_SEC = 60


def normalize_ip(value: str) -> str:
    value = (value or "").strip()
    if "/" in value:
        value = value.split("/", 1)[0].strip()
    return value


def extract_ip(row: dict) -> str:
    ip = str(row.get("ip", "")).strip()
    if ip:
        return normalize_ip(ip)

    for key, value in row.items():
        if "ip" in key.lower() and value:
            return normalize_ip(str(value))
    return ""


def open_db(path: str, timeout_sec: int) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=timeout_sec)
    except Exception:
        connection = sqlite3.connect(path, timeout=timeout_sec)

    pragmas = [
        f"PRAGMA busy_timeout={int(timeout_sec) * 1000};",
        "PRAGMA query_only=ON;",
        "PRAGMA temp_store=MEMORY;",
        "PRAGMA cache_size=-200000;",
    ]
    for pragma in pragmas:
        try:
            connection.execute(pragma)
        except Exception:
            continue
    return connection


def lookup_domains_stream(cursor: sqlite3.Cursor, ip: str, limit: int) -> Iterable[str]:
    cursor.execute("SELECT domain FROM domain_ip WHERE ip = ? LIMIT ?;", (ip, limit))
    for (domain,) in cursor:
        if domain:
            yield domain


def lru_get(cache: "OrderedDict[str, Tuple[str, ...]]", key: str) -> Optional[Tuple[str, ...]]:
    value = cache.get(key)
    if value is not None:
        cache.move_to_end(key)
    return value


def lru_put(cache: "OrderedDict[str, Tuple[str, ...]]", key: str, value: Tuple[str, ...], maxsize: int) -> None:
    cache[key] = value
    cache.move_to_end(key)
    if len(cache) > maxsize:
        cache.popitem(last=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Expand test_input.csv by mapping domains from SQLite in overwrite mode."
    )
    parser.add_argument("--db", required=True, help="SQLite DB path (domain_ip.sqlite)")
    parser.add_argument("--out-dir", required=True, help="Directory containing test_input.csv")
    parser.add_argument("--in-csv", default="test_input.csv", help="Input CSV filename")
    parser.add_argument("--max-domains-per-ip", type=int, default=MAX_DOMAINS_PER_IP)
    parser.add_argument("--progress-every", type=int, default=PROGRESS_EVERY)
    parser.add_argument("--cache-max-ips", type=int, default=CACHE_MAX_IPS)
    parser.add_argument("--db-timeout", type=int, default=DB_TIMEOUT_SEC)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_csv = os.path.join(args.out_dir, args.in_csv)
    if not os.path.exists(input_csv):
        sys.exit(f"[ERROR] File not found: {input_csv}")

    connection = open_db(args.db, int(args.db_timeout))
    cursor = connection.cursor()

    backup_csv = f"{input_csv}.bak"
    temp_csv = f"{input_csv}.tmp"

    try:
        if os.path.exists(backup_csv):
            os.remove(backup_csv)
    except OSError:
        pass

    os.rename(input_csv, backup_csv)
    print(f"[INFO] Backup created: {backup_csv}", flush=True)

    start_time = time.time()
    total_rows = 0
    written_rows = 0
    expanded_rows = 0
    cache: "OrderedDict[str, Tuple[str, ...]]" = OrderedDict()

    with open(backup_csv, "r", encoding="utf-8", newline="") as source, open(
        temp_csv, "w", encoding="utf-8", newline=""
    ) as target:
        reader = csv.DictReader(source)
        headers = reader.fieldnames or ["ip", "hostname", "port", "scid", "dcid"]
        writer = csv.DictWriter(target, fieldnames=headers)
        writer.writeheader()

        for row in reader:
            total_rows += 1
            ip = extract_ip(row)
            if not ip:
                writer.writerow(row)
                written_rows += 1
                continue

            domains = lru_get(cache, ip)
            if domains is None:
                domains = tuple(lookup_domains_stream(cursor, ip, int(args.max_domains_per_ip)))
                lru_put(cache, ip, domains, int(args.cache_max_ips))

            if domains:
                for domain in domains:
                    new_row = dict(row)
                    new_row["hostname"] = domain
                    writer.writerow(new_row)
                    written_rows += 1
                expanded_rows += len(domains)
            else:
                writer.writerow(row)
                written_rows += 1

            if total_rows % int(args.progress_every) == 0:
                elapsed = time.time() - start_time
                rate = total_rows / elapsed if elapsed > 0 else 0.0
                print(
                    f"[PROGRESS] read={total_rows} written={written_rows} expanded={expanded_rows} "
                    f"rate={rate:.0f} rows/s cache={len(cache)}",
                    file=sys.stderr,
                    flush=True,
                )

    os.replace(temp_csv, input_csv)
    elapsed = time.time() - start_time
    print(f"[DONE] Overwrote {input_csv}", flush=True)
    print(
        f"[STATS] Read {total_rows} rows, wrote {written_rows} rows, expanded {expanded_rows} lines in {elapsed:.1f}s",
        flush=True,
    )
    connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


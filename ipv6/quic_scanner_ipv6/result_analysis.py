#!/usr/bin/env python3
"""Analyze IPv6 QScanner output and optionally enrich successful IPs with geo data."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import ipaddress
import json
import os
import sys
import time
from typing import Iterable, Sequence
from urllib import parse, request
from urllib.error import HTTPError, URLError

try:
    import pyshark

    HAS_PYSHARK = True
except Exception:
    HAS_PYSHARK = False


IPAPI_FIELDS = [
    "query",
    "status",
    "continent",
    "continentCode",
    "country",
    "countryCode",
    "region",
    "regionName",
    "city",
    "district",
    "zip",
    "lat",
    "lon",
    "timezone",
    "offset",
    "currency",
    "isp",
    "org",
    "as",
    "asname",
    "mobile",
    "proxy",
    "hosting",
    "reverse",
]

IP2LOCATION_FIELDS = [
    "ip",
    "country_code",
    "country_name",
    "region_name",
    "city_name",
    "latitude",
    "longitude",
    "zip_code",
    "time_zone",
    "asn",
    "as",
    "is_proxy",
]


Rows = list[dict[str, str]]


def normalize_ip(value: str) -> str:
    value = (value or "").strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1].strip()
    if "%" in value:
        value = value.split("%", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def read_csv_rows(path: str) -> tuple[list[str], Rows]:
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        rows = []
        for row in reader:
            row = dict(row)
            row["address_original"] = row.get("address", "")
            row["address"] = normalize_ip(row.get("address", ""))
            row["errorMessage"] = (row.get("errorMessage") or "").strip()
            rows.append(row)
        if "address_original" not in fieldnames:
            fieldnames = list(fieldnames) + ["address_original"]
        return fieldnames, rows


def classify_qscanner(rows: Rows) -> tuple[Rows, Rows]:
    success_rows: Rows = []
    error_rows: Rows = []
    for row in rows:
        if row.get("errorMessage", ""):
            error_rows.append(row)
        else:
            success_rows.append(row)
    return success_rows, error_rows


def write_rows(path: str, fieldnames: Sequence[str], rows: Rows) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def save_basic_stats(out_dir: str, fieldnames: Sequence[str], success_rows: Rows, error_rows: Rows) -> None:
    os.makedirs(out_dir, exist_ok=True)
    stats_file = os.path.join(out_dir, "statistics.txt")

    with open(stats_file, "w", encoding="utf-8") as handle:
        handle.write("--------- QScanner statistics ---------\n")
        handle.write(f"Total QScanner entries: {len(success_rows) + len(error_rows)}\n")
        handle.write(f"QScanner successful count: {len(success_rows)}\n")
        handle.write(f"QScanner error count: {len(error_rows)}\n")

        if error_rows:
            handle.write("Error targets with QScanner:\n")
            for row in error_rows:
                handle.write(f"\t{row.get('address_original', row.get('address', ''))} : {row.get('errorMessage', '')}\n")

            handle.write("\nError message distribution:\n")
            for message, count in Counter(row.get("errorMessage", "") for row in error_rows).items():
                handle.write(f"    {message} => {count}\n")

    write_rows(os.path.join(out_dir, "statistics_qscanner_error.csv"), fieldnames, error_rows)
    write_rows(os.path.join(out_dir, "statistics_qscanner.csv"), fieldnames, success_rows)


def _batched(values: Sequence[str], batch_size: int) -> Iterable[Sequence[str]]:
    for index in range(0, len(values), batch_size):
        yield values[index : index + batch_size]


def geo_enrich_ipapi(addresses: Sequence[str], out_csv: str, batch_size: int = 100, sleep_sec: float = 1.0) -> None:
    url = "http://ip-api.com/batch"
    with open(out_csv, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(IPAPI_FIELDS)
        for batch in _batched(addresses, batch_size):
            payload = json.dumps([{"query": ip} for ip in batch]).encode("utf-8")
            req = request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            try:
                with request.urlopen(req, timeout=10) as response:
                    items = json.loads(response.read().decode("utf-8"))
                for item in items:
                    writer.writerow([item.get(field, "") for field in IPAPI_FIELDS])
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
                for ip in batch:
                    writer.writerow([ip] + [""] * (len(IPAPI_FIELDS) - 1))
            time.sleep(sleep_sec)


def _ip2location_request(url: str) -> dict:
    req = request.Request(url, headers={"User-Agent": "vn-quic-scanner/1.0"})
    with request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def geo_enrich_ip2location(addresses: Sequence[str], out_csv: str, api_key: str, sleep_sec: float = 1.0) -> None:
    base_url = "https://api.ip2location.io/"
    with open(out_csv, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(IP2LOCATION_FIELDS)

        for ip in addresses:
            row = [ip] + [""] * (len(IP2LOCATION_FIELDS) - 1)
            try:
                query = parse.urlencode({"key": api_key, "ip": ip})
                url = f"{base_url}?{query}"
                try:
                    payload = _ip2location_request(url)
                except HTTPError as exc:
                    if exc.code not in {403, 429, 500, 502, 503, 504}:
                        raise
                    time.sleep(2.5)
                    payload = _ip2location_request(url)
                row = [
                    ip,
                    payload.get("country_code", ""),
                    payload.get("country_name", ""),
                    payload.get("region_name", ""),
                    payload.get("city_name", ""),
                    payload.get("latitude", ""),
                    payload.get("longitude", ""),
                    payload.get("zip_code", ""),
                    payload.get("time_zone", ""),
                    payload.get("asn", ""),
                    payload.get("as", ""),
                    payload.get("is_proxy", ""),
                ]
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
                print(f"[WARN] IP2Location lookup failed for {ip}: {exc}", file=sys.stderr)

            writer.writerow(row)
            time.sleep(sleep_sec)


def pcap_stats(pcap_path: str, out_file: str) -> None:
    if not HAS_PYSHARK:
        with open(out_file, "a", encoding="utf-8") as handle:
            handle.write("\n(Note) pyshark not installed; skipping PCAP stats.\n")
        return

    retry_filter = "quic and quic.long.packet_type==3"
    try:
        capture = pyshark.FileCapture(pcap_path, display_filter=retry_filter)
        retry_ips = {packet.ip.src for packet in capture if hasattr(packet, "ip")}
        capture.close()
    except Exception:
        retry_ips = set()

    if retry_ips:
        with open(out_file, "a", encoding="utf-8") as handle:
            handle.write("\nServers that sent a QUIC Retry (IPs):\n")
            for ip in sorted(retry_ips):
                handle.write(f"\t{ip}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze IPv6 QScanner results.")
    parser.add_argument("--root", default=".", help="Project root")
    parser.add_argument("--out-dir", default="output", help="Output directory relative to --root")
    parser.add_argument(
        "--qscanner-csv",
        default=None,
        help="Path to quic_connection_info.csv (default: <out-dir>/qscanner/output/quic_connection_info.csv)",
    )
    parser.add_argument("--geo", choices=["none", "ipapi", "ip2location"], default="none")
    parser.add_argument("--ip2location-key", default="", help="Required when --geo ip2location")
    parser.add_argument("--pcap", default=None, help="Optional PCAP path for additional stats")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = os.path.join(args.root, args.out_dir)
    qscanner_csv = args.qscanner_csv
    if not qscanner_csv:
        candidates = [
            os.path.join(out_dir, "qscanner", "output", "quic_connection_info.csv"),
            os.path.join(out_dir, "output_quic_ipv6", "qscanner_output", "quic_connection_info.csv"),
        ]
        qscanner_csv = next((path for path in candidates if os.path.isfile(path)), candidates[0])

    if not os.path.isfile(qscanner_csv):
        print(f"[ERROR] qscanner CSV not found: {qscanner_csv}")
        return 1

    fieldnames, rows = read_csv_rows(qscanner_csv)
    success_rows, error_rows = classify_qscanner(rows)
    save_basic_stats(out_dir, fieldnames, success_rows, error_rows)

    if args.geo != "none":
        success_ips = sorted({row.get("address", "").strip() for row in success_rows if row.get("address", "").strip()})
        geo_out_csv = os.path.join(out_dir, "statistics_qscanner_geo.csv")
        if args.geo == "ipapi":
            geo_enrich_ipapi(success_ips, geo_out_csv)
        elif not args.ip2location_key:
            print("[ERROR] ip2location key is required for --geo ip2location")
            return 2
        else:
            geo_enrich_ip2location(success_ips, geo_out_csv, args.ip2location_key)

    if args.pcap and os.path.isfile(args.pcap):
        pcap_stats(args.pcap, os.path.join(out_dir, "statistics.txt"))

    print(f"[OK] Analysis written to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

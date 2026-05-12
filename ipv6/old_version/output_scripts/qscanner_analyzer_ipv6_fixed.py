#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import os
import time

import pandas as pd
import requests

try:
    import pyshark
    HAS_PYSHARK = True
except Exception:
    HAS_PYSHARK = False


EXPECTED_COLUMNS = [
    "targetid", "address", "port", "hostname", "scid", "dcid", "hasRetry",
    "startTime", "handshakeTime", "closeTime", "handshakeDuration",
    "connectionDuration", "quicVersion", "errorMessage"
]


def normalize_ip(value):
    """Normalize IPv4/IPv6 strings for further processing.

    Examples:
    - "[2001:db8::1]" -> "2001:db8::1"
    - " 192.0.2.1 " -> "192.0.2.1"
    - invalid/empty -> ""
    """
    if pd.isna(value):
        return ""

    s = str(value).strip()
    if not s:
        return ""

    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()

    # Remove zone index if present, e.g. fe80::1%eth0
    if "%" in s:
        s = s.split("%", 1)[0].strip()

    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s



def load_qscanner_csv(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    # Remove accidental spaces in column names
    df.columns = [str(c).strip() for c in df.columns]

    missing = [c for c in EXPECTED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            "Missing required columns in input CSV: " + ", ".join(missing)
        )

    # Keep original address for reporting, and normalized address for geo/API usage
    df["address_original"] = df["address"]
    df["address"] = df["address"].map(normalize_ip)

    # Normalize errorMessage so empty cells, NaN, and whitespace-only values are treated consistently
    df["errorMessage"] = df["errorMessage"].fillna("").astype(str).str.strip()

    return df



def classify_qscanner(df: pd.DataFrame):
    success_mask = df["errorMessage"].eq("")
    df_success = df[success_mask].copy()
    df_error = df[~success_mask].copy()
    return df_success, df_error



def save_basic_stats(out_dir: str, df_succ: pd.DataFrame, df_err: pd.DataFrame):
    os.makedirs(out_dir, exist_ok=True)
    stats_file = os.path.join(out_dir, "statistics.txt")

    with open(stats_file, "w", encoding="utf-8") as f:
        f.write("--------- QScanner statistics ---------\n")
        f.write(f"Total QScanner entries: {df_succ.shape[0] + df_err.shape[0]}\n")
        f.write(f"QScanner successful count: {df_succ.shape[0]}\n")
        f.write(f"QScanner error count: {df_err.shape[0]}\n")

        if not df_err.empty:
            f.write("Error targets with QScanner:\n")
            for _, row in df_err.iterrows():
                shown_addr = row.get("address_original", row.get("address", ""))
                f.write(f"\t {shown_addr} : {row.get('errorMessage', '')}\n")

            f.write("\nError message distribution:\n")
            counts = df_err["errorMessage"].value_counts(dropna=False)
            for msg, cnt in counts.items():
                f.write(f"    {msg} => {cnt}\n")

    df_err.to_csv(os.path.join(out_dir, "statistics_qscanner_error.csv"), index=False)
    df_succ.to_csv(os.path.join(out_dir, "statistics_qscanner.csv"), index=False)



def geo_enrich_ipapi(addresses, out_csv, batch_size=100, sleep_sec=1.0):
    url = "http://ip-api.com/batch"
    fields = [
        "query", "status", "continent", "continentCode", "country", "countryCode", "region",
        "regionName", "city", "district", "zip", "lat", "lon", "timezone", "offset", "currency",
        "isp", "org", "as", "asname", "mobile", "proxy", "hosting", "reverse"
    ]

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(fields)
        for i in range(0, len(addresses), batch_size):
            seg = addresses[i:i + batch_size]
            payload = [{"query": ip} for ip in seg]
            try:
                r = requests.post(url, json=payload, timeout=10)
                if r.status_code != 200:
                    time.sleep(sleep_sec)
                    continue
                data = r.json()
                for item in data:
                    row = [item.get(k, "") for k in fields]
                    writer.writerow(row)
            except Exception:
                time.sleep(sleep_sec)
            time.sleep(sleep_sec)



def geo_enrich_ip2location(addresses, out_csv, api_key, sleep_sec=1.0):
    base = "https://api.ip2location.io/"
    fields = [
        "ip", "country_code", "country_name", "region_name", "city_name", "latitude", "longitude",
        "zip_code", "time_zone", "asn", "as", "is_proxy"
    ]
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(fields)
        for ip in addresses:
            try:
                r = requests.get(base, params={"key": api_key, "ip": ip}, timeout=10)
                if r.status_code == 429:
                    time.sleep(2.5)
                    r = requests.get(base, params={"key": api_key, "ip": ip}, timeout=10)
                if r.status_code == 200:
                    d = r.json()
                    row = [
                        ip, d.get("country_code", ""), d.get("country_name", ""), d.get("region_name", ""),
                        d.get("city_name", ""), d.get("latitude", ""), d.get("longitude", ""),
                        d.get("zip_code", ""), d.get("time_zone", ""), d.get("asn", ""),
                        d.get("as", ""), d.get("is_proxy", "")
                    ]
                    writer.writerow(row)
                else:
                    writer.writerow([ip, "", "", "", "", "", "", "", "", "", "", ""])
            except Exception:
                writer.writerow([ip, "", "", "", "", "", "", "", "", "", "", ""])
            time.sleep(sleep_sec)



def pcap_stats(pcap_path: str, out_file: str):
    if not HAS_PYSHARK:
        with open(out_file, "a", encoding="utf-8") as f:
            f.write("\n(Note) pyshark not installed; skipping PCAP stats.\n")
        return

    with open(out_file, "a", encoding="utf-8") as f:
        f.write("\n-------- Wireshark statistics ---------\n")

    hrr_filter = (
        "tls.handshake.random == "
        "cf:21:ad:74:e5:9a:61:11:be:1d:8c:02:1e:65:b8:91:c2:"
        "a2:11:16:7a:bb:8c:5e:07:9e:09:e2:c8:a8:33:9c"
    )
    try:
        cap = pyshark.FileCapture(pcap_path, display_filter=hrr_filter)
        hrr_ips = {pkt.ip.src for pkt in cap if hasattr(pkt, "ip")}
        cap.close()
    except Exception:
        hrr_ips = set()

    if hrr_ips:
        with open(out_file, "a", encoding="utf-8") as f:
            f.write("Servers that sent TLS Hello Retry Requests (IPs):\n")
            for ip in sorted(hrr_ips):
                f.write(f"\t{ip}\n")

    retry_filter = "quic and quic.long.packet_type==3"
    try:
        cap2 = pyshark.FileCapture(pcap_path, display_filter=retry_filter)
        retry_ips = {pkt.ip.src for pkt in cap2 if hasattr(pkt, "ip")}
        cap2.close()
    except Exception:
        retry_ips = set()

    if retry_ips:
        with open(out_file, "a", encoding="utf-8") as f:
            f.write("Servers that sent a QUIC Retry (IPs):\n")
            for ip in sorted(retry_ips):
                f.write(f"\t{ip}\n")



def main():
    ap = argparse.ArgumentParser(
        description="Unified analyzer for QScanner results, with optional geo & pcap"
    )
    ap.add_argument("--root", default=".", help="Project root (default: .)")
    ap.add_argument("--out-dir", default="output", help="Output dir (default: output)")
    ap.add_argument(
        "--qscanner-csv",
        default=None,
        help="Path to QScanner CSV (default: <out-dir>/qscanner/output/quic_connection_info.csv)",
    )
    ap.add_argument("--geo", choices=["none", "ipapi", "ip2location"], default="none", help="Geo enrichment provider")
    ap.add_argument("--ip2location-key", default="", help="API key for ip2location (required if --geo ip2location)")
    ap.add_argument("--pcap", default=None, help="Optional PCAP path for extra stats")
    args = ap.parse_args()

    out_dir = os.path.join(args.root, args.out_dir)
    q_csv = args.qscanner_csv or os.path.join(out_dir, "qscanner", "output", "quic_connection_info.csv")

    if not os.path.isfile(q_csv):
        print(f"[!] qscanner CSV not found: {q_csv}")
        return

    try:
        df = load_qscanner_csv(q_csv)
    except Exception as e:
        print(f"[!] Failed to read/validate QScanner CSV: {e}")
        return

    succ, err = classify_qscanner(df)
    save_basic_stats(out_dir, succ, err)

    if args.geo != "none":
        succ_ips = list(pd.Series(succ["address"]).dropna())
        succ_ips = [ip for ip in succ_ips if str(ip).strip()]
        succ_ips = list(dict.fromkeys(succ_ips))

        geo_out = os.path.join(out_dir, "statistics_qscanner_geo.csv")
        if args.geo == "ipapi":
            geo_enrich_ipapi(succ_ips, geo_out)
        elif args.geo == "ip2location":
            if not args.ip2location_key:
                print("[!] ip2location key is required for --geo ip2location")
            else:
                geo_enrich_ip2location(succ_ips, geo_out, args.ip2location_key)

    if args.pcap and os.path.isfile(args.pcap):
        pcap_stats(args.pcap, os.path.join(out_dir, "statistics.txt"))

    print("✅ Analysis done. See outputs in:", out_dir)


if __name__ == "__main__":
    main()

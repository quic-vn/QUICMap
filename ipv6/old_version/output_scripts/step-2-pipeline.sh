#!/usr/bin/env bash
set -euo pipefail

IP_LIST="${1:?Usage: $0 <ip_list.txt>}"
OUTDIR="${OUTDIR:-output_quic_ipv6}"
THREADS="${THREADS:-200}"
ZDNS_BIN="${ZDNS_BIN:-zdns}"
QSCANNER_BIN="${QSCANNER_BIN:-../qscanner/qscanner}"
DNS_SERVERS="${DNS_SERVERS:-8.8.8.8,8.8.4.4}"

mkdir -p "$OUTDIR"

echo "=== Step 1: zDNS PTR lookup ==="
"$ZDNS_BIN" PTR \
  --input-file "$IP_LIST" \
  --output-file "$OUTDIR/zdns_results.json" \
  --threads "$THREADS" \
  --name-servers "$DNS_SERVERS"

echo "=== Step 2: Generate QScanner input ==="

python3 << 'EOF'
import csv
import json

inp = "output_quic_ipv6/zdns_results.json"
out = "output_quic_ipv6/test_input.csv"

with open(out, "w", newline="", encoding="utf-8") as f_out:
    writer = csv.writer(f_out)
    writer.writerow(["ip", "hostname", "port", "scid", "dcid"])

    with open(inp, "r", encoding="utf-8") as f_in:
        for line in f_in:
            line = line.strip()
            if not line:
                continue

            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = r.get("name", "")
            hostname = ""

            try:
                answers = r["results"]["PTR"]["data"].get("answers", [])
                if answers:
                    hostname = answers[0].get("answer", "").rstrip(".")
            except Exception:
                pass

            writer.writerow([ip, hostname, 443, "", ""])
EOF

echo "=== Step 3: Run QScanner ==="
"$QSCANNER_BIN" \
  --input "$OUTDIR/test_input.csv" \
  --output "$OUTDIR/qscanner_output" \
  --bucket-size 50 \
  --keylog

echo "=== DONE ==="
echo "Results:"
echo "$OUTDIR/qscanner_output/quic_connection_info.csv"
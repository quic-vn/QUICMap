# IPv4 QUIC Pipeline

This directory contains the IPv4 QUIC scan pipeline. It discovers responsive targets with ZMap, resolves PTR names with ZDNS, builds QScanner input, enriches missing domains from a local SQLite database, runs QScanner, and analyzes the result.

## Pipeline

```text
input/*.txt
  -> zmap UDP/TCP discovery
  -> zDNS PTR lookup
  -> zmap/test_input.csv
  -> domain enrichment from database/domain_ip.sqlite
  -> QScanner
  -> output/<target>-YYYY-MM-DD/
```

## Ignored Local Data

These paths are generated locally and are not committed:

- `config.env`: host-specific paths and scan parameters.
- `qscanner`: local QScanner executable.
- `database/domain_ip.sqlite`: generated enrichment database.
- `database/raw/`, `database/output*`, `database/domain*`: large raw or generated database files.
- `output/`, `output_latest/`: scan outputs.
- `__pycache__/`, `*.py[cod]`: Python cache files.

## Setup

Install Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Install external tools:

```bash
sudo apt update
sudo apt install -y zmap golang-go
go install github.com/zmap/zdns/v2@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

Provide QScanner:

```bash
cp /path/to/qscanner ./qscanner
chmod +x ./qscanner
```

Create local configuration:

```bash
cat > config.env <<'EOF'
ZMAP_RATE=3000
ZMAP_MODE=quic_vn
ZMAP_PAYLOAD_FILE=initial_qscanner_1a1a1a1a.pkt
ZDNS_THREADS=200
QSCANNER_BIN=./qscanner
DOMAIN_DB=./database/domain_ip.sqlite
EOF
```

## Recreate the Ignored Database

Put raw domain/IP source files under `database/raw/`. The database builder accepts:

- text rows formatted as `domain ip`
- CSV rows containing domain and IP columns
- JSON/JSONL rows with `domain`, `hostname`, or `name` plus `ip` or `address`

Rebuild the SQLite database:

```bash
python3 build_domain_ip_db.py \
  --source-dir database/raw \
  --db database/domain_ip.sqlite \
  --recreate
```

The pipeline uses this database during the enrichment stage. To run without enrichment, pass `--enrich=false`.

## Run

Show resolved configuration:

```bash
bash scan_all.sh --input=vietnam_ipv4.txt --date=2026-04-25 --print-config
```

Run a full scan:

```bash
bash scan_all.sh --input=vietnam_ipv4.txt --date=2026-04-25
```

Common examples:

```bash
bash scan_all.sh --input=thailand_ipv4.txt --target=thailand --date=2026-04-26
bash scan_all.sh --input=input/singapore_ipv4.txt
bash scan_all.sh --input=vietnam_ipv4.txt --output-root=output
bash scan_all.sh --input=vietnam_ipv4.txt --out-dir=output/custom-run
```

Run only discovery:

```bash
bash scan_all.sh --input=vietnam_ipv4.txt --zmap-only
```

## Output

By default, each run writes to:

```text
output/<target>-YYYY-MM-DD/
```

The target name is inferred from the input filename:

```text
input/vietnam_ipv4.txt      -> output/vietnam-YYYY-MM-DD/
input/thailand_ipv4.txt     -> output/thailand-YYYY-MM-DD/
input/vietnam_ips_test.txt  -> output/vietnam-YYYY-MM-DD/
```

Important generated files:

- `zmap/zmap_udp_raw.csv`: raw UDP discovery output.
- `zmap/zmap_tcp_raw.csv`: raw TCP baseline output.
- `zmap/ip_list.txt`: union of discovered IPs.
- `zmap/zdns_results.json`: PTR results.
- `zmap/test_input.csv`: QScanner input.
- `qscanner/output/quic_connection_info.csv`: primary QScanner result.
- `scan_history.log`: append-only run summary.

## Analyze

```bash
python3 analyze_results.py --root . --out-dir output/vietnam-2026-04-25 --geo ipapi
```

With IP2Location:

```bash
python3 analyze_results.py \
  --root . \
  --out-dir output/vietnam-2026-04-25 \
  --geo ip2location \
  --ip2location-key YOUR_KEY
```

Show all pipeline options:

```bash
bash scan_all.sh --help
```

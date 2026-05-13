# QUICMap

QUICMap contains scripts, input data, and analysis notebooks for scanning and analyzing QUIC deployment in Vietnam and Southeast Asia.

The repository stores source code, small input lists, notebooks, and summary statistics. Large generated data is intentionally ignored and must be recreated locally.

## Repository Layout

- `ipv4/`: IPv4 scan pipeline, input lists, enrichment code, and analysis code.
- `ipv6/`: IPv6 scan pipeline, input lists, hitlist builder, and analysis code.
- `statistics/`: Committed summary tables generated from prior analysis runs.
- `analyze_asean_outputs.py`: ASEAN-level output analysis.
- `analyze_vietnam_geo.py`: Vietnam geographic analysis.
- `visualize_vietnam.ipynb`: Visualization notebook.

## Ignored Data

The following paths are not stored in Git:

- `zmap/`, `zdns/`: local dependency checkouts.
- `config.env`, `*.env`: local runtime configuration.
- `__pycache__/`, `*.py[cod]`: Python cache files.
- `ipv4/output/`, `ipv4/output_latest/`: IPv4 scan outputs.
- `ipv4/database/domain*`, `ipv4/database/output*`: generated IPv4 enrichment database and large raw domain/IP sources.
- `ipv6/output/`, `ipv6/output_latest/`: IPv6 scan outputs.
- `ipv6/old_version/output-*/`, `ipv6/old_version/root_outputs/`: historical generated outputs.
- `ipv4/qscanner`, `ipv6/qscanner`: local QScanner binaries.
- `*.log`, `ipv6/log.txt`: runtime logs.

## Requirements

Install system packages:

```bash
sudo apt update
sudo apt install -y python3 python3-pip git curl build-essential cmake pkg-config libgmp3-dev libjson-c-dev libpcap-dev gengetopt
```

Install Python dependencies:

```bash
python3 -m pip install -r ipv4/requirements.txt
python3 -m pip install -r ipv6/requirements.txt
```

Install the external scanners:

```bash
sudo apt install -y zmap golang-go
go install github.com/zmap/zdns/v2@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

If the Ubuntu/Debian `zmap` package does not include the required IPv6 QUIC probe module, build ZMap from the upstream source or from the local development checkout outside this repo:

```bash
git clone https://github.com/zmap/zmap.git /tmp/zmap
cd /tmp/zmap
cmake .
make -j"$(nproc)"
sudo make install
```

Verify the tools:

```bash
zmap --version
zdns --help
```

QScanner is expected as an executable binary. Put it at `ipv4/qscanner` and make it executable:

```bash
cp /path/to/qscanner ipv4/qscanner
chmod +x ipv4/qscanner
```

The IPv6 pipeline defaults to `../ipv4/qscanner`, so the same binary is reused.

## Recreate Ignored IPv4 Data

Create a local IPv4 config file:

```bash
cat > ipv4/config.env <<'EOF'
ZMAP_RATE=3000
ZMAP_MODE=quic_vn
ZMAP_PAYLOAD_FILE=initial_qscanner_1a1a1a1a.pkt
ZDNS_THREADS=200
QSCANNER_BIN=./qscanner
DOMAIN_DB=./database/domain_ip.sqlite
EOF
```

Rebuild the ignored enrichment database from local raw domain/IP files. Place raw files in `ipv4/database/raw/` using the existing parser format: text files with `domain ip`, CSV files with domain/IP columns, or JSON/JSONL rows with `domain`/`hostname`/`name` and `ip`/`address`.

```bash
cd ipv4
python3 build_domain_ip_db.py \
  --source-dir database/raw \
  --db database/domain_ip.sqlite \
  --recreate
```

Run the IPv4 pipeline to recreate `ipv4/output/` and `ipv4/output_latest/`:

```bash
cd ipv4
bash scan_all.sh --input=vietnam_ipv4.txt --date=2026-04-25 --print-config
bash scan_all.sh --input=vietnam_ipv4.txt --date=2026-04-25
```

The output directory is:

```text
ipv4/output/<target>-YYYY-MM-DD/
```

## Recreate Ignored IPv6 Data

Create a local IPv6 config file:

```bash
cat > ipv6/config.env <<'EOF'
ZMAP_BIN=/usr/local/sbin/zmap
ZMAP_INTERFACE=eth0
ZMAP_IPV6_SOURCE_IP=2001:db8::1
ZMAP_GATEWAY_MAC=00:00:00:00:00:00
ZMAP_RATE=1000
ZDNS_BIN=zdns
QSCANNER_BIN=../ipv4/qscanner
EOF
```

Replace `ZMAP_INTERFACE`, `ZMAP_IPV6_SOURCE_IP`, and `ZMAP_GATEWAY_MAC` with values for the scan host.

To regenerate country IPv6 hitlists, provide the ignored local source files:

- `ipv6/database/apnic/delegated-apnic-extended-latest`
- `ipv6/database/hitlist-world-responsive-addresses.txt.xz`

Then run:

```bash
cd ipv6
python3 build_country_hitlists.py --countries VN,TH,SG,ID,MY,PH,KH,LA,MM,BN,TL
```

This recreates files such as:

```text
ipv6/input/vietnam_ipv6.txt
ipv6/input/thailand_ipv6.txt
ipv6/database/apnic/vietnam_prefix.txt
```

Run the IPv6 pipeline to recreate `ipv6/output/` and `ipv6/output_latest/`:

```bash
cd ipv6
bash scan_all.sh --input=vietnam_ipv6.txt --date=2026-04-25 --print-config
bash scan_all.sh --input=vietnam_ipv6.txt --date=2026-04-25
```

The output directory is:

```text
ipv6/output/<target>-YYYY-MM-DD/
```

## Analysis

IPv4:

```bash
cd ipv4
python3 analyze_results.py --root . --out-dir output/vietnam-2026-04-25 --geo ipapi
```

IPv6:

```bash
cd ipv6
python3 analyze_results.py --root . --out-dir output/vietnam-2026-04-25 --geo ipapi
```

ASEAN/Vietnam summary scripts:

```bash
python3 analyze_asean_outputs.py
python3 analyze_vietnam_geo.py
```

# IPv6 QUIC Pipeline

This directory contains the IPv6 QUIC scan pipeline. It can regenerate per-country IPv6 hitlists, scan them with the ZMap IPv6 QUIC probe, resolve PTR names with ZDNS, build QScanner input, run QScanner, and analyze the result.

## Pipeline

```text
database/apnic/delegated-apnic-extended-latest
database/hitlist-world-responsive-addresses.txt.xz
  -> build_country_hitlists.py
  -> input/<country>_ipv6.txt
  -> zmap IPv6 QUIC discovery
  -> zDNS PTR lookup
  -> zmap/test_input.csv
  -> QScanner
  -> output/<target>-YYYY-MM-DD/
```

## Ignored Local Data

These paths are generated locally and are not committed:

- `config.env`: host-specific IPv6 interface, source IP, gateway MAC, and paths.
- `output/`, `output_latest/`: scan outputs.
- `old_version/output-*/`, `old_version/root_outputs/`: historical generated outputs.
- `log.txt`, `*.log`: runtime logs.
- `__pycache__/`, `*.py[cod]`: Python cache files.

The large source files used to rebuild hitlists are also local operational data:

- `database/apnic/delegated-apnic-extended-latest`
- `database/hitlist-world-responsive-addresses.txt.xz`

## Setup

Install Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Install external tools:

```bash
sudo apt update
sudo apt install -y golang-go
go install github.com/zmap/zdns/v2@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

Use a ZMap build that includes the IPv6 QUIC module expected by `scan_pipeline.sh`:

```bash
git clone https://github.com/zmap/zmap.git /tmp/zmap
cd /tmp/zmap
cmake .
make -j"$(nproc)"
sudo make install
```

Provide QScanner. By default the IPv6 pipeline reuses the IPv4 binary:

```bash
cp /path/to/qscanner ../ipv4/qscanner
chmod +x ../ipv4/qscanner
```

Create local configuration:

```bash
cat > config.env <<'EOF'
ZMAP_BIN=/usr/local/sbin/zmap
ZMAP_INTERFACE=eth0
ZMAP_IPV6_SOURCE_IP=2001:db8::1
ZMAP_GATEWAY_MAC=00:00:00:00:00:00
ZMAP_RATE=1000
ZDNS_BIN=zdns
QSCANNER_BIN=../ipv4/qscanner
EOF
```

Replace the interface, source IPv6 address, and gateway MAC with values from the scan host.

## Recreate Ignored Hitlist Inputs

Download or provide the source files:

```text
database/apnic/delegated-apnic-extended-latest
database/hitlist-world-responsive-addresses.txt.xz
```

Regenerate Southeast Asia hitlists:

```bash
python3 build_country_hitlists.py --countries VN,TH,SG,ID,MY,PH,KH,LA,MM,BN,TL
```

This creates:

```text
input/vietnam_ipv6.txt
input/thailand_ipv6.txt
input/singapore_ipv6.txt
...
database/apnic/vietnam_prefix.txt
database/apnic/thailand_prefix.txt
...
```

For a small test run:

```bash
python3 build_country_hitlists.py --countries VN --limit 10000
```

To use a custom prefix file for one country:

```bash
python3 build_country_hitlists.py \
  --countries VN \
  --prefix-file database/apnic/vietnam_prefix.txt \
  --output-dir input
```

## Run

Show resolved configuration:

```bash
bash scan_all.sh --input=vietnam_ipv6.txt --date=2026-04-25 --print-config
```

Run a full scan:

```bash
bash scan_all.sh --input=vietnam_ipv6.txt --date=2026-04-25
```

Common examples:

```bash
bash scan_all.sh --input=singapore_ipv6.txt --target=singapore --date=2026-04-26
bash scan_all.sh --input=input/thailand_ipv6.txt --rate=500
bash scan_all.sh --input=vietnam_ipv6.txt --out-dir=output/custom-run
```

Disable stages when reusing intermediate files:

```bash
bash scan_all.sh --input=vietnam_ipv6.txt --zmap=false
bash scan_all.sh --input=vietnam_ipv6.txt --zdns=false --generate=false
```

## Output

By default, each run writes to:

```text
output/<target>-YYYY-MM-DD/
```

Important generated files:

- `zmap/zmap_ipv6_quic_responses.csv`: raw IPv6 discovery output.
- `zmap/ip_list.txt`: QScanner target list.
- `zmap/zdns_results.json`: PTR results.
- `zmap/test_input.csv`: QScanner input.
- `qscanner/output/quic_connection_info.csv`: primary QScanner result.
- `scan_history.log`: append-only run summary.

## Analyze

```bash
python3 analyze_results.py --root . --out-dir output/vietnam-2026-04-25 --geo ipapi
```

Show all pipeline options:

```bash
bash scan_all.sh --help
```

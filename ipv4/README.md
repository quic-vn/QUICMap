# IPv4 QUIC Scanner

Pipeline IPv4 gom cac buoc:

```text
input/*.txt -> zmap -> zDNS PTR -> QScanner input -> domain enrichment -> QScanner -> analysis
```

## Cach chay chinh

Dat file input vao thu muc `input/`. File co the la danh sach IP/CIDR cua Vietnam, Singapore, Thailand, Google, hoac bat ky nhom nao.

Vi du:

```bash
bash scan_all.sh --input=vietnam_ipv4.txt
bash scan_all.sh --input=thailand_ipv4.txt
bash scan_all.sh --input=google_ipv4.txt
```

Neu chi truyen ten file, scanner tu tim trong `input/`. Neu muon truyen duong dan ro rang:

```bash
bash scan_all.sh --input=input/singapore_ipv4.txt
```

## Quy tac output

Mac dinh ket qua nam trong:

```text
output/<target>-YYYY-MM-DD/
```

Ten `<target>` duoc suy ra tu ten file input:

```text
input/vietnam_ipv4.txt      -> output/vietnam-2026-04-25/
input/thailand_ipv4.txt     -> output/thailand-2026-04-25/
input/google_ipv4.txt       -> output/google-2026-04-25/
input/vietnam_ipv4_test.txt -> output/vietnam-2026-04-25/
```

Co the chi dinh target/date:

```bash
bash scan_all.sh --input=thailand_ipv4.txt --target=thailand --date=2026-04-26
```

Kiem tra cau hinh resolve truoc khi scan:

```bash
bash scan_all.sh --input=vietnam_ipv4.txt --date=2026-04-25 --print-config
```

Co the doi thu muc goc:

```bash
bash scan_all.sh --input=vietnam_ipv4.txt --output-root=output
```

Hoac override hoan toan thu muc output:

```bash
bash scan_all.sh --input=vietnam_ipv4.txt --out-dir=output/custom-run
```

## Cau truc file

- `scan_all.sh`: entrypoint chinh de chay pipeline IPv4.
- `scan_pipeline.sh`: pipeline shell chinh, duoc goi boi `scan_all.sh`.
- `analyze_results.py`: entrypoint chinh de phan tich ket qua.
- `build_domain_ip_db.py`: build SQLite DB domain/IP tu cac file raw trong `database/`.
- `config.env`: cau hinh mac dinh cho pipeline.
- `quic_scanner_ipv4/targets.py`: chuan hoa input va ten target.
- `quic_scanner_ipv4/qscanner_input.py`: tao `test_input.csv` cho QScanner.
- `quic_scanner_ipv4/domain_enrichment.py`: enrich hostname tu SQLite.
- `quic_scanner_ipv4/result_analysis.py`: phan tich output cua QScanner.
- `old_version/`: wrapper tuong thich voi ten file cu.

## Phan tich ket qua

```bash
python3 analyze_results.py --root . --out-dir output/vietnam-2026-04-25 --geo ipapi
python3 analyze_results.py --root . --out-dir output/vietnam-2026-04-25 --geo ip2location --ip2location-key C02AA07C50F3CBB0CA97BDBFCC03F917
```

Hoac chi ro file QScanner:

```bash
python3 analyze_results.py \
  --qscanner-csv output/vietnam-2026-04-25/qscanner/output/quic_connection_info.csv
```

## Tuy chon pipeline

```bash
bash scan_all.sh --help
```

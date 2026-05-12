# IPv6 QUIC Scanner

Pipeline IPv6 gom cac buoc:

```text
input/*.txt -> zmap IPv6 -> zDNS PTR -> QScanner input -> QScanner -> analysis
```

## Cach chay chinh

Dat danh sach IPv6 vao thu muc `input/` theo ten ro rang:

```bash
bash scan_all.sh --input=vietnam_ipv6.txt
bash scan_all.sh --input=singapore_ipv6.txt
```

Neu chi truyen ten file, scanner tu tim trong `input/`.

## Quy tac output

Mac dinh ket qua nam trong:

```text
output/<target>-YYYY-MM-DD/
```

Vi du:

```text
input/vietnam_ipv6.txt -> output/vietnam-2026-04-25/
input/vn_ipv6_hitlist.txt -> output/vietnam-2026-04-25/
```

Kiem tra cau hinh truoc khi scan:

```bash
bash scan_all.sh --input=vietnam_ipv6.txt --date=2026-04-25 --print-config
```

## Cau truc file

- `scan_all.sh`: entrypoint chinh.
- `scan_pipeline.sh`: pipeline shell IPv6.
- `analyze_results.py`: phan tich ket qua QScanner.
- `build_country_hitlists.py`: tao hitlist IPv6 rieng cho tung quoc gia tu APNIC va world hitlist.
- `config.env`: cau hinh network/zmap/qscanner mac dinh.
- `quic_scanner_ipv6/targets.py`: chuan hoa input va target.
- `quic_scanner_ipv6/qscanner_input.py`: tao `test_input.csv`.
- `quic_scanner_ipv6/result_analysis.py`: tao statistics va geo CSV.
- `quic_scanner_ipv6/country_hitlists.py`: logic loc hitlist theo prefix APNIC.
- `old_version/`: wrapper va script cu.

## Tao IPv6 hitlist theo quoc gia

Tao tat ca cac quoc gia co prefix IPv6 trong APNIC:

```bash
python3 build_country_hitlists.py
```

Chi tao mot so quoc gia:

```bash
python3 build_country_hitlists.py --countries VN,TH,SG,ID,MY,PH,KH,LA,MM,BN,TL
```

Output mac dinh:

```text
input/vietnam_ipv6.txt
input/thailand_ipv6.txt
input/singapore_ipv6.txt
...
```

Script cung cap nhat prefix APNIC theo quoc gia trong `database/apnic/<country>_prefix.txt`.

Test nhanh voi N dong dau cua hitlist:

```bash
python3 build_country_hitlists.py --countries VN --limit 10000
```

## Phan tich ket qua

```bash
sudo python3 analyze_results.py --root . --out-dir output/vietnam-2026-04-25 --geo ipapi
```

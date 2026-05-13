# IPv4 Old Version Wrappers

This directory keeps compatibility wrappers for older command names. New work should use the maintained IPv4 pipeline one level up.

## Current Entry Points

- `../scan_all.sh`: main IPv4 pipeline entrypoint.
- `../scan_pipeline.sh`: implementation called by `scan_all.sh`.
- `../analyze_results.py`: result analysis entrypoint.
- `../build_domain_ip_db.py`: rebuilds ignored `../database/domain_ip.sqlite`.
- `../quic_scanner_ipv4/`: shared IPv4 Python package.

## Reproduction Notes

Ignored outputs from older runs are not stored here. Recreate current outputs from `../`:

```bash
cd ..
python3 build_domain_ip_db.py --source-dir database/raw --db database/domain_ip.sqlite --recreate
bash scan_all.sh --input=vietnam_ipv4.txt --date=2026-04-25
```

See `../README.md` for the full IPv4 workflow and the root `../../README.md` for repository-wide setup.

# IPv6 Old Version Wrappers

This directory keeps compatibility wrappers and archived helper scripts for older IPv6 workflows. New work should use the maintained IPv6 pipeline one level up.

## Current Entry Points

- `../scan_all.sh`: main IPv6 pipeline entrypoint.
- `../scan_pipeline.sh`: implementation called by `scan_all.sh`.
- `../build_country_hitlists.py`: regenerates country hitlists from local APNIC and world-hitlist sources.
- `../analyze_results.py`: result analysis entrypoint.
- `../quic_scanner_ipv6/`: shared IPv6 Python package.

## Archived Helpers

Older experimental scripts that used to live under generated output folders are kept in `output_scripts/` so they remain versioned while generated run outputs stay ignored.

## Reproduction Notes

Ignored historical outputs are not stored here:

- `output-*/`
- `root_outputs/`

Recreate current outputs from `../`:

```bash
cd ..
python3 build_country_hitlists.py --countries VN,TH,SG,ID,MY,PH,KH,LA,MM,BN,TL
bash scan_all.sh --input=vietnam_ipv6.txt --date=2026-04-25
```

See `../README.md` for the full IPv6 workflow and the root `../../README.md` for repository-wide setup.

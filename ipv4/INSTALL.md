# Install Notes

## Python

```bash
python3 -m pip install -r requirements.txt
```

`pyshark` is optional and only needed when using `--pcap`.

## System tools

The scanner expects these external binaries to be available:

- `zmap`
- `zdns`
- `qscanner`

Set explicit paths in `config.env` when they are not on `PATH`:

```bash
ZMAP_BIN=/usr/local/sbin/zmap
ZDNS_BIN=/home/user/go/bin/zdns
QSCANNER_BIN=./qscanner
```

# IPv4 Install Notes

This file is a short install checklist for `ipv4/README.md`. Use the README for the full reproduction workflow.

## Python

```bash
python3 -m pip install -r requirements.txt
```

`pyshark` is optional and only needed when using packet-capture analysis paths.

## System Tools

The IPv4 pipeline expects these binaries:

- `zmap`
- `zdns`
- `qscanner`

Install ZMap and ZDNS:

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

Set explicit paths in ignored `config.env` if the binaries are not on `PATH`:

```bash
ZMAP_BIN=/usr/local/sbin/zmap
ZDNS_BIN=/home/user/go/bin/zdns
QSCANNER_BIN=./qscanner
```

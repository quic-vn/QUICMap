# QUICMap

QUICMap contains scripts, input data, and analysis notebooks for scanning and analyzing QUIC deployment in Vietnam and Southeast Asia.

## Requirements

The scan pipeline expects the following external tools to be installed locally:

- ZMap
- ZDNS

These tools are not vendored in this repository. Install them separately before running scan scripts.

## Install ZMap

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y zmap
```

To build from source instead:

```bash
sudo apt update
sudo apt install -y build-essential cmake gengetopt libgmp3-dev libjson-c-dev libpcap-dev pkg-config
git clone https://github.com/zmap/zmap.git
cd zmap
cmake .
make -j"$(nproc)"
sudo make install
```

Verify the installation:

```bash
zmap --version
```

## Install ZDNS

Install Go first if it is not available:

```bash
sudo apt update
sudo apt install -y golang-go
```

Install ZDNS:

```bash
go install github.com/zmap/zdns/v2@latest
```

Make sure the Go binary directory is on your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Verify the installation:

```bash
zdns --help
```

## Repository Layout

- `ipv4/`: IPv4 scan scripts, inputs, and analysis code.
- `ipv6/`: IPv6 scan scripts, inputs, and analysis code.
- `statistics/`: Generated summary statistics used by the analysis.
- `analyze_asean_outputs.py`: ASEAN scan output analysis.
- `analyze_vietnam_geo.py`: Vietnam geographic analysis.
- `visualize_vietnam.ipynb`: Notebook for visualization.


#!/usr/bin/env python3
"""Aggregate IPv4/IPv6 QUIC scan outputs for ASEAN countries."""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import ipaddress
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


ASEAN_COUNTRIES = [
    "brunei",
    "cambodia",
    "indonesia",
    "laos",
    "malaysia",
    "myanmar",
    "philippines",
    "singapore",
    "thailand",
    "timorleste",
    "vietnam",
]

RUN_DIR_RE = re.compile(r"^(?P<country>[a-z]+)-(?P<date>\d{4}-\d{2}-\d{2})$")


@dataclass
class RunStats:
    ip_version: str
    country: str
    scan_date: str
    run_dir: str
    total_scan_ips: int = 0
    quic_enable_ip_potential: int = 0
    input_targets: int = 0
    zmap_udp_raw_rows: int = 0
    zmap_tcp_raw_rows: int = 0
    zmap_udp_rows: int = 0
    zmap_tcp_rows: int = 0
    zmap_quic_success_rows: int = 0
    zmap_quic_success_unique_ips: int = 0
    zdns_rows: int = 0
    qscanner_targets: int = 0
    qscanner_target_unique_ips: int = 0
    qscanner_target_duplicate_rows: int = 0
    qscanner_total: int = 0
    qscanner_success: int = 0
    qscanner_error: int = 0
    qscanner_unique_addresses: int = 0
    qscanner_success_unique_addresses: int = 0
    qscanner_error_unique_addresses: int = 0
    qscanner_duplicate_rows: int = 0
    qscanner_retry: int = 0
    http_header_rows: int = 0
    tls_certificate_rows: int = 0
    tls_shared_config_rows: int = 0
    quic_shared_config_rows: int = 0

    @property
    def qscanner_success_rate(self) -> float:
        if self.qscanner_total == 0:
            return 0.0
        return self.qscanner_success / self.qscanner_total

    @property
    def qscanner_unique_success_rate(self) -> float:
        if self.qscanner_unique_addresses == 0:
            return 0.0
        return self.qscanner_success_unique_addresses / self.qscanner_unique_addresses


def normalize_ip(value: str) -> str:
    value = (value or "").strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1].strip()
    if "%" in value:
        value = value.split("%", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def count_text_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    count = 0
    with path.open("rb") as handle:
        for _ in handle:
            count += 1
    return count


def count_csv_rows(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.reader(handle)
        try:
            next(reader)
        except StopIteration:
            return 0
        return sum(1 for _ in reader)


def count_unique_text_values(path: Path) -> int:
    if not path.is_file():
        return 0
    values = set()
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = normalize_ip(line.strip())
            if value:
                values.add(value)
    return len(values)


def count_input_scan_ips(path: Path) -> int:
    if not path.is_file():
        return 0

    total = 0
    seen_ips = set()
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                if "/" in value:
                    total += ipaddress.ip_network(value, strict=False).num_addresses
                else:
                    seen_ips.add(str(ipaddress.ip_address(value)))
            except ValueError:
                normalized = normalize_ip(value)
                if normalized:
                    seen_ips.add(normalized)
    return total + len(seen_ips)


def iter_csv_dicts(path: Path) -> Iterable[dict[str, str]]:
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield dict(row)


def count_unique_csv_ips(path: Path, columns: tuple[str, ...] = ("ip", "address", "saddr")) -> int:
    if not path.is_file():
        return 0
    values = set()
    for row in iter_csv_dicts(path) or []:
        for column in columns:
            value = normalize_ip(row.get(column, ""))
            if value:
                values.add(value)
                break
    return len(values)


def count_unique_ips_across_csv(paths: Iterable[Path], columns: tuple[str, ...] = ("saddr", "ip", "address")) -> int:
    values = set()
    for path in paths:
        if not path.is_file():
            continue
        for row in iter_csv_dicts(path) or []:
            for column in columns:
                value = normalize_ip(row.get(column, ""))
                if value:
                    values.add(value)
                    break
    return len(values)


def csv_value_distribution(
    path: Path,
    value_column: str,
    address_column: str = "address",
    success_only: bool = False,
) -> Counter[tuple[str, str]]:
    values: Counter[tuple[str, str]] = Counter()
    unique_ips_by_value: dict[tuple[str, str], set[str]] = defaultdict(set)
    if not path.is_file():
        return values

    for row in iter_csv_dicts(path) or []:
        if success_only and (row.get("errorMessage") or "").strip():
            continue
        value = (row.get(value_column) or "").strip() or "(empty)"
        status = "success" if not (row.get("errorMessage") or "").strip() else "error"
        key = (status, value)
        values[key] += 1
        address = normalize_ip(row.get(address_column, ""))
        if address:
            unique_ips_by_value[key].add(address)

    for key, addresses in unique_ips_by_value.items():
        values[(f"{key[0]}__unique_ips", key[1])] = len(addresses)
    return values


def extract_alpn_from_extensions(value: str) -> str:
    try:
        extensions = json.loads(value or "[]")
    except json.JSONDecodeError:
        return "(parse_error)"

    alpns: list[str] = []
    for extension in extensions:
        if not isinstance(extension, list) or len(extension) < 2:
            continue
        if str(extension[0]) != "16":
            continue
        try:
            encoded = str(extension[1])
            encoded += "=" * (-len(encoded) % 4)
            payload = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return "(decode_error)"
        if len(payload) < 2:
            return "(empty)"

        offset = 2
        while offset < len(payload):
            length = payload[offset]
            offset += 1
            protocol = payload[offset : offset + length]
            offset += length
            if protocol:
                alpns.append(protocol.decode("ascii", errors="replace"))

    return ",".join(alpns) if alpns else "(empty)"


def tls_alpn_distribution(path: Path) -> Counter[tuple[str, str]]:
    values: Counter[tuple[str, str]] = Counter()
    unique_ips_by_value: dict[tuple[str, str], set[str]] = defaultdict(set)
    if not path.is_file():
        return values

    for row in iter_csv_dicts(path) or []:
        value = extract_alpn_from_extensions(row.get("serverEncryptedExtensions", ""))
        key = ("success", value)
        values[key] += 1
        address = normalize_ip(row.get("address", ""))
        if address:
            unique_ips_by_value[key].add(address)

    for key, addresses in unique_ips_by_value.items():
        values[(f"{key[0]}__unique_ips", key[1])] = len(addresses)
    return values


def input_path_for_run(root: Path, ip_version: str, country: str) -> Path:
    return root / ip_version / "input" / f"{country}_{ip_version}.txt"


def discover_runs(root: Path, ip_version: str) -> list[Path]:
    base = root / ip_version / "output"
    if not base.is_dir():
        return []
    runs = []
    for child in base.iterdir():
        if child.is_dir() and RUN_DIR_RE.match(child.name):
            country = RUN_DIR_RE.match(child.name).group("country")  # type: ignore[union-attr]
            if country in ASEAN_COUNTRIES:
                runs.append(child)
    return sorted(runs, key=lambda item: item.name)


def analyze_run(run_dir: Path, ip_version: str) -> tuple[RunStats, Counter[str]]:
    match = RUN_DIR_RE.match(run_dir.name)
    if not match:
        raise ValueError(f"Invalid run directory name: {run_dir}")

    country = match.group("country")
    stats = RunStats(
        ip_version=ip_version,
        country=country,
        scan_date=match.group("date"),
        run_dir=str(run_dir),
    )

    zmap_dir = run_dir / "zmap"
    qscanner_dir = run_dir / "qscanner" / "output"
    root = run_dir.parents[2]
    stats.total_scan_ips = count_input_scan_ips(input_path_for_run(root, ip_version, country))

    if ip_version == "ipv4":
        stats.input_targets = count_text_lines(zmap_dir / "allowlist.normalized.txt")
        stats.zmap_udp_raw_rows = count_csv_rows(zmap_dir / "zmap_udp_raw.csv")
        stats.zmap_tcp_raw_rows = count_csv_rows(zmap_dir / "zmap_tcp_raw.csv")
        stats.zmap_udp_rows = count_csv_rows(zmap_dir / "zmap_udp.csv")
        stats.zmap_tcp_rows = count_csv_rows(zmap_dir / "zmap_tcp.csv")
        stats.quic_enable_ip_potential = count_unique_ips_across_csv(
            [zmap_dir / "zmap_udp_raw.csv", zmap_dir / "zmap_tcp_raw.csv"]
        )
    else:
        stats.input_targets = count_text_lines(zmap_dir / "ip_list.txt")
        success_path = zmap_dir / "zmap_ipv6_quic_success.txt"
        responses_path = zmap_dir / "zmap_ipv6_quic_responses.txt"
        responses_csv_path = zmap_dir / "zmap_ipv6_quic_responses.csv"
        stats.zmap_quic_success_rows = count_text_lines(success_path) or count_text_lines(responses_path)
        stats.zmap_quic_success_unique_ips = count_unique_text_values(success_path) or count_unique_text_values(
            responses_path
        ) or count_unique_csv_ips(responses_csv_path)
        if stats.zmap_quic_success_rows == 0:
            stats.zmap_quic_success_rows = count_csv_rows(responses_csv_path)
        stats.quic_enable_ip_potential = stats.zmap_quic_success_unique_ips

    stats.zdns_rows = count_text_lines(zmap_dir / "zdns_results.json")
    stats.qscanner_targets = count_csv_rows(zmap_dir / "test_input.csv")
    stats.qscanner_target_unique_ips = count_unique_csv_ips(zmap_dir / "test_input.csv")
    stats.qscanner_target_duplicate_rows = max(0, stats.qscanner_targets - stats.qscanner_target_unique_ips)
    stats.http_header_rows = count_csv_rows(qscanner_dir / "http_header.csv")
    stats.tls_certificate_rows = count_csv_rows(qscanner_dir / "tls_certificates.csv")
    stats.tls_shared_config_rows = count_csv_rows(qscanner_dir / "tls_shared_config.csv")
    stats.quic_shared_config_rows = count_csv_rows(qscanner_dir / "quic_shared_config.csv")

    error_distribution: Counter[str] = Counter()
    all_addresses: set[str] = set()
    success_addresses: set[str] = set()
    error_addresses: set[str] = set()
    for row in iter_csv_dicts(qscanner_dir / "quic_connection_info.csv") or []:
        stats.qscanner_total += 1
        address = normalize_ip(row.get("address", ""))
        if address:
            all_addresses.add(address)

        error_message = (row.get("errorMessage") or "").strip()
        if error_message:
            stats.qscanner_error += 1
            error_distribution[error_message] += 1
            if address:
                error_addresses.add(address)
        else:
            stats.qscanner_success += 1
            if address:
                success_addresses.add(address)

        if (row.get("hasRetry") or "").strip().lower() == "true":
            stats.qscanner_retry += 1

    stats.qscanner_unique_addresses = len(all_addresses)
    stats.qscanner_success_unique_addresses = len(success_addresses)
    stats.qscanner_error_unique_addresses = len(error_addresses - success_addresses)
    stats.qscanner_duplicate_rows = max(0, stats.qscanner_total - stats.qscanner_unique_addresses)
    return stats, error_distribution


def aggregate_totals(rows: list[RunStats]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], list[RunStats]] = defaultdict(list)
    for row in rows:
        grouped[(row.ip_version, row.country)].append(row)

    totals = []
    for (ip_version, country), items in sorted(grouped.items()):
        total_qscanner = sum(item.qscanner_total for item in items)
        success = sum(item.qscanner_success for item in items)
        unique_total = sum(item.qscanner_unique_addresses for item in items)
        unique_success = sum(item.qscanner_success_unique_addresses for item in items)
        totals.append(
            {
                "ip_version": ip_version,
                "country": country,
                "runs": len(items),
                "total_scan_ips": max((item.total_scan_ips for item in items), default=0),
                "quic_enable_ip_potential": max((item.quic_enable_ip_potential for item in items), default=0),
                "input_targets": sum(item.input_targets for item in items),
                "qscanner_targets": sum(item.qscanner_targets for item in items),
                "qscanner_target_unique_ips": sum(item.qscanner_target_unique_ips for item in items),
                "qscanner_target_duplicate_rows": sum(item.qscanner_target_duplicate_rows for item in items),
                "qscanner_total": total_qscanner,
                "qscanner_success": success,
                "qscanner_error": sum(item.qscanner_error for item in items),
                "qscanner_success_rate": round(success / total_qscanner, 6) if total_qscanner else 0.0,
                "qscanner_unique_addresses": unique_total,
                "qscanner_success_unique_addresses": unique_success,
                "qscanner_error_unique_addresses": sum(item.qscanner_error_unique_addresses for item in items),
                "qscanner_duplicate_rows": sum(item.qscanner_duplicate_rows for item in items),
                "qscanner_unique_success_rate": round(unique_success / unique_total, 6) if unique_total else 0.0,
                "qscanner_retry": sum(item.qscanner_retry for item in items),
                "http_header_rows": sum(item.http_header_rows for item in items),
                "tls_certificate_rows": sum(item.tls_certificate_rows for item in items),
                "tls_shared_config_rows": sum(item.tls_shared_config_rows for item in items),
                "quic_shared_config_rows": sum(item.quic_shared_config_rows for item in items),
            }
        )
    return totals


def append_distribution_rows(
    rows: list[dict[str, object]],
    *,
    ip_version: str,
    country: str,
    scan_date: str,
    metric: str,
    distribution: Counter[tuple[str, str]],
) -> None:
    grouped_values = sorted(
        ((status, value, count) for (status, value), count in distribution.items() if not status.endswith("__unique_ips")),
        key=lambda item: (item[0], item[1]),
    )
    for status, value, count in grouped_values:
        unique_count = distribution.get((f"{status}__unique_ips", value), 0)
        rows.append(
            {
                "ip_version": ip_version,
                "country": country,
                "scan_date": scan_date,
                "metric": metric,
                "status": status,
                "value": value,
                "rows": count,
                "unique_ips": unique_count,
            }
        )


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, run_rows: list[dict[str, object]], total_rows: list[dict[str, object]]) -> None:
    lines = [
        "# ASEAN QUIC Scan Summary",
        "",
        "## Totals by country",
        "",
        "| IP version | Country | Total scan IPs | QUIC potential | Unique IPs | Unique success | Unique error | Unique success rate | Duplicate rows |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in total_rows:
        lines.append(
            "| {ip_version} | {country} | {total_scan_ips} | {quic_enable_ip_potential} | {qscanner_unique_addresses} | "
            "{qscanner_success_unique_addresses} | {qscanner_error_unique_addresses} | "
            "{rate:.2%} | {qscanner_duplicate_rows} |".format(
                rate=float(row["qscanner_unique_success_rate"]),
                **row,
            )
        )

    lines.extend(
        [
            "",
            "## Runs",
            "",
            "| IP version | Country | Date | Total scan IPs | QUIC potential | Rows | Unique IPs | Unique success | Unique error | Duplicate rows | Unique success rate |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in run_rows:
        lines.append(
            "| {ip_version} | {country} | {scan_date} | {total_scan_ips} | {quic_enable_ip_potential} | "
            "{qscanner_total} | {qscanner_unique_addresses} | "
            "{qscanner_success_unique_addresses} | {qscanner_error_unique_addresses} | "
            "{qscanner_duplicate_rows} | {rate:.2%} |".format(
                rate=float(row["qscanner_unique_success_rate"]),
                **row,
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aggregate ASEAN IPv4/IPv6 QUIC scanner output statistics.")
    parser.add_argument("--root", default=".", help="Repository root. Default: current directory")
    parser.add_argument("--output-dir", default="statistics", help="Directory for generated summary files")
    parser.add_argument("--ip-version", choices=["ipv4", "ipv6", "both"], default="both")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    output_dir = root / args.output_dir
    ip_versions = ["ipv4", "ipv6"] if args.ip_version == "both" else [args.ip_version]

    run_stats: list[RunStats] = []
    error_rows: list[dict[str, object]] = []
    quic_version_rows: list[dict[str, object]] = []
    quic_config_rows: list[dict[str, object]] = []
    tls_config_rows: list[dict[str, object]] = []
    for ip_version in ip_versions:
        for run_dir in discover_runs(root, ip_version):
            stats, errors = analyze_run(run_dir, ip_version)
            run_stats.append(stats)
            qscanner_dir = run_dir / "qscanner" / "output"
            append_distribution_rows(
                quic_version_rows,
                ip_version=ip_version,
                country=stats.country,
                scan_date=stats.scan_date,
                metric="quicVersion",
                distribution=csv_value_distribution(qscanner_dir / "quic_connection_info.csv", "quicVersion"),
            )
            append_distribution_rows(
                quic_config_rows,
                ip_version=ip_version,
                country=stats.country,
                scan_date=stats.scan_date,
                metric="disable_active_migration",
                distribution=csv_value_distribution(qscanner_dir / "quic_shared_config.csv", "disable_active_migration"),
            )
            for metric in ("ciphersuite", "keyShareGroup"):
                append_distribution_rows(
                    tls_config_rows,
                    ip_version=ip_version,
                    country=stats.country,
                    scan_date=stats.scan_date,
                    metric=metric,
                    distribution=csv_value_distribution(qscanner_dir / "tls_shared_config.csv", metric),
                )
            append_distribution_rows(
                tls_config_rows,
                ip_version=ip_version,
                country=stats.country,
                scan_date=stats.scan_date,
                metric="ALPN",
                distribution=tls_alpn_distribution(qscanner_dir / "tls_shared_config.csv"),
            )
            for message, count in errors.most_common():
                error_rows.append(
                    {
                        "ip_version": ip_version,
                        "country": stats.country,
                        "scan_date": stats.scan_date,
                        "errorMessage": message,
                        "count": count,
                    }
                )

    run_rows = []
    for stats in run_stats:
        row = asdict(stats)
        row["qscanner_success_rate"] = round(stats.qscanner_success_rate, 6)
        row["qscanner_unique_success_rate"] = round(stats.qscanner_unique_success_rate, 6)
        run_rows.append(row)

    total_rows = aggregate_totals(run_stats)

    write_csv(output_dir / "asean_quic_runs.csv", run_rows)
    write_csv(output_dir / "asean_quic_summary.csv", total_rows)
    write_csv(output_dir / "asean_quic_error_distribution.csv", error_rows)
    write_csv(output_dir / "asean_quic_version_distribution.csv", quic_version_rows)
    write_csv(output_dir / "asean_quic_transport_config_distribution.csv", quic_config_rows)
    write_csv(output_dir / "asean_tls_config_distribution.csv", tls_config_rows)
    write_markdown(output_dir / "asean_quic_summary.md", run_rows, total_rows)
    (output_dir / "asean_quic_summary.json").write_text(
        json.dumps(
            {
                "runs": run_rows,
                "totals": total_rows,
                "errors": error_rows,
                "quic_versions": quic_version_rows,
                "quic_transport_config": quic_config_rows,
                "tls_config": tls_config_rows,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"[OK] Runs analyzed: {len(run_rows)}")
    print(f"[OK] Summary written to: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

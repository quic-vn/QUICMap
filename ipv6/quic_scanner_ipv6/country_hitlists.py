#!/usr/bin/env python3
"""Build per-country IPv6 hitlists from APNIC delegated data and a world hitlist."""

from __future__ import annotations

import argparse
from collections import defaultdict
import ipaddress
import lzma
import os
from pathlib import Path
from typing import Iterable


COUNTRY_NAMES = {
    "BN": "brunei",
    "KH": "cambodia",
    "ID": "indonesia",
    "LA": "laos",
    "MY": "malaysia",
    "MM": "myanmar",
    "PH": "philippines",
    "SG": "singapore",
    "TH": "thailand",
    "TL": "timorleste",
    "VN": "vietnam",
}


class TrieNode:
    __slots__ = ("children", "countries")

    def __init__(self) -> None:
        self.children: dict[int, TrieNode] = {}
        self.countries: set[str] = set()


def country_slug(country_code: str) -> str:
    country_code = country_code.upper()
    return COUNTRY_NAMES.get(country_code, country_code.lower())


def parse_country_filter(values: str) -> set[str]:
    if not values:
        return set()
    return {value.strip().upper() for value in values.split(",") if value.strip()}


def parse_apnic_prefixes(apnic_file: Path, countries: set[str]) -> dict[str, list[ipaddress.IPv6Network]]:
    prefixes: dict[str, list[ipaddress.IPv6Network]] = defaultdict(list)
    with open(apnic_file, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split("|")]
            if len(parts) < 6:
                continue
            registry, country_code, resource_type, prefix, prefix_len = parts[:5]
            country_code = country_code.upper()
            if registry.lower() != "apnic" or resource_type.lower() != "ipv6":
                continue
            if countries and country_code not in countries:
                continue
            try:
                network = ipaddress.IPv6Network(f"{prefix}/{prefix_len}", strict=False)
            except ValueError:
                continue
            prefixes[country_code].append(network)

    return {
        country_code: sorted(set(networks), key=lambda network: (int(network.network_address), network.prefixlen))
        for country_code, networks in prefixes.items()
    }


def parse_prefix_file(prefix_file: Path, country_code: str) -> dict[str, list[ipaddress.IPv6Network]]:
    networks = []
    with open(prefix_file, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                network = ipaddress.IPv6Network(value, strict=False)
            except ValueError:
                continue
            networks.append(network)
    return {
        country_code.upper(): sorted(
            set(networks),
            key=lambda network: (int(network.network_address), network.prefixlen),
        )
    }


def write_prefix_files(prefixes: dict[str, list[ipaddress.IPv6Network]], prefix_output_dir: Path) -> None:
    prefix_output_dir.mkdir(parents=True, exist_ok=True)
    for country_code, networks in sorted(prefixes.items()):
        output_file = prefix_output_dir / f"{country_slug(country_code)}_prefix.txt"
        with open(output_file, "w", encoding="utf-8") as handle:
            for network in networks:
                handle.write(f"{network}\n")


def build_prefix_trie(prefixes: dict[str, list[ipaddress.IPv6Network]]) -> TrieNode:
    root = TrieNode()
    for country_code, networks in prefixes.items():
        for network in networks:
            node = root
            network_int = int(network.network_address)
            for bit_index in range(network.prefixlen):
                bit = (network_int >> (127 - bit_index)) & 1
                node = node.children.setdefault(bit, TrieNode())
            node.countries.add(country_code)
    return root


def match_countries(root: TrieNode, address: ipaddress.IPv6Address) -> set[str]:
    node = root
    address_int = int(address)
    matches: set[str] = set(node.countries)
    for bit_index in range(128):
        bit = (address_int >> (127 - bit_index)) & 1
        node = node.children.get(bit)
        if node is None:
            break
        matches.update(node.countries)
    return matches


def iter_hitlist(hitlist_file: Path) -> Iterable[str]:
    opener = lzma.open if hitlist_file.suffix == ".xz" else open
    mode = "rt"
    with opener(hitlist_file, mode, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            yield value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Filter a world IPv6 hitlist into per-country hitlists using APNIC delegated prefixes."
    )
    parser.add_argument(
        "--apnic",
        default="database/apnic/delegated-apnic-extended-latest",
        help="APNIC delegated IPv6 file",
    )
    parser.add_argument(
        "--hitlist",
        default="database/hitlist-world-responsive-addresses.txt.xz",
        help="World responsive IPv6 hitlist (.txt or .txt.xz)",
    )
    parser.add_argument("--countries", default="", help="Comma-separated country codes, e.g. VN,TH,SG. Default: all")
    parser.add_argument(
        "--prefix-file",
        default="",
        help="Use a custom IPv6 CIDR prefix file for exactly one country instead of parsing APNIC",
    )
    parser.add_argument("--output-dir", default="input", help="Directory for <country>_ipv6.txt hitlists")
    parser.add_argument(
        "--prefix-output-dir",
        default="database/apnic",
        help="Directory for regenerated <country>_prefix.txt APNIC prefix files",
    )
    parser.add_argument("--no-prefix-files", action="store_true", help="Do not write APNIC prefix files")
    parser.add_argument("--limit", type=int, default=0, help="Process only first N hitlist rows for testing")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    apnic_file = Path(args.apnic)
    hitlist_file = Path(args.hitlist)
    output_dir = Path(args.output_dir)
    prefix_output_dir = Path(args.prefix_output_dir)
    countries = parse_country_filter(args.countries)

    if not apnic_file.is_file():
        print(f"[ERROR] APNIC file not found: {apnic_file}")
        return 1
    if not hitlist_file.is_file():
        print(f"[ERROR] hitlist file not found: {hitlist_file}")
        return 1

    if args.prefix_file:
        if len(countries) != 1:
            print("[ERROR] --prefix-file requires exactly one country in --countries, for example --countries VN")
            return 1
        prefixes = parse_prefix_file(Path(args.prefix_file), next(iter(countries)))
    else:
        prefixes = parse_apnic_prefixes(apnic_file, countries)
    if not prefixes:
        print("[ERROR] no APNIC IPv6 prefixes matched the requested countries")
        return 2

    if not args.no_prefix_files:
        write_prefix_files(prefixes, prefix_output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    trie = build_prefix_trie(prefixes)
    output_handles = {
        country_code: open(output_dir / f"{country_slug(country_code)}_ipv6.txt", "w", encoding="utf-8")
        for country_code in prefixes
    }
    counts = defaultdict(int)
    processed = 0
    matched = 0

    try:
        for value in iter_hitlist(hitlist_file):
            if args.limit and processed >= args.limit:
                break
            processed += 1
            try:
                address = ipaddress.IPv6Address(value)
            except ValueError:
                continue
            matched_countries = match_countries(trie, address)
            if not matched_countries:
                continue
            matched += 1
            for country_code in matched_countries:
                output_handles[country_code].write(f"{value}\n")
                counts[country_code] += 1
    finally:
        for handle in output_handles.values():
            handle.close()

    print(f"[OK] Processed hitlist rows: {processed}")
    print(f"[OK] Matched rows: {matched}")
    for country_code in sorted(prefixes):
        print(
            f"[OK] {country_code} {country_slug(country_code)}: "
            f"prefixes={len(prefixes[country_code])}, hitlist={counts[country_code]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

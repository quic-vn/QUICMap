#!/usr/bin/env python3
import argparse
import ipaddress
from pathlib import Path


def extract_ipv6_by_country(input_file: Path, country_code: str):
    country_code = country_code.upper()
    prefixes = []

    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split("|")]

            # File delegated-apnic-ipv6-assigned-latest có 6 cột:
            # apnic|VN|ipv6|2001:df0:c::|48|20080610
            if len(parts) < 6:
                continue

            registry = parts[0].lower()
            cc = parts[1].upper()
            rtype = parts[2].lower()
            prefix = parts[3]
            prefix_len = parts[4]

            if registry != "apnic":
                continue

            if cc != country_code:
                continue

            if rtype != "ipv6":
                continue

            try:
                net = ipaddress.IPv6Network(f"{prefix}/{prefix_len}", strict=False)
                prefixes.append(str(net))
            except ValueError:
                print(f"[!] Skip invalid line: {line}")

    return sorted(set(prefixes), key=lambda x: ipaddress.IPv6Network(x))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-c", "--country", required=True)
    parser.add_argument("-o", "--output", default=None)

    args = parser.parse_args()

    input_file = Path(args.input)
    country = args.country.upper()

    output_file = Path(args.output) if args.output else Path(f"{country.lower()}_prefix.txt")

    prefixes = extract_ipv6_by_country(input_file, country)

    with open(output_file, "w", encoding="utf-8") as f:
        for p in prefixes:
            f.write(p + "\n")

    print(f"[+] Country: {country}")
    print(f"[+] IPv6 prefixes: {len(prefixes)}")
    print(f"[+] Output: {output_file}")


if __name__ == "__main__":
    main()

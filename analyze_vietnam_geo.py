#!/usr/bin/env python3
"""Summarize Vietnam GEO rows from IPv4 and IPv6 QUIC scanner outputs."""

from __future__ import annotations

import argparse
import csv
import json
import re
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Iterable


DEFAULT_INPUTS = {
    "ipv4": Path("ipv4/output/vietnam-2026-04-28/statistics_qscanner_geo.csv"),
    "ipv6": Path("ipv6/output/vietnam-2026-04-25/statistics_qscanner_geo.csv"),
}

OLD_PROVINCE_TO_34 = {
    "ha giang": "Tuyên Quang",
    "tuyen quang": "Tuyên Quang",
    "cao bang": "Cao Bằng",
    "lai chau": "Lai Châu",
    "lao cai": "Lào Cai",
    "yen bai": "Lào Cai",
    "bac kan": "Thái Nguyên",
    "thai nguyen": "Thái Nguyên",
    "dien bien": "Điện Biên",
    "lang son": "Lạng Sơn",
    "son la": "Sơn La",
    "hoa binh": "Phú Thọ",
    "vinh phuc": "Phú Thọ",
    "phu tho": "Phú Thọ",
    "bac giang": "Bắc Ninh",
    "bac ninh": "Bắc Ninh",
    "quang ninh": "Quảng Ninh",
    "ha noi": "TP. Hà Nội",
    "hanoi": "TP. Hà Nội",
    "hai duong": "TP. Hải Phòng",
    "hai phong": "TP. Hải Phòng",
    "haiphong": "TP. Hải Phòng",
    "thai binh": "Hưng Yên",
    "hung yen": "Hưng Yên",
    "ha nam": "Ninh Bình",
    "ninh binh": "Ninh Bình",
    "nam dinh": "Ninh Bình",
    "thanh hoa": "Thanh Hóa",
    "nghe an": "Nghệ An",
    "ha tinh": "Hà Tĩnh",
    "quang binh": "Quảng Trị",
    "quang tri": "Quảng Trị",
    "thua thien hue": "TP. Huế",
    "hue": "TP. Huế",
    "da nang": "TP. Đà Nẵng",
    "quang nam": "TP. Đà Nẵng",
    "quang ngai": "Quảng Ngãi",
    "kon tum": "Quảng Ngãi",
    "gia lai": "Gia Lai",
    "binh dinh": "Gia Lai",
    "phu yen": "Đắk Lắk",
    "dak lak": "Đắk Lắk",
    "dak nong": "Lâm Đồng",
    "lam dong": "Lâm Đồng",
    "binh thuan": "Lâm Đồng",
    "khanh hoa": "Khánh Hòa",
    "ninh thuan": "Khánh Hòa",
    "binh phuoc": "Đồng Nai",
    "dong nai": "Đồng Nai",
    "tay ninh": "Tây Ninh",
    "long an": "Tây Ninh",
    "binh duong": "TP. Hồ Chí Minh",
    "ho chi minh": "TP. Hồ Chí Minh",
    "ho chi minh city": "TP. Hồ Chí Minh",
    "tp ho chi minh": "TP. Hồ Chí Minh",
    "tphcm": "TP. Hồ Chí Minh",
    "ba ria vung tau": "TP. Hồ Chí Minh",
    "ba ria - vung tau": "TP. Hồ Chí Minh",
    "tien giang": "Đồng Tháp",
    "dong thap": "Đồng Tháp",
    "kien giang": "An Giang",
    "an giang": "An Giang",
    "ben tre": "Vĩnh Long",
    "vinh long": "Vĩnh Long",
    "tra vinh": "Vĩnh Long",
    "soc trang": "TP. Cần Thơ",
    "hau giang": "TP. Cần Thơ",
    "can tho": "TP. Cần Thơ",
    "bac lieu": "Cà Mau",
    "ca mau": "Cà Mau",
}

CITY_TO_34 = {
    "bien hoa": "Đồng Nai",
    "buon ma thuot": "Đắk Lắk",
    "ca mau": "Cà Mau",
    "can gio": "TP. Hồ Chí Minh",
    "da nang": "TP. Đà Nẵng",
    "dien bien phu": "Điện Biên",
    "di linh": "Lâm Đồng",
    "dong da": "TP. Hà Nội",
    "dong ha": "Quảng Trị",
    "duong to": "An Giang",
    "ha long": "Quảng Ninh",
    "ha tinh": "Hà Tĩnh",
    "hai duong": "TP. Hải Phòng",
    "haiphong": "TP. Hải Phòng",
    "hanoi": "TP. Hà Nội",
    "hoi an": "TP. Đà Nẵng",
    "ho chi minh city": "TP. Hồ Chí Minh",
    "hue": "TP. Huế",
    "kon tum": "Quảng Ngãi",
    "long xuyen": "An Giang",
    "muong nhe": "Điện Biên",
    "nam dinh": "Ninh Bình",
    "nha trang": "Khánh Hòa",
    "phan rang thap cham": "Khánh Hòa",
    "phu quoc": "An Giang",
    "phu rieng": "Đồng Nai",
    "pleiku": "Gia Lai",
    "qui nhon": "Gia Lai",
    "tan an": "Tây Ninh",
    "tan binh": "TP. Hồ Chí Minh",
    "tan phu": "TP. Hồ Chí Minh",
    "thanh hoa": "Thanh Hóa",
    "thu dau mot": "TP. Hồ Chí Minh",
    "vinh": "Nghệ An",
    "vinh long": "Vĩnh Long",
    "vinh yen": "Phú Thọ",
}

ASN_TO_ORGANIZATION = {
    "7552": "Viettel",
    "24086": "Viettel",
    "38731": "Viettel",
    "133606": "Viettel",
    "45899": "VNPT",
    "7643": "VNPT",
    "135905": "VNPT",
    "18403": "FPT Telecom",
    "45894": "FPT Telecom",
    "140766": "FPT Telecom",
    "45903": "CMC Telecom",
    "38732": "CMC Telecom",
    "38733": "CMC Telecom",
    "24088": "Hanoi Telecom",
    "38253": "Hanoi Telecom",
    "131386": "Long Van",
    "131414": "Long Van",
    "131423": "Long Van",
    "131429": "MobiFone",
    "38247": "Vietnamobile",
    "7602": "Saigon Postel",
    "45543": "Saigontourist Cable Television",
    "45544": "SUPERDATA",
    "38244": "VNG",
    "24173": "NetNam",
}

AS_NAME_ALIASES = {
    "viettel corporation": "Viettel",
    "viettel group": "Viettel",
    "viettel timor leste": "Viettel",
    "vietel cht compamy ltd": "Viettel",
    "vnpt corp": "VNPT",
    "vietnam posts and telecommunications": "VNPT",
    "vietnam posts and telecommunications group": "VNPT",
    "vietnam posts and telecommunications vnpt": "VNPT",
    "fpt telecom company": "FPT Telecom",
    "fpt online jsc": "FPT Telecom",
    "fpt smart cloud company limited": "FPT Telecom",
    "cmc telecom infrastructure company": "CMC Telecom",
    "hanoi telecom joint stock company hcmc branch": "Hanoi Telecom",
    "hanoi telecom jsc": "Hanoi Telecom",
    "long van system solution jsc": "Long Van",
    "long van soft solution jsc": "Long Van",
    "branch of long van system solution jsc hanoi": "Long Van",
    "mobifone corporation": "MobiFone",
    "vietnamobile telecommunications joint stock company": "Vietnamobile",
    "sai gon postel corporation": "Saigon Postel",
    "vng corporation": "VNG",
    "netnam company": "NetNam",
}


def clean(value: str | None, empty: str = "(empty)") -> str:
    value = (value or "").strip()
    return value if value else empty


def normalize_key(value: str | None) -> str:
    value = clean(value, "")
    value = unicodedata.normalize("NFKD", value)
    value = "".join(char for char in value if not unicodedata.combining(char))
    value = value.replace("Đ", "D").replace("đ", "d")
    value = re.sub(r"[^a-zA-Z0-9]+", " ", value).strip().lower()
    return re.sub(r"\s+", " ", value)


def normalized_province_34(row: dict[str, str]) -> str:
    region_key = normalize_key(row.get("region_name"))
    if region_key in OLD_PROVINCE_TO_34:
        return OLD_PROVINCE_TO_34[region_key]

    city_key = normalize_key(row.get("city_name"))
    if city_key in CITY_TO_34:
        return CITY_TO_34[city_key]
    if city_key in OLD_PROVINCE_TO_34:
        return OLD_PROVINCE_TO_34[city_key]

    return "(unmapped)"


def normalized_as_organization(row: dict[str, str]) -> str:
    asn = clean(row.get("asn"), "")
    if asn in ASN_TO_ORGANIZATION:
        return ASN_TO_ORGANIZATION[asn]

    name_key = normalize_key(row.get("as"))
    if name_key in AS_NAME_ALIASES:
        return AS_NAME_ALIASES[name_key]

    return clean(row.get("as"))


def is_geolocated(row: dict[str, str]) -> bool:
    return any(
        clean(row.get(column), "") != ""
        for column in (
            "country_code",
            "country_name",
            "region_name",
            "city_name",
            "latitude",
            "longitude",
            "asn",
            "as",
        )
    )


def is_vietnam(row: dict[str, str]) -> bool:
    country_code = clean(row.get("country_code"), "").upper()
    country_name = clean(row.get("country_name"), "").lower()
    return country_code == "VN" or country_name in {"viet nam", "vietnam"}


def iter_rows(path: Path) -> Iterable[dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        yield from csv.DictReader(handle)


def top_rows(
    *,
    ip_version: str,
    dimension: str,
    counter: Counter[str],
    total: int,
) -> list[dict[str, object]]:
    output = []
    for value, count in counter.most_common():
        output.append(
            {
                "ip_version": ip_version,
                "dimension": dimension,
                "value": value,
                "count": count,
                "percent_of_total": round(count / total, 6) if total else 0.0,
            }
        )
    return output


def summarize_file(ip_version: str, path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing input file for {ip_version}: {path}")

    total_rows = 0
    geolocated_rows = 0
    vietnam_rows = 0
    empty_geo_rows = 0
    unique_ips: set[str] = set()
    vietnam_unique_ips: set[str] = set()
    proxy_counter: Counter[str] = Counter()
    province_counter: Counter[str] = Counter()
    raw_region_counter: Counter[str] = Counter()
    city_counter: Counter[str] = Counter()
    timezone_counter: Counter[str] = Counter()
    asn_counter: Counter[str] = Counter()
    org_counter: Counter[str] = Counter()
    raw_org_counter: Counter[str] = Counter()
    region_city_counter: Counter[str] = Counter()
    province_unmapped_rows = 0

    for row in iter_rows(path):
        total_rows += 1
        ip = clean(row.get("ip"), "")
        if ip:
            unique_ips.add(ip)

        if is_geolocated(row):
            geolocated_rows += 1
        else:
            empty_geo_rows += 1

        if not is_vietnam(row):
            continue

        vietnam_rows += 1
        if ip:
            vietnam_unique_ips.add(ip)
        region = clean(row.get("region_name"))
        city = clean(row.get("city_name"))
        province = normalized_province_34(row)
        asn = clean(row.get("asn"))
        org = normalized_as_organization(row)
        raw_org = clean(row.get("as"))

        province_counter[province] += 1
        raw_region_counter[region] += 1
        city_counter[city] += 1
        timezone_counter[clean(row.get("time_zone"))] += 1
        asn_counter[asn] += 1
        org_counter[org] += 1
        raw_org_counter[raw_org] += 1
        region_city_counter[f"{region} / {city}"] += 1
        proxy_counter[clean(row.get("is_proxy"))] += 1
        if province == "(unmapped)":
            province_unmapped_rows += 1

    summary = {
        "ip_version": ip_version,
        "source_file": str(path),
        "total_rows": total_rows,
        "unique_ips": len(unique_ips),
        "geolocated_rows": geolocated_rows,
        "empty_geo_rows": empty_geo_rows,
        "vietnam_rows": vietnam_rows,
        "vietnam_unique_ips": len(vietnam_unique_ips),
        "province_unmapped_rows": province_unmapped_rows,
        "geolocated_rate": round(geolocated_rows / total_rows, 6) if total_rows else 0.0,
        "vietnam_rate": round(vietnam_rows / total_rows, 6) if total_rows else 0.0,
        "province_unmapped_rate": round(province_unmapped_rows / vietnam_rows, 6) if vietnam_rows else 0.0,
    }

    distributions: list[dict[str, object]] = []
    distributions.extend(
        top_rows(ip_version=ip_version, dimension="province_34", counter=province_counter, total=vietnam_rows)
    )
    distributions.extend(
        top_rows(ip_version=ip_version, dimension="region_name_raw", counter=raw_region_counter, total=vietnam_rows)
    )
    distributions.extend(
        top_rows(ip_version=ip_version, dimension="city_name", counter=city_counter, total=vietnam_rows)
    )
    distributions.extend(
        top_rows(
            ip_version=ip_version,
            dimension="region_city",
            counter=region_city_counter,
            total=vietnam_rows,
        )
    )
    distributions.extend(
        top_rows(ip_version=ip_version, dimension="asn", counter=asn_counter, total=vietnam_rows)
    )
    distributions.extend(
        top_rows(ip_version=ip_version, dimension="as_organization", counter=org_counter, total=vietnam_rows)
    )
    distributions.extend(
        top_rows(ip_version=ip_version, dimension="as_raw", counter=raw_org_counter, total=vietnam_rows)
    )
    distributions.extend(
        top_rows(ip_version=ip_version, dimension="time_zone", counter=timezone_counter, total=vietnam_rows)
    )
    distributions.extend(
        top_rows(ip_version=ip_version, dimension="is_proxy", counter=proxy_counter, total=vietnam_rows)
    )
    return summary, distributions


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, summaries: list[dict[str, object]], distributions: list[dict[str, object]]) -> None:
    dimension_labels = {
        "province_34": "34-province city",
        "city_name": "raw city_name",
        "asn": "ASN",
        "as_organization": "normalized AS organization",
    }
    lines = [
        "# Vietnam GEO Statistics",
        "",
        "## Overview",
        "",
        "| IP version | Total rows | Unique IPs | Geolocated rows | Empty GEO rows | Vietnam rows | Vietnam unique IPs | Unmapped province rows | Vietnam rate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summaries:
        lines.append(
            "| {ip_version} | {total_rows} | {unique_ips} | {geolocated_rows} | {empty_geo_rows} | "
            "{vietnam_rows} | {vietnam_unique_ips} | {province_unmapped_rows} | {rate:.2%} |".format(
                rate=float(row["vietnam_rate"]),
                **row,
            )
        )

    for dimension in ("province_34", "city_name", "asn", "as_organization"):
        for ip_version in ("ipv4", "ipv6"):
            lines.extend(["", f"## Top {dimension_labels[dimension]} ({ip_version})", ""])
            lines.append("| Value | Count | Percent of Vietnam rows |")
            lines.append("|---|---:|---:|")
            selected = [
                row
                for row in distributions
                if row["dimension"] == dimension and row["ip_version"] == ip_version
            ]
            for row in selected[:20]:
                lines.append(
                    "| {value} | {count} | {percent:.2%} |".format(
                        percent=float(row["percent_of_total"]),
                        **row,
                    )
                )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize Vietnam GEO data from IPv4/IPv6 statistics_qscanner_geo.csv files.")
    parser.add_argument("--root", default=".", help="Repository root. Default: current directory")
    parser.add_argument("--output-dir", default="statistics", help="Directory for generated output files")
    parser.add_argument("--ipv4", default=str(DEFAULT_INPUTS["ipv4"]), help="IPv4 statistics_qscanner_geo.csv path")
    parser.add_argument("--ipv6", default=str(DEFAULT_INPUTS["ipv6"]), help="IPv6 statistics_qscanner_geo.csv path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    output_dir = root / args.output_dir
    inputs = {
        "ipv4": root / args.ipv4,
        "ipv6": root / args.ipv6,
    }

    summaries: list[dict[str, object]] = []
    distributions: list[dict[str, object]] = []
    for ip_version, path in inputs.items():
        summary, rows = summarize_file(ip_version, path)
        summaries.append(summary)
        distributions.extend(rows)

    write_csv(output_dir / "vietnam_geo_summary.csv", summaries)
    write_csv(output_dir / "vietnam_geo_distribution.csv", distributions)
    write_markdown(output_dir / "vietnam_geo_summary.md", summaries, distributions)
    (output_dir / "vietnam_geo_summary.json").write_text(
        json.dumps({"summary": summaries, "distribution": distributions}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"[OK] Vietnam GEO files analyzed: {len(summaries)}")
    print(f"[OK] Summary written to: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

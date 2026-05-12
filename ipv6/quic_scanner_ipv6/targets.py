"""Target input helpers for the IPv6 scanner."""

from __future__ import annotations

import argparse
import os
import re


TARGET_ALIASES = {
    "vn": "vietnam",
}


def derive_target_name(input_path: str) -> str:
    base_name = os.path.splitext(os.path.basename(input_path))[0].lower()
    base_name = re.sub(r"(_|-)?ipv6(_|-)?(hitlist|test|list)?$", "", base_name)
    base_name = re.sub(r"(_|-)?(hitlist|test|list)$", "", base_name)
    target = re.sub(r"[^a-z0-9]+", "-", base_name).strip("-") or "targets"
    return TARGET_ALIASES.get(target, target)


def resolve_input_path(value: str, input_dir: str = "input") -> str:
    if not value:
        raise ValueError("input file is required")
    if os.path.isabs(value) or os.path.dirname(value):
        return value
    return os.path.join(input_dir, value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resolve IPv6 scanner target metadata.")
    parser.add_argument("--input", required=True, help="Input text file path or file name under input/")
    parser.add_argument("--target", default="", help="Optional explicit target name")
    parser.add_argument("--input-dir", default="input", help="Default input directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = resolve_input_path(args.input, args.input_dir)
    target_name = args.target or derive_target_name(input_path)
    print(f"input={input_path}")
    print(f"target={target_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


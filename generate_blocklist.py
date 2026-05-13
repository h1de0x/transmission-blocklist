#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 h1de0x
# Project: https://github.com/h1de0x/transmission-blocklist

import gzip
import ipaddress
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml


CONFIG_PATH = "sources.yml"
OUTPUT_PATH = "dist/blocklist.p2p"

USER_AGENT = "transmission-blocklist-generator/1.0"

IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"

CIDR_RE = re.compile(rf"\b({IPV4}/\d{{1,2}})\b")
RANGE_RE = re.compile(rf"\b({IPV4})\s*-\s*({IPV4})\b")
IP_RE = re.compile(rf"\b({IPV4})\b")

# DShield format:
# Start              End                Netmask Attacks Name Country email
# 45.148.10.0        45.148.10.255      24      ...
DSHIELD_RE = re.compile(rf"^({IPV4})\s+({IPV4})\s+\d+\b")


def is_public_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return ip.version == 4 and ip.is_global


def normalize_ip(value: str) -> ipaddress.IPv4Address | None:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None

    if ip.version != 4:
        return None

    if not is_public_ipv4(ip):
        return None

    return ip


def add_range(ranges: list[tuple[int, int]], start: str, end: str) -> None:
    start_ip = normalize_ip(start)
    end_ip = normalize_ip(end)

    if start_ip is None or end_ip is None:
        return

    start_int = int(start_ip)
    end_int = int(end_ip)

    if start_int > end_int:
        start_int, end_int = end_int, start_int

    ranges.append((start_int, end_int))


def add_cidr(ranges: list[tuple[int, int]], cidr: str) -> None:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return

    if network.version != 4:
        return

    start_ip = network.network_address
    end_ip = network.broadcast_address

    if not is_public_ipv4(start_ip) or not is_public_ipv4(end_ip):
        return

    ranges.append((int(start_ip), int(end_ip)))


def strip_inline_comment(line: str) -> str:
    for marker in (";", "#"):
        if marker in line:
            line = line.split(marker, 1)[0]

    return line.strip()


def parse_text_to_ranges(text: str, source_name: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        # DShield has a special table-like format:
        # start_ip end_ip mask attacks name country email
        if source_name == "dshield":
            match = DSHIELD_RE.search(line)
            if match:
                add_range(ranges, match.group(1), match.group(2))
            continue

        line = strip_inline_comment(line)

        if not line:
            continue

        # IP range: 1.2.3.4-1.2.3.9
        range_match = RANGE_RE.search(line)
        if range_match:
            add_range(ranges, range_match.group(1), range_match.group(2))
            continue

        # CIDR: 1.2.3.0/24
        cidr_matches = CIDR_RE.findall(line)
        if cidr_matches:
            for cidr in cidr_matches:
                add_cidr(ranges, cidr)
            continue

        # Single IPv4: 1.2.3.4
        ip_match = IP_RE.search(line)
        if ip_match:
            add_range(ranges, ip_match.group(1), ip_match.group(1))

    return ranges


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []

    ranges = sorted(ranges)
    merged = [ranges[0]]

    for start, end in ranges[1:]:
        last_start, last_end = merged[-1]

        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))

    return merged


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def safe_source_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def download_source(name: str, url: str) -> str:
    print(f"Downloading {name}: {url}")

    response = requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=60,
    )
    response.raise_for_status()

    return response.text


def load_sources(config_path: str) -> list[dict]:
    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    config = yaml.safe_load(path.read_text(encoding="utf-8"))

    if not isinstance(config, dict):
        raise ValueError("Invalid sources.yml: root must be a mapping")

    sources = config.get("sources", [])

    if not isinstance(sources, list):
        raise ValueError("Invalid sources.yml: 'sources' must be a list")

    return sources


def write_blocklist(
    output_path: str,
    ranges_by_source: dict[str, list[tuple[int, int]]],
) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()
    total_ranges = sum(len(ranges) for ranges in ranges_by_source.values())

    with output.open("w", encoding="utf-8") as file:
        file.write("# Generated by: https://github.com/h1de0x/transmission-blocklist\n")
        file.write(f"# Generated at: {generated_at}\n")
        file.write("# Generator license: MIT\n")
        file.write("# Upstream feed data rights remain with their respective maintainers\n")
        file.write("# Format: Transmission P2P plaintext blocklist\n")
        file.write(f"# Total ranges: {total_ranges}\n")
        file.write("# Sources:\n")

        for source_name in sorted(ranges_by_source):
            file.write(
                f"# - {source_name}: "
                f"{len(ranges_by_source[source_name])} ranges\n"
            )

        file.write("\n")

        for source_name in sorted(ranges_by_source):
            label = safe_source_name(source_name)

            for start, end in ranges_by_source[source_name]:
                file.write(f"{label}:{int_to_ip(start)}-{int_to_ip(end)}\n")


def write_gzip_copy(input_path: str) -> str:
    source = Path(input_path)
    gzip_path = source.with_suffix(source.suffix + ".gz")

    with source.open("rb") as src:
        with gzip.open(gzip_path, "wb", compresslevel=9) as dst:
            dst.writelines(src)

    return str(gzip_path)


def main() -> int:
    try:
        sources = load_sources(CONFIG_PATH)
    except Exception as exc:
        print(f"ERROR: failed to load config: {exc}", file=sys.stderr)
        return 1

    ranges_by_source: dict[str, list[tuple[int, int]]] = {}

    raw_ranges_count = 0
    merged_ranges_count = 0
    failed_sources = 0

    for source in sources:
        name = source.get("name")
        url = source.get("url")

        if not name or not url:
            print(f"Skipping invalid source entry: {source}", file=sys.stderr)
            continue

        try:
            text = download_source(name, url)
            ranges = parse_text_to_ranges(text, name)
            merged_ranges = merge_ranges(ranges)

            if len(ranges) == 0:
                print(f"  WARNING: {name} returned 0 parsed ranges", file=sys.stderr)

            ranges_by_source[name] = merged_ranges

            raw_ranges_count += len(ranges)
            merged_ranges_count += len(merged_ranges)

            print(f"  parsed ranges: {len(ranges)}")
            print(f"  merged ranges: {len(merged_ranges)}")

        except Exception as exc:
            failed_sources += 1
            print(f"  ERROR: {name}: {exc}", file=sys.stderr)

    write_blocklist(
        output_path=OUTPUT_PATH,
        ranges_by_source=ranges_by_source,
    )

    gzip_output_path = write_gzip_copy(OUTPUT_PATH)

    print()
    print(f"Written: {OUTPUT_PATH}")
    print(f"Written gzip: {gzip_output_path}")
    print(f"Raw ranges: {raw_ranges_count}")
    print(f"Merged ranges by source: {merged_ranges_count}")
    print(f"Failed sources: {failed_sources}")

    if not merged_ranges_count:
        print("ERROR: generated blocklist is empty", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

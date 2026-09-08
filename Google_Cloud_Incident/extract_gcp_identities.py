#!/usr/bin/env python3
"""Extract identities and source IPs from Google Cloud Audit Logs.

This script searches GCP audit-log JSON for ``principalSubject`` and
``callerIp`` values, removes duplicates, and writes the results to:

    ips.txt
    principal_subjects.txt

It supports JSON objects, JSON arrays, and newline-delimited JSON (NDJSON).
By default, the output files are created in the current working directory.

Usage:
    python3 extract_gcp_identities.py /path/to/gcp.json
    python3 extract_gcp_identities.py /path/to/gcp.json --output-dir ./results

Run ``python3 extract_gcp_identities.py --help`` for additional options.

Author: Kevin Pigney
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterator, TextIO


CHUNK_SIZE = 1024 * 1024


def _skip_space(buffer: str, position: int) -> int:
    while position < len(buffer) and buffer[position].isspace():
        position += 1
    return position


def iter_json_records(stream: TextIO) -> Iterator[Any]:
    """Stream records from a JSON array, NDJSON, or concatenated JSON values."""
    decoder = json.JSONDecoder()
    buffer = ""
    position = 0
    eof = False
    in_array: bool | None = None

    while True:
        if position:
            buffer = buffer[position:]
            position = 0

        if not eof and len(buffer) < CHUNK_SIZE:
            chunk = stream.read(CHUNK_SIZE)
            if chunk:
                buffer += chunk
            else:
                eof = True

        position = _skip_space(buffer, position)

        if in_array is None:
            if position >= len(buffer):
                if eof:
                    return
                continue
            in_array = buffer[position] == "["
            if in_array:
                position += 1

        position = _skip_space(buffer, position)
        if in_array:
            while position < len(buffer) and buffer[position] == ",":
                position = _skip_space(buffer, position + 1)
            if position < len(buffer) and buffer[position] == "]":
                return

        if position >= len(buffer):
            if eof:
                return
            continue

        try:
            value, end = decoder.raw_decode(buffer, position)
        except json.JSONDecodeError as error:
            if not eof:
                chunk = stream.read(CHUNK_SIZE)
                if chunk:
                    buffer += chunk
                    continue
                eof = True
                continue
            raise ValueError(
                f"Invalid or incomplete JSON near character {error.pos}: {error.msg}"
            ) from error

        yield value
        position = end


def collect_fields(value: Any, ips: set[str], subjects: set[str]) -> None:
    if isinstance(value, dict):
        caller_ip = value.get("callerIp")
        if isinstance(caller_ip, str) and caller_ip.strip():
            ips.add(caller_ip.strip())

        principal_subject = value.get("principalSubject")
        if isinstance(principal_subject, str) and principal_subject.strip():
            subjects.add(principal_subject.strip())

        for child in value.values():
            if isinstance(child, (dict, list)):
                collect_fields(child, ips, subjects)
    elif isinstance(value, list):
        for child in value:
            collect_fields(child, ips, subjects)


def write_lines(path: Path, values: set[str]) -> None:
    path.write_text("".join(f"{value}\n" for value in sorted(values)), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract unique callerIp and principalSubject values from GCP audit logs."
    )
    parser.add_argument("input", type=Path, help="GCP JSON, JSON array, or NDJSON file")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.cwd(),
        help="output directory (default: current working directory)",
    )
    parser.add_argument("--ips-file", default="ips.txt", help="IP output filename")
    parser.add_argument(
        "--subjects-file",
        default="principal_subjects.txt",
        help="principal-subject output filename",
    )
    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"input file not found: {args.input}")

    ips: set[str] = set()
    subjects: set[str] = set()

    try:
        with args.input.open("r", encoding="utf-8-sig") as stream:
            for record in iter_json_records(stream):
                collect_fields(record, ips, subjects)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ips_path = args.output_dir / args.ips_file
    subjects_path = args.output_dir / args.subjects_file
    write_lines(ips_path, ips)
    write_lines(subjects_path, subjects)

    print(f"Wrote {len(ips)} unique IP(s) to {ips_path.resolve()}")
    print(f"Wrote {len(subjects)} unique principal subject(s) to {subjects_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

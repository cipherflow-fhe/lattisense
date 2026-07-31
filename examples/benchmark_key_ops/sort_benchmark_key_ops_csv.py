#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path


SCHEME_ORDER = {
    'CKKS': 0,
    'BFV': 1,
}

THREAD_LABEL_ORDER = {
    'CPU_单线程': 0,
    'cpu_1t': 0,
    'CPU_多线程': 1,
    'cpu_mt': 1,
    'GPU': 2,
    'gpu': 2,
}


FIELD_ALIASES = {
    'N': ('N', 'n'),
}


def get_field(row: dict[str, str], name: str) -> str:
    for candidate in FIELD_ALIASES.get(name, (name,)):
        if candidate in row:
            return row.get(candidate, '')
    return ''


def to_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def sort_key(row: dict[str, str]) -> tuple[int, str, int, int, int, str]:
    scheme = row.get('scheme', '')
    op = row.get('op', '')
    n = to_int(get_field(row, 'N'))
    level = to_int(row.get('level', ''))
    thread_label = row.get('thread_label', '')

    return (
        SCHEME_ORDER.get(scheme, 99),
        op,
        n,
        level,
        THREAD_LABEL_ORDER.get(thread_label, 99),
        thread_label,
    )


def sort_csv(input_path: Path, output_path: Path) -> None:
    with input_path.open('r', encoding='utf-8', newline='') as input_file:
        reader = csv.DictReader(input_file)
        fieldnames = reader.fieldnames
        if not fieldnames:
            raise ValueError(f'CSV has no header: {input_path}')
        rows = list(reader)

    rows.sort(key=sort_key)

    with output_path.open('w', encoding='utf-8', newline='') as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description='Sort benchmark_key_ops CSV rows by scheme/op/N/level/thread_label.')
    parser.add_argument(
        'input',
        nargs='?',
        default='benchmark_key_ops.csv',
        help='Input CSV path. Default: benchmark_key_ops.csv',
    )
    parser.add_argument(
        '-o',
        '--output',
        default='benchmark_key_ops.sorted.csv',
        help='Output CSV path. Default: benchmark_key_ops.sorted.csv',
    )
    parser.add_argument(
        '--in-place',
        action='store_true',
        help='Overwrite the input CSV after sorting.',
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = input_path if args.in_place else Path(args.output)

    sort_csv(input_path, output_path)
    print(f'Sorted CSV written to: {output_path}')


if __name__ == '__main__':
    main()

# Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys

CONFIGURED_LATTISENSE_ROOT = '@LATTISENSE_ROOT_DIR@'
LATTISENSE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INFERENCE_ROOT = os.path.dirname(LATTISENSE_ROOT)

if not CONFIGURED_LATTISENSE_ROOT.startswith('@'):
    sys.path.insert(0, CONFIGURED_LATTISENSE_ROOT)
    sys.path.insert(0, os.path.dirname(CONFIGURED_LATTISENSE_ROOT))
sys.path.insert(0, LATTISENSE_ROOT)
sys.path.insert(0, INFERENCE_ROOT)

from frontend.custom_task import *  # noqa: F403


DEFAULT_N_VALUES = [4096, 8192, 16384, 32768, 65536]
DEFAULT_OPS = 1024
DEFAULT_MAX_AUTO_LEVEL = 9


def _parse_n_values(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(',') if item.strip()]


def _parse_level_values(value: str, max_level: int, *, min_level: int = 0) -> list[int]:
    value = value.strip().lower()
    if value == 'all':
        return list(range(min_level, min(max_level, DEFAULT_MAX_AUTO_LEVEL) + 1))

    levels: list[int] = []
    for item in value.split(','):
        item = item.strip()
        if not item:
            continue
        if '-' in item:
            start_text, end_text = item.split('-', 1)
            start = int(start_text.strip())
            end = int(end_text.strip())
            if end < start:
                raise ValueError(f'Invalid level range "{item}".')
            levels.extend(range(start, end + 1))
        else:
            levels.append(int(item))

    result = sorted(set(level for level in levels if min_level <= level <= max_level))
    if not result:
        print(f'Skip levels="{value}": no valid levels in [{min_level}, {max_level}]')
    return result


def _task_path(name: str, n: int, level: int) -> str:
    return f'{name}_N{n}_L{level}'


def _make_bfv_param(n: int):
    try:
        return Param.create_bfv_default_param(n)  # noqa: F405
    except Exception as exc:
        print(f'Skip BFV N={n}: unsupported parameter ({exc})')
        return None


def _make_ckks_param(n: int):
    try:
        return Param.create_ckks_default_param(n)  # noqa: F405
    except Exception as exc:
        print(f'Skip CKKS N={n}: unsupported parameter ({exc})')
        return None


def generate_bfv_mult_relin(n: int, level: int, n_op: int) -> None:
    param = _make_bfv_param(n)
    if param is None:
        return
    set_fhe_param(param)  # noqa: F405

    xs = [BfvCiphertextNode(f'x_{i}', level) for i in range(n_op)]  # noqa: F405
    ys = [BfvCiphertextNode(f'y_{i}', level) for i in range(n_op)]  # noqa: F405
    zs = [mult_relin(xs[i], ys[i], f'z_{i}') for i in range(n_op)]  # noqa: F405

    process_custom_task(  # noqa: F405
        input_args=[Argument('xs', xs), Argument('ys', ys)],  # noqa: F405
        output_args=[Argument('zs', zs)],  # noqa: F405
        output_instruction_path=_task_path('bfv_mult_relin', n, level),
    )


def generate_bfv_rotate_col(n: int, level: int, n_op: int) -> None:
    param = _make_bfv_param(n)
    if param is None:
        return
    set_fhe_param(param)  # noqa: F405

    xs = [BfvCiphertextNode(f'x_{i}', level) for i in range(n_op)]  # noqa: F405
    ys = [rotate_cols(xs[i], 1, f'y_{i}')[0] for i in range(n_op)]  # noqa: F405

    process_custom_task(  # noqa: F405
        input_args=[Argument('xs', xs)],  # noqa: F405
        output_args=[Argument('ys', ys)],  # noqa: F405
        output_instruction_path=_task_path('bfv_rotate_col', n, level),
    )


def generate_bfv_rotate_rows(n: int, level: int, n_op: int) -> None:
    param = _make_bfv_param(n)
    if param is None:
        return
    set_fhe_param(param)  # noqa: F405

    xs = [BfvCiphertextNode(f'x_{i}', level) for i in range(n_op)]  # noqa: F405
    ys = [rotate_rows(xs[i], f'y_{i}') for i in range(n_op)]  # noqa: F405

    process_custom_task(  # noqa: F405
        input_args=[Argument('xs', xs)],  # noqa: F405
        output_args=[Argument('ys', ys)],  # noqa: F405
        output_instruction_path=_task_path('bfv_rotate_rows', n, level),
    )


def generate_ckks_mult_relin(n: int, level: int, n_op: int) -> None:
    param = _make_ckks_param(n)
    if param is None:
        return
    set_fhe_param(param)  # noqa: F405

    xs = [CkksCiphertextNode(f'x_{i}', level) for i in range(n_op)]  # noqa: F405
    ys = [CkksCiphertextNode(f'y_{i}', level) for i in range(n_op)]  # noqa: F405
    zs = [mult_relin(xs[i], ys[i], f'z_{i}') for i in range(n_op)]  # noqa: F405

    process_custom_task(  # noqa: F405
        input_args=[Argument('xs', xs), Argument('ys', ys)],  # noqa: F405
        output_args=[Argument('zs', zs)],  # noqa: F405
        output_instruction_path=_task_path('ckks_mult_relin', n, level),
    )


def generate_ckks_mult_relin_rescale(n: int, level: int, n_op: int) -> None:
    if level <= 0:
        return

    param = _make_ckks_param(n)
    if param is None:
        return
    set_fhe_param(param)  # noqa: F405

    xs = [CkksCiphertextNode(f'x_{i}', level) for i in range(n_op)]  # noqa: F405
    ys = [CkksCiphertextNode(f'y_{i}', level) for i in range(n_op)]  # noqa: F405
    zs = [rescale(mult_relin(xs[i], ys[i], f'z_{i}_before_rescale'), f'z_{i}') for i in range(n_op)]  # noqa: F405

    process_custom_task(  # noqa: F405
        input_args=[Argument('xs', xs), Argument('ys', ys)],  # noqa: F405
        output_args=[Argument('zs', zs)],  # noqa: F405
        output_instruction_path=_task_path('ckks_mult_relin_rescale', n, level),
    )


def generate_ckks_rotate_step1(n: int, level: int, n_op: int) -> None:
    param = _make_ckks_param(n)
    if param is None:
        return
    set_fhe_param(param)  # noqa: F405

    xs = [CkksCiphertextNode(f'x_{i}', level) for i in range(n_op)]  # noqa: F405
    ys = [rotate_cols(xs[i], 1, f'y_{i}')[0] for i in range(n_op)]  # noqa: F405

    process_custom_task(  # noqa: F405
        input_args=[Argument('xs', xs)],  # noqa: F405
        output_args=[Argument('ys', ys)],  # noqa: F405
        output_instruction_path=_task_path('ckks_rotate_step1', n, level),
    )


def _bfv_levels(n: int, levels: str) -> list[int]:
    param = _make_bfv_param(n)
    if param is None:
        return []
    return _parse_level_values(levels, param.max_level)


def _ckks_levels(n: int, levels: str, *, min_level: int = 0) -> list[int]:
    param = _make_ckks_param(n)
    if param is None:
        return []
    return _parse_level_values(levels, param.max_level, min_level=min_level)


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate BFV/CKKS key-operator benchmark task graphs.')
    parser.add_argument('--n', default=','.join(str(n) for n in DEFAULT_N_VALUES), help='Comma-separated N values.')
    parser.add_argument(
        '--levels',
        default='all',
        help='Levels to generate: all (auto-capped at level 9), comma list such as 0,1,2, or range such as 1-3.',
    )
    parser.add_argument('--ops', type=int, default=DEFAULT_OPS, help='Number of independent operators per task.')
    args = parser.parse_args()

    n_values = _parse_n_values(args.n)
    for n in n_values:
        for level in _bfv_levels(n, args.levels):
            generate_bfv_mult_relin(n, level, args.ops)
            generate_bfv_rotate_col(n, level, args.ops)
            generate_bfv_rotate_rows(n, level, args.ops)

        for level in _ckks_levels(n, args.levels):
            generate_ckks_mult_relin(n, level, args.ops)
            generate_ckks_rotate_step1(n, level, args.ops)

        for level in _ckks_levels(n, args.levels, min_level=1):
            generate_ckks_mult_relin_rescale(n, level, args.ops)


if __name__ == '__main__':
    main()

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

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from frontend.custom_task import *


def bfv_mult_relin():
    param = Param.create_bfv_default_param(n=16384)
    set_fhe_param(param)

    n_op = 1024
    level = 3
    xs = [BfvCiphertextNode(f'x_{i}', level) for i in range(n_op)]
    ys = [BfvCiphertextNode(f'y_{i}', level) for i in range(n_op)]
    zs = [mult_relin(xs[i], ys[i], f'z_{i}') for i in range(n_op)]

    process_custom_task(
        input_args=[Argument('xs', xs), Argument('ys', ys)],
        output_args=[Argument('zs', zs)],
        output_instruction_path='bfv_mult_relin',
    )


def ckks_mult_relin():
    param = Param.create_ckks_default_param(n=16384)
    set_fhe_param(param)

    n_op = 1024
    level = 3
    xs = [CkksCiphertextNode(f'x_{i}', level) for i in range(n_op)]
    ys = [CkksCiphertextNode(f'y_{i}', level) for i in range(n_op)]
    zs = [mult_relin(xs[i], ys[i], f'z_{i}') for i in range(n_op)]

    process_custom_task(
        input_args=[Argument('xs', xs), Argument('ys', ys)],
        output_args=[Argument('zs', zs)],
        output_instruction_path='ckks_mult_relin',
    )


def bfv_rotate_col():
    param = Param.create_bfv_default_param(n=16384)
    set_fhe_param(param)

    n_op = 1024
    level = 3
    xs = [BfvCiphertextNode(f'x_{i}', level) for i in range(n_op)]
    ys = [rotate_cols(xs[i], 1, f'y_{i}') for i in range(n_op)]

    process_custom_task(
        input_args=[Argument('xs', xs)],
        output_args=[Argument('ys', ys)],
        output_instruction_path='bfv_rotate_col',
    )


if __name__ == '__main__':
    bfv_mult_relin()
    ckks_mult_relin()
    bfv_rotate_col()

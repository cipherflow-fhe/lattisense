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


def ckks_euclidean_distance(
    x_input: list[CkksCiphertextNode] = None,
    w_input: list[CkksCiphertextNode] = None,
    pack: int = 4,
    skip: int = 256,
):
    n_ct = len(x_input)
    assert len(x_input) == len(w_input)
    mask = CkksPlaintextRingtNode(id=f'mask')

    sum_ct_list = []
    for i in range(n_ct):
        z = add(x_input[i], w_input[i], f'z_{i}')
        u = rescale(mult_relin(z, z), f'u_{i}')
        # rotate
        u_rot_list = [u]
        step = skip
        for j in range(pack - 1):
            u_rot_list.append(rotate_cols(u, step, f'u_rot_{i}_{j}')[0])
            step += skip
        # sum
        sum_ct = u_rot_list[0]
        for k in range(1, len(u_rot_list)):
            sum_ct = add(sum_ct, u_rot_list[k], f'sum_{i}_{k}')
        sum_ct_list.append(sum_ct)

    sum = sum_ct_list[0]
    for i in range(1, n_ct):
        sum = add(sum, sum_ct_list[i], f'sum_{i}')
    # mask
    distance = rescale(mult(sum, mask, f'distance'))

    # compile FHE task
    process_custom_task(
        input_args=[
            Argument('x_input', x_input),
            Argument('w_input_inv', w_input),
            Argument('mask', mask),
        ],
        output_args=[Argument('d', distance)],
        output_instruction_path='project',
    )


if __name__ == '__main__':
    # set global FHE param at the very beginning of the application
    param = Param.create_ckks_default_param(n=16384)
    set_fhe_param(param)

    # describe FHE task MegaAG
    level = 3
    n_ct = 1
    pack = 4
    skip = 256
    x_input = []
    w_input = []
    for i in range(n_ct):
        x_input.append(CkksCiphertextNode(f'x_{i}', level=level))
        w_input.append(CkksCiphertextNode(f'w_{i}', level=level))
    ckks_euclidean_distance(x_input, w_input, pack, skip)

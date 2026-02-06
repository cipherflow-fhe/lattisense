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


def bfv_poly_7():
    # set global FHE param at the very beginning of the application
    param = Param.create_bfv_default_param(n=16384)
    set_fhe_param(param)

    # describe FHE task MegaAG
    x = BfvCiphertextNode('x', 4)
    a0 = BfvPlaintextNode('a_0', 1)
    a = [BfvPlaintextMulNode(f'a_{i}', 1) for i in range(1, 8)]

    x1_lv4 = x
    x2_lv3 = rescale(mult_relin(x1_lv4, x1_lv4))
    x1_lv3 = rescale(x1_lv4)
    x3_lv2 = rescale(mult_relin(x1_lv3, x2_lv3))
    x4_lv2 = rescale(mult_relin(x2_lv3, x2_lv3))
    x2_lv2 = rescale(x2_lv3)
    x5_lv1 = rescale(mult_relin(x2_lv2, x3_lv2))
    x6_lv1 = rescale(mult_relin(x3_lv2, x3_lv2))
    x7_lv1 = rescale(mult_relin(x3_lv2, x4_lv2))
    x2_lv1 = rescale(x2_lv2)
    x3_lv1 = rescale(x3_lv2)
    x4_lv1 = rescale(x4_lv2)
    x1_lv2 = rescale(x1_lv3)
    x1_lv1 = rescale(x1_lv2)
    x_powers = [x1_lv1, x2_lv1, x3_lv1, x4_lv1, x5_lv1, x6_lv1, x7_lv1]
    y = a0
    for i in range(7):
        y = add(y, mult(x_powers[i], a[i]))

    # compile FHE task
    process_custom_task(
        input_args=[Argument('x', x), Argument('a0', a0), Argument('a', a)],
        output_args=[Argument('y', y)],
        output_instruction_path='project',
    )


if __name__ == '__main__':
    bfv_poly_7()

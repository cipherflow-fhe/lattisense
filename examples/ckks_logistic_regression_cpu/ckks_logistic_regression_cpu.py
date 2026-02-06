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

import math
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from frontend.custom_task import *


def ckks_logistic_regression():
    # set global FHE param at the very beginning of the application
    param = Param.create_ckks_default_param(n=16384)
    set_fhe_param(param)

    # describe FHE task MegaAG
    level = 3
    n_input_feature = 30
    x = CkksCiphertextNode(level=level)
    w = CkksPlaintextRingtNode()
    b = CkksPlaintextNode(level=level - 1)
    mask = CkksPlaintextRingtNode()

    u = rescale(mult(x, w))
    n_rotate = math.ceil(math.log(n_input_feature, 2))
    step = int(math.pow(2, n_rotate) / 2)
    for _ in range(n_rotate):
        u_rot = rotate_cols(u, step)
        u = add(u, u_rot[0])
        step = step // 2
    s = add(u, b)
    y = rescale(mult(s, mask))

    # compile FHE task
    process_custom_task(
        input_args=[
            Argument('x', x),
            Argument('w', w),
            Argument('b', b),
            Argument('mask', mask),
        ],
        output_args=[Argument('y', y)],
        output_instruction_path='project',
    )


if __name__ == '__main__':
    ckks_logistic_regression()

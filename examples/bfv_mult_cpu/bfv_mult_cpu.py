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

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from frontend.custom_task import *


def bfv_mult():
    # set global FHE param at the very beginning of the application
    param = Param.create_bfv_default_param(n=16384)
    set_fhe_param(param)

    # describe FHE task MegaAG
    level = 3
    x = BfvCiphertextNode('x', level)
    y = BfvCiphertextNode('y', level)
    z = mult_relin(x, y, 'z')

    # compile FPGA FHE task
    process_custom_task(
        input_args=[Argument('x', x), Argument('y', y)],
        output_args=[Argument('z', z)],
        output_instruction_path='bfv_mult_cpu',
    )


if __name__ == '__main__':
    bfv_mult()

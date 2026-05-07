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


def ckks_sparse_bootstrap():
    # Sparse bootstrap keeps only 2^log_slots active slots, shrinking the
    # CtS/StC matrices and cutting wall time vs full packing.
    param = CkksBtpParam.create_toy_sparse_param(log_slots=8)
    set_fhe_param(param)

    x = CkksCiphertextNode('x', level=0)
    y = bootstrap(x, 'y')

    process_custom_task(
        input_args=[Argument('x', x)],
        output_args=[Argument('y', y)],
        output_instruction_path='project',
        fpga_acc=False,
    )


if __name__ == '__main__':
    ckks_sparse_bootstrap()

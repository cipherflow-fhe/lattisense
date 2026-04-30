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


def ckks_sparse_bootstrap(is_toy=False, sparse_slots=[2, 8, 6, 10]):
    # set global FHE param at the very beginning of the application
    if is_toy:
        param = CkksBtpParam.create_toy_param()
    else:
        param = CkksBtpParam.create_default_param()
    set_fhe_param(param)

    # describe FHE task MegaAG
    level = 0
    x_list = []
    y_list = []
    for i in range(len(sparse_slots)):
        x_list.append(CkksCiphertextNode(f'x_{i}', level))
        y_list.append(bootstrap(x_list[i], log_slots=sparse_slots[i], output_id=f'y_{i}'))
    
    arg_x = Argument('in_x_list', x_list)
    arg_y = Argument('out_y_list', y_list)

    # compile FHE task
    process_custom_task(
        input_args=[arg_x],
        output_args=[arg_y],
        output_instruction_path=f'project_{"toy" if is_toy else "default"}_sparse_bootstrap/slots_{sparse_slots}',
    )


if __name__ == '__main__':
    ckks_sparse_bootstrap()

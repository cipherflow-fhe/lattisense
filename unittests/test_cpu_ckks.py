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

import sys
import os

# Add project root to path for frontend imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Add current directory to path for test_config imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

import unittest

from frontend.custom_task import *

# Try to import from generated test_config, fallback to default paths
try:
    from test_config import CPU_OUTPUT_BASE_DIR
except ImportError:
    CPU_OUTPUT_BASE_DIR = os.path.join(current_dir, 'test_data', 'cpu')

param = Param.create_ckks_default_param(n=16384)


class TestTask(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        set_fhe_param(param)

    def test_cap(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cap(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(add(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cap/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksPlaintextNode(f'y_{i}', level=lv))

                z_list = cap(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cap_ringt(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cap(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(add(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cap_ringt/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksPlaintextRingtNode(f'y_{i}'))

                z_list = cap(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cac(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cac(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(add(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cac/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksCiphertextNode(f'y_{i}', level=lv))

                z_list = cac(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_casc(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cac(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(add(x[i], x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_casc/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                z_list = cac(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_csp(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def csp(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(sub(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_csp/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksPlaintextNode(f'y_{i}', level=lv))

                z_list = csp(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_csp_ringt(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def csp(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(sub(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_csp_ringt/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksPlaintextRingtNode(f'y_{i}'))

                z_list = csp(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_csc(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def csc(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(sub(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_csc/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksCiphertextNode(f'y_{i}', level=lv))

                z_list = csc(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cneg(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cneg(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(neg(x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cneg/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                z_list = cneg(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cmp_ringt(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode], lv) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(mult(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cmp_ringt/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksPlaintextRingtNode(f'y_{i}'))

                z_list = cmp(x_list, y_list, lv)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cmp(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode], lv) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(mult(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cmp/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksPlaintextNode(f'y_{i}', level=lv))

                z_list = cmp(x_list, y_list, lv)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cmp_mul(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode], lv) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(mult(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cmp_mul/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksPlaintextMulNode(f'y_{i}', level=lv))

                z_list = cmp(x_list, y_list, lv)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_ct_pt_mac(self, levels=[i for i in range(1, param.max_level + 1)]):
        for lv in levels:
            for m in range(2, 21):
                with self.subTest(m=m, lv=lv):
                    task = f'CKKS_cmpac/level_{lv}_m_{m}'
                    task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                    c_list = []
                    p_list = []
                    for i in range(m):
                        c_list.append(CkksCiphertextNode(f'c_{i}', level=lv))
                        p_list.append(CkksPlaintextNode(f'p_{i}', level=lv))

                    z = ct_pt_mult_accumulate(c_list, p_list)

                    arg_c = Argument('in_c_list', c_list)
                    arg_p = Argument('in_p_list', p_list)
                    arg_z = Argument('out_z_list', [z])

                    process_custom_task(
                        input_args=[arg_c, arg_p],
                        offline_input_args=[],
                        output_args=[arg_z],
                        output_instruction_path=task_dir,
                    )

    def test_ct_pt_ringt_mac(self, levels=[i for i in range(1, param.max_level + 1)]):
        for lv in levels:
            for m in range(2, 21):
                with self.subTest(m=m, lv=lv):
                    task = f'CKKS_cmpac_ringt/level_{lv}_m_{m}'
                    task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                    c_list = []
                    p_list = []
                    for i in range(m):
                        c_list.append(CkksCiphertextNode(f'c_{i}', level=lv))
                        p_list.append(CkksPlaintextRingtNode(f'p_{i}'))

                    z = ct_pt_mult_accumulate(c_list, p_list)

                    arg_c = Argument('in_c_list', c_list)
                    arg_p = Argument('in_p_list', p_list)
                    arg_z = Argument('out_z_list', [z])

                    process_custom_task(
                        input_args=[arg_c, arg_p],
                        offline_input_args=[],
                        output_args=[arg_z],
                        output_instruction_path=task_dir,
                    )

    def test_cmc(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmc(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(mult(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cmc/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksCiphertextNode(f'y_{i}', level=lv))

                z_list = cmc(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cmc_relin(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmc_relin(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(mult_relin(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cmc_relin/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksCiphertextNode(f'y_{i}', level=lv))

                z_list = cmc_relin(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cmc_relin_rescale(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmc_relin_rescale(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(rescale(mult_relin(x[i], y[i]), f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cmc_relin_rescale/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksCiphertextNode(f'y_{i}', level=lv))

                z_list = cmc_relin_rescale(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_csqr(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def square(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(mult(x[i], x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_csqr/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                z_list = square(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_csqr_relin(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def square_relin(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(mult_relin(x[i], x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_csqr_relin/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                z_list = square_relin(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_csqr_relin_rescale(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def square_relin_rescale(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(rescale(mult_relin(x[i], x[i]), f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_csqr_relin_rescale/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                z_list = square_relin_rescale(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_rescale(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def rescale_l(x: list[DataNode]) -> DataNode:
            res_list = []
            for i in range(len(x_list)):
                res_list.append(rescale(x[i], f'y_{i}'))
            return res_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_rescale/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                y_list = rescale_l(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('out_y_list', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                )

    def test_drop_level(self, n_op=4, levels=[i for i in range(3, param.max_level + 1)], drop_lv=2):
        def drop_level_l(x: list[DataNode]) -> DataNode:
            res_list = []
            for i in range(len(x)):
                res_list.append(drop_level(x[i], drop_lv, f'y_{i}'))
            return res_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_drop_level/level_{lv}/drop_{drop_lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                y_list = drop_level_l(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('out_y_list', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                )

    def test_rotate_col(
        self, n_op=4, levels=[i for i in range(1, param.max_level + 1)], steps=[i + 1 for i in range(8)]
    ):
        random.seed(1)

        def rotate_steps(x: list[DataNode]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(rotate_cols(x[i], steps, f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_rotate_col/level_{lv}/steps_{steps[0]}_to_{steps[-1]}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                y_list = rotate_steps(x_list)

                arg_x = Argument('arg_x', x_list)
                arg_y = Argument('arg_y', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                )

    def test_advanced_rotate_col(
        self, n_op=4, levels=[i for i in range(1, param.max_level + 1)], steps=[-500, 20, 200, 2000, 4000]
    ):
        def rotate_steps(x: list[DataNode]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(advanced_rotate_cols(x[i], steps, f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                steps_str = '_'.join(map(str, steps))
                task = f'CKKS_{n_op}_advanced_rotate_col/level_{lv}/steps_{steps_str}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                y_list = rotate_steps(x_list)

                arg_x = Argument('arg_x', x_list)
                arg_y = Argument('arg_y', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                )

    def test_rotate_row(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def rotate(x: list[DataNode]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(rotate_rows(x[i], f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_rotate_row/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                y_list = rotate(x_list)

                arg_x = Argument('arg_x', x_list)
                arg_y = Argument('arg_y', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                )

    def test_toy_bootstrap(self, n_op=4, levels=[0]):
        param = CkksBtpParam.create_toy_param()
        set_fhe_param(param)

        def bootstrapping(x: list[DataNode]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(bootstrap(x[i], f'y_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_toy_bootstrap/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                y_list = bootstrapping(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('out_y_list', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                )
        default_param = Param.create_ckks_default_param(n=16384)
        set_fhe_param(default_param)

    def test_bootstrap(self, n_op=4, levels=[0]):
        param = CkksBtpParam.create_default_param()
        set_fhe_param(param)

        def bootstrapping(x: list[DataNode]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(bootstrap(x[i], f'y_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_bootstrap/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))

                y_list = bootstrapping(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('out_y_list', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                )
        default_param = Param.create_ckks_default_param(n=16384)
        set_fhe_param(default_param)

    def test_cmc_relin_rescale_bootstrap(self, n_op=4, levels=[3]):
        param = CkksBtpParam.create_default_param()
        set_fhe_param(param)

        def cmc_relin_rescale_bootstrap(x: DataNode, y: DataNode, idx: int) -> DataNode:
            z = mult_relin(x, y, f'z_{idx}')
            z_rescaled = rescale(z, f'z_rescaled_{idx}')
            z_dropped = drop_level(z_rescaled, drop_level=2)
            result = bootstrap(z_dropped, f'result_{idx}')
            return result

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_{n_op}_cmc_relin_rescale_bootstrap/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksCiphertextNode(f'y_{i}', level=lv))

                result_list = []
                for i in range(n_op):
                    result_list.append(cmc_relin_rescale_bootstrap(x_list[i], y_list[i], i))

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_result = Argument('out_z_list', result_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_result],
                    output_instruction_path=task_dir,
                )
        default_param = Param.create_ckks_default_param(n=16384)
        set_fhe_param(default_param)

    def test_cap_2d(self, row=1, col=1, levels=[i for i in range(0, param.max_level + 1)]):
        def cap_2d(x_ct_2d: list[list[CkksCiphertextNode]], y_pt_2d: list[list[CkksPlaintextNode]]) -> DataNode:
            z_ct_2d = []
            for x_ct_1d, y_pt_1d in zip(x_ct_2d, y_pt_2d):
                z_ct_1d = []
                for x_ct, y_pt in zip(x_ct_1d, y_pt_1d):
                    z_ct_1d.append(add(x_ct, y_pt))
                z_ct_2d.append(z_ct_1d)
            return z_ct_2d

        for lv in levels:
            with self.subTest(row=3, col=3, lv=lv):
                task = f'CKKS_cap_row_{row}_col_{col}/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_ct_2d = []
                y_pt_2d = []
                for _ in range(row):
                    x_ct_1d = []
                    y_pt_1d = []
                    for _ in range(col):
                        x_ct_1d.append(CkksCiphertextNode(level=lv))
                        y_pt_1d.append(CkksPlaintextNode(level=lv))
                    x_ct_2d.append(x_ct_1d)
                    y_pt_2d.append(y_pt_1d)

                z_ct_2d = cap_2d(x_ct_2d, y_pt_2d)

                arg_x = Argument('x_ct_2d', x_ct_2d)
                arg_y = Argument('y_pt_2d', y_pt_2d)
                arg_z = Argument('z_ct_2d', z_ct_2d)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cap_3d(self, dim0=1, dim1=1, dim2=1, levels=[3, 4, 5]):
        def cap_3d(x_ct_3d: list, y_pt_3d: list) -> DataNode:
            z_ct_3d = []
            for x_ct_2d, y_ct_2d in zip(x_ct_3d, y_pt_3d):
                z_ct_2d = []
                for x_ct_1d, y_ct_1d in zip(x_ct_2d, y_ct_2d):
                    z_ct_1d = []
                    for x_ct, y_ct in zip(x_ct_1d, y_ct_1d):
                        z_ct_1d.append(add(x_ct, y_ct))
                    z_ct_2d.append(z_ct_1d)
                z_ct_3d.append(z_ct_2d)
            return z_ct_3d

        for lv in levels:
            with self.subTest(dim0=dim0, dim1=dim1, dim2=dim2, lv=lv):
                task = f'CKKS_cap_3d/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_ct_3d = []
                y_pt_3d = []
                for _ in range(dim0):
                    x_ct_2d = []
                    y_pt_2d = []
                    for _ in range(dim1):
                        x_ct_1d = []
                        y_pt_1d = []
                        for _ in range(dim2):
                            x_ct_1d.append(CkksCiphertextNode(level=lv))
                            y_pt_1d.append(CkksPlaintextNode(level=lv))
                        x_ct_2d.append(x_ct_1d)
                        y_pt_2d.append(y_pt_1d)
                    x_ct_3d.append(x_ct_2d)
                    y_pt_3d.append(y_pt_2d)

                z_ct_3d = cap_3d(x_ct_3d, y_pt_3d)

                arg_x = Argument('x_ct_3d', x_ct_3d)
                arg_y = Argument('y_pt_3d', y_pt_3d)
                arg_z = Argument('z_ct_3d', z_ct_3d)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cmc_relin_4d(self, dim0=1, dim1=1, dim2=1, dim3=1, levels=[3, 4, 5]):
        def cmc_relin_4d(x_ct_4d: list, y_ct_4d: list) -> DataNode:
            z_ct_4d = []
            for x_ct_3d, y_ct_3d in zip(x_ct_4d, y_ct_4d):
                z_ct_3d = []
                for x_ct_2d, y_ct_2d in zip(x_ct_3d, y_ct_3d):
                    z_ct_2d = []
                    for x_ct_1d, y_ct_1d in zip(x_ct_2d, y_ct_2d):
                        z_ct_1d = []
                        for x_ct, y_ct in zip(x_ct_1d, y_ct_1d):
                            z_ct_1d.append(mult_relin(x_ct, y_ct))
                        z_ct_2d.append(z_ct_1d)
                    z_ct_3d.append(z_ct_2d)
                z_ct_4d.append(z_ct_3d)
            return z_ct_4d

        for lv in levels:
            with self.subTest(dim0=dim0, dim1=dim1, dim2=dim2, dim3=dim3, lv=lv):
                task = f'CKKS_cmc_relin_4d/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_ct_4d = []
                y_ct_4d = []
                for _ in range(dim0):
                    x_ct_3d = []
                    y_ct_3d = []
                    for _ in range(dim1):
                        x_ct_2d = []
                        y_ct_2d = []
                        for _ in range(dim2):
                            x_ct_1d = []
                            y_ct_1d = []
                            for _ in range(dim3):
                                x_ct_1d.append(CkksCiphertextNode(level=lv))
                                y_ct_1d.append(CkksCiphertextNode(level=lv))
                            x_ct_2d.append(x_ct_1d)
                            y_ct_2d.append(y_ct_1d)
                        x_ct_3d.append(x_ct_2d)
                        y_ct_3d.append(y_ct_2d)
                    x_ct_4d.append(x_ct_3d)
                    y_ct_4d.append(y_ct_3d)
                z_ct_4d = cmc_relin_4d(x_ct_4d, y_ct_4d)

                arg_x = Argument('x_ct_4d', x_ct_4d)
                arg_y = Argument('y_ct_4d', y_ct_4d)
                arg_z = Argument('z_ct_4d', z_ct_4d)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cmp_3d(self, dim0=1, dim1=1, dim2=1, levels=[3, 4, 5]):
        def cmp_3d(x_ct_3d: list, y_pt_3d: list) -> DataNode:
            z_ct_3d = []
            for x_ct_2d, y_ct_2d in zip(x_ct_3d, y_pt_3d):
                z_ct_2d = []
                for x_ct_1d, y_ct_1d in zip(x_ct_2d, y_ct_2d):
                    z_ct_1d = []
                    for x_ct, y_ct in zip(x_ct_1d, y_ct_1d):
                        z_ct_1d.append(mult(x_ct, y_ct))
                    z_ct_2d.append(z_ct_1d)
                z_ct_3d.append(z_ct_2d)
            return z_ct_3d

        for lv in levels:
            with self.subTest(dim0=dim0, dim1=dim1, dim2=dim2, lv=lv):
                task = f'CKKS_cmp_3d/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_ct_3d = []
                y_pt_3d = []
                for _ in range(dim0):
                    x_ct_2d = []
                    y_pt_2d = []
                    for _ in range(dim1):
                        x_ct_1d = []
                        y_pt_1d = []
                        for _ in range(dim2):
                            x_ct_1d.append(CkksCiphertextNode(level=lv))
                            y_pt_1d.append(CkksPlaintextNode(level=lv))
                        x_ct_2d.append(x_ct_1d)
                        y_pt_2d.append(y_pt_1d)
                    x_ct_3d.append(x_ct_2d)
                    y_pt_3d.append(y_pt_2d)

                z_ct_3d = cmp_3d(x_ct_3d, y_pt_3d)

                arg_x = Argument('x_ct_3d', x_ct_3d)
                arg_y = Argument('y_pt_3d', y_pt_3d)
                arg_z = Argument('z_ct_3d', z_ct_3d)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_cmp_4d(self, dim0=1, dim1=1, dim2=1, dim3=1, levels=[3, 4, 5]):
        def cmp_4d(x_ct_4d: list, y_ct_4d: list) -> DataNode:
            z_ct_4d = []
            for x_ct_3d, y_ct_3d in zip(x_ct_4d, y_ct_4d):
                z_ct_3d = []
                for x_ct_2d, y_ct_2d in zip(x_ct_3d, y_ct_3d):
                    z_ct_2d = []
                    for x_ct_1d, y_ct_1d in zip(x_ct_2d, y_ct_2d):
                        z_ct_1d = []
                        for x_ct, y_ct in zip(x_ct_1d, y_ct_1d):
                            z_ct_1d.append(mult(x_ct, y_ct))
                        z_ct_2d.append(z_ct_1d)
                    z_ct_3d.append(z_ct_2d)
                z_ct_4d.append(z_ct_3d)
            return z_ct_4d

        for lv in levels:
            with self.subTest(dim0=dim0, dim1=dim1, dim2=dim2, dim3=dim3, lv=lv):
                task = f'CKKS_cmp_4d/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_ct_4d = []
                y_pt_4d = []
                for _ in range(dim0):
                    x_ct_3d = []
                    y_ct_3d = []
                    for _ in range(dim1):
                        x_ct_2d = []
                        y_ct_2d = []
                        for _ in range(dim2):
                            x_ct_1d = []
                            y_ct_1d = []
                            for _ in range(dim3):
                                x_ct_1d.append(CkksCiphertextNode(level=lv))
                                y_ct_1d.append(CkksPlaintextNode(level=lv))
                            x_ct_2d.append(x_ct_1d)
                            y_ct_2d.append(y_ct_1d)
                        x_ct_3d.append(x_ct_2d)
                        y_ct_3d.append(y_ct_2d)
                    x_ct_4d.append(x_ct_3d)
                    y_pt_4d.append(y_ct_3d)
                z_ct_4d = cmp_4d(x_ct_4d, y_pt_4d)

                arg_x = Argument('x_ct_4d', x_ct_4d)
                arg_y = Argument('y_pt_4d', y_pt_4d)
                arg_z = Argument('z_ct_4d', z_ct_4d)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

    def test_custom_param_cmc_relin_rescale(self, n_op=4, levels=[1, 2, 3, 4, 5]):
        """测试使用自定义参数"""
        custom_param = Param.create_ckks_custom_param(
            n=8192, q=[0x1FFFEC001, 0x3FFF4001, 0x3FFE8001, 0x40020001, 0x40038001, 0x3FFC0001], p=[0x800004001]
        )

        assert custom_param.algo.value == 'CKKS'
        assert custom_param.n == 8192
        assert custom_param.max_level == 5
        assert len(custom_param.p) == 1
        assert len(custom_param.q) == 6

        set_fhe_param(custom_param)

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_custom_param_{n_op}_cmc_relin_rescale/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksCiphertextNode(f'y_{i}', level=lv))

                z_list = []
                for i in range(n_op):
                    z_list.append(rescale(mult_relin(x_list[i], y_list[i]), f'z_rescale_{i}'))

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z_rescale = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z_rescale],
                    output_instruction_path=task_dir,
                )

        # 重置为默认参数，避免影响其他测试
        default_param = Param.create_ckks_default_param(n=16384)
        set_fhe_param(default_param)

    def test_custom_param_cap(self, n_op=4, levels=[0, 1, 2, 3, 4, 5]):
        """测试使用自定义参数"""
        custom_param = Param.create_ckks_custom_param(
            n=8192, q=[0x1FFFEC001, 0x3FFF4001, 0x3FFE8001, 0x40020001, 0x40038001, 0x3FFC0001], p=[0x800004001]
        )

        assert custom_param.algo.value == 'CKKS'
        assert custom_param.n == 8192
        assert custom_param.max_level == 5
        assert len(custom_param.p) == 1
        assert len(custom_param.q) == 6

        set_fhe_param(custom_param)

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_custom_param_{n_op}_cap/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksPlaintextNode(f'y_{i}', level=lv))

                z_list = []
                for i in range(n_op):
                    z_list.append(add(x_list[i], y_list[i], f'z_{i}'))

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z_rescale = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z_rescale],
                    output_instruction_path=task_dir,
                )

        # 重置为默认参数，避免影响其他测试
        default_param = Param.create_ckks_default_param(n=16384)
        set_fhe_param(default_param)

    def test_custom_param_cac(self, n_op=4, levels=[0, 1, 2, 3, 4, 5]):
        """测试使用自定义参数"""
        custom_param = Param.create_ckks_custom_param(
            n=8192, q=[0x1FFFEC001, 0x3FFF4001, 0x3FFE8001, 0x40020001, 0x40038001, 0x3FFC0001], p=[0x800004001]
        )

        assert custom_param.algo.value == 'CKKS'
        assert custom_param.n == 8192
        assert custom_param.max_level == 5
        assert len(custom_param.p) == 1
        assert len(custom_param.q) == 6

        set_fhe_param(custom_param)

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_custom_param_{n_op}_cac/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksCiphertextNode(f'y_{i}', level=lv))

                z_list = []
                for i in range(n_op):
                    z_list.append(add(x_list[i], y_list[i], f'z_{i}'))

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z_rescale = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z_rescale],
                    output_instruction_path=task_dir,
                )

        # 重置为默认参数，避免影响其他测试
        default_param = Param.create_ckks_default_param(n=16384)
        set_fhe_param(default_param)


if __name__ == '__main__':
    unittest.main()

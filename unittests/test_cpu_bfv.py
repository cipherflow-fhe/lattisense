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

param = Param.create_bfv_default_param(n=16384)


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
                task = f'BFV_{n_op}_cap/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvPlaintextNode(f'y_{i}', level=lv))

                z_list = cap(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cap_ringt(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cap(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(add(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cap_ringt/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvPlaintextRingtNode(f'y_{i}'))

                z_list = cap(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cac(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cac(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(add(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cac/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

                z_list = cac(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_casc(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def casc(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(add(x[i], x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_casc/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                z_list = casc(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_csp(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def csp(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(sub(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_csp/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvPlaintextNode(f'y_{i}', level=lv))

                z_list = csp(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_csp_ringt(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def csp(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(sub(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_csp_ringt/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvPlaintextRingtNode(f'y_{i}'))

                z_list = csp(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_csc(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def csc(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(sub(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_csc/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

                z_list = csc(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cssc(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cssc(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(sub(x[i], x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cssc/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                z_list = cssc(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cneg(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cneg(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(neg(x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cneg/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                z_list = cneg(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cmp_ringt(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode], lv) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(mult(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmp_ringt/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvPlaintextRingtNode(f'y_{i}'))

                z_list = cmp(x_list, y_list, lv)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cmp(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode], lv) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(mult(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmp/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvPlaintextNode(f'y_{i}', level=lv))

                z_list = cmp(x_list, y_list, lv)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cmp_mul(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(mult(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmp_mul/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvPlaintextMulNode(f'y_{i}', level=lv))

                z_list = cmp(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cmc(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmc(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(mult(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmc/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

                z_list = cmc(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cmc_relin(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmc_relin(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(mult_relin(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmc_relin/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

                z_list = cmc_relin(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_cmc_relin_rescale(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmc_relin_rescale(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(rescale(mult_relin(x[i], y[i]), f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmc_relin_rescale/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

                z_list = cmc_relin_rescale(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_csqr(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def square(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(mult(x[i], x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_csqr/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                z_list = square(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_csqr_relin(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def square_relin(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(mult_relin(x[i], x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_csqr_relin/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                z_list = square_relin(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_csqr_relin_rescale(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def square_relin_rescale(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(rescale(mult_relin(x[i], x[i]), f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_csqr_relin_rescale/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                z_list = square_relin_rescale(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_rotate_col(
        self, n_op=4, levels=[i for i in range(1, param.max_level + 1)], steps=[i + 1 for i in range(8)]
    ):
        def rotate_steps(x: list[DataNode], steps: list[int]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(rotate_cols(x[i], steps, f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv, steps=steps):
                task = f'BFV_{n_op}_rotate_col/level_{lv}/steps_{steps[0]}_to_{steps[-1]}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                y_list = rotate_steps(x_list, steps)

                arg_x = Argument('arg_x', x_list)
                arg_y = Argument('arg_y', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_advanced_rotate_col(
        self, n_op=4, levels=[i for i in range(1, param.max_level + 1)], steps=[-900, 20, 400, 2000, 3009]
    ):
        def rotate_steps(x: list[DataNode], steps: list[int]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(advanced_rotate_cols(x[i], steps, f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv, steps=steps):
                steps_str = '_'.join(map(str, steps))
                task = f'BFV_{n_op}_advanced_rotate_col/level_{lv}/steps_{steps_str}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                y_list = rotate_steps(x_list, steps)

                arg_x = Argument('arg_x', x_list)
                arg_y = Argument('arg_y', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_rotate_row(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def rotate(x: list[DataNode]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(rotate_rows(x[i], f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_rotate_row/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                y_list = rotate(x_list)

                arg_x = Argument('arg_x', x_list)
                arg_y = Argument('arg_y', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_rescale(self, n_op=4, levels=[i for i in range(2, param.max_level + 1)]):
        def rescale_l(x: list[DataNode]) -> DataNode:
            res_list = []
            for i in range(len(x_list)):
                res_list.append(rescale(x[i], f'y_{i}'))
            return res_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_rescale/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                y_list = rescale_l(x_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('out_y_list', y_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_y],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_ctc_ctc_0(self, levels=[3]):
        def cmc_multi_block(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            tmp_0 = mult_relin(x[0], y[0], 'tmp_0')
            z_0 = mult_relin(tmp_0, x[1], 'z_0')
            z_1 = mult_relin(x[1], y[1], 'z_1')
            z_2 = mult_relin(x[2], y[2], 'z_2')
            z_3 = mult_relin(x[3], y[3], 'z_3')
            z_list = [tmp_0, z_0, z_1, z_2, z_3]
            return z_list

        for lv in levels:
            task = f'BFV_ctc_ctc_0/level_{lv}'
            task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

            x_list = []
            y_list = []
            for i in range(4):
                x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

            z_list = cmc_multi_block(x_list, y_list)

            arg_x = Argument('in_x_list', x_list)
            arg_y = Argument('in_y_list', y_list)
            arg_z = Argument('out_z_list', z_list)

            process_custom_task(
                input_args=[arg_x, arg_y],
                offline_input_args=[],
                output_args=[arg_z],
                output_instruction_path=task_dir,
                fpga_acc=False,
            )

    def test_ctc_ctc_1(self, levels=[3]):
        def multi_block(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []

            t_0 = mult_relin(x[0], y[0], 't_0')
            t_1 = mult_relin(x[1], y[1], 't_1')
            t_2 = mult_relin(x[2], y[2], 't_2')
            t_3 = mult_relin(x[3], y[3], 't_3')

            z_0 = mult_relin(t_0, t_1, 'z_0')
            z_1 = mult_relin(t_1, x[2], 'z_1')
            z_2 = mult_relin(t_2, x[3], 'z_2')
            z_3 = mult_relin(t_2, t_3, 'z_3')

            z_list = [z_0, z_1, z_2, z_3]
            return z_list

        for lv in levels:
            task = f'BFV_ctc_ctc_1/level_{lv}'
            task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

            x_list = []
            y_list = []

            for i in range(4):
                x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

            z_list = multi_block(x_list, y_list)

            arg_x = Argument('in_x_list', x_list)
            arg_y = Argument('in_y_list', y_list)
            arg_z = Argument('out_z_list', z_list)

            process_custom_task(
                input_args=[arg_x, arg_y],
                offline_input_args=[],
                output_args=[arg_z],
                output_instruction_path=task_dir,
                fpga_acc=False,
            )

    def test_1_square_square(self, levels=[3]):
        def square_square(x: list[DataNode]) -> DataNode:
            t_list = []
            z_list = []
            for i in range(len(x_list)):
                t_list.append(mult_relin(x[i], x[i], f'x^2_{i}'))
                z_list.append(mult_relin(t_list[i], t_list[i], f'x^4_{i}'))
            return z_list

        for lv in levels:
            task = f'BFV_1_square_square/level_{lv}'
            task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

            x_list = []
            for i in range(1):
                x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

            z_list = square_square(x_list)

            arg_x = Argument('in_x_list', x_list)
            arg_z = Argument('out_z_list', z_list)

            process_custom_task(
                input_args=[arg_x],
                offline_input_args=[],
                output_args=[arg_z],
                output_instruction_path=task_dir,
                fpga_acc=False,
            )

    def test_ctc_rotate_cac(self, levels=[3]):
        def ctc_rotate_cac(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                xy = mult_relin(x[i], y[i], f'xy_{i}')
                xyr = advanced_rotate_cols(xy, 1, f'rotated_xy_{i}')
                xyaxyr = add(xy, xyr[0], f'xyaxyr_{i}')
                z_list.append(xyaxyr)
            return z_list

        for lv in levels:
            task = f'BFV_1_ctc_rotate_cac/level_{lv}'
            task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

            x_list = []
            y_list = []
            for i in range(1):
                x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

            z_list = ctc_rotate_cac(x_list, y_list)

            arg_x = Argument('in_x_list', x_list)
            arg_y = Argument('in_y_list', y_list)
            arg_z = Argument('out_z_list', z_list)

            process_custom_task(
                input_args=[arg_x, arg_y],
                offline_input_args=[],
                output_args=[arg_z],
                output_instruction_path=task_dir,
                fpga_acc=False,
            )

    def test_double(self):
        def double(x: list[DataNode]) -> DataNode:
            z_list = []
            z_0 = mult_relin(x[0], x[1], 'z_0')
            z_1 = mult_relin(x[0], x[2], 'z_1')
            z_list = [z_0, z_1]
            return z_list

        task = 'BFV_1_double'
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

        x_list = []
        for i in range(3):
            x_list.append(BfvCiphertextNode(f'x_{i}', level=1))

        z_list = double(x_list)

        arg_x = Argument('in_x_list', x_list)
        arg_z = Argument('out_z_list', z_list)

        process_custom_task(
            input_args=[arg_x],
            offline_input_args=[],
            output_args=[arg_z],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    def test_braid(self):
        task = 'BFV_braid'
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

        input_list: list[DataNode] = []
        for i in range(4):
            input_list.append(BfvCiphertextNode(f'x_{i}', level=3))

        x = input_list
        for i in range(2):
            y: list[DataNode] = []
            for j in range(4):
                y.append(mult_relin(x[j], x[((j + 1) % 4)], f'y_{i * 4 + j}'))
            x = y
        output_list = x

        arg_in = Argument('in_list', input_list)
        arg_out = Argument('out_list', output_list)

        process_custom_task(
            input_args=[arg_in],
            offline_input_args=[],
            output_args=[arg_out],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    def test_poly(self, n_op=4, levels=[3]):
        def compute_poly(x: list[BfvCiphertextNode], coeffs: list[BfvCiphertextNode]) -> list[BfvCiphertextNode]:
            z = []
            for i in range(n_op):
                ax = mult_relin(x[i], coeffs[0], f'ax_{i}')
                ax2 = mult_relin(ax, x[i], f'ax2_{i}')
                bx = mult_relin(coeffs[1], x[i], f'bx_{i}')
                ax2_bx = add(ax2, bx, f'ax2_bx_{i}')
                ax2_bx_c = add(ax2_bx, coeffs[2], f'ax2_bx_c_{i}')
                z.append(ax2_bx_c)
            return z

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_n_poly/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                coeffs = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))

                for i in range(3):
                    coeffs.append(BfvCiphertextNode(f'coeffs_{i}', level=lv))

                z_list = compute_poly(x_list, coeffs)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_a_list', coeffs)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_poly_2(self, levels=[5]):
        def poly2(x: BfvCiphertextNode, coeffs: list[BfvPlaintextMulNode]) -> CiphertextNode:
            x_powers = [x]
            x_powers.append(mult_relin(x_powers[0], x_powers[0], 'x^2'))
            y = mult(coeffs[0], x_powers[0], 'a_0*x^0')
            for i in range(1, 2):
                y = add(y, mult(x_powers[i], coeffs[i], f'a_{i}*x^{i}'), f'sum_{i}')
            return y

        for lv in levels:
            task = f'BFV_poly_2/level_{lv}'
            task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

            x = BfvCiphertextNode('x', level=lv)
            coeffs = [BfvPlaintextMulNode(f'a_{i}', level=lv) for i in range(0, 2)]
            y = poly2(x, coeffs)

            arg_x = Argument('in_x', x)
            arg_coeffs = Argument('in_coeffs', coeffs)
            arg_y = Argument('out_y', y)

            process_custom_task(
                input_args=[arg_x, arg_coeffs],
                offline_input_args=[],
                output_args=[arg_y],
                output_instruction_path=task_dir,
                fpga_acc=False,
            )

    def test_ct_pt_ringt_mac(self, levels=[i for i in range(1, 2)]):
        for lv in levels:
            for m in range(44, 51):
                with self.subTest(m=m, lv=lv):
                    task = f'BFV_cmpac/level_{lv}_m_{m}'
                    task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                    c_list = []
                    p_list = []
                    for i in range(m):
                        c_list.append(BfvCiphertextNode(f'c_{i}', level=lv))
                        p_list.append(BfvPlaintextRingtNode(f'p_{i}'))

                    z = ct_pt_mult_accumulate(c_list, p_list)

                    arg_c = Argument('in_c_list', c_list)
                    arg_p = Argument('in_p_list', p_list)
                    arg_z = Argument('out_z_list', [z])

                    process_custom_task(
                        input_args=[arg_c, arg_p],
                        offline_input_args=[],
                        output_args=[arg_z],
                        output_instruction_path=task_dir,
                        fpga_acc=False,
                    )

    def test_power_dag(self, levels=[param.max_level]):
        # param = Param.from_bfv_custom_params(n=8192,
        #                                      p=[0x7ffffffffb4001],
        #                                      q=[0x3fffffffef8001,0x4000000011c001,0x40000000120001],
        #                                      t=0x28001)
        # param = Param.from_bfv_custom_params(n=16384,
        #                                      p=[0x80000000130001, 0x7fffffffe90001],
        #                                      q=[0x100000000060001, 0x80000000068001, 0x80000000080001, 0x3fffffffef8001, 0x40000000120001, 0x3fffffffeb8001],
        #                                      t=163841)

        def get_noise_budget(level: int):
            Q = 1
            for i in range(level + 1):
                Q *= param.q[i]

            noise_budget = Q.bit_length() - math.ceil(math.log2(param.t))
            # noise_budget -= 10
            return noise_budget

        def get_required_noise_budget(dag_level: int, max_power: int):
            mult_noise = math.ceil(math.log2(param.t)) + math.ceil(math.log2(param.n))
            return (dag_level + 1) * mult_noise + math.ceil(math.log2(param.t)) + math.floor(math.log2(max_power))

        def power_dag(source_power: list[int], max_power: int, x: list[BfvCiphertextNode]):
            z_list: list[BfvCiphertextNode] = []
            assert len(x) == len(source_power)

            src_power_str = ''
            for power in source_power:
                src_power_str += f'{power}-' if power != source_power[-1] else f'{power}'
            with open(
                os.path.join(
                    CPU_OUTPUT_BASE_DIR,
                    f'origin_powerdag/PD-{max_power}#{src_power_str}.json',
                ),
            ) as f:
                power_dag = json.load(f)

            x_all_power = {}
            j = 0
            for sp in source_power:
                x_all_power[sp] = x[j]
                j += 1

            x_all_leveled_power = [list() for _ in range(max_power + 1)]
            for i in range(max_power + 1):
                # x_all_leveled_power[i] = [None for _ in range(power_dag['level'] + 2)]
                x_all_leveled_power[i] = [None for _ in range(param.max_level + 1)]

            for d in range(0, power_dag['depth'] + 1):
                for pid, compute_info in power_dag['data'].items():
                    if compute_info['depth'] == d:
                        if d == 0:
                            tmp = x_all_power[int(pid[1:])]
                            while tmp.level > 1:
                                x_all_leveled_power[int(pid[1:])][tmp.level] = tmp
                                # if tmp.level < power_dag['level'] + 2:
                                #     x_all_leveled_power[int(pid[1:])][tmp.level] = tmp
                                tmp = rescale(tmp)
                            x_all_leveled_power[int(pid[1:])][tmp.level] = tmp

                        else:
                            required_budget = get_required_noise_budget(compute_info['level'], max_power)
                            parent_level = 0
                            for lvl in range(param.max_level + 1):
                                if get_noise_budget(lvl) > required_budget:
                                    parent_level = lvl
                                    break

                            from_power0 = int(power_dag['compute'][compute_info['from_compute']]['inputs'][0][1:])
                            from_power1 = int(power_dag['compute'][compute_info['from_compute']]['inputs'][1][1:])
                            dest_power = from_power0 + from_power1

                            tmp = mult_relin(
                                x_all_leveled_power[from_power0][parent_level],
                                x_all_leveled_power[from_power1][parent_level],
                                output_id=f'x{dest_power}_lv{parent_level}',
                            )
                            # x_all_leveled_power[dest_power][parent_level] = tmp

                            # level = compute_info['level'] + 1
                            # tmp = mult_relin(
                            #     x_all_leveled_power[from_power0][level + 1], x_all_leveled_power[from_power1][level + 1],
                            #     output_id=f'x{dest_power}_lv{level + 1}'
                            # )
                            while tmp.level > 1:
                                x_all_leveled_power[dest_power][tmp.level] = tmp
                                tmp = rescale(tmp, output_id=f'x{dest_power}_lv{tmp.level - 1}')
                            x_all_leveled_power[dest_power][tmp.level] = tmp

            for i in range(1, max_power + 1):
                x_all_power[i] = x_all_leveled_power[i][1]

            for power in sorted(x_all_power):
                tmp = x_all_power[power]
                z_list.append(tmp)
            return z_list

        all_power_dags = []
        power_dag_info = os.listdir(os.path.join(CPU_OUTPUT_BASE_DIR, 'origin_powerdag'))
        for power_info in power_dag_info:
            max_power = int(power_info.split('#')[0].split('-')[1])
            source_power = [int(x) for x in power_info.split('#')[1].split('.')[0].split('-')]
            all_power_dags.append([max_power, source_power])

        all_power_dags = sorted(all_power_dags, key=lambda x: x[0])

        for lv in levels:
            # source_power = [1, 3]
            # max_power = 10

            # source_power = [1, 8, 13]
            # max_power = 69

            # source_power = [1, 7, 12]
            # max_power = 52

            # source_power = [1,9,15,78,115]
            # max_power = 512

            source_power = [1, 7, 18, 62, 104, 244, 259]
            max_power = 1137

            # source_power = [1, 8, 61, 164]
            # max_power = 1094

            # for max_power, source_power in all_power_dags:
            src_power_str = ''
            for power in source_power:
                src_power_str += f'{power}-' if power != source_power[-1] else f'{power}'
            task_power_str = f'PD-{max_power}#{src_power_str}'

            task = f'BFV_power_dag/{task_power_str}'
            task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

            print(f'{task} begin --')

            x_list: list[BfvCiphertextNode] = []
            for j in source_power:
                x_list.append(BfvCiphertextNode(f'x{j}', level=lv))

            z_list = power_dag(source_power, max_power, x_list)

            arg_x = Argument('in_x_list', x_list)
            arg_z = Argument('out_z_list', z_list)

            process_custom_task(
                input_args=[arg_x],
                offline_input_args=[],
                output_args=[arg_z],
                output_instruction_path=task_dir,
                fpga_acc=False,
            )

            print(f'{task} end --')

    def test_power_mul_coeff(self, levels=[1], index_per_fpga_func=[2, 1, 5]):
        def power_mul_coeff(lane_cipher_size):
            all_power_dags = []
            power_dag_info = os.listdir(os.path.join(CPU_OUTPUT_BASE_DIR, 'origin_powerdag'))
            for power_info in power_dag_info:
                max_power = int(power_info.split('#')[0].split('-')[1])
                source_power = [int(x) for x in power_info.split('#')[1].split('.')[0].split('-')]
                all_power_dags.append([max_power, source_power])

            all_power_dags = sorted(all_power_dags, key=lambda x: x[0])

            for lv in levels:
                # source_power = [1, 3, 11, 18]
                # max_power = 44

                # source_power = [1, 9, 15, 78, 115]
                # max_power = 512

                # source_power = [1, 4, 9, 24, 26, 42, 104, 115, 174, 185]
                # max_power = 422

                source_power = [1, 7, 18, 62, 104, 244, 259]
                max_power = 1137

                # for max_power, source_power in all_power_dags:
                src_power_str = ''
                for power in source_power:
                    src_power_str += f'{power}-' if power != source_power[-1] else f'{power}'
                task_power_str = f'PD-{max_power}#{src_power_str}'

                task = f'BFV_power_mul_coeff/{task_power_str}/{lane_cipher_size[0]}_{lane_cipher_size[1]}_{lane_cipher_size[2]}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                print(f'{task} begin --')

                all_c = []
                all_p0 = []
                all_p = []
                all_z = []

                # all_c_mul = []

                for k in range(lane_cipher_size[1]):
                    c_list = []
                    # c_mul_list = []
                    for i in range(max_power):
                        c_list.append(BfvCiphertextNode(f'c{k}_{i + 1}', level=lv))
                        # c_mul_list.append(ct_to_mul(c_list[-1], f'c{k}_{i+1}_mul'))
                    all_c.append(c_list)
                    # all_c_mul.append(c_mul_list)

                for r in range(lane_cipher_size[0]):
                    p0_l_list = []
                    p_l_list = []
                    z_l_list = []
                    for k in range(lane_cipher_size[1]):
                        p0_list = []
                        p_list = []
                        for i in range(lane_cipher_size[2]):
                            # pi_list = [BfvPlaintextNode(f'p{r}_{k}_{i}_0', level=lv)]
                            p0_list.append(BfvPlaintextNode(f'p{r}_{k}_{i}_0', level=lv))
                            pi_list = []
                            for j in range(max_power):
                                pi_list.append(BfvPlaintextRingtNode(f'p{r}_{k}_{i}_{j + 1}'))
                            p_list.append(pi_list)

                        # pl_list = [BfvPlaintextNode(f'p{r}_{k}_{lane_cipher_size[2]-1}_0', level=lv)]
                        # for j in range(max_power):
                        #     pl_list.append(BfvPlaintextRingtNode(f'p{r}_{k}_{lane_cipher_size[2]-1}_{j+1}'))
                        # p_list.append(pl_list)
                        p0_l_list.append(p0_list)
                        p_l_list.append(p_list)

                        z = []
                        for i in range(lane_cipher_size[2]):
                            if max_power <= 100:
                                # x = ct_pt_mult_accumulate(all_c[k][: len(p_list[i][1:])], p_list[i][1:])
                                # x = ct_pt_mult_accumulate(all_c[k], p_list[i][1:])
                                x = ct_pt_mult_accumulate(all_c[k], p_list[i])
                                # x_ntt = ct_pt_mult_accumulate(all_c_mul[k][: len(p_list[i][1:])], p_list[i][1:], output_mform=False)
                                # x = ct_ntt_to_ct(x_ntt)
                            else:
                                n_split = 4
                                for i_split in range(n_split):
                                    start_idx = int(max_power / n_split * i_split)
                                    end_idx = int(max_power / n_split * (i_split + 1))
                                    # x_ntt = ct_pt_mult_accumulate(all_c_mul[k][start_idx:end_idx], p_list[i][1+start_idx:1+end_idx], output_mform=False)
                                    # x = ct_ntt_to_ct(x_ntt)
                                    x = ct_pt_mult_accumulate(all_c[k][start_idx:end_idx], p_list[i][start_idx:end_idx])
                                    if i_split == 0:
                                        x_mac = x
                                    else:
                                        x_mac = add(x, x_mac)
                                x = x_mac

                            y = add(x, p0_list[i], f'y{r}_{k}_{i}')
                            z.append(rescale(y, f'z{r}_{k}_{i}'))

                        z_l_list.append(z)

                    all_p0.append(p0_l_list)
                    all_p.append(p_l_list)
                    all_z.append(z_l_list)

                arg_c = Argument('in_c_list', all_c)
                arg_p0 = Argument('in_p0_list', all_p0)
                arg_p = Argument('in_p_list', all_p)
                arg_z = Argument('out_z_list', all_z)

                param = Param('BFV', n=16384)

                process_custom_task(
                    input_args=[arg_c, arg_p0, arg_p],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

                print(f'{task} end --')

        # for bi in range(1, index_per_fpga_func[0]+1):
        #     for bj in range(1, index_per_fpga_func[1]+1):
        #         for bk in range(1, index_per_fpga_func[2]+1):
        #             lane_cipher_size = [bi, bj, bk]
        #             power_mul_coeff(lane_cipher_size)

        power_mul_coeff(lane_cipher_size=[index_per_fpga_func[0], index_per_fpga_func[1], index_per_fpga_func[2]])

    def test_custom_cmpac(self, n_op=1, levels=[i for i in range(1, param.max_level + 1)]):
        def custom_cmpac(x: list[DataNode], y: list[DataNode]) -> DataNode:
            mult_results = []
            for i in range(7):
                encoded_y_ringt = BfvPlaintextRingtNode(f'encoded_y_ringt_{i}')
                custom_compute(
                    inputs=[y[i]],
                    output=encoded_y_ringt,
                    type='encode_ringt',
                )
                mult_result = mult(x[i], encoded_y_ringt, f'mult_{i}')
                mult_results.append(mult_result)

            result = mult_results[0]
            for i in range(1, 7):
                result = add(result, mult_results[i], f'partial_sum_{i}')

            encoded_y_last = BfvPlaintextNode(f'encoded_y_last', level=result.level)
            custom_compute(
                inputs=[y[7]],
                output=encoded_y_last,
                type='encode',
                attributes={
                    'level': result.level,
                },
            )

            final_result = add(result, encoded_y_last, 'z_final')

            return final_result

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_custom_cmpac/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(7):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CustomDataNode(type='msg', id=f'y_{i}', attributes={'level': 0}))
                y_list.append(CustomDataNode(f'y_{7}'))

                z = custom_cmpac(x_list, y_list)

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

    def test_custom_param_cmc_relin(self, n_op=4, levels=[1, 2]):
        """测试使用自定义参数"""
        custom_param = Param.create_bfv_custom_param(
            n=8192,
            q=[0x3FFFFFFFEF8001, 0x4000000011C001, 0x40000000120001],
            p=[0x7FFFFFFFFB4001],
            t=65537,
        )

        assert custom_param.algo.value == 'BFV'
        assert custom_param.n == 8192
        assert custom_param.t == 65537
        assert custom_param.max_level == 2
        assert len(custom_param.p) == 1
        assert len(custom_param.q) == 3

        set_fhe_param(custom_param)

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_custom_param_{n_op}_cmc_relin/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

                z_list = []
                for i in range(n_op):
                    z_list.append(mult_relin(x_list[i], y_list[i], f'z_mul_{i}'))

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

        # 重置为默认参数，避免影响其他测试
        default_param = Param.create_bfv_default_param(n=16384)
        set_fhe_param(default_param)

    def test_custom_param_cac(self, n_op=4, levels=[1, 2]):
        """测试使用自定义参数"""
        custom_param = Param.create_bfv_custom_param(
            n=8192,
            q=[0x3FFFFFFFEF8001, 0x4000000011C001, 0x40000000120001],
            p=[0x7FFFFFFFFB4001],
            t=65537,
        )

        assert custom_param.algo.value == 'BFV'
        assert custom_param.n == 8192
        assert custom_param.t == 65537
        assert custom_param.max_level == 2
        assert len(custom_param.p) == 1
        assert len(custom_param.q) == 3

        set_fhe_param(custom_param)

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_custom_param_{n_op}_cac/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvCiphertextNode(f'y_{i}', level=lv))

                z_list = []
                for i in range(n_op):
                    z_list.append(add(x_list[i], y_list[i], f'z_{i}'))

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

        # 重置为默认参数
        default_param = Param.create_bfv_default_param(n=16384)
        set_fhe_param(default_param)

    def test_custom_param_cap(self, n_op=4, levels=[1, 2]):
        """测试使用自定义参数"""
        custom_param = Param.create_bfv_custom_param(
            n=8192,
            q=[0x3FFFFFFFEF8001, 0x4000000011C001, 0x40000000120001],
            p=[0x7FFFFFFFFB4001],
            t=65537,
        )

        assert custom_param.algo.value == 'BFV'
        assert custom_param.n == 8192
        assert custom_param.t == 65537
        assert custom_param.max_level == 2
        assert len(custom_param.p) == 1
        assert len(custom_param.q) == 3

        set_fhe_param(custom_param)

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_custom_param_{n_op}_cap/level_{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(BfvPlaintextNode(f'y_{i}', level=lv))

                z_list = []
                for i in range(n_op):
                    z_list.append(add(x_list[i], y_list[i], f'z_{i}'))

                arg_x = Argument('in_x_list', x_list)
                arg_y = Argument('in_y_list', y_list)
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                    fpga_acc=False,
                )

        # 重置为默认参数
        default_param = Param.create_bfv_default_param(n=16384)
        set_fhe_param(default_param)


if __name__ == '__main__':
    unittest.main()

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

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import unittest

from frontend.custom_task import *
from test_config import GPU_OUTPUT_BASE_DIR

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                )

    def test_rescale(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def rescale_l(x: list[DataNode]) -> DataNode:
            res_list = []
            for i in range(len(x_list)):
                res_list.append(rescale(x[i], f'y_{i}'))
            return res_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_rescale/level_{lv}'
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
            task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
            task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
            task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
            task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
            )

    def test_double(self):
        def double(x: list[DataNode]) -> DataNode:
            z_list = []
            z_0 = mult_relin(x[0], x[1], 'z_0')
            z_1 = mult_relin(x[0], x[2], 'z_1')
            z_list = [z_0, z_1]
            return z_list

        task = 'BFV_1_double'
        task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
        )

    def test_braid(self):
        task = 'BFV_braid'
        task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                )

    def test_ct_pt_ringt_mac(self, levels=[i for i in range(1, param.max_level + 1)]):
        for lv in levels:
            for m in range(44, 51):
                with self.subTest(m=m, lv=lv):
                    task = f'BFV_cmpac/level_{lv}_m_{m}'
                    task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(GPU_OUTPUT_BASE_DIR, task)

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
                )

        # 重置为默认参数
        default_param = Param.create_bfv_default_param(n=16384)
        set_fhe_param(default_param)


if __name__ == '__main__':
    unittest.main()

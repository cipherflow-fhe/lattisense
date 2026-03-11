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
import json
import math

# Add project root to path for frontend imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Add current directory to path for test_config imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

import pytest

from frontend.custom_task import *

# Try to import from generated test_config, fallback to default paths
try:
    from test_config import CPU_OUTPUT_BASE_DIR
except ImportError:
    CPU_OUTPUT_BASE_DIR = os.path.join(current_dir, 'test_data', 'cpu')


_p1 = Param.create_bfv_default_param(n=16384)
_p2 = Param.create_bfv_custom_param(
    n=8192,
    q=[0x3FFFFFFFEF8001, 0x4000000011C001, 0x40000000120001],
    p=[0x7FFFFFFFFB4001],
    t=65537,
)

N_OP = 4  # Number of parallel operators per test

# ---- Define all BFV parameter sets to be tested here ----
_BFV_PARAM_TAGS = {
    id(_p1): f'bfv_param_default_n{_p1.n}_t{hex(_p1.t)[2:]}',
    id(_p2): f'bfv_param_custom_n{_p2.n}_t{hex(_p2.t)[2:]}',
}

BFV_PARAMS = [_p1, _p2]


def _param_tag(param) -> str:
    return _BFV_PARAM_TAGS[id(param)]


class TestTask:
    @pytest.mark.min_level(0)
    def test_cap(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cap', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvPlaintextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [add(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(0)
    def test_cap_ringt(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cap_ringt', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvPlaintextRingtNode(f'y_{i}') for i in range(N_OP)]
        z_list = [add(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(0)
    def test_cac(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cac', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [add(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(0)
    def test_casc(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_casc', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [add(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(0)
    def test_csp(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_csp', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvPlaintextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [sub(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(0)
    def test_csp_ringt(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_csp_ringt', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvPlaintextRingtNode(f'y_{i}') for i in range(N_OP)]
        z_list = [sub(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(0)
    def test_csc(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_csc', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [sub(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(0)
    def test_cssc(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cssc', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [sub(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(0)
    def test_cneg(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cneg', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [neg(x_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_cmp_ringt(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cmp_ringt', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvPlaintextRingtNode(f'y_{i}') for i in range(N_OP)]
        z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_cmp(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cmp', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvPlaintextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_cmp_mul(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cmp_mul', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvPlaintextMulNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_cmc(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cmc', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_cmc_relin(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cmc_relin', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult_relin(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_cmc_relin_rescale(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_cmc_relin_rescale', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [rescale(mult_relin(x_list[i], y_list[i]), f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_csqr(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_csqr', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_csqr_relin(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_csqr_relin', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult_relin(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_csqr_relin_rescale(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_csqr_relin_rescale', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [rescale(mult_relin(x_list[i], x_list[i]), f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_rotate_col(self, param, lv, steps=[i + 1 for i in range(8)]):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(
            CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_rotate_col', f'level_{lv}', f'steps_{steps[0]}_to_{steps[-1]}'
        )
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [rotate_cols(x_list[i], steps, f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            offline_input_args=[],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_advanced_rotate_col(self, param, lv, steps=[-900, 20, 400, 2000, 3009]):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        steps_str = '_'.join(map(str, steps))
        task_dir = os.path.join(
            CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_advanced_rotate_col', f'level_{lv}', f'steps_{steps_str}'
        )
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [advanced_rotate_cols(x_list[i], steps, f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            offline_input_args=[],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_rotate_row(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_rotate_row', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [rotate_rows(x_list[i], f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            offline_input_args=[],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.min_level(1)
    def test_rescale(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_{N_OP}_rescale', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [rescale(x_list[i], f'y_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_y_list', y_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.at_level(3)
    def test_ctc_ctc_0(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        if param.max_level < 3:
            pytest.skip(f'requires max_level >= 3, got {param.max_level}')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_ctc_ctc_0', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        tmp_0 = mult_relin(x_list[0], y_list[0], 'tmp_0')
        z_list = [
            tmp_0,
            mult_relin(tmp_0, x_list[1], 'z_0'),
            mult_relin(x_list[1], y_list[1], 'z_1'),
            mult_relin(x_list[2], y_list[2], 'z_2'),
            mult_relin(x_list[3], y_list[3], 'z_3'),
        ]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.at_level(3)
    def test_ctc_ctc_1(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        if param.max_level < 3:
            pytest.skip(f'requires max_level >= 3, got {param.max_level}')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_ctc_ctc_1', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [BfvCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        t = [mult_relin(x_list[i], y_list[i], f't_{i}') for i in range(N_OP)]
        z_list = [
            mult_relin(t[0], t[1], 'z_0'),
            mult_relin(t[1], x_list[2], 'z_1'),
            mult_relin(t[2], x_list[3], 'z_2'),
            mult_relin(t[2], t[3], 'z_3'),
        ]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.at_level(3)
    def test_1_square_square(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        if param.max_level < 3:
            pytest.skip(f'requires max_level >= 3, got {param.max_level}')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_1_square_square', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(1)]
        t_list = [mult_relin(x_list[i], x_list[i], f'x^2_{i}') for i in range(1)]
        z_list = [mult_relin(t_list[i], t_list[i], f'x^4_{i}') for i in range(1)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.at_level(3)
    def test_1_ctc_rotate_cac(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        if param.max_level < 3:
            pytest.skip(f'requires max_level >= 3, got {param.max_level}')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_1_ctc_rotate_cac', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(1)]
        y_list = [BfvCiphertextNode(f'y_{i}', level=lv) for i in range(1)]
        z_list = []
        for i in range(len(x_list)):
            xy = mult_relin(x_list[i], y_list[i], f'xy_{i}')
            xyr = advanced_rotate_cols(xy, 1, f'rotated_xy_{i}')
            z_list.append(add(xy, xyr[0], f'xyaxyr_{i}'))
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.at_level(1)
    def test_double(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_1_double')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(3)]
        z_list = [
            mult_relin(x_list[0], x_list[1], 'z_0'),
            mult_relin(x_list[0], x_list[2], 'z_1'),
        ]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.at_level(3)
    def test_braid(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        if param.max_level < 3:
            pytest.skip(f'requires max_level >= 3, got {param.max_level}')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_braid')
        input_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(4)]
        x = input_list
        for i in range(2):
            y: list[DataNode] = []
            for j in range(4):
                y.append(mult_relin(x[j], x[(j + 1) % 4], f'y_{i * 4 + j}'))
            x = y
        output_list = x
        process_custom_task(
            input_args=[Argument('in_list', input_list)],
            offline_input_args=[],
            output_args=[Argument('out_list', output_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.at_level(3)
    def test_poly(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        if param.max_level < 3:
            pytest.skip(f'requires max_level >= 3, got {param.max_level}')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_n_poly', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(4)]
        coeffs = [BfvCiphertextNode(f'coeffs_{i}', level=lv) for i in range(3)]
        z_list = []
        for i in range(4):
            ax = mult_relin(x_list[i], coeffs[0], f'ax_{i}')
            ax2 = mult_relin(ax, x_list[i], f'ax2_{i}')
            bx = mult_relin(coeffs[1], x_list[i], f'bx_{i}')
            ax2_bx = add(ax2, bx, f'ax2_bx_{i}')
            z_list.append(add(ax2_bx, coeffs[2], f'ax2_bx_c_{i}'))
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_a_list', coeffs)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.at_level(5)
    def test_poly_2(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        if param.max_level < 5:
            pytest.skip(f'requires max_level >= 5, got {param.max_level}')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_poly_2', f'level_{lv}')
        x = BfvCiphertextNode('x', level=lv)
        coeffs = [BfvPlaintextMulNode(f'a_{i}', level=lv) for i in range(2)]
        x_powers = [x, mult_relin(x, x, 'x^2')]
        y = mult(coeffs[0], x_powers[0], 'a_0*x^0')
        for i in range(1, 2):
            y = add(y, mult(x_powers[i], coeffs[i], f'a_{i}*x^{i}'), f'sum_{i}')
        process_custom_task(
            input_args=[Argument('in_x', x), Argument('in_coeffs', coeffs)],
            offline_input_args=[],
            output_args=[Argument('out_y', y)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

    @pytest.mark.at_level(1)
    def test_ct_pt_ringt_mac(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        for m in range(44, 51):
            task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_cmpac', f'level_{lv}_m_{m}')
            c_list = [BfvCiphertextNode(f'c_{i}', level=lv) for i in range(m)]
            p_list = [BfvPlaintextRingtNode(f'p_{i}') for i in range(m)]
            z = ct_pt_mult_accumulate(c_list, p_list)
            process_custom_task(
                input_args=[Argument('in_c_list', c_list), Argument('in_p_list', p_list)],
                offline_input_args=[],
                output_args=[Argument('out_z_list', [z])],
                output_instruction_path=task_dir,
                fpga_acc=False,
            )

    @pytest.mark.at_max_level
    def test_power_dag(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        origin_powerdag_dir = os.path.join(CPU_OUTPUT_BASE_DIR, 'origin_powerdag')
        if not os.path.isdir(origin_powerdag_dir):
            pytest.skip(f'origin_powerdag directory not found: {origin_powerdag_dir}')

        def get_noise_budget(level: int):
            Q = 1
            for i in range(level + 1):
                Q *= param.q[i]
            return Q.bit_length() - math.ceil(math.log2(param.t))

        def get_required_noise_budget(dag_level: int, max_power: int):
            mult_noise = math.ceil(math.log2(param.t)) + math.ceil(math.log2(param.n))
            return (dag_level + 1) * mult_noise + math.ceil(math.log2(param.t)) + math.floor(math.log2(max_power))

        def run_power_dag(source_power: list[int], max_power: int, x: list[BfvCiphertextNode]):
            assert len(x) == len(source_power)
            src_power_str = '-'.join(str(p) for p in source_power)
            with open(os.path.join(origin_powerdag_dir, f'PD-{max_power}#{src_power_str}.json')) as f:
                dag = json.load(f)

            x_all_power = {sp: x[j] for j, sp in enumerate(source_power)}
            x_all_leveled_power = [[None] * (param.max_level + 1) for _ in range(max_power + 1)]

            for d in range(0, dag['depth'] + 1):
                for pid, compute_info in dag['data'].items():
                    if compute_info['depth'] != d:
                        continue
                    if d == 0:
                        tmp = x_all_power[int(pid[1:])]
                        while tmp.level > 1:
                            x_all_leveled_power[int(pid[1:])][tmp.level] = tmp
                            tmp = rescale(tmp)
                        x_all_leveled_power[int(pid[1:])][tmp.level] = tmp
                    else:
                        required_budget = get_required_noise_budget(compute_info['level'], max_power)
                        parent_level = next(
                            lvl for lvl in range(param.max_level + 1) if get_noise_budget(lvl) > required_budget
                        )
                        from_power0 = int(dag['compute'][compute_info['from_compute']]['inputs'][0][1:])
                        from_power1 = int(dag['compute'][compute_info['from_compute']]['inputs'][1][1:])
                        dest_power = from_power0 + from_power1
                        tmp = mult_relin(
                            x_all_leveled_power[from_power0][parent_level],
                            x_all_leveled_power[from_power1][parent_level],
                            output_id=f'x{dest_power}_lv{parent_level}',
                        )
                        while tmp.level > 1:
                            x_all_leveled_power[dest_power][tmp.level] = tmp
                            tmp = rescale(tmp, output_id=f'x{dest_power}_lv{tmp.level - 1}')
                        x_all_leveled_power[dest_power][tmp.level] = tmp

            for i in range(1, max_power + 1):
                x_all_power[i] = x_all_leveled_power[i][1]
            return [x_all_power[power] for power in sorted(x_all_power)]

        source_power = [1, 7, 18, 62, 104, 244, 259]
        max_power = 1137
        src_power_str = '-'.join(str(p) for p in source_power)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, 'BFV_power_dag', f'PD-{max_power}#{src_power_str}')

        print(f'BFV_power_dag PD-{max_power}#{src_power_str} begin --')
        x_list = [BfvCiphertextNode(f'x{j}', level=lv) for j in source_power]
        z_list = run_power_dag(source_power, max_power, x_list)
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )
        print(f'BFV_power_dag PD-{max_power}#{src_power_str} end --')

    @pytest.mark.at_level(1)
    def test_power_mul_coeff(self, param, lv, index_per_fpga_func=[2, 1, 5]):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        origin_powerdag_dir = os.path.join(CPU_OUTPUT_BASE_DIR, 'origin_powerdag')
        if not os.path.isdir(origin_powerdag_dir):
            pytest.skip(f'origin_powerdag directory not found: {origin_powerdag_dir}')

        source_power = [1, 7, 18, 62, 104, 244, 259]
        max_power = 1137
        src_power_str = '-'.join(str(p) for p in source_power)
        lane_cipher_size = index_per_fpga_func
        task_dir = os.path.join(
            CPU_OUTPUT_BASE_DIR,
            param_tag,
            'BFV_power_mul_coeff',
            f'PD-{max_power}#{src_power_str}',
            f'{lane_cipher_size[0]}_{lane_cipher_size[1]}_{lane_cipher_size[2]}',
        )

        print(f'BFV_power_mul_coeff begin --')

        all_c = [
            [BfvCiphertextNode(f'c{k}_{i + 1}', level=lv) for i in range(max_power)] for k in range(lane_cipher_size[1])
        ]
        all_p0 = []
        all_p = []
        all_z = []

        for r in range(lane_cipher_size[0]):
            p0_l_list = []
            p_l_list = []
            z_l_list = []
            for k in range(lane_cipher_size[1]):
                p0_list = [BfvPlaintextNode(f'p{r}_{k}_{i}_0', level=lv) for i in range(lane_cipher_size[2])]
                p_list = [
                    [BfvPlaintextRingtNode(f'p{r}_{k}_{i}_{j + 1}') for j in range(max_power)]
                    for i in range(lane_cipher_size[2])
                ]
                p0_l_list.append(p0_list)
                p_l_list.append(p_list)

                z = []
                for i in range(lane_cipher_size[2]):
                    if max_power <= 100:
                        x = ct_pt_mult_accumulate(all_c[k], p_list[i])
                    else:
                        n_split = 4
                        x_mac = None
                        for i_split in range(n_split):
                            start_idx = int(max_power / n_split * i_split)
                            end_idx = int(max_power / n_split * (i_split + 1))
                            x = ct_pt_mult_accumulate(all_c[k][start_idx:end_idx], p_list[i][start_idx:end_idx])
                            x_mac = x if i_split == 0 else add(x, x_mac)
                        x = x_mac
                    y = add(x, p0_list[i], f'y{r}_{k}_{i}')
                    z.append(rescale(y, f'z{r}_{k}_{i}'))
                z_l_list.append(z)

            all_p0.append(p0_l_list)
            all_p.append(p_l_list)
            all_z.append(z_l_list)

        process_custom_task(
            input_args=[Argument('in_c_list', all_c), Argument('in_p0_list', all_p0), Argument('in_p_list', all_p)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', all_z)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )
        print(f'BFV_power_mul_coeff end --')

    @pytest.mark.min_level(1)
    def test_custom_cmpac(self, param, lv):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, param_tag, f'BFV_custom_cmpac', f'level_{lv}')
        x_list = [BfvCiphertextNode(f'x_{i}', level=lv) for i in range(7)]
        y_list = [CustomDataNode(type='msg', id=f'y_{i}', attributes={'level': 0}) for i in range(7)]
        y_list.append(CustomDataNode(f'y_7'))

        mult_results = []
        for i in range(7):
            encoded_y_ringt = BfvPlaintextRingtNode(f'encoded_y_ringt_{i}')
            custom_compute(inputs=[y_list[i]], output=encoded_y_ringt, type='encode_ringt')
            mult_results.append(mult(x_list[i], encoded_y_ringt, f'mult_{i}'))

        result = mult_results[0]
        for i in range(1, 7):
            result = add(result, mult_results[i], f'partial_sum_{i}')

        encoded_y_last = BfvPlaintextNode(f'encoded_y_last', level=result.level)
        custom_compute(
            inputs=[y_list[7]],
            output=encoded_y_last,
            type='encode',
            attributes={'level': result.level},
        )
        final_result = add(result, encoded_y_last, 'z_final')

        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', final_result)],
            output_instruction_path=task_dir,
            fpga_acc=False,
        )

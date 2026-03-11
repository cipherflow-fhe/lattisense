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

import pytest

from frontend.custom_task import *

# Try to import from generated test_config, fallback to default paths
try:
    from test_config import FPGA_OUTPUT_BASE_DIR
except ImportError:
    FPGA_OUTPUT_BASE_DIR = os.path.join(current_dir, 'test_data', 'fpga_tests', 'noc_config_16c_3')


_p1 = Param.create_ckks_fpga_param()

N_OP = 4  # Number of parallel operators per test

# ---- Define all CKKS parameter sets to be tested here ----
_CKKS_PARAM_TAGS = {
    id(_p1): f'ckks_param_fpga_n{_p1.n}',
}

CKKS_PARAMS = [_p1]


def _param_tag(param) -> str:
    return _CKKS_PARAM_TAGS[id(param)]


class TestTask:
    @pytest.mark.min_level(0)
    def test_cap(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_cap', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksPlaintextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [add(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(0)
    def test_cac(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_cac', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [add(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(0)
    def test_casc(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_casc', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [add(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(0)
    def test_csp(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_csp', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksPlaintextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [sub(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(0)
    def test_csc(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_csc', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [sub(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(0)
    def test_cneg(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_cneg', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [neg(x_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_cmp_ringt(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_cmp_ringt', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksPlaintextRingtNode(f'y_{i}') for i in range(N_OP)]
        z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_cmp(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_cmp', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksPlaintextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_cmp_mul(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_cmp_mul', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksPlaintextMulNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.at_level(3)
    def test_ct_pt_ringt_mult_accumulate(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        for m in range(2, 21):
            task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, 'CKKS_cmpac_ringt', f'level_{lv}_m_{m}')
            c_list = [CkksCiphertextNode(f'c_{i}', level=lv) for i in range(m)]
            p_list = [CkksPlaintextRingtNode(f'p_{i}') for i in range(m)]
            z = ct_pt_mult_accumulate(c_list, p_list)
            process_custom_task(
                input_args=[Argument('in_c_list', c_list), Argument('in_p_list', p_list)],
                offline_input_args=[],
                output_args=[Argument('out_z_list', [z])],
                output_instruction_path=task_dir,
            )

    @pytest.mark.min_level(1)
    def test_cmc(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_cmc', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_cmc_relin(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_cmc_relin', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult_relin(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_cmc_relin_rescale(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_cmc_relin_rescale', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [CkksCiphertextNode(f'y_{i}', level=lv) for i in range(N_OP)]
        z_list = [rescale(mult_relin(x_list[i], y_list[i]), f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_csqr(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_csqr', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_csqr_relin(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_csqr_relin', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [mult_relin(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_csqr_relin_rescale(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_csqr_relin_rescale', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        z_list = [rescale(mult_relin(x_list[i], x_list[i]), f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_rescale(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_rescale', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [rescale(x_list[i], f'y_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_y_list', y_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(2)
    def test_drop_level(self, param, lv, drop_lv=2):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(
            FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_drop_level', f'level_{lv}', f'drop_{drop_lv}'
        )
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [drop_level(x_list[i], drop_lv, f'y_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            offline_input_args=[],
            output_args=[Argument('out_y_list', y_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_rotate_col(self, param, lv, steps=[i + 1 for i in range(128)]):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(
            FPGA_OUTPUT_BASE_DIR,
            param_tag,
            f'CKKS_{N_OP}_rotate_col',
            f'level_{lv}',
            f'steps_{steps[0]}_to_{steps[-1]}',
        )
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [rotate_cols(x_list[i], steps, f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            offline_input_args=[],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_advanced_rotate_col(self, param, lv, steps=[-500, 20, 200, 2000, 4000]):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        steps_str = '_'.join(map(str, steps))
        task_dir = os.path.join(
            FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_advanced_rotate_col', f'level_{lv}', f'steps_{steps_str}'
        )
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [advanced_rotate_cols(x_list[i], steps, f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            offline_input_args=[],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_rotate_row(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_rotate_row', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [rotate_rows(x_list[i], f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            offline_input_args=[],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.at_max_level
    def test_seal_rotate_row(self, param, lv):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_seal_rotate_row', f'level_{lv}')
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [seal_rotate_rows(x_list[i], f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            offline_input_args=[],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.at_max_level
    def test_seal_rotate_col(self, param, lv, steps=[-500, 20, 200, 2000, 4000]):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        steps_str = '_'.join(map(str, steps))
        task_dir = os.path.join(
            FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_{N_OP}_seal_rotate_col', f'level_{lv}', f'steps_{steps_str}'
        )
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [seal_rotate_cols(x_list[i], steps, f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            offline_input_args=[],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.at_max_level
    def test_seal_advanced_rotate_col(self, param, lv, steps=[-500, 20, 200, 2000, 4000]):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        steps_str = '_'.join(map(str, steps))
        task_dir = os.path.join(
            FPGA_OUTPUT_BASE_DIR,
            param_tag,
            f'CKKS_{N_OP}_seal_advanced_rotate_col',
            f'level_{lv}',
            f'steps_{steps_str}',
        )
        x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(N_OP)]
        y_list = [seal_advanced_rotate_cols(x_list[i], steps, f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            offline_input_args=[],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.at_level(4)
    def test_n_poly(self, param, lv):
        if param.max_level < 4:
            pytest.skip(f'requires max_level >= 4, got {param.max_level}')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, 'CKKS_n_poly', f'level_{lv}')
        x = CkksCiphertextNode('x', 4)
        coeff0 = CkksPlaintextNode('a_0', 2)
        coeffs = [CkksPlaintextRingtNode(f'a_{i}') for i in range(1, 4)]
        x1_lv4 = x
        x2_lv3 = rescale(mult_relin(x1_lv4, x1_lv4))
        x2_lv2 = drop_level(x2_lv3, drop_level=1)
        x1_lv3 = drop_level(x1_lv4, drop_level=1)
        x1_lv2 = drop_level(x1_lv3, drop_level=1)
        x3_lv2 = rescale(mult_relin(x1_lv3, x2_lv3))
        x_powers = [x1_lv2, x2_lv2, x3_lv2]
        y = coeff0
        for i in range(3):
            y = add(y, mult(x_powers[i], coeffs[i]))
        process_custom_task(
            input_args=[Argument('x', x), Argument('coeff0', coeff0), Argument('coeffs', coeffs)],
            offline_input_args=[],
            output_args=[Argument('y', y)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(0)
    def test_cap_2d(self, param, lv, row=1, col=1):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, f'CKKS_cap_row_{row}_col_{col}', f'level_{lv}')
        x_ct_2d = [[CkksCiphertextNode(level=lv) for _ in range(col)] for _ in range(row)]
        y_pt_2d = [[CkksPlaintextNode(level=lv) for _ in range(col)] for _ in range(row)]
        z_ct_2d = [[add(x_ct_2d[r][c], y_pt_2d[r][c]) for c in range(col)] for r in range(row)]
        process_custom_task(
            input_args=[Argument('x_ct_2d', x_ct_2d), Argument('y_pt_2d', y_pt_2d)],
            offline_input_args=[],
            output_args=[Argument('z_ct_2d', z_ct_2d)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(0)
    def test_cap_3d(self, param, lv, dim0=1, dim1=1, dim2=1):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, 'CKKS_cap_3d', f'level_{lv}')
        x_ct_3d = [[[CkksCiphertextNode(level=lv) for _ in range(dim2)] for _ in range(dim1)] for _ in range(dim0)]
        y_pt_3d = [[[CkksPlaintextNode(level=lv) for _ in range(dim2)] for _ in range(dim1)] for _ in range(dim0)]
        z_ct_3d = [
            [[add(x_ct_3d[i][j][k], y_pt_3d[i][j][k]) for k in range(dim2)] for j in range(dim1)] for i in range(dim0)
        ]
        process_custom_task(
            input_args=[Argument('x_ct_3d', x_ct_3d), Argument('y_pt_3d', y_pt_3d)],
            offline_input_args=[],
            output_args=[Argument('z_ct_3d', z_ct_3d)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_cmc_relin_4d(self, param, lv, dim0=1, dim1=1, dim2=1, dim3=1):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, 'CKKS_cmc_relin_4d', f'level_{lv}')
        x_ct_4d = [
            [[[CkksCiphertextNode(level=lv) for _ in range(dim3)] for _ in range(dim2)] for _ in range(dim1)]
            for _ in range(dim0)
        ]
        y_ct_4d = [
            [[[CkksCiphertextNode(level=lv) for _ in range(dim3)] for _ in range(dim2)] for _ in range(dim1)]
            for _ in range(dim0)
        ]
        z_ct_4d = [
            [
                [[mult_relin(x_ct_4d[i][j][k][ll], y_ct_4d[i][j][k][ll]) for ll in range(dim3)] for k in range(dim2)]
                for j in range(dim1)
            ]
            for i in range(dim0)
        ]
        process_custom_task(
            input_args=[Argument('x_ct_4d', x_ct_4d), Argument('y_ct_4d', y_ct_4d)],
            offline_input_args=[],
            output_args=[Argument('z_ct_4d', z_ct_4d)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_cmp_3d(self, param, lv, dim0=1, dim1=1, dim2=1):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, 'CKKS_cmp_3d', f'level_{lv}')
        x_ct_3d = [[[CkksCiphertextNode(level=lv) for _ in range(dim2)] for _ in range(dim1)] for _ in range(dim0)]
        y_pt_3d = [[[CkksPlaintextNode(level=lv) for _ in range(dim2)] for _ in range(dim1)] for _ in range(dim0)]
        z_ct_3d = [
            [[mult(x_ct_3d[i][j][k], y_pt_3d[i][j][k]) for k in range(dim2)] for j in range(dim1)] for i in range(dim0)
        ]
        process_custom_task(
            input_args=[Argument('x_ct_3d', x_ct_3d), Argument('y_pt_3d', y_pt_3d)],
            offline_input_args=[],
            output_args=[Argument('z_ct_3d', z_ct_3d)],
            output_instruction_path=task_dir,
        )

    @pytest.mark.min_level(1)
    def test_cmp_4d(self, param, lv, dim0=1, dim1=1, dim2=1, dim3=1):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, param_tag, 'CKKS_cmp_4d', f'level_{lv}')
        x_ct_4d = [
            [[[CkksCiphertextNode(level=lv) for _ in range(dim3)] for _ in range(dim2)] for _ in range(dim1)]
            for _ in range(dim0)
        ]
        y_pt_4d = [
            [[[CkksPlaintextNode(level=lv) for _ in range(dim3)] for _ in range(dim2)] for _ in range(dim1)]
            for _ in range(dim0)
        ]
        z_ct_4d = [
            [
                [[mult(x_ct_4d[i][j][k][ll], y_pt_4d[i][j][k][ll]) for ll in range(dim3)] for k in range(dim2)]
                for j in range(dim1)
            ]
            for i in range(dim0)
        ]
        process_custom_task(
            input_args=[Argument('x_ct_4d', x_ct_4d), Argument('y_pt_4d', y_pt_4d)],
            offline_input_args=[],
            output_args=[Argument('z_ct_4d', z_ct_4d)],
            output_instruction_path=task_dir,
        )

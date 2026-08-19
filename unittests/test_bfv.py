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
from frontend.types import BfvParam

try:
    from test_config import CPU_OUTPUT_BASE_DIR, GPU_OUTPUT_BASE_DIR
except ImportError as e:
    raise RuntimeError(
        'Failed to import CPU_OUTPUT_BASE_DIR/GPU_OUTPUT_BASE_DIR from test_config. Run CMake to generate unittests/test_config.py.'
    ) from e


_p1 = BfvParam.create_default_param(log_n=14)
_p2 = BfvParam.create_custom_param(
    log_n=13,
    q=[0x3FFFFFFFEF8001, 0x4000000011C001, 0x40000000120001],
    p=[0x7FFFFFFFFB4001],
    t=65537,
)

N_OP = 4  # Number of parallel operators per test

# ---- Define all BFV parameter sets to be tested here ----
_BFV_PARAM_TAGS = {
    id(_p1): f'bfv_param_default_n{1 << _p1.log_n}_t{hex(_p1.t)[2:]}',
    id(_p2): f'bfv_param_custom_n{1 << _p2.log_n}_t{hex(_p2.t)[2:]}',
}

BFV_PARAMS = [_p1, _p2]
PROCESSORS = [Processor.CPU, Processor.GPU]


def _param_tag(param) -> str:
    return _BFV_PARAM_TAGS[id(param)]


class TestTask:
    @pytest.mark.min_level(0)
    @pytest.mark.parametrize('is_ringt', [False, True], ids=['pt', 'pt-ringt'])
    def test_cap(self, param, lv, is_ringt, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_name = 'cap_ringt' if is_ringt else 'cap'
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_{task_name}', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [BfvPlaintextNode(id=f'y_{i}', level=0 if is_ringt else lv, is_ringt=is_ringt) for i in range(N_OP)]
        z_list = [add(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(0)
    @pytest.mark.parametrize('same_input', [False, True], ids=['ct', 'same-ct'])
    def test_cac(self, param, lv, same_input, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_name = 'casc' if same_input else 'cac'
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_{task_name}', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        if same_input:
            z_list = [add(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list)]
        else:
            y_list = [BfvCiphertextNode(level=lv, id=f'y_{i}') for i in range(N_OP)]
            z_list = [add(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list), Argument('in_y_list', y_list)]
        process_custom_task(
            input_args=input_args,
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(0)
    @pytest.mark.parametrize(
        'scalar_tag, scalar',
        [('int', 3), ('int64_t', -105), ('uint64_t', 11)],
        ids=['int', 'int64_t', 'uint64_t'],
    )
    def test_add_scalar(self, param, lv, scalar_tag, scalar, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_add_scalar', scalar_tag, f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        z_list = [add(x_list[i], scalar, f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(0)
    @pytest.mark.parametrize('is_ringt', [False, True], ids=['pt', 'pt-ringt'])
    def test_csp(self, param, lv, is_ringt, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_name = 'csp_ringt' if is_ringt else 'csp'
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_{task_name}', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [BfvPlaintextNode(id=f'y_{i}', level=0 if is_ringt else lv, is_ringt=is_ringt) for i in range(N_OP)]
        z_list = [sub(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(0)
    @pytest.mark.parametrize('same_input', [False, True], ids=['ct', 'same-ct'])
    def test_csc(self, param, lv, same_input, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_name = 'cssc' if same_input else 'csc'
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_{task_name}', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        if same_input:
            z_list = [sub(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list)]
        else:
            y_list = [BfvCiphertextNode(level=lv, id=f'y_{i}') for i in range(N_OP)]
            z_list = [sub(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list), Argument('in_y_list', y_list)]
        process_custom_task(
            input_args=input_args,
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(0)
    @pytest.mark.parametrize(
        'scalar_tag, scalar',
        [('int', 3), ('int64_t', 5), ('uint64_t', 11)],
        ids=['int', 'int64_t', 'uint64_t'],
    )
    def test_sub_scalar(self, param, lv, scalar_tag, scalar, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_sub_scalar', scalar_tag, f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        z_list = [sub(x_list[i], scalar, f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    @pytest.mark.parametrize('is_ringt', [False, True], ids=['pt', 'pt-ringt'])
    def test_cmp(self, param, lv, is_ringt, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_name = 'cmp_ringt' if is_ringt else 'cmp'
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_{task_name}', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [BfvPlaintextNode(id=f'y_{i}', level=0 if is_ringt else lv, is_ringt=is_ringt) for i in range(N_OP)]
        z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    @pytest.mark.parametrize(
        'scalar_tag, scalar',
        [('int', 3), ('int64_t', -5), ('uint64_t', 11)],
        ids=['int', 'int64_t', 'uint64_t'],
    )
    def test_mult_scalar(self, param, lv, scalar_tag, scalar, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_mult_scalar', scalar_tag, f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        z_list = [mult(x_list[i], scalar, f'z_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    @pytest.mark.parametrize('same_input', [False, True], ids=['ct', 'same-ct'])
    def test_cmc(self, param, lv, same_input, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_name = 'csqr' if same_input else 'cmc'
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_{task_name}', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        if same_input:
            z_list = [mult(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list)]
        else:
            y_list = [BfvCiphertextNode(level=lv, id=f'y_{i}') for i in range(N_OP)]
            z_list = [mult(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list), Argument('in_y_list', y_list)]
        process_custom_task(
            input_args=input_args,
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    @pytest.mark.parametrize('same_input', [False, True], ids=['ct', 'same-ct'])
    def test_cmc_relin(self, param, lv, same_input, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_name = 'csqr_relin' if same_input else 'cmc_relin'
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_{task_name}', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        if same_input:
            z_list = [mult_relin(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list)]
        else:
            y_list = [BfvCiphertextNode(level=lv, id=f'y_{i}') for i in range(N_OP)]
            z_list = [mult_relin(x_list[i], y_list[i], f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list), Argument('in_y_list', y_list)]
        process_custom_task(
            input_args=input_args,
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    @pytest.mark.parametrize('same_input', [False, True], ids=['ct', 'same-ct'])
    def test_cmc_relin_rescale(self, param, lv, same_input, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_name = 'csqr_relin_rescale' if same_input else 'cmc_relin_rescale'
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_{task_name}', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        if same_input:
            z_list = [rescale(mult_relin(x_list[i], x_list[i]), f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list)]
        else:
            y_list = [BfvCiphertextNode(level=lv, id=f'y_{i}') for i in range(N_OP)]
            z_list = [rescale(mult_relin(x_list[i], y_list[i]), f'z_{i}') for i in range(N_OP)]
            input_args = [Argument('in_x_list', x_list), Argument('in_y_list', y_list)]
        process_custom_task(
            input_args=input_args,
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    @pytest.mark.parametrize('use_default_rotation_keys', [True, False], ids=['default', 'non-default'])
    def test_rotate_col(self, param, lv, use_default_rotation_keys, processor, steps=[i + 1 for i in range(8)]):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        steps_tag = f'steps_{steps[0]}_to_{steps[-1]}'
        key_mode_tag = 'default' if use_default_rotation_keys else 'non-default'
        task_dir = os.path.join(
            output_base_dir, param_tag, f'BFV_{N_OP}_rotate_col', f'level_{lv}', steps_tag, key_mode_tag
        )
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [
            rotate_cols(x_list[i], steps, f'rotated_x_{i}', use_default_rotation_keys=use_default_rotation_keys)
            for i in range(N_OP)
        ]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    def test_rotate_row(self, param, lv, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_rotate_row', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [rotate_rows(x_list[i], f'rotated_x_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('arg_x', x_list)],
            output_args=[Argument('arg_y', y_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(2)
    def test_drop_level(self, param, lv, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_drop_level', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [drop_level(x_list[i], drop_level=2, output_id=f'y_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            output_args=[Argument('out_y_list', y_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    def test_rescale(self, param, lv, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_{N_OP}_rescale', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [rescale(x_list[i], output_id=f'y_{i}') for i in range(N_OP)]
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            output_args=[Argument('out_y_list', y_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.at_level(1)
    def test_ct_pt_ringt_mac(self, param, lv, processor):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        for m in range(44, 51):
            task_dir = os.path.join(output_base_dir, param_tag, 'BFV_cmpac', f'level_{lv}_m_{m}')
            c_list = [BfvCiphertextNode(level=lv, id=f'c_{i}') for i in range(m)]
            p_list = [BfvPlaintextNode(id=f'p_{i}', is_ringt=True) for i in range(m)]
            z = ct_pt_mult_accumulate(c_list, p_list)
            process_custom_task(
                input_args=[Argument('in_c_list', c_list), Argument('in_p_list', p_list)],
                output_args=[Argument('out_z_list', [z])],
                output_instruction_path=task_dir,
                processor=processor,
            )

    @pytest.mark.at_max_level
    def test_power_dag(self, param, lv, processor):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        origin_powerdag_dir = os.path.join(output_base_dir, 'origin_powerdag')
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
                        while tmp.metadata.level > 1:
                            x_all_leveled_power[int(pid[1:])][tmp.metadata.level] = tmp
                            tmp = rescale(tmp)
                        x_all_leveled_power[int(pid[1:])][tmp.metadata.level] = tmp
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
                        while tmp.metadata.level > 1:
                            x_all_leveled_power[dest_power][tmp.metadata.level] = tmp
                            tmp = rescale(tmp, output_id=f'x{dest_power}_lv{tmp.metadata.level - 1}')
                        x_all_leveled_power[dest_power][tmp.metadata.level] = tmp

            for i in range(1, max_power + 1):
                x_all_power[i] = x_all_leveled_power[i][1]
            return [x_all_power[power] for power in sorted(x_all_power)]

        source_power = [1, 7, 18, 62, 104, 244, 259]
        max_power = 1137
        # source_power = [1, 3, 7, 9, 19, 24]
        # max_power = 52
        src_power_str = '-'.join(str(p) for p in source_power)
        task_dir = os.path.join(output_base_dir, param_tag, 'BFV_power_dag', f'PD-{max_power}#{src_power_str}')

        print(f'BFV_power_dag PD-{max_power}#{src_power_str} begin --')
        x_list = [BfvCiphertextNode(level=lv, id=f'x{j}') for j in source_power]
        z_list = run_power_dag(source_power, max_power, x_list)
        process_custom_task(
            input_args=[Argument('in_x_list', x_list)],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )
        print(f'BFV_power_dag PD-{max_power}#{src_power_str} end --')

    @pytest.mark.at_level(1)
    def test_power_mul_coeff(self, param, lv, processor, index_per_fpga_func=[2, 1, 5]):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        origin_powerdag_dir = os.path.join(output_base_dir, 'origin_powerdag')
        if not os.path.isdir(origin_powerdag_dir):
            pytest.skip(f'origin_powerdag directory not found: {origin_powerdag_dir}')

        source_power = [1, 7, 18, 62, 104, 244, 259]
        max_power = 1137
        # source_power = [1, 3, 7, 9, 19, 24]
        # max_power = 52
        src_power_str = '-'.join(str(p) for p in source_power)
        lane_cipher_size = index_per_fpga_func
        task_dir = os.path.join(
            output_base_dir,
            param_tag,
            'BFV_power_mul_coeff',
            f'PD-{max_power}#{src_power_str}',
            f'{lane_cipher_size[0]}_{lane_cipher_size[1]}_{lane_cipher_size[2]}',
        )

        print(f'BFV_power_mul_coeff begin --')

        all_c = [
            [BfvCiphertextNode(level=lv, id=f'c{k}_{i + 1}') for i in range(max_power)]
            for k in range(lane_cipher_size[1])
        ]
        all_p0 = []
        all_p = []
        all_z = []

        for r in range(lane_cipher_size[0]):
            p0_l_list = []
            p_l_list = []
            z_l_list = []
            for k in range(lane_cipher_size[1]):
                p0_list = [
                    BfvPlaintextNode(id=f'p{r}_{k}_{i}_0', level=lv, is_ringt=False) for i in range(lane_cipher_size[2])
                ]
                p_list = [
                    [BfvPlaintextNode(id=f'p{r}_{k}_{i}_{j + 1}', is_ringt=True) for j in range(max_power)]
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
                    z.append(rescale(y, output_id=f'z{r}_{k}_{i}'))
                z_l_list.append(z)

            all_p0.append(p0_l_list)
            all_p.append(p_l_list)
            all_z.append(z_l_list)

        process_custom_task(
            input_args=[Argument('in_c_list', all_c), Argument('in_p0_list', all_p0), Argument('in_p_list', all_p)],
            output_args=[Argument('out_z_list', all_z)],
            output_instruction_path=task_dir,
            processor=processor,
        )
        print(f'BFV_power_mul_coeff end --')

    @pytest.mark.min_level(1)
    def test_custom_cmpac(self, param, lv, processor):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_custom_cmpac', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(7)]
        y_list = [CustomDataNode(type='msg', id=f'y_{i}', attributes={'level': 0}) for i in range(7)]
        y_list.append(CustomDataNode(f'y_7'))

        mult_results = []
        for i in range(7):
            encoded_y_ringt = BfvPlaintextNode(id=f'encoded_y_ringt_{i}', is_ringt=True)
            custom_compute(inputs=[y_list[i]], output=encoded_y_ringt, type='encode_ringt')
            mult_results.append(mult(x_list[i], encoded_y_ringt, f'mult_{i}'))

        result = mult_results[0]
        for i in range(1, 7):
            result = add(result, mult_results[i], f'partial_sum_{i}')

        encoded_y_last = BfvPlaintextNode(id='encoded_y_last', level=result.metadata.level, is_ringt=False)
        custom_compute(
            inputs=[y_list[7]],
            output=encoded_y_last,
            type='encode',
            attributes={'level': result.metadata.level},
        )
        final_result = add(result, encoded_y_last, 'z_final')

        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            output_args=[Argument('out_z_list', final_result)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    def test_custom_compute_at_start(self, param, lv, processor):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, 'BFV_custom_compute_at_start', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(7)]
        y_list = [CustomDataNode(type='msg', id=f'y_{i}', attributes={'level': 0}) for i in range(7)]
        y_list.append(CustomDataNode(type='msg', id='y_7', attributes={'level': 0}))

        mult_results = []
        for i in range(7):
            encoded_y_ringt = BfvPlaintextNode(id=f'encoded_y_ringt_{i}', is_ringt=True)
            custom_compute(
                inputs=[y_list[i]],
                output=encoded_y_ringt,
                type='encode_ringt',
            )
            mult_results.append(mult(x_list[i], encoded_y_ringt, f'mult_{i}'))

        result = mult_results[0]
        for i in range(1, 7):
            result = add(result, mult_results[i], f'partial_sum_{i}')

        encoded_y_last = BfvPlaintextNode(id='encoded_y_last', level=result.metadata.level, is_ringt=False)
        custom_compute(
            inputs=[y_list[7]],
            output=encoded_y_last,
            type='encode',
            attributes={'level': result.metadata.level},
        )
        final_result = add(result, encoded_y_last, 'z_final')

        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            output_args=[Argument('out_z_list', final_result)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    def test_custom_compute_at_end(self, param, lv, processor):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_custom_compute_at_end', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [BfvCiphertextNode(level=lv, id=f'y_{i}') for i in range(N_OP)]

        m_list = [relin(mult(x_list[i], y_list[i], f'x_mult_y_{i}'), f'm_{i}') for i in range(N_OP)]
        z_list = []
        for i in range(N_OP):
            zi = BfvCiphertextNode(id=f'z_{i}', level=m_list[i].metadata.level)
            zi.metadata = m_list[i].metadata.copy()
            custom_compute(
                inputs=[m_list[i]],
                output=zi,
                type='custom_add',
            )
            z_list.append(zi)

        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.min_level(1)
    def test_custom_compute_in_middle(self, param, lv, processor):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'BFV_custom_compute_in_middle', f'level_{lv}')
        x_list = [BfvCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [BfvCiphertextNode(level=lv, id=f'y_{i}') for i in range(N_OP)]

        m_list = [relin(mult(x_list[i], y_list[i], f'x_mult_y_{i}'), f'm_{i}') for i in range(N_OP)]
        z_list = []
        for i in range(N_OP):
            zi = BfvCiphertextNode(id=f'z_{i}', level=m_list[i].metadata.level)
            zi.metadata = m_list[i].metadata.copy()
            custom_compute(
                inputs=[m_list[i]],
                output=zi,
                type='custom_add',
            )
            zi = rotate_cols(zi, -990, f'rotated_z_{i}')[0]
            z_list.append(zi)

        z_sum = z_list[0]
        for i in range(1, len(z_list)):
            z_sum = add(z_sum, z_list[i], f'z_sum_{i}')

        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            output_args=[Argument('out_z_list', z_sum)],
            output_instruction_path=task_dir,
            processor=processor,
        )

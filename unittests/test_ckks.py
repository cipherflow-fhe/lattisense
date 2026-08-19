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
    from test_config import CPU_OUTPUT_BASE_DIR, GPU_OUTPUT_BASE_DIR
except ImportError:
    CPU_OUTPUT_BASE_DIR = os.path.join(current_dir, 'test_data', 'cpu')
    GPU_OUTPUT_BASE_DIR = os.path.join(current_dir, 'test_data', 'gpu')


_p1 = CkksParam.create_default_param(log_n=14)
_p2 = CkksParam.create_custom_param(
    log_n=13,
    q=[0x1FFFEC001, 0x3FFF4001, 0x3FFE8001, 0x40020001, 0x40038001, 0x3FFC0001],
    p=[0x800004001],
    log_scale=30,
)


N_OP = 4  # Number of parallel operators per test
SPARSE_LOG_SLOTS = 9
SPARSE_BINARY_RHS_LOG_SLOTS = 11

# ---- Define all CKKS parameter sets to be tested here ----
_CKKS_PARAM_TAGS = {
    id(_p1): f'ckks_param_default_n{_p1.n}',
    id(_p2): f'ckks_param_custom_n{_p2.n}',
}

CKKS_PARAMS = [_p1, _p2]
PROCESSORS = [Processor.CPU, Processor.GPU]


def _param_tag(param) -> str:
    return _CKKS_PARAM_TAGS[id(param)]


class TestTask:
    @pytest.mark.min_level(0)
    @pytest.mark.parametrize('is_ringt', [False, True], ids=['pt', 'pt-ringt'])
    def test_cap(self, param, lv, is_ringt, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        full_log_slots = param.log_n - 1
        slot_cases = [(full_log_slots, full_log_slots)]
        if param is _p1:
            slot_cases.append((SPARSE_LOG_SLOTS, SPARSE_BINARY_RHS_LOG_SLOTS))

        for lhs_log_slots, rhs_log_slots in slot_cases:
            task_name = 'cap_ringt' if is_ringt else 'cap'
            slot_tag = f'lslots{lhs_log_slots}_rslots{rhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_{task_name}',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            y_list = [
                CkksPlaintextNode(
                    id=f'y_{i}',
                    level=0 if is_ringt else lv,
                    is_ringt=is_ringt,
                    log_slots=rhs_log_slots,
                )
                for i in range(N_OP)
            ]
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
        full_log_slots = param.log_n - 1
        slot_cases = [(full_log_slots, full_log_slots)]
        if param is _p1:
            rhs_log_slots = SPARSE_LOG_SLOTS if same_input else SPARSE_BINARY_RHS_LOG_SLOTS
            slot_cases.append((SPARSE_LOG_SLOTS, rhs_log_slots))

        for lhs_log_slots, rhs_log_slots in slot_cases:
            task_name = 'casc' if same_input else 'cac'
            slot_tag = f'lslots{lhs_log_slots}' if same_input else f'lslots{lhs_log_slots}_rslots{rhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_{task_name}',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            if same_input:
                z_list = [add(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
                input_args = [Argument('in_x_list', x_list)]
            else:
                y_list = [CkksCiphertextNode(level=lv, id=f'y_{i}', log_slots=rhs_log_slots) for i in range(N_OP)]
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
        [('0_75', 0.75), ('minus_1', -1.0), ('i', 1j), ('minus_i', -1j)],
        ids=['0.75', '-1', 'i', '-i'],
    )
    def test_add_scalar(self, param, lv, scalar_tag, scalar, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        full_log_slots = param.log_n - 1
        slot_cases = [full_log_slots]
        if param is _p1:
            slot_cases.append(SPARSE_LOG_SLOTS)

        for lhs_log_slots in slot_cases:
            slot_tag = f'lslots{lhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_add_scalar',
                scalar_tag,
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
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
        full_log_slots = param.log_n - 1
        slot_cases = [(full_log_slots, full_log_slots)]
        if param is _p1:
            slot_cases.append((SPARSE_LOG_SLOTS, SPARSE_BINARY_RHS_LOG_SLOTS))

        for lhs_log_slots, rhs_log_slots in slot_cases:
            task_name = 'csp_ringt' if is_ringt else 'csp'
            slot_tag = f'lslots{lhs_log_slots}_rslots{rhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_{task_name}',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            y_list = [
                CkksPlaintextNode(
                    id=f'y_{i}',
                    level=0 if is_ringt else lv,
                    is_ringt=is_ringt,
                    log_slots=rhs_log_slots,
                )
                for i in range(N_OP)
            ]
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
        full_log_slots = param.log_n - 1
        slot_cases = [(full_log_slots, full_log_slots)]
        if param is _p1:
            rhs_log_slots = SPARSE_LOG_SLOTS if same_input else SPARSE_BINARY_RHS_LOG_SLOTS
            slot_cases.append((SPARSE_LOG_SLOTS, rhs_log_slots))

        for lhs_log_slots, rhs_log_slots in slot_cases:
            task_name = 'cssc' if same_input else 'csc'
            slot_tag = f'lslots{lhs_log_slots}' if same_input else f'lslots{lhs_log_slots}_rslots{rhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_{task_name}',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            if same_input:
                z_list = [sub(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
                input_args = [Argument('in_x_list', x_list)]
            else:
                y_list = [CkksCiphertextNode(level=lv, id=f'y_{i}', log_slots=rhs_log_slots) for i in range(N_OP)]
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
        [('0_75', 0.75), ('minus_1', -1.0), ('i', 1j), ('minus_i', -1j)],
        ids=['0.75', '-1', 'i', '-i'],
    )
    def test_sub_scalar(self, param, lv, scalar_tag, scalar, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        full_log_slots = param.log_n - 1
        slot_cases = [full_log_slots]
        if param is _p1:
            slot_cases.append(SPARSE_LOG_SLOTS)

        for lhs_log_slots in slot_cases:
            slot_tag = f'lslots{lhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_sub_scalar',
                scalar_tag,
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
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
        full_log_slots = param.log_n - 1
        slot_cases = [(full_log_slots, full_log_slots)]
        if param is _p1:
            slot_cases.append((SPARSE_LOG_SLOTS, SPARSE_BINARY_RHS_LOG_SLOTS))

        for lhs_log_slots, rhs_log_slots in slot_cases:
            task_name = 'cmp_ringt' if is_ringt else 'cmp'
            slot_tag = f'lslots{lhs_log_slots}_rslots{rhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_{task_name}',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            y_list = [
                CkksPlaintextNode(
                    id=f'y_{i}',
                    level=0 if is_ringt else lv,
                    is_ringt=is_ringt,
                    log_slots=rhs_log_slots,
                )
                for i in range(N_OP)
            ]
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
        [('0_75', 0.75), ('minus_1', -1.0), ('i', 1j), ('minus_i', -1j)],
        ids=['0.75', '-1', 'i', '-i'],
    )
    def test_mult_scalar(self, param, lv, scalar_tag, scalar, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        full_log_slots = param.log_n - 1
        slot_cases = [full_log_slots]
        if param is _p1:
            slot_cases.append(SPARSE_LOG_SLOTS)

        for lhs_log_slots in slot_cases:
            slot_tag = f'lslots{lhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_mult_scalar',
                scalar_tag,
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
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
        full_log_slots = param.log_n - 1
        slot_cases = [(full_log_slots, full_log_slots)]
        if param is _p1:
            rhs_log_slots = SPARSE_LOG_SLOTS if same_input else SPARSE_BINARY_RHS_LOG_SLOTS
            slot_cases.append((SPARSE_LOG_SLOTS, rhs_log_slots))

        for lhs_log_slots, rhs_log_slots in slot_cases:
            task_name = 'csqr' if same_input else 'cmc'
            slot_tag = f'lslots{lhs_log_slots}' if same_input else f'lslots{lhs_log_slots}_rslots{rhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_{task_name}',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            if same_input:
                z_list = [mult(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
                input_args = [Argument('in_x_list', x_list)]
            else:
                y_list = [CkksCiphertextNode(level=lv, id=f'y_{i}', log_slots=rhs_log_slots) for i in range(N_OP)]
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
        full_log_slots = param.log_n - 1
        slot_cases = [(full_log_slots, full_log_slots)]
        if param is _p1:
            rhs_log_slots = SPARSE_LOG_SLOTS if same_input else SPARSE_BINARY_RHS_LOG_SLOTS
            slot_cases.append((SPARSE_LOG_SLOTS, rhs_log_slots))

        for lhs_log_slots, rhs_log_slots in slot_cases:
            task_name = 'csqr_relin' if same_input else 'cmc_relin'
            slot_tag = f'lslots{lhs_log_slots}' if same_input else f'lslots{lhs_log_slots}_rslots{rhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_{task_name}',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            if same_input:
                z_list = [mult_relin(x_list[i], x_list[i], f'z_{i}') for i in range(N_OP)]
                input_args = [Argument('in_x_list', x_list)]
            else:
                y_list = [CkksCiphertextNode(level=lv, id=f'y_{i}', log_slots=rhs_log_slots) for i in range(N_OP)]
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
        full_log_slots = param.log_n - 1
        slot_cases = [(full_log_slots, full_log_slots)]
        if param is _p1:
            rhs_log_slots = SPARSE_LOG_SLOTS if same_input else SPARSE_BINARY_RHS_LOG_SLOTS
            slot_cases.append((SPARSE_LOG_SLOTS, rhs_log_slots))

        for lhs_log_slots, rhs_log_slots in slot_cases:
            task_name = 'csqr_relin_rescale' if same_input else 'cmc_relin_rescale'
            slot_tag = f'lslots{lhs_log_slots}' if same_input else f'lslots{lhs_log_slots}_rslots{rhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_{task_name}',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            if same_input:
                z_list = [rescale(mult_relin(x_list[i], x_list[i]), f'z_{i}') for i in range(N_OP)]
                input_args = [Argument('in_x_list', x_list)]
            else:
                y_list = [CkksCiphertextNode(level=lv, id=f'y_{i}', log_slots=rhs_log_slots) for i in range(N_OP)]
                z_list = [rescale(mult_relin(x_list[i], y_list[i]), f'z_{i}') for i in range(N_OP)]
                input_args = [Argument('in_x_list', x_list), Argument('in_y_list', y_list)]
            process_custom_task(
                input_args=input_args,
                output_args=[Argument('out_z_list', z_list)],
                output_instruction_path=task_dir,
                processor=processor,
            )

    @pytest.mark.min_level(1)
    def test_rescale(self, param, lv, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        full_log_slots = param.log_n - 1
        slot_cases = [full_log_slots]
        if param is _p1:
            slot_cases.append(SPARSE_LOG_SLOTS)

        for lhs_log_slots in slot_cases:
            slot_tag = f'lslots{lhs_log_slots}'
            task_dir = os.path.join(output_base_dir, param_tag, f'CKKS_{N_OP}_rescale', slot_tag, f'level_{lv}')
            input_scale = param.default_scale * float(param.q[lv])
            x_list = [
                CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots, scale=input_scale)
                for i in range(N_OP)
            ]
            y_list = [rescale(x_list[i], f'y_{i}') for i in range(N_OP)]
            process_custom_task(
                input_args=[Argument('in_x_list', x_list)],
                output_args=[Argument('out_y_list', y_list)],
                output_instruction_path=task_dir,
                processor=processor,
            )

    @pytest.mark.min_level(2)
    def test_drop_level(self, param, lv, processor, drop_lv=2):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        full_log_slots = param.log_n - 1
        slot_cases = [full_log_slots]
        if param is _p1:
            slot_cases.append(SPARSE_LOG_SLOTS)

        for lhs_log_slots in slot_cases:
            slot_tag = f'lslots{lhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_drop_level',
                f'drop_{drop_lv}',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            y_list = [drop_level(x_list[i], drop_lv, f'y_{i}') for i in range(N_OP)]
            process_custom_task(
                input_args=[Argument('in_x_list', x_list)],
                output_args=[Argument('out_y_list', y_list)],
                output_instruction_path=task_dir,
                processor=processor,
            )

    @pytest.mark.min_level(1)
    @pytest.mark.parametrize('use_default_rotation_keys', [True, False], ids=['default', 'non-default'])
    def test_rotate_col(self, param, lv, use_default_rotation_keys, processor, steps=[i + 1 for i in range(8)]):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        full_log_slots = param.log_n - 1
        slot_cases = [full_log_slots]
        if param is _p1:
            slot_cases.append(SPARSE_LOG_SLOTS)

        for lhs_log_slots in slot_cases:
            steps_tag = f'steps_{steps[0]}_to_{steps[-1]}'
            key_mode_tag = 'default' if use_default_rotation_keys else 'non-default'
            slot_tag = f'lslots{lhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_rotate_col',
                steps_tag,
                key_mode_tag,
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
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
    def test_conjugate(self, param, lv, processor):
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        full_log_slots = param.log_n - 1
        slot_cases = [full_log_slots]
        if param is _p1:
            slot_cases.append(SPARSE_LOG_SLOTS)

        for lhs_log_slots in slot_cases:
            slot_tag = f'lslots{lhs_log_slots}'
            task_dir = os.path.join(output_base_dir, param_tag, f'CKKS_{N_OP}_conjugate', slot_tag, f'level_{lv}')
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            y_list = [conjugate(x_list[i], f'rotated_x_{i}') for i in range(N_OP)]
            process_custom_task(
                input_args=[Argument('arg_x', x_list)],
                output_args=[Argument('arg_y', y_list)],
                output_instruction_path=task_dir,
                processor=processor,
            )

    @pytest.mark.min_level(1)
    def test_ct_pt_ringt_mac(self, param, lv, processor):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        for m in range(2, 21):
            task_dir = os.path.join(output_base_dir, param_tag, f'CKKS_cmpac_ringt', f'level_{lv}_m_{m}')
            c_list = [CkksCiphertextNode(level=lv, id=f'c_{i}') for i in range(m)]
            p_list = [CkksPlaintextNode(id=f'p_{i}', is_ringt=True) for i in range(m)]
            z = ct_pt_mult_accumulate(c_list, p_list)
            process_custom_task(
                input_args=[Argument('in_c_list', c_list), Argument('in_p_list', p_list)],
                output_args=[Argument('out_z_list', [z])],
                output_instruction_path=task_dir,
                processor=processor,
            )

    @pytest.mark.min_level(1)
    def test_custom_encode_and_cap(self, param, lv, processor):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, f'CKKS_{N_OP}_custom_encode_and_cap', f'level_{lv}')
        x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}') for i in range(N_OP)]
        y_list = [CustomDataNode(type='msg', id=f'y_{i}') for i in range(N_OP)]
        z_list = []
        for i in range(N_OP):
            encoded_y = CkksPlaintextNode(id=f'encoded_y_{i}', level=x_list[i].metadata.level, is_ringt=False)
            custom_compute(
                inputs=[y_list[i]],
                output=encoded_y,
                type='encode',
                attributes={'level': x_list[i].metadata.level, 'scale': pow(2.0, 34)},
            )
            z_list.append(add(x_list[i], encoded_y, f'z_{i}'))
        process_custom_task(
            input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
            output_args=[Argument('out_z_list', z_list)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.at_level(4)
    def test_n_poly(self, param, lv, processor):
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        if param.max_level < 4:
            pytest.skip(f'requires max_level >= 4, got {param.max_level}')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        task_dir = os.path.join(output_base_dir, param_tag, 'CKKS_n_poly', f'level_{lv}')
        x = CkksCiphertextNode(level=4, id='x')
        coeff0 = CkksPlaintextNode(id='a_0', level=1, is_ringt=False)
        coeffs = [CkksPlaintextNode(id=f'a_{i}', is_ringt=True) for i in range(1, 4)]
        x1_lv4 = x
        x2_lv3 = rescale(mult_relin(x1_lv4, x1_lv4))
        x2_lv2 = drop_level(x2_lv3, drop_level=1)
        x1_lv3 = drop_level(x1_lv4, drop_level=1)
        x1_lv2 = drop_level(x1_lv3, drop_level=1)
        x3_lv2 = rescale(mult_relin(x1_lv3, x2_lv3))
        x_powers = [x1_lv2, x2_lv2, x3_lv2]
        y = coeff0
        for i in range(3):
            y = add(y, rescale(mult(x_powers[i], coeffs[i])))
        process_custom_task(
            input_args=[Argument('x', x), Argument('coeff0', coeff0), Argument('coeffs', coeffs)],
            output_args=[Argument('y', y)],
            output_instruction_path=task_dir,
            processor=processor,
        )

    @pytest.mark.at_level(0)
    def test_bootstrap(self, param, lv, processor):
        if processor == Processor.GPU:
            pytest.skip('GPU bootstrap is temporarily disabled')
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        slot_cases = [param.log_n - 1, SPARSE_LOG_SLOTS]
        for log_slots in slot_cases:
            slot_tag = f'lslots{log_slots}'
            task_dir = os.path.join(output_base_dir, param_tag, f'CKKS_{N_OP}_bootstrap', slot_tag, f'level_{lv}')
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=log_slots) for i in range(N_OP)]
            y_list = [bootstrap(x_list[i], f'y_{i}') for i in range(N_OP)]
            process_custom_task(
                input_args=[Argument('in_x_list', x_list)],
                output_args=[Argument('out_y_list', y_list)],
                output_instruction_path=task_dir,
                processor=processor,
            )

    @pytest.mark.at_level(3)
    def test_cmc_relin_rescale_bootstrap(self, param, lv, processor):
        if processor == Processor.GPU:
            pytest.skip('GPU bootstrap is temporarily disabled')
        if param is not _p1:
            pytest.skip('only runs for default param (n=16384)')
        set_fhe_param(param)
        param_tag = _param_tag(param)
        output_base_dir = CPU_OUTPUT_BASE_DIR if processor == Processor.CPU else GPU_OUTPUT_BASE_DIR
        slot_cases = [(param.log_n - 1, param.log_n - 1), (SPARSE_LOG_SLOTS, SPARSE_BINARY_RHS_LOG_SLOTS)]
        for lhs_log_slots, rhs_log_slots in slot_cases:
            slot_tag = f'lslots{lhs_log_slots}_rslots{rhs_log_slots}'
            task_dir = os.path.join(
                output_base_dir,
                param_tag,
                f'CKKS_{N_OP}_cmc_relin_rescale_bootstrap',
                slot_tag,
                f'level_{lv}',
            )
            x_list = [CkksCiphertextNode(level=lv, id=f'x_{i}', log_slots=lhs_log_slots) for i in range(N_OP)]
            y_list = [CkksCiphertextNode(level=lv, id=f'y_{i}', log_slots=rhs_log_slots) for i in range(N_OP)]
            z_list = []
            for i in range(N_OP):
                z = mult_relin(x_list[i], y_list[i], f'z_relin_{i}')
                z_rescaled = rescale(z, f'z_rescaled_{i}')
                z_dropped = drop_level(z_rescaled, drop_level=2, output_id=f'z_dropped_{i}')
                z_list.append(bootstrap(z_dropped, f'z_{i}'))
            process_custom_task(
                input_args=[Argument('in_x_list', x_list), Argument('in_y_list', y_list)],
                output_args=[Argument('out_z_list', z_list)],
                output_instruction_path=task_dir,
                processor=processor,
            )

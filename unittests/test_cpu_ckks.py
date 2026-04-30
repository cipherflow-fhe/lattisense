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
import random
from typing import Optional

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
    # n_op=4：默认同时进行 4 组加法运算（即 4 对密文）
    # levels：一个列表，默认从 0 到 param.max_level，表示要测试的密文模数链级别（level）。不同 level 对应不同精度和容量
    def test_cac(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        # 内部定义 cac 函数
        # 输入两个列表 x 和 y，长度相同。个索引 i，调用 add(x[i], y[i], f'z_{i}')，生成一个新的节点（DataNode 类型），命名为 f'z_{i}'。
        # 将所有 z 节点收集到 z_list 并返回。
        # 这个 add 就是同态加法算子，它返回的结果节点代表两个密文相加后的密文
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

###########################################################################################################################################
## 新增测试
###########################################################################################################################################
    # 指数函数测试
    def test_exp(self, n_op=4, levels=[7, 8]):
        """Test exponential function approximation."""
        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_exp_n{n_op}_lv{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(n_op)]
                exp_list = [
                    poly_eval(x=x_list[i], func='exp', degree = 6, left = -1.0, right = 1.0, output_id=f'exp_{i}')
                    for i in range(n_op)
                ]

                arg_x = Argument('in_x_list', x_list)
                arg_exp = Argument('out_exp_list', exp_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_exp],
                    output_instruction_path=task_dir,
                )

    # 多项式计算测试
    def test_reciprocal(self, n_op=4, levels=[8, 9]):
        """Test reciprocal function approximation."""
        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'CKKS_reciprocal_n{n_op}_lv{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(n_op)]
                reciprocal_list = [
                    poly_eval(x=x_list[i], func='reciprocal', degree = 6, left = 1.0, right = 5.0, output_id=f'reciprocal_{i}')
                    for i in range(n_op)
                ]
                arg_x = Argument('in_x_list', x_list)
                arg_reciprocal = Argument('out_reciprocal_list', reciprocal_list)
                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_reciprocal],
                    output_instruction_path=task_dir,
                )
    # 迭代计算测试
    def test_newton_reciprocal(self, n_op=4, iterations=4, init_guess=1.0, input_range=(0.5, 1.5), levels=[8, 9]):
        """
        测试牛顿倒数算子 (NewtonReciprocalComputeNode)。
    
        参数:
        n_op: 批处理密文数量
        iterations: 牛顿迭代次数
        init_guess: 初始猜测值（密文初始化）
        input_range: 输入值的有效收敛区间 (min, max)
        levels: 要测试的 CKKS level 列表，默认为 [5, 6, 7, 8, 9, 10]
        """
        if levels is None:
            max_lv = param.max_level
            levels = [lv for lv in range(5, max_lv + 1) if lv - 2 * iterations >= 0]
        for lv in levels:
            output_level = lv - 2 * iterations
            if output_level < 0:
                print(f"跳过 level={lv}，因为深度不足以完成 {iterations} 次迭代")
                continue
        
            with self.subTest(n=n_op, lv=lv, iter=iterations):
                task = f'CKKS_newtonreciprocal_n{n_op}_lv{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)
            
            # 创建计算图节点
                x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(n_op)]
                z_list = [newton_reciprocal(x_list[i], iterations=iterations, init_guess=init_guess, output_id=f'inv_{i}')
                        for i in range(n_op)
                ]
            
            # 构建任务参数
                arg_x = Argument('in_x_list', x_list)
                arg_z = Argument('out_z_list', z_list)
            
            # 导出任务指令
                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )
                print(f"已生成任务: {task_dir}")

    # 迭代计算测试
    def test_goldschmidt_reciprocal(self, n_op=4, iterations=4, levels=[8, 9]):
        """
        测试倒数算子 (GoldschmidtReciprocalComputeNode)。
    
        参数:
        n_op: 批处理密文数量
        iterations: 迭代次数
        init_guess: 初始猜测值（密文初始化）
        """
        if levels is None:
            max_lv = param.max_level
            levels = [lv for lv in range(5, max_lv + 1) if lv - iterations >= 0]
        for lv in levels:
            output_level = lv - iterations - 1
            if output_level < 0:
                print(f"跳过 level={lv}，因为深度不足以完成 {iterations} 次迭代")
                continue
        
            with self.subTest(n=n_op, lv=lv, iter=iterations):
                task = f'CKKS_goldschmidtreciprocal_n{n_op}_lv{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)
            
            # 创建计算图节点
                # 输入 1: 待求倒数的值 x
                x_list = [CkksCiphertextNode(f'x_{i}', level=lv) for i in range(n_op)]
                # 输入 2: 初始猜测值 y_init (作为密文传入，设定同样的初始 Level)
                y_init_list = [CkksCiphertextNode(f'y_init_{i}', level=lv) for i in range(n_op)]
                # 调用前端图构建函数，传入两个密文节点
                z_list = [goldschmidt_reciprocal(x=x_list[i], init_guess=y_init_list[i], iterations=iterations, output_id=f'inv_{i}')
                        for i in range(n_op)
                ]
                arg_x = Argument('in_x_list', x_list)
                arg_y_init = Argument('in_y_init_list', y_init_list) # 新增的输入参数
                arg_z = Argument('out_z_list', z_list)
            
                process_custom_task(
                    input_args=[arg_x, arg_y_init],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )
                print(f"已生成任务: {task_dir}")

    # chebyshev+自举测试
    def test_poly_chebyshev_bootstrap_toy(self, n_op=4, levels=[7]):
        # 使用支持自举的参数
        param = CkksBtpParam.create_toy_param()
        set_fhe_param(param)

        def poly_bootstrap_logic(x: DataNode, idx: int) -> DataNode:
            z = poly_eval(
                x=x, 
                func="reciprocal", 
                degree=6, 
                left=1.0, 
                right=5.0, 
                output_id=f'poly_z_{idx}'
            )   
            result = bootstrap(z, f'btp_result_{idx}')
            return result
        for lv in levels:
            current_lv = lv[0] if isinstance(lv, list) else lv

            with self.subTest(n=n_op, lv=current_lv):
                task = f'CKKS_{n_op}_poly_bootstrap_toy/level_{current_lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                # 准备输入列表
                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=current_lv))
                # 准备结果列表 (通过调用逻辑函数)
                result_list = []
                for i in range(n_op):
                    result_list.append(poly_bootstrap_logic(x_list[i], i))

                # 构建并生成任务
                arg_x = Argument('in_x_list', x_list)
                arg_result = Argument('out_z_list', result_list)

                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_result],
                    output_instruction_path=task_dir,
                )
            # 恢复默认参数，防止影响后续测试
            default_param = Param.create_ckks_default_param(n=16384)
            set_fhe_param(default_param)

    def test_goldschmidt_bootstrap_toy(self, n_op=4, iterations=4, levels=[0]):
        """
        测试自举+倒数算子 (GoldschmidtReciprocalComputeNode)。
    
        参数:
        n_op: 批处理密文数量
        iterations: 迭代次数
        init_guess: 初始猜测值（密文初始化）
        """
        # 使用支持自举的参数
        param = CkksBtpParam.create_toy_param()
        set_fhe_param(param)

        def bootstrap_goldschmidt(x: DataNode, y: DataNode, idx: int) -> DataNode:
            z0 = bootstrap(y, f'btp_result0_{idx}')
            z1 = bootstrap(x, f'btp_result1_{idx}')
            # 第二步：迭代 (只有完成自举后才能执行)
            result = goldschmidt_reciprocal(x=z1, init_guess=z0, iterations=iterations, output_id=f'inv_{idx}')
            return result
        
        for lv in levels:
            with self.subTest(n=n_op, lv=lv, iter=iterations):
                task = f'CKKS_goldschmidt_btstoy_reciprocal_n{n_op}_lv{lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)
            
            # 创建计算图节点
                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(CkksCiphertextNode(f'y_{i}', level=lv))
                # 准备结果列表
                z_list = []
                for i in range(n_op):
                    z_list.append(bootstrap_goldschmidt(x_list[i], y_list[i], i))

                arg_x = Argument('in_x_list', x_list)
                arg_y_init = Argument('in_y_init_list', y_list) # 新增的输入参数
                arg_z = Argument('out_z_list', z_list)

                process_custom_task(
                    input_args=[arg_x, arg_y_init],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )
                print(f"已生成任务: {task_dir}")
            default_param = Param.create_ckks_default_param(n=16384)
            set_fhe_param(default_param)

    # chebyshev+自举+goldschmidt测试
    def test_poly_chebyshev_bootstrap_toy_goldschmidt(self, n_op=4, iterations=3, levels=[9]):
        param = CkksBtpParam.create_toy_param()
        set_fhe_param(param)

        def poly_bootstrap_logic(x: DataNode, idx: int) -> DataNode:
            z1 = poly_eval(
                x=x, 
                func="reciprocal", 
                degree=4, 
                left=1.0, 
                right=10.0, 
                output_id=f'poly_z_{idx}'
            )  
            z2 = drop_level(z1, 4, f'drop_{idx}')
            btp_res = bootstrap(z2, f'btp_result_{idx}')
            result = goldschmidt_reciprocal(x=x, init_guess=btp_res, iterations=iterations, output_id=f'inv_{idx}')
            return z1, btp_res, result
        
        for lv in levels:
            current_lv = lv[0] if isinstance(lv, list) else lv

            with self.subTest(n=n_op, lv=current_lv, iter=iterations):
                task = f'CKKS_{n_op}_poly_bootstrap_toy_goldschmidt/level_{current_lv}'
                task_dir = os.path.join(CPU_OUTPUT_BASE_DIR, task)

                # 准备输入列表
                x_list = []
                for i in range(n_op):
                    x_list.append(CkksCiphertextNode(f'x_{i}', level=current_lv))
                # 准备结果列表
                z1_list = []
                bts_list = []
                result_list = []
                for i in range(n_op):
                    node_z1, node_bts, node_res = poly_bootstrap_logic(x_list[i], i)
                    z1_list.append(node_z1)
                    bts_list.append(node_bts)
                    result_list.append(node_res)

                # 构建并生成任务
                arg_x = Argument('in_x_list', x_list)
                arg_z1 = Argument('out_z1_list', z1_list)   
                arg_bts = Argument('out_bts_list', bts_list)
                arg_result = Argument('out_z_list', result_list)  # 真正的输出

                # 生成图
                process_custom_task(
                    input_args=[arg_x],
                    offline_input_args=[],
                    output_args=[arg_result, arg_z1, arg_bts],
                    output_instruction_path=task_dir,
                )
            default_param = Param.create_ckks_default_param(n=16384)
            set_fhe_param(default_param)


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

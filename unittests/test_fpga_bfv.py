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
    from test_config import FPGA_OUTPUT_BASE_DIR
except ImportError:
    FPGA_OUTPUT_BASE_DIR = os.path.join(current_dir, 'test_data', 'fpga_tests', 'noc_config_16c_3')

param = Param.create_bfv_fpga_param(t=0x1B4001)


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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_cac(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cac(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(add(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cac/level_{lv}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_csc(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def csc(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(sub(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_csc/level_{lv}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_cneg(self, n_op=4, levels=[i for i in range(0, param.max_level + 1)]):
        def cneg(x: list[DataNode]) -> DataNode:
            z_list = []
            for i in range(len(x_list)):
                z_list.append(neg(x[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cneg/level_{lv}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_cmp(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode], lv) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(mult(x[i], y[i], f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmp/level_{lv}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                )

    def test_ct_mul_mult_pt_ringt(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode], lv) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(to_inv_ntt(mult(to_mul(x[i]), y[i]), f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmp_ct-mul_pt-ringt/level_{lv}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_ct_ntt_mult_pt_ringt(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode], lv) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(to_inv_ntt(mult(to_ntt(x[i]), y[i]), f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmp_ct-ntt_pt-ringt/level_{lv}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    @unittest.skip('')
    def test_ct_mult_compressed_pt_ringt(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def cmp(x: list[DataNode], y: list[DataNode], cstarts: list[int], lv) -> DataNode:
            z_list = []
            for i in range(len(x)):
                z_list.append(mult(x[i], y[i], start_block_idx=cstarts[i], output_id=f'z_{i}'))
            return z_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_cmp_ct_compressed_pt_ringt/level_{lv}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

                x_list = []
                y_list = []
                for i in range(n_op):
                    x_list.append(BfvCiphertextNode(f'x_{i}', level=lv))
                    y_list.append(
                        BfvCompressedPlaintextRingtNode(
                            compressed_block_info=[[0, 2], [2, 4], [4, 7], [7, 10]], id=f'y_{i}'
                        )
                    )

                z_list = cmp(x_list, y_list, [1, 2, 3, 1], lv)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
        self, n_op=4, levels=[i for i in range(1, param.max_level + 1)], steps=[i + 1 for i in range(128)]
    ):
        def rotate_steps(x: list[DataNode], steps: list[int]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(rotate_cols(x[i], steps, f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv, steps=steps):
                task = f'BFV_{n_op}_rotate_col/level_{lv}/steps_{steps[0]}_to_{steps[-1]}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    # @unittest.skip('')
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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_advanced_rotate_col_imul(
        self, n_op=4, levels=[i for i in range(1, param.max_level + 1)], steps=[-900, 20, 400, 2000, 3009]
    ):
        def rotate_steps(x: list[DataNode], steps: list[int]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(advanced_rotate_cols(to_mul(x[i]), steps, f'rotated_x_{i}', out_ct_type='ct'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv, steps=steps):
                steps_str = '_'.join(map(str, steps))
                task = f'BFV_{n_op}_advanced_rotate_col_imul/level_{lv}/steps_{steps_str}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_advanced_rotate_col_imul_ontt(
        self, n_op=4, levels=[i for i in range(1, param.max_level + 1)], steps=[-900, 20, 400, 2000, 3009]
    ):
        def rotate_steps(x: list[DataNode], steps: list[int]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                tmp = advanced_rotate_cols(to_mul(x[i]), steps, f'rotated_x_{i}', out_ct_type='ct-ntt')
                y_list.append([to_inv_ntt(t) for t in tmp])
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv, steps=steps):
                steps_str = '_'.join(map(str, steps))
                task = f'BFV_{n_op}_advanced_rotate_col_imul_ontt/level_{lv}/steps_{steps_str}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_advanced_rotate_col_intt_ontt(
        self, n_op=4, levels=[i for i in range(1, param.max_level + 1)], steps=[-900, 20, 400, 2000, 3009]
    ):
        def rotate_steps(x: list[DataNode], steps: list[int]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                tmp = advanced_rotate_cols(to_ntt(x[i]), steps, f'rotated_x_{i}', out_ct_type='ct-ntt')
                y_list.append([to_inv_ntt(t) for t in tmp])
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv, steps=steps):
                steps_str = '_'.join(map(str, steps))
                task = f'BFV_{n_op}_advanced_rotate_col_intt_ontt/level_{lv}/steps_{steps_str}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    # @unittest.skip('')
    def test_seal_rotate_row(self, n_op=4, levels=[param.max_level]):
        def rotate(x: list[DataNode]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(seal_rotate_rows(x[i], f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_seal_rotate_row/level_{lv}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    # @unittest.skip('')
    def test_seal_rotate_col(self, n_op=4, levels=[param.max_level], steps=[-900, 20, 400, 2000, 3009]):
        def rotate_steps(x: list[DataNode], steps: list[int]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(seal_rotate_cols(x[i], steps, f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv, steps=steps):
                steps_str = '_'.join(map(str, steps))
                task = f'BFV_{n_op}_seal_rotate_col/level_{lv}/steps_{steps_str}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    # @unittest.skip('')
    def test_seal_advanced_rotate_col(self, n_op=4, levels=[param.max_level], steps=[-900, 20, 400, 2000, 3009]):
        def rotate_steps(x: list[DataNode], steps: list[int]) -> DataNode:
            y_list = []
            for i in range(len(x_list)):
                y_list.append(seal_advanced_rotate_cols(x[i], steps, f'rotated_x_{i}'))
            return y_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv, steps=steps):
                steps_str = '_'.join(map(str, steps))
                task = f'BFV_{n_op}_seal_advanced_rotate_col/level_{lv}/steps_{steps_str}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_rescale(self, n_op=4, levels=[i for i in range(1, param.max_level + 1)]):
        def rescale_l(x: list[DataNode]) -> DataNode:
            res_list = []
            for i in range(len(x_list)):
                res_list.append(rescale(x[i], f'y_{i}'))
            return res_list

        for lv in levels:
            with self.subTest(n=n_op, lv=lv):
                task = f'BFV_{n_op}_rescale/level_{lv}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
            task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
            task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
            task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
            task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    def test_one_block_diff_cal(self):
        """单个block 相同算子 不同level"""

        def one_block_diff_cal(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            z_0 = mult_relin(x[0], y[0], 'z_0')
            z_1 = mult_relin(x[1], y[1], 'z_1')
            z_2 = mult_relin(x[2], y[2], 'z_2')
            z_3 = mult_relin(x[3], y[3], 'z_3')

            z_list = [z_0, z_1, z_2, z_3]
            return z_list

        task = 'BFV_one_block_diff/'
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

        x_list = []
        y_list = []
        x_0 = BfvCiphertextNode('x_0', level=3)
        x_1 = BfvCiphertextNode('x_1', level=5)
        x_2 = BfvCiphertextNode('x_2', level=2)
        x_3 = BfvCiphertextNode('x_3', level=1)
        x_list.extend([x_0, x_1, x_2, x_3])

        y_0 = BfvCiphertextNode('y_0', level=3)
        y_1 = BfvCiphertextNode('y_1', level=5)
        y_2 = BfvCiphertextNode('y_2', level=2)
        y_3 = BfvCiphertextNode('y_3', level=1)
        y_list.extend([y_0, y_1, y_2, y_3])

        z_list = one_block_diff_cal(x_list, y_list)

        arg_x = Argument('in_x_list', x_list)
        arg_y = Argument('in_y_list', y_list)
        arg_z = Argument('out_z_list', z_list)

        process_custom_task(
            input_args=[arg_x, arg_y],
            offline_input_args=[],
            output_args=[arg_z],
            output_instruction_path=task_dir,
        )

    def test_one_block_diff_cal_2(self, levels=[3]):
        """单个block 不同算子 相同level"""

        def one_block_diff_cal(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            z_0 = mult_relin(x[0], y[0], 'z_0')
            z_1 = advanced_rotate_cols(x[1], steps=1, output_id='z_1')
            z_2 = mult_relin(x[2], y[1], 'z_2')
            z_3 = advanced_rotate_cols(x[3], steps=1, output_id='z_3')

            z_list = [z_0, z_1[0], z_2, z_3[0]]
            return z_list

        for lv in levels:
            task = 'BFV_one_block_diff_2'
            task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, f'{task}/level_{lv}')

            x_list = []
            y_list = []
            x_0 = BfvCiphertextNode('x_0', level=lv)
            x_1 = BfvCiphertextNode('x_1', level=lv)
            x_2 = BfvCiphertextNode('x_2', level=lv)
            x_3 = BfvCiphertextNode('x_3', level=lv)
            x_list.extend([x_0, x_1, x_2, x_3])

            y_0 = BfvCiphertextNode('y_0', level=lv)
            y_1 = BfvCiphertextNode('y_1', level=lv)

            y_list.extend([y_0, y_1])

            z_list = one_block_diff_cal(x_list, y_list)

            arg_x = Argument('in_x_list', x_list)
            arg_y = Argument('in_y_list', y_list)
            arg_z = Argument('out_z_list', z_list)

            process_custom_task(
                input_args=[arg_x, arg_y],
                offline_input_args=[],
                output_args=[arg_z],
                output_instruction_path=task_dir,
            )

    def test_one_block_diff_cal_3(self):
        """单个block 不同算子 不同level"""

        def one_block_diff_cal(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            z_0 = mult_relin(x[0], y[0], 'z_0')
            z_1 = advanced_rotate_cols(x[1], steps=1, output_id='z_1')
            z_2 = mult_relin(x[2], y[1], 'z_2')
            z_3 = advanced_rotate_cols(x[3], steps=3, output_id='z_3')

            z_list = [z_0, z_1[0], z_2, z_3[0]]
            return z_list

        task = 'BFV_one_block_diff_3/'
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

        x_list = []
        y_list = []
        x_0 = BfvCiphertextNode('x_0', level=1)
        x_1 = BfvCiphertextNode('x_1', level=2)
        x_2 = BfvCiphertextNode('x_2', level=3)
        x_3 = BfvCiphertextNode('x_3', level=5)
        x_list.extend([x_0, x_1, x_2, x_3])

        y_0 = BfvCiphertextNode('y_0', level=1)
        y_1 = BfvCiphertextNode('y_1', level=3)
        y_list.extend([y_0, y_1])

        z_list = one_block_diff_cal(x_list, y_list)

        arg_x = Argument('in_x_list', x_list)
        arg_y = Argument('in_y_list', y_list)
        arg_z = Argument('out_z_list', z_list)

        process_custom_task(
            input_args=[arg_x, arg_y],
            offline_input_args=[],
            output_args=[arg_z],
            output_instruction_path=task_dir,
        )

    def test_one_block_diff_cal_4(self):
        """两个(多个) block 不同算子 不同level 无数据依赖"""

        def one_block_diff_cal(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            z_0 = mult_relin(x[0], y[0], 'z_0')  # lv 5      q2-0
            z_1 = advanced_rotate_cols(x[1], steps=1, output_id='z_1')  # lv 1      q3-0
            z_2 = mult_relin(x[2], y[1], 'z_2')  # lv 5      q0-1
            z_3 = advanced_rotate_cols(x[3], steps=3, output_id='z_3')  # lv 1      q0-0

            z_4 = advanced_rotate_cols(x[4], steps=1, output_id='z_4')  # lv 1      q3-1
            z_5 = mult_relin(x[5], y[2], 'z_5')  # lv 4      q1-1
            z_6 = advanced_rotate_cols(x[6], steps=3, output_id='z_6')  # lv 1      q1-0
            z_7 = mult_relin(x[7], y[3], 'z_7')  # lv 3      q3-2

            z_list = [z_0, z_1[0], z_2, z_3[0], z_4[0], z_5, z_6[0], z_7]
            return z_list

        task = 'BFV_one_block_diff_4/'
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

        x_list = []
        y_list = []
        x_0 = BfvCiphertextNode('x_0', level=5)
        x_1 = BfvCiphertextNode('x_1', level=1)
        x_2 = BfvCiphertextNode('x_2', level=5)
        x_3 = BfvCiphertextNode('x_3', level=1)
        x_4 = BfvCiphertextNode('x_4', level=1)
        x_5 = BfvCiphertextNode('x_5', level=4)
        x_6 = BfvCiphertextNode('x_6', level=1)
        x_7 = BfvCiphertextNode('x_7', level=3)
        x_list.extend([x_0, x_1, x_2, x_3, x_4, x_5, x_6, x_7])

        y_0 = BfvCiphertextNode('y_0', level=5)
        y_1 = BfvCiphertextNode('y_1', level=5)
        y_2 = BfvCiphertextNode('y_2', level=4)
        y_3 = BfvCiphertextNode('y_3', level=3)
        y_list.extend([y_0, y_1, y_2, y_3])

        z_list = one_block_diff_cal(x_list, y_list)

        arg_x = Argument('in_x_list', x_list)
        arg_y = Argument('in_y_list', y_list)
        arg_z = Argument('out_z_list', z_list)

        process_custom_task(
            input_args=[arg_x, arg_y],
            offline_input_args=[],
            output_args=[arg_z],
            output_instruction_path=task_dir,
        )

    def test_one_block_diff_cal_5(self):
        """两个(多个) block 不同算子 不同level 有数据依赖"""

        def one_block_diff_cal(x: list[DataNode], y: list[DataNode]) -> DataNode:
            z_list = []
            t_0 = mult_relin(x[0], y[0], 't_0')
            t_1 = advanced_rotate_cols(x[1], steps=1, output_id='t_1')
            t_2 = mult_relin(x[2], y[1], 't_2')
            t_3 = advanced_rotate_cols(x[3], steps=3, output_id='t_3')

            z_0 = mult_relin(t_0, t_1[0], 'z_0')
            z_1 = advanced_rotate_cols(t_1[0], steps=1, output_id='z_1')
            z_2 = mult_relin(t_2, t_3[0], 'z_2')
            z_3 = advanced_rotate_cols(t_3[0], steps=3, output_id='z_3')

            z_list = [z_0, z_1[0], z_2, z_3[0]]
            return z_list

        task = 'BFV_one_block_diff_5/'
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

        x_list = []
        y_list = []
        x_0 = BfvCiphertextNode('x_0', level=5)
        x_1 = BfvCiphertextNode('x_1', level=5)
        x_2 = BfvCiphertextNode('x_2', level=3)
        x_3 = BfvCiphertextNode('x_3', level=3)
        x_list.extend([x_0, x_1, x_2, x_3])

        y_0 = BfvCiphertextNode('y_0', level=5)
        y_1 = BfvCiphertextNode('y_1', level=3)
        y_list.extend([y_0, y_1])

        z_list = one_block_diff_cal(x_list, y_list)

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
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
        task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
            task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
            )

    def test_ct_pt_ringt_mac(self, levels=[1]):
        for lv in levels:
            for m in range(2, 21):
                with self.subTest(m=m, lv=lv):
                    task = f'BFV_cmpac/level_{lv}_m_{m}'
                    task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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

    # @unittest.skip('')
    def test_ct_pt_mult_accumulate_1(self, levels=[1]):
        for lv in levels:
            for m in range(2, 21):
                with self.subTest(m=m, lv=lv):
                    task = f'BFV_cmpac_1/level_{lv}_m_{m}'
                    task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

                    c_list = []
                    p_list = []
                    for i in range(m):
                        c_list.append(BfvCiphertextNode(f'c_{i}', level=lv))
                        p_list.append(BfvPlaintextRingtNode(f'p_{i}'))

                    z = ct_pt_mult_accumulate_1(c_list, p_list)

                    arg_c = Argument('in_c_list', c_list)
                    arg_p = Argument('in_p_list', p_list)
                    arg_z = Argument('out_z_list', [z])

                    process_custom_task(
                        input_args=[arg_c, arg_p],
                        offline_input_args=[],
                        output_args=[arg_z],
                        output_instruction_path=task_dir,
                    )

    @unittest.skip('')
    def test_ct_pt_mult_accumulate_and_rotate(self, levels=[1]):
        for lv in levels:
            for m in range(9, 10):
                with self.subTest(m=m, lv=lv):
                    task = f'BFV_cmpac_and_rotate/level_{lv}_m_{m}'
                    task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

                    c_list = []
                    p_list = []
                    for i in range(m):
                        c_list.append(BfvCiphertextNode(f'c_{i}', level=lv))
                        p_list.append(BfvPlaintextRingtNode(f'p_{i}'))
                    c_list.append(BfvCiphertextNode(f'c_{m}', level=lv))

                    cm_list = []
                    for i in range(len(c_list)):
                        cm_list.append(to_ntt(c_list[i]))

                    z = to_inv_ntt(ct_pt_mult_accumulate(cm_list[:-1], p_list), output_id='z')
                    z1 = to_inv_ntt(
                        advanced_rotate_cols(cm_list[-1], steps=[3], out_ct_type='ct-ntt')[0], output_id='z1'
                    )

                    arg_c = Argument('in_c_list', c_list)
                    arg_p = Argument('in_p_list', p_list)
                    arg_z = Argument('out_z_list', [z, z1])

                    process_custom_task(
                        input_args=[arg_c, arg_p],
                        offline_input_args=[],
                        output_args=[arg_z],
                        output_instruction_path=task_dir,
                    )

    @unittest.skip('')
    def test_ct_pt_mult_accumulate_1_and_rotate(self, levels=[1]):
        for lv in levels:
            for m in range(8, 9):
                with self.subTest(m=m, lv=lv):
                    task = f'BFV_cmpac1_and_rotate/level_{lv}_m_{m}'
                    task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

                    c_list = []
                    p_list = []
                    for i in range(m):
                        c_list.append(BfvCiphertextNode(f'c_{i}', level=lv))
                        p_list.append(BfvPlaintextRingtNode(f'p_{i}'))
                    c_list.append(BfvCiphertextNode(f'c_{m}', level=lv))

                    cm_list = []
                    for i in range(len(c_list)):
                        cm_list.append(to_ntt(c_list[i]))

                    z = to_inv_ntt(ct_pt_mult_accumulate_1(cm_list[:-1], p_list), output_id='z')
                    z1 = to_inv_ntt(
                        advanced_rotate_cols(cm_list[-1], steps=[3], out_ct_type='ct-ntt')[0], output_id='z1'
                    )

                    arg_c = Argument('in_c_list', c_list)
                    arg_p = Argument('in_p_list', p_list)
                    arg_z = Argument('out_z_list', [z, z1])

                    process_custom_task(
                        input_args=[arg_c, arg_p],
                        offline_input_args=[],
                        output_args=[arg_z],
                        output_instruction_path=task_dir,
                    )

    # @unittest.skip('')
    def test_ct_mul_pt_ringt_mac(self, levels=[1]):
        for lv in levels:
            for m in range(2, 21):
                with self.subTest(m=m, lv=lv):
                    task = f'BFV_cmpac_mul/level_{lv}_m_{m}'
                    task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

                    c_list = []
                    p_list = []
                    for i in range(m):
                        c_list.append(BfvCiphertextNode(f'c_{i}', level=lv))
                        p_list.append(BfvPlaintextRingtNode(f'p_{i}'))

                    cm_list = []
                    for i in range(m):
                        cm_list.append(to_mul(c_list[i]))
                    z = to_inv_ntt(ct_pt_mult_accumulate(cm_list, p_list, output_mform=False))

                    arg_c = Argument('in_c_list', c_list)
                    arg_p = Argument('in_p_list', p_list)
                    arg_z = Argument('out_z_list', [z])

                    process_custom_task(
                        input_args=[arg_c, arg_p],
                        offline_input_args=[],
                        output_args=[arg_z],
                        output_instruction_path=task_dir,
                    )

    # @unittest.skip('')
    def test_ct_ntt_pt_ringt_mac(self, levels=[1]):
        for lv in levels:
            for m in range(2, 21):
                with self.subTest(m=m, lv=lv):
                    task = f'BFV_cmpac_ntt/level_{lv}_m_{m}'
                    task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

                    c_list = []
                    p_list = []
                    for i in range(m):
                        c_list.append(BfvCiphertextNode(f'c_{i}', level=lv))
                        p_list.append(BfvPlaintextRingtNode(f'p_{i}'))

                    cm_list = []
                    for i in range(m):
                        cm_list.append(to_ntt(c_list[i]))
                    z1 = ct_pt_mult_accumulate(cm_list, p_list)
                    z = to_inv_ntt(z1)

                    arg_c = Argument('in_c_list', c_list)
                    arg_p = Argument('in_p_list', p_list)
                    arg_z = Argument('out_z_list', [z])

                    process_custom_task(
                        input_args=[arg_c, arg_p],
                        offline_input_args=[],
                        output_args=[arg_z],
                        output_instruction_path=task_dir,
                    )

    @unittest.skip('')
    def test_ct_compressed_pt_mult_accumulate(self, levels=[1]):
        for lv in levels:
            for m in range(20, 21):
                with self.subTest(m=m, lv=lv):
                    task = f'BFV_compressed_cmpac/level_{lv}_m_{m}'
                    task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

                    c_list = []
                    for i in range(m):
                        c_list.append(BfvCiphertextNode(f'c_{i}', level=lv))

                    p = BfvCompressedPlaintextRingtNode('p', [[i, i + 2] for i in range(0, 40, 2)])
                    z = ct_pt_mult_accumulate(c_list, p)

                    arg_c = Argument('in_c_list', c_list)
                    arg_p = Argument('in_p_list', [p])
                    arg_z = Argument('out_z_list', [z])

                    process_custom_task(
                        input_args=[arg_c, arg_p],
                        offline_input_args=[],
                        output_args=[arg_z],
                        output_instruction_path=task_dir,
                    )

    def test_power_dag(self, levels=[param.max_level]):
        def power_dag(source_power: list[int], max_power: int, x: list[BfvCiphertextNode]):
            z_list: list[BfvCiphertextNode] = []
            assert len(x) == len(source_power)

            src_power_str = ''
            for power in source_power:
                src_power_str += f'{power}-' if power != source_power[-1] else f'{power}'
            with open(
                os.path.join(
                    FPGA_OUTPUT_BASE_DIR,
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
                x_all_leveled_power[i] = [None for _ in range(power_dag['level'] + 2)]

            for d in range(0, power_dag['depth'] + 1):
                for pid, compute_info in power_dag['data'].items():
                    if compute_info['depth'] == d:
                        if d == 0:
                            tmp = x_all_power[int(pid[1:])]
                            while tmp.level > 1:
                                if tmp.level < power_dag['level'] + 2:
                                    x_all_leveled_power[int(pid[1:])][tmp.level] = tmp
                                tmp = rescale(tmp)
                            x_all_leveled_power[int(pid[1:])][tmp.level] = tmp

                        else:
                            from_power0 = int(power_dag['compute'][compute_info['from_compute']]['inputs'][0][1:])
                            from_power1 = int(power_dag['compute'][compute_info['from_compute']]['inputs'][1][1:])
                            dest_power = from_power0 + from_power1

                            level = compute_info['level'] + 1
                            tmp = mult_relin(
                                x_all_leveled_power[from_power0][level + 1],
                                x_all_leveled_power[from_power1][level + 1],
                                output_id=f'x{dest_power}_lv{level + 1}',
                            )
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
        power_dag_info = os.listdir(os.path.join(FPGA_OUTPUT_BASE_DIR, 'origin_powerdag'))
        for power_info in power_dag_info:
            max_power = int(power_info.split('#')[0].split('-')[1])
            source_power = [int(x) for x in power_info.split('#')[1].split('.')[0].split('-')]
            all_power_dags.append([max_power, source_power])

        all_power_dags = sorted(all_power_dags, key=lambda x: x[0])

        for lv in levels:
            # source_power = [1,7,12]
            # max_power = 52

            # source_power = [1, 9, 15, 78, 115]
            # max_power = 512

            source_power = [1, 7, 18, 62, 104, 244, 259]
            max_power = 1137

            # for max_power, source_power in all_power_dags:
            src_power_str = ''
            for power in source_power:
                src_power_str += f'{power}-' if power != source_power[-1] else f'{power}'
            task_power_str = f'PD-{max_power}#{src_power_str}'

            task = f'BFV_power_dag/{task_power_str}/level_{lv}'
            task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

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
            )

            print(f'{task} end --')

    # @unittest.skip('')
    def test_power_mul_coeff(self, levels=[1], index_per_fpga_func=[2, 1, 5]):
        def power_mul_coeff(lane_cipher_size):
            all_power_dags = []
            power_dag_info = os.listdir(os.path.join(FPGA_OUTPUT_BASE_DIR, 'origin_powerdag'))
            for power_info in power_dag_info:
                max_power = int(power_info.split('#')[0].split('-')[1])
                source_power = [int(x) for x in power_info.split('#')[1].split('.')[0].split('-')]
                all_power_dags.append([max_power, source_power])

            all_power_dags = sorted(all_power_dags, key=lambda x: x[0])

            for lv in levels:
                # source_power = [1, 7, 12]
                # max_power = 52

                source_power = [1, 7, 18, 62, 104, 244, 259]
                max_power = 1137

                # for max_power, source_power in all_power_dags:
                src_power_str = ''
                for power in source_power:
                    src_power_str += f'{power}-' if power != source_power[-1] else f'{power}'
                task_power_str = f'PD-{max_power}#{src_power_str}'

                task = f'BFV_power_mul_coeff/{task_power_str}/level_{lv}/{lane_cipher_size[0]}_{lane_cipher_size[1]}_{lane_cipher_size[2]}'
                task_dir = os.path.join(FPGA_OUTPUT_BASE_DIR, task)

                print(f'{task} begin --')

                all_c = []
                all_p = []
                all_z = []

                all_c_mul = []

                for k in range(lane_cipher_size[1]):
                    c_list = []
                    c_mul_list = []
                    for i in range(max_power):
                        c_list.append(BfvCiphertextNode(f'c{k}_{i + 1}', level=lv))
                        c_mul_list.append(to_mul(c_list[-1], f'c{k}_{i + 1}_mul'))
                    all_c.append(c_list)
                    all_c_mul.append(c_mul_list)

                for r in range(lane_cipher_size[0]):
                    p_l_list = []
                    z_l_list = []
                    for k in range(lane_cipher_size[1]):
                        p_list = []
                        for i in range(lane_cipher_size[2]):
                            pi_list = [BfvPlaintextNode(f'p{r}_{k}_{i}_0', level=lv)]
                            for j in range(max_power):
                                pi_list.append(BfvPlaintextRingtNode(f'p{r}_{k}_{i}_{j + 1}'))
                            p_list.append(pi_list)

                        # pl_list = [BfvPlaintextNode(f'p{r}_{k}_{lane_cipher_size[2]-1}_0', level=lv)]
                        # for j in range(max_power):
                        #     pl_list.append(BfvPlaintextRingtNode(f'p{r}_{k}_{lane_cipher_size[2]-1}_{j+1}'))
                        # p_list.append(pl_list)

                        p_l_list.append(p_list)

                        z = []
                        for i in range(lane_cipher_size[2]):
                            if max_power <= 50:
                                # x = ct_pt_mult_accumulate(all_c[k][: len(p_list[i][1:])], p_list[i][1:])
                                x_ntt = ct_pt_mult_accumulate(
                                    all_c_mul[k][: len(p_list[i][1:])], p_list[i][1:], output_mform=False
                                )
                                x = to_inv_ntt(x_ntt)
                            else:
                                n_split = 4
                                for i_split in range(n_split):
                                    start_idx = int(max_power / n_split * i_split)
                                    end_idx = int(max_power / n_split * (i_split + 1))
                                    x_ntt = ct_pt_mult_accumulate(
                                        all_c_mul[k][start_idx:end_idx],
                                        p_list[i][1 + start_idx : 1 + end_idx],
                                        output_mform=False,
                                    )
                                    x = to_inv_ntt(x_ntt)
                                    if i_split == 0:
                                        x_mac = x
                                    else:
                                        x_mac = add(x, x_mac)
                                x = x_mac

                            y = add(x, p_list[i][0], f'y{r}_{k}_{i}')
                            z.append(rescale(y, f'z{r}_{k}_{i}'))

                        z_l_list.append(z)

                    all_p.append(p_l_list)
                    all_z.append(z_l_list)

                arg_c = Argument(
                    'in_c_list', [all_c[i][j] for i in range(lane_cipher_size[1]) for j in range(max_power)]
                )
                arg_p0 = Argument(
                    'in_p0_list',
                    [
                        all_p[r][i][j][0]
                        for r in range(lane_cipher_size[0])
                        for i in range(lane_cipher_size[1])
                        for j in range(lane_cipher_size[2])
                    ],
                )
                arg_p = Argument(
                    'in_p_list',
                    [
                        all_p[r][i][j][k]
                        for r in range(lane_cipher_size[0])
                        for i in range(lane_cipher_size[1])
                        for j in range(lane_cipher_size[2])
                        for k in range(1, len(all_p[r][i][j]))
                    ],
                )
                arg_z = Argument('out_z_list', all_z)

                process_custom_task(
                    input_args=[arg_c, arg_p0, arg_p],
                    offline_input_args=[],
                    output_args=[arg_z],
                    output_instruction_path=task_dir,
                )

                print(f'{task} end --')

        # for bi in range(1, index_per_fpga_func[0]+1):
        #     for bj in range(1, index_per_fpga_func[1]+1):
        #         for bk in range(1, index_per_fpga_func[2]+1):
        #             lane_cipher_size = [bi, bj, bk]
        #             power_mul_coeff(lane_cipher_size)

        power_mul_coeff(lane_cipher_size=[2, 1, 5])


if __name__ == '__main__':
    unittest.main()

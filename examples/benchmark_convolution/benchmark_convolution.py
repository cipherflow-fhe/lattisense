#!/usr/bin/env python3
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

"""
Convolution Benchmark Computation Graph Generator

"""

import math
import os
import sys

# Add the frontend module path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from frontend.custom_task import (
    Argument,
    CkksCiphertextNode,
    CkksPlaintextNode,
    Param,
    add,
    mult,
    process_custom_task,
    rescale,
    rotate_cols,
    set_fhe_param,
)


class Conv2DPackedLayer:
    """
    2D Packed Convolution Layer.
    Supports multi-channel convolution with channel packing.
    """

    def __init__(
        self,
        n_out_channel,
        n_in_channel,
        input_shape,
        kernel_shape,
        stride,
        skip,
        pack,
        n_packed_in_channel,
        n_packed_out_channel,
    ):
        self.n_out_channel = n_out_channel
        self.n_in_channel = n_in_channel
        self.input_shape = input_shape
        self.kernel_shape = kernel_shape
        self.stride = stride
        self.skip = skip

        self.pack = pack  # n_channel_per_ct
        self.n_packed_in_channel = n_packed_in_channel
        self.n_packed_out_channel = n_packed_out_channel
        padding_shape = [kernel_shape[0] // 2, kernel_shape[1] // 2]
        self.input_shape_ct = [input_shape[0] * skip[0], input_shape[1] * skip[1]]
        self.input_rotate_units = [skip[0] * self.input_shape_ct[1], skip[0] * 1]
        self.input_rotate_ranges = [padding_shape[1], padding_shape[0]]

    @staticmethod
    def populate_rotations_1_side(x, n_rotation, unit):
        """Generate rotations in one direction (0 to n_rotation)."""
        result = [x]
        steps = []
        for i in range(1, n_rotation + 1):
            steps.append(i * unit)
        result += rotate_cols(x, steps)
        return result

    @staticmethod
    def populate_rotations_2_sides(x, n_rotation, unit):
        """Generate rotations in both directions (-n_rotation to +n_rotation)."""
        post_steps = []
        nega_steps = []
        for i in range(1, n_rotation + 1):
            post_steps.append(i * unit)
            nega_steps.append(-i * unit)
        steps = nega_steps + post_steps
        r_temp = rotate_cols(x, steps)
        result = []

        # negative reversed
        result += list(reversed(r_temp[0 : len(nega_steps)]))
        result.append(x)
        result += r_temp[len(nega_steps) :]
        return result

    def gen_rotated_x(self, x):
        """Generate all rotated versions of input for convolution kernel positions."""
        rotated_x = []
        for c in x:
            row = []
            rotations = self.populate_rotations_2_sides(c, self.input_rotate_ranges[0], self.input_rotate_units[0])
            for r in rotations:
                temp = self.populate_rotations_2_sides(r, self.input_rotate_ranges[1], self.input_rotate_units[1])
                row += temp
            rotated_x.append(row)
        return rotated_x

    def call(self, x, weight_pt, bias_pt):
        """
        Execute packed convolution.

        Args:
            x: List of input ciphertext nodes [n_packed_in_channel]
            weight_pt: Nested list of weight plaintext nodes
                       [n_packed_out_channel][n_packed_in_channel * pack][kernel_size]
            bias_pt: List of bias plaintext nodes [n_packed_out_channel]

        Returns:
            List of output ciphertext nodes [n_packed_out_channel]
        """
        # Generate channel rotations
        rotated_x = []
        for x_ct in x:
            rotated_x += Conv2DPackedLayer.populate_rotations_1_side(
                x_ct, self.pack - 1, self.input_shape[0] * self.skip[0] * self.input_shape[1] * self.skip[1]
            )

        # Generate spatial rotations
        rotated_x_2d = self.gen_rotated_x(rotated_x)

        result = []

        for packed_out_channel_idx in range(self.n_packed_out_channel):
            partial_sum = None

            for in_channel_idx in range(self.n_packed_in_channel * self.pack):
                for i in range(self.kernel_shape[0]):
                    for j in range(self.kernel_shape[1]):
                        index = i * self.kernel_shape[1] + j
                        x_ct = rotated_x_2d[in_channel_idx][index]
                        w_pt = weight_pt[packed_out_channel_idx][in_channel_idx][index]

                        product = mult(x_ct, w_pt)
                        if partial_sum is None:
                            partial_sum = product
                        else:
                            partial_sum = add(partial_sum, product)

            partial_sum = rescale(partial_sum)
            b = bias_pt[packed_out_channel_idx]
            result_ct = add(partial_sum, b)
            result.append(result_ct)

        return result


def gen_conv_benchmark(n_in_channel, n_out_channel, input_shape, kernel_shape, stride, skip, init_level, output_base):
    """Generate convolution benchmark computation graph."""

    # Set FHE parameters
    param = Param.create_ckks_default_param(n=16384)
    set_fhe_param(param)

    n_slot = 16384 // 2
    n_channel_per_ct = n_slot // (input_shape[0] * input_shape[1])

    n_packed_in_channel = math.ceil(n_in_channel / n_channel_per_ct)
    n_packed_out_channel = math.ceil(n_out_channel / n_channel_per_ct)
    k_size = kernel_shape[0] * kernel_shape[1]

    # Create input ciphertext nodes
    x = [CkksCiphertextNode(f'input_0_{i}', level=init_level) for i in range(n_packed_in_channel)]

    # Create weight plaintext nodes
    # Structure: [n_packed_out][n_packed_in * n_channel_per_ct][kernel_size]
    weight_pt = [
        [
            [CkksPlaintextNode(f'convw__conv1_Conv_{out_idx}_{in_idx}_{k_idx}', init_level) for k_idx in range(k_size)]
            for in_idx in range(n_packed_in_channel * n_channel_per_ct)
        ]
        for out_idx in range(n_packed_out_channel)
    ]

    # Create bias plaintext nodes [n_packed_out_channel]
    bias_pt = [CkksPlaintextNode(f'convb__conv1_Conv_{i}', init_level - 1) for i in range(n_packed_out_channel)]

    # Create convolution layer and execute
    conv_layer = Conv2DPackedLayer(
        n_out_channel,
        n_in_channel,
        input_shape,
        kernel_shape,
        stride,
        skip,
        n_channel_per_ct,
        n_packed_in_channel,
        n_packed_out_channel,
    )
    y = conv_layer.call(x, weight_pt, bias_pt)

    # Generate output path
    task_name = (
        f'CKKS_conv2d_{n_in_channel}_in_{n_out_channel}_out_channel_'
        f'{stride[0]}_stride_{input_shape[0]}_{input_shape[1]}_'
        f'{kernel_shape[0]}_{kernel_shape[1]}'
    )
    output_path = os.path.join(output_base, task_name, f'level_{init_level}', 'server')

    os.makedirs(output_path, exist_ok=True)

    # Generate computation graph
    process_custom_task(
        input_args=[
            Argument('input_0', x),
            Argument('convw__conv1_Conv', weight_pt),
            Argument('convb__conv1_Conv', bias_pt),
        ],
        output_args=[Argument('output', y)],
        output_instruction_path=output_path,
    )

    print(f'Generated: {output_path}')
    return task_name


def main():
    """Generate computation graphs for various convolution configurations."""

    output_base = os.path.dirname(os.path.abspath(__file__))

    configs = [
        # (n_in_channel, n_out_channel, input_shape, kernel_shape)
        (1, 1, (4, 4), (5, 5)),
        (1, 1, (8, 8), (5, 5)),
        (1, 1, (16, 16), (5, 5)),
        (1, 1, (32, 32), (5, 5)),
        (1, 1, (64, 64), (5, 5)),
        (1, 32, (32, 32), (3, 3)),
        (4, 4, (32, 32), (3, 3)),
        (32, 1, (32, 32), (3, 3)),
        (1, 1, (16, 16), (1, 1)),
        (1, 1, (16, 16), (3, 3)),
        (1, 1, (16, 16), (5, 5)),
    ]

    stride = [1, 1]
    skip = [1, 1]
    init_level = 2

    print('Generating convolution computation graphs...')
    print('=' * 60)

    generated_tasks = []
    for n_in_channel, n_out_channel, input_shape, kernel_shape in configs:
        print(f'\nGenerating: in_ch={n_in_channel}, out_ch={n_out_channel}, input={input_shape}, kernel={kernel_shape}')
        try:
            task_name = gen_conv_benchmark(
                n_in_channel=n_in_channel,
                n_out_channel=n_out_channel,
                input_shape=list(input_shape),
                kernel_shape=list(kernel_shape),
                stride=stride,
                skip=skip,
                init_level=init_level,
                output_base=output_base,
            )
            generated_tasks.append(task_name)
        except Exception as e:
            import traceback

            print(f'  Error: {e}')
            traceback.print_exc()

    print('\n' + '=' * 60)
    print(f'Generated {len(generated_tasks)} computation graphs')
    print('Done!')


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Generate convolution computation graphs')
    parser.add_argument('--n-in-channel', type=int, default=1, help='Number of input channels')
    parser.add_argument('--n-out-channel', type=int, default=1, help='Number of output channels')
    parser.add_argument('--input-size', type=int, default=4, help='Input feature map size')
    parser.add_argument('--kernel-size', type=int, default=5, help='Kernel size')
    parser.add_argument('--all', action='store_true', help='Generate all default configurations')

    args = parser.parse_args()

    if args.all:
        main()
    else:
        output_base = os.path.dirname(os.path.abspath(__file__))
        gen_conv_benchmark(
            n_in_channel=args.n_in_channel,
            n_out_channel=args.n_out_channel,
            input_shape=[args.input_size, args.input_size],
            kernel_shape=[args.kernel_size, args.kernel_size],
            stride=[1, 1],
            skip=[1, 1],
            init_level=2,
            output_base=output_base,
        )

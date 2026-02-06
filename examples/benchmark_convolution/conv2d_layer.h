/*
 * Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "ndarray.h"
#include "types.h"
#include <fhe_ops_lib/fhe_lib_v2.h>
#include <array>
#include <cstdint>
#include <vector>

using namespace fhe_ops_lib;

class Conv2DLayer {
public:
    Conv2DLayer(const CkksParameter& param,
                const Duo& input_shape,
                const Array<double, 4>& weight,
                const Array<double, 1>& bias,
                const Duo& stride,
                const Duo& skip);
    virtual ~Conv2DLayer();

    Array<double, 3> run_plaintext(const Array<double, 3>& x, double multiplier = 1.0);

    Array<double, 4> weight_;
    Array<double, 1> bias_;

protected:
    CkksParameter param_;

    uint32_t n_out_channel_;
    uint32_t n_in_channel_;

    Duo input_shape_;
    Duo kernel_shape_;
    Duo stride_;
    Duo skip_;

    uint32_t n_slot_;

    std::vector<std::vector<double>> kernel_masks_;
    std::vector<int> input_rotate_units_;
    std::vector<int> input_rotate_ranges_;

    void compute_output_element(Array<double, 3>& result,
                                uint32_t out_ch,
                                uint32_t out_i,
                                uint32_t out_j,
                                const std::vector<double>& padded_input,
                                uint32_t padded_h,
                                uint32_t padded_w,
                                const std::array<uint32_t, 2>& output_shape,
                                double weight_scale) const;
};

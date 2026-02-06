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

#include "conv2d_layer.h"
#include <vector>

class Conv2DPackedLayer : public Conv2DLayer {
public:
    Conv2DPackedLayer(const CkksParameter& param,
                      const Duo& input_shape,
                      const Array<double, 4>& weight,
                      const Array<double, 1>& bias,
                      const Duo& stride,
                      const Duo& skip,
                      uint32_t n_channel_per_ct,
                      uint32_t level,
                      double residual_scale = 1.0);

    ~Conv2DPackedLayer() override = default;

    Conv2DPackedLayer(const Conv2DPackedLayer&) = delete;
    Conv2DPackedLayer& operator=(const Conv2DPackedLayer&) = delete;

    void prepare_weight();

    // Weight structure: [n_packed_ct_out][n_packed_ct_in * n_channel_per_ct][kernel_size]
    std::vector<std::vector<std::vector<CkksPlaintext>>> weight_pt_;
    std::vector<CkksPlaintext> bias_pt_;

private:
    uint32_t n_channel_per_ct_;
    uint32_t n_packed_ct_in_;
    uint32_t n_packed_ct_out_;
    uint32_t level_;
    double weight_scale_;
};

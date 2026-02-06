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

#include "conv2d_packed_layer.h"

#include <array>
#include <cmath>

#ifdef _OPENMP
#    include <omp.h>
#endif

// ============================================================================
// Constructor
// ============================================================================

Conv2DPackedLayer::Conv2DPackedLayer(const CkksParameter& param,
                                     const Duo& input_shape,
                                     const Array<double, 4>& weight,
                                     const Array<double, 1>& bias,
                                     const Duo& stride,
                                     const Duo& skip,
                                     uint32_t n_channel_per_ct,
                                     uint32_t level,
                                     double residual_scale)
    : Conv2DLayer(param, input_shape, weight, bias, stride, skip), n_channel_per_ct_(n_channel_per_ct),
      n_packed_ct_in_(div_ceil(n_in_channel_, n_channel_per_ct)),
      n_packed_ct_out_(div_ceil(n_out_channel_, n_channel_per_ct)), level_(level),
      weight_scale_(param_.get_q(level) * residual_scale) {}

// ============================================================================
// Weight Preparation
// ============================================================================

void Conv2DPackedLayer::prepare_weight() {
    const std::array<uint32_t, 2> padding_shape{kernel_shape_[0] / 2, kernel_shape_[1] / 2};

    const std::array<uint32_t, 2> input_shape_ct{input_shape_[0] * skip_[0], input_shape_[1] * skip_[1]};

    const double encode_pt_scale = weight_scale_;
    const double bias_scale = param_.get_default_scale();

    kernel_masks_.clear();
    for (uint32_t ki = 0; ki < kernel_shape_[0]; ki++) {
        for (uint32_t kj = 0; kj < kernel_shape_[1]; kj++) {
            std::vector<double> mask;
            mask.reserve(input_shape_ct[0] * input_shape_ct[1]);

            for (uint32_t i_s = 0; i_s < input_shape_ct[0]; i_s++) {
                for (uint32_t j_s = 0; j_s < input_shape_ct[1]; j_s++) {
                    const bool valid_i = (ki * skip_[0] + i_s >= padding_shape[0]) &&
                                         (ki * skip_[0] + i_s - padding_shape[0] < input_shape_ct[0]);
                    const bool valid_j = (kj * skip_[1] + j_s >= padding_shape[1]) &&
                                         (kj * skip_[1] + j_s - padding_shape[1] < input_shape_ct[1]);
                    const bool aligned_stride = (i_s % stride_[0] == 0) && (j_s % stride_[1] == 0);
                    const bool aligned_skip_stride =
                        (i_s % (skip_[0] * stride_[0]) == 0) && (j_s % (skip_[1] * stride_[1]) == 0);
                    const bool aligned_skip = (i_s % skip_[0] == 0) && (j_s % skip_[1] == 0);

                    if (valid_i && valid_j && aligned_stride && aligned_skip_stride && aligned_skip) {
                        mask.push_back(1.0);
                    } else {
                        mask.push_back(0.0);
                    }
                }
            }
            kernel_masks_.push_back(std::move(mask));
        }
    }

    input_rotate_units_.clear();
    input_rotate_units_.push_back(skip_[0] * input_shape_ct[1]);
    input_rotate_units_.push_back(skip_[0] * 1);

    input_rotate_ranges_.clear();
    input_rotate_ranges_.push_back(padding_shape[1]);
    input_rotate_ranges_.push_back(padding_shape[0]);

    weight_pt_.clear();
    bias_pt_.clear();

    weight_pt_.resize(n_packed_ct_out_);
    const uint32_t kernel_size = kernel_shape_[0] * kernel_shape_[1];

    for (uint32_t i = 0; i < n_packed_ct_out_; i++) {
        weight_pt_[i].resize(n_packed_ct_in_ * n_channel_per_ct_);
        for (uint32_t j = 0; j < n_packed_ct_in_ * n_channel_per_ct_; j++) {
            CkksPlaintext dummy(0);
            weight_pt_[i][j].push_back(std::move(dummy));
        }
        CkksPlaintext bias_dummy(0);
        bias_pt_.push_back(std::move(bias_dummy));
    }

    CkksContext ctx = CkksContext::create_empty_context(this->param_);
    ctx.resize_copies(n_packed_ct_out_);

#ifdef _OPENMP
#    pragma omp parallel for schedule(dynamic)
#endif
    for (int packed_out_ct_idx = 0; packed_out_ct_idx < static_cast<int>(n_packed_ct_out_); packed_out_ct_idx++) {
        CkksContext& ctx_copy = ctx.get_copy(packed_out_ct_idx);

        for (uint32_t packed_in_ct_idx = 0; packed_in_ct_idx < n_packed_ct_in_; packed_in_ct_idx++) {
            for (uint32_t rotate_idx = 0; rotate_idx < n_channel_per_ct_; rotate_idx++) {
                std::vector<CkksPlaintext> encoded_kernels;

                for (uint32_t ki = 0; ki < kernel_shape_[0]; ki++) {
                    for (uint32_t kj = 0; kj < kernel_shape_[1]; kj++) {
                        const uint32_t mask_idx = ki * kernel_shape_[1] + kj;
                        const auto& mask = kernel_masks_[mask_idx];

                        std::vector<double> packed_weights;
                        packed_weights.reserve(n_slot_);

                        for (uint32_t pack_idx = 0; pack_idx < n_channel_per_ct_; pack_idx++) {
                            const uint32_t out_ch_idx = packed_out_ct_idx * n_channel_per_ct_ + pack_idx;
                            const uint32_t in_ch_idx = packed_in_ct_idx * n_channel_per_ct_ +
                                                       (rotate_idx + pack_idx + n_channel_per_ct_) % n_channel_per_ct_;

                            // prepare plaintext weight for (out_ch_idx, in_ch_idx)-SISO convolution
                            if (in_ch_idx < n_in_channel_ && out_ch_idx < n_out_channel_) {
                                const double weight_val = weight_.get(out_ch_idx, in_ch_idx, ki, kj);
                                for (uint32_t slot_idx = 0; slot_idx < input_shape_ct[0] * input_shape_ct[1];
                                     slot_idx++) {
                                    packed_weights.push_back(weight_val * mask[slot_idx]);
                                }
                            } else {
                                packed_weights.insert(packed_weights.end(), input_shape_ct[0] * input_shape_ct[1], 0.0);
                            }
                        }

                        auto encoded = ctx_copy.encode(packed_weights, level_, encode_pt_scale);
                        encoded_kernels.push_back(std::move(encoded));
                    }
                }
                weight_pt_[packed_out_ct_idx][packed_in_ct_idx * n_channel_per_ct_ + rotate_idx] =
                    std::move(encoded_kernels);
            }
        }

        std::vector<double> packed_bias;
        for (uint32_t pack_idx = 0; pack_idx < n_channel_per_ct_; pack_idx++) {
            const uint32_t out_ch_idx = packed_out_ct_idx * n_channel_per_ct_ + pack_idx;

            for (uint32_t i = 0; i < input_shape_ct[0]; i++) {
                for (uint32_t j = 0; j < input_shape_ct[1]; j++) {
                    const bool is_output_position =
                        (i % (skip_[0] * stride_[0]) == 0) && (j % (skip_[1] * stride_[1]) == 0);
                    if (is_output_position && out_ch_idx < n_out_channel_) {
                        packed_bias.push_back(bias_.get(out_ch_idx));
                    } else {
                        packed_bias.push_back(0.0);
                    }
                }
            }
        }

        auto encoded_bias = ctx_copy.encode(packed_bias, level_ - 1, bias_scale);
        bias_pt_[packed_out_ct_idx] = std::move(encoded_bias);
    }
}

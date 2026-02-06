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

#include <cmath>
#include <vector>
#include <cstdio>
#include <cstdint>
#include "ndarray.h"
#include "types.h"
#include <fhe_ops_lib/fhe_lib_v2.h>

using namespace fhe_ops_lib;

// Feature2DEncrypted class (header-only)
// Only supports MultChannelPack mode for simplicity
class Feature2DEncrypted {
public:
    CkksContext* context;
    uint32_t n_channel = 0;
    uint32_t n_channel_per_ct = 0;
    uint32_t level;

    Duo shape = {0, 0};
    Duo skip;
    std::vector<CkksCiphertext> data;

    Feature2DEncrypted(CkksContext* context_in, int ct_level, Duo skip_in = {1, 1})
        : context(context_in), level(ct_level), skip(skip_in) {}

    ~Feature2DEncrypted() = default;

    // Pack a 3D array (channels, height, width) into encrypted ciphertexts
    // Uses MultChannelPack mode: multiple channels packed per ciphertext
    void pack(const Array<double, 3>& feature_mg, bool is_symmetric = false, double scale_in = 0) {
        if (scale_in == 0) {
            scale_in = context->get_parameter().get_default_scale();
        }

        auto input_shape = feature_mg.get_shape();
        n_channel = input_shape[0];
        shape[0] = input_shape[1];
        shape[1] = input_shape[2];
        skip[0] = 1;
        skip[1] = 1;

        int n_slot = context->get_parameter().get_n() / 2;
        n_channel_per_ct = n_slot / (shape[0] * shape[1]);
        uint32_t n_ct = div_ceil(n_channel, n_channel_per_ct);

        std::vector<std::vector<double>> feature_tmp_pack(n_ct);

        for (uint32_t ct_idx = 0; ct_idx < n_ct; ct_idx++) {
            std::vector<double> image_flat;
            image_flat.reserve(n_channel_per_ct * shape[0] * shape[1]);
            for (uint32_t k = 0; k < n_channel_per_ct; k++) {
                uint32_t ch = ct_idx * n_channel_per_ct + k;
                if (ch < n_channel) {
                    for (uint32_t i = 0; i < shape[0]; i++) {
                        for (uint32_t j = 0; j < shape[1]; j++) {
                            image_flat.push_back(feature_mg.get(ch, i, j));
                        }
                    }
                } else {
                    // Pad with values from first channels (cyclic)
                    for (uint32_t i = 0; i < shape[0]; i++) {
                        for (uint32_t j = 0; j < shape[1]; j++) {
                            image_flat.push_back(feature_mg.get(ch % n_channel, i, j));
                        }
                    }
                }
            }
            feature_tmp_pack[ct_idx] = std::move(image_flat);
        }

        data.clear();
        data.reserve(n_ct);

        for (uint32_t ct_idx = 0; ct_idx < n_ct; ct_idx++) {
            auto image_flat_pt = context->encode(feature_tmp_pack[ct_idx], level, scale_in);
            if (is_symmetric) {
                auto image_flat_ct = context->encrypt_symmetric(image_flat_pt);
                data.push_back(std::move(image_flat_ct));
            } else {
                auto image_flat_ct = context->encrypt_asymmetric(image_flat_pt);
                data.push_back(std::move(image_flat_ct));
            }
        }
    }

    // Unpack ciphertexts back to a 3D array
    Array<double, 3> unpack() const {
        int n_ct = data.size();
        Duo pre_skip_shape = {shape[0] * skip[0], shape[1] * skip[1]};

        Array<double, 3> result({n_channel, shape[0], shape[1]});

        for (int ct_idx = 0; ct_idx < n_ct; ct_idx++) {
            CkksPlaintext x_pt = context->decrypt(data[ct_idx]);
            Array1D x_mg = context->decode(x_pt);

            for (uint32_t i = 0; i < n_channel_per_ct; i++) {
                uint32_t channel_idx = ct_idx * n_channel_per_ct + i;
                if (channel_idx >= n_channel) {
                    continue;
                }
                for (uint32_t j = 0; j < shape[0]; j++) {
                    for (uint32_t k = 0; k < shape[1]; k++) {
                        result.set(channel_idx, j, k,
                                   x_mg[i * pre_skip_shape[0] * pre_skip_shape[1] + j * pre_skip_shape[1] * skip[0] +
                                        k * skip[1]]);
                    }
                }
            }
        }
        return result;
    }
};

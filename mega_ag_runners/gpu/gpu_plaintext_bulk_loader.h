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

#include <cstddef>
#include <cstdint>

#include "../mega_ag.h"

extern "C" {
#include "../../abi/c_types.h"
}

namespace gpu_wrapper {

constexpr size_t kBulkPlaintextRingtPayloadBytes = 512 * 1024;

inline bool is_contiguous_plaintext_payload(const CPlaintext& plaintext) {
    const CPolynomial& poly = plaintext.poly;
    if (poly.contiguous_data == nullptr || poly.components == nullptr || poly.n_component <= 0) {
        return false;
    }

    const int n = poly.components[0].n;
    if (n <= 0) {
        return false;
    }

    for (int i = 0; i < poly.n_component; ++i) {
        if (poly.components[i].n != n ||
            poly.components[i].data != poly.contiguous_data + static_cast<size_t>(i) * static_cast<size_t>(n)) {
            return false;
        }
    }
    return true;
}

inline size_t plaintext_payload_bytes(const CPlaintext& plaintext) {
    if (!is_contiguous_plaintext_payload(plaintext)) {
        return 0;
    }
    return static_cast<size_t>(plaintext.poly.n_component) * static_cast<size_t>(plaintext.poly.components[0].n) *
           sizeof(uint64_t);
}

inline bool is_bulk_plaintext_ringt_payload(const CPlaintext& plaintext,
                                            size_t expected_bytes = kBulkPlaintextRingtPayloadBytes) {
    if (plaintext.level != 0 || plaintext.poly.n_component != 1) {
        return false;
    }
    return plaintext_payload_bytes(plaintext) == expected_bytes;
}

inline bool should_use_bulk_plaintext_ringt_batch(size_t count, size_t payload_bytes, size_t min_bulk_bytes) {
    if (count < 2 || payload_bytes == 0) {
        return false;
    }
    return count * payload_bytes >= min_bulk_bytes;
}

inline bool is_bulk_plaintext_ringt_load_node(const ComputeNode& node) {
    if (!node.fhe_prop.has_value() || node.fhe_prop->op_type != OperationType::LOAD_TO_BACKEND ||
        node.input_nodes.size() != 1 || node.output_nodes.size() != 1) {
        return false;
    }

    const DatumNode* input_node = node.input_nodes[0];
    if (input_node == nullptr || input_node->datum_type != TYPE_PLAINTEXT || !input_node->fhe_prop.has_value() ||
        !input_node->fhe_prop->p.has_value()) {
        return false;
    }

    return input_node->fhe_prop->p->is_ringt;
}

}  // namespace gpu_wrapper

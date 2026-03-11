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

/**
 * @file fpga_abi_bridge_executors.h
 * @brief ABI layer ↔ FPGA backend bridge executors for heterogeneous computing
 *
 * This module provides ABI bridge executors between ABI layer (C struct types)
 * and FPGA backend types (polyvec_64):
 * - LOAD_TO_FPGA: CCiphertext/CPlaintext/CRelinKey/CGaloisKey → polyvec_64 pointers
 *
 * These executors handle data export for FPGA acceleration.
 */

#ifndef FPGA_ABI_BRIDGE_EXECUTORS_H
#define FPGA_ABI_BRIDGE_EXECUTORS_H

#include "../mega_ag.h"
#include <memory>
#include <stdexcept>
#include <any>

extern "C" {
#include "../../fhe_ops_lib/fhe_types_v2.h"
#include "../../fhe_ops_lib/structs_v2.h"
#include "../../backends/lattisense-fpga/lattisense-fpga-runtime/libbfv2/include/poly.h"
#include "../../backends/lattisense-fpga/lattisense-fpga-runtime/fpga_ops/utils.h"
#include "log/log.h"
}

/**
 * @brief Export CCiphertext pointers to FPGA polyvec_64 structure
 */
inline int export_ct_pointers(CCiphertext* ct, polyvec_64* pv, int offset) {
    for (int i = 0; i < ct->degree + 1; i++) {
        for (int j = 0; j < ct->polys->n_component; j++) {
            if (offset < pv->len) {
                pv->p[offset].term = ct->polys[i].components[j].data;
                offset++;
            } else {
                log_error("Error: Index %d out of range %d", offset, pv->len);
            }
        }
    }
    return offset;
}

/**
 * @brief Export CPlaintext pointers to FPGA polyvec_64 structure
 */
inline int export_pt_pointers(CPlaintext* pt, polyvec_64* pv, int offset) {
    for (int j = 0; j < pt->poly.n_component; j++) {
        if (offset < pv->len) {
            pv->p[offset].term = pt->poly.components[j].data;
            offset++;
        } else {
            log_error("Error: Index %d out of range %d", offset, pv->len);
        }
    }
    return offset;
}

/**
 * @brief Export CRelinKey pointers to FPGA polyvec_64 structure
 */
inline int export_rlk_pointers(CRelinKey* rlk, polyvec_64* pv, int offset) {
    for (int m = 0; m < rlk->n_public_key; m++) {
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < rlk->public_keys->polys->n_component; j++) {
                if (offset < pv->len) {
                    pv->p[offset].term = rlk->public_keys[m].polys[i].components[j].data;
                    offset++;
                } else {
                    log_error("Error: Index %d out of range %d", offset, pv->len);
                }
            }
        }
    }
    return offset;
}

/**
 * @brief Export CGaloisKey pointers to FPGA polyvec_64 structure
 */
inline int export_glk_pointers(CGaloisKey* glk, polyvec_64* pv, int offset) {
    for (int gal_idx = 0; gal_idx < glk->n_key_switch_key; gal_idx++) {
        for (int m = 0; m < glk->key_switch_keys->n_public_key; m++) {
            for (int i = 0; i < 2; i++) {
                for (int j = 0; j < glk->key_switch_keys->public_keys->polys->n_component; j++) {
                    if (offset < pv->len) {
                        pv->p[offset].term = glk->key_switch_keys[gal_idx].public_keys[m].polys[i].components[j].data;
                        offset++;
                    } else {
                        log_error("Error: Index %d out of range %d", offset, pv->len);
                    }
                }
            }
        }
    }
    return offset;
}

/**
 * @brief Create executor for loading ABI data to FPGA
 *
 * Exports C struct pointers to FPGA polyvec_64 structure:
 * - CCiphertext → export_ct_pointers
 * - CPlaintext → export_pt_pointers
 * - CRelinKey → export_rlk_pointers
 * - CGaloisKey → export_glk_pointers
 *
 * @return ExecutorFunc that performs pointer export
 *
 * @note This executor runs in FPGA execution context
 * @note Input: std::shared_ptr<CCiphertext/CPlaintext/etc> from available_data
 * @note Output: new offset (int) stored in std::any
 * @note Requires polyvec_64* in ExecutionContext other_args[0]
 * @note Requires current offset (int) in ExecutionContext other_args[1]
 */
inline ExecutorFunc create_load_to_fpga_executor() {
    return [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
              const ComputeNode& self) -> void {
        // Check if FHE properties exist
        if (!self.fhe_prop.has_value()) {
            throw std::runtime_error("ComputeNode missing FHE properties for FPGA executor");
        }

        // Get polyvec_64* from execution context
        auto* pv = ctx.get_other_arg<polyvec_64>(0);
        if (!pv) {
            throw std::runtime_error("polyvec_64 not found in execution context");
        }

        int offset = std::any_cast<int>(ctx.other_args[1]);

        const DatumNode* input_node = self.input_nodes[0];

        // Determine data type
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties");
        }

        DataType data_type = input_node->datum_type;
        int new_offset = offset;

        std::any c_struct = inputs.at(input_node->index);

        // Export pointers based on data type
        switch (data_type) {
            case TYPE_CIPHERTEXT: {
                auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(c_struct);
                new_offset = export_ct_pointers(c_ct_ptr.get(), pv, new_offset);
                break;
            }
            case TYPE_PLAINTEXT: {
                auto c_pt_ptr = std::any_cast<std::shared_ptr<CPlaintext>>(c_struct);
                new_offset = export_pt_pointers(c_pt_ptr.get(), pv, new_offset);
                break;
            }
            case TYPE_RELIN_KEY: {
                auto c_rlk_ptr = std::any_cast<std::shared_ptr<CRelinKey>>(c_struct);
                new_offset = export_rlk_pointers(c_rlk_ptr.get(), pv, new_offset);
                break;
            }
            case TYPE_GALOIS_KEY: {
                auto c_glk_ptr = std::any_cast<std::shared_ptr<CGaloisKey>>(c_struct);
                new_offset = export_glk_pointers(c_glk_ptr.get(), pv, new_offset);
                break;
            }
            default: throw std::runtime_error("Unsupported data type for C_STRUCT_TO_FPGA conversion");
        }

        // Output is the new offset (for verification/debugging)
        output = new_offset;
    };
}

#endif  // FPGA_ABI_BRIDGE_EXECUTORS_H

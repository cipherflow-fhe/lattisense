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
#include "../../abi/c_types.h"
#include "../../abi/c_structs.h"
#include "../../backends/lattisense-fpga/lattisense-fpga-runtime/libbfv2/include/poly.h"
#include "../../backends/lattisense-fpga/lattisense-fpga-runtime/fpga_ops/utils.h"
#include "log/log.h"
}

/**
 * @brief Set polyvec_64 term from one RNS limb (pointer assign or copy).
 * @param need_copy  true = malloc + memcpy (caller must free term later);
 *                   false = pointer assign (zero-copy, data must outlive polyvec usage).
 */
inline void set_pv_term(polyvec_64* pv, int offset, uint64_t* rns_limb, int ring_degree, bool need_copy) {
    if (need_copy) {
        pv->p[offset].term = (uint64_t*)malloc((size_t)ring_degree * sizeof(uint64_t));
        memcpy(pv->p[offset].term, rns_limb, (size_t)ring_degree * sizeof(uint64_t));
    } else {
        pv->p[offset].term = rns_limb;
    }
}

/**
 * @brief Export CCiphertext to FPGA polyvec_64 structure
 * @param need_copy  true for input polyvec (data may be freed before run_project)
 */
inline int export_ct_pointers(CCiphertext* ct, polyvec_64* pv, int offset, bool need_copy = true) {
    for (int poly_idx = 0; poly_idx < ct->cipher_size; poly_idx++) {
        for (int rns_idx = 0; rns_idx < c_ciphertext_rns_size(ct); rns_idx++) {
            if (offset < pv->len) {
                set_pv_term(pv, offset, c_ciphertext_rns_limb(ct, poly_idx, rns_idx), ct->ring_degree, need_copy);
                offset++;
            } else {
                log_error("Error: Index %d out of range %d", offset, pv->len);
            }
        }
    }
    return offset;
}

/**
 * @brief Export CPlaintext to FPGA polyvec_64 structure
 */
inline int export_pt_pointers(CPlaintext* pt, polyvec_64* pv, int offset, bool need_copy = true) {
    for (int rns_idx = 0; rns_idx < c_plaintext_rns_size(pt); rns_idx++) {
        if (offset < pv->len) {
            set_pv_term(pv, offset, c_plaintext_rns_limb(pt, rns_idx), pt->ring_degree, need_copy);
            offset++;
        } else {
            log_error("Error: Index %d out of range %d", offset, pv->len);
        }
    }
    return offset;
}

/**
 * @brief Export CRelinKey to FPGA polyvec_64 structure
 */
inline int export_rlk_pointers(CRelinKey* rlk, polyvec_64* pv, int offset, bool need_copy = true) {
    for (int decomp_idx = 0; decomp_idx < c_relin_key_decomp_rns(rlk); decomp_idx++) {
        for (int poly_idx = 0; poly_idx < 2; poly_idx++) {
            for (int rns_idx = 0; rns_idx < c_relin_key_rns_size(rlk); rns_idx++) {
                if (offset < pv->len) {
                    set_pv_term(pv, offset, c_relin_key_rns_limb(rlk, decomp_idx, poly_idx, rns_idx), rlk->ring_degree,
                                need_copy);
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
 * @brief Export CGaloisKey to FPGA polyvec_64 structure
 */
inline int export_glk_pointers(CGaloisKey* glk, polyvec_64* pv, int offset, bool need_copy = true) {
    for (int switching_key_idx = 0; switching_key_idx < glk->n_switching_key; switching_key_idx++) {
        CSwitchingKey* switching_key = &glk->switching_keys[switching_key_idx];
        for (int decomp_idx = 0; decomp_idx < c_switching_key_decomp_rns(switching_key); decomp_idx++) {
            for (int poly_idx = 0; poly_idx < 2; poly_idx++) {
                for (int rns_idx = 0; rns_idx < c_switching_key_rns_size(switching_key); rns_idx++) {
                    if (offset < pv->len) {
                        set_pv_term(pv, offset, c_switching_key_rns_limb(switching_key, decomp_idx, poly_idx, rns_idx),
                                    switching_key->ring_degree, need_copy);
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
 * @brief Free all term pointers in a polyvec_64 (for cleaning up copied input data after run_project)
 */
inline void free_polyvec_64_terms(polyvec_64* pv) {
    for (int i = 0; i < pv->len; i++) {
        free(pv->p[i].term);
        pv->p[i].term = NULL;
    }
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
    return [](ExecutionContext& ctx, std::unordered_map<NodeIndex, std::any>& local_data,
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

        std::any c_struct = local_data.at(input_node->index);

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
        local_data[self.output_nodes[0]->index] = new_offset;
    };
}

#endif  // FPGA_ABI_BRIDGE_EXECUTORS_H

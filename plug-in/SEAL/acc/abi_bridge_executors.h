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
 * @file abi_bridge_executors.h
 * @brief SEAL plug-in ↔ ABI layer bridge executors for heterogeneous computing
 *
 * Mirrors cxx_sdk_v2/cxx_abi_bridge_executors.h but for the external SEAL
 * plug-in. The EXPORT_TO_ABI executor reads seal::* pointers from CArgument.data
 * and calls _export_* / _import_* helpers to perform SEAL ↔ C struct conversion.
 *
 * seal::SEALContext* is read from the global g_seal_context, which is set by
 * the runner (via set_seal_context) before each run_fhe_*_task call and cleared
 * by clear_seal_context afterwards.
 */

#pragma once

#include "../../../mega_ag_runners/mega_ag.h"
#include "c_struct_import_export.h"

#include <any>
#include <cmath>
#include <memory>
#include <stdexcept>
#include <unordered_map>

extern "C" {
#include "../../../fhe_ops_lib/structs_v2.h"
#include "../../../mega_ag_runners/c_argument.h"
}

// Global state set by the runner before each run and cleared after.
static seal::SEALContext* g_seal_context = nullptr;
static uint64_t g_seal_param_id = 0;

inline void set_seal_context(seal::SEALContext* ctx, uint64_t param_id) {
    g_seal_context = ctx;
    g_seal_param_id = param_id;
}
inline void clear_seal_context() {
    g_seal_context = nullptr;
    g_seal_param_id = 0;
}

/**
 * @brief Create SEAL ABI export executor
 *
 * Creates an executor that reads a seal::* pointer from CArgument.data and
 * exports it to a C struct. seal::SEALContext* and param_id are read at
 * execution time from g_seal_context / g_seal_param_id set by set_seal_context().
 *
 * @param mf_nbits Montgomery form bits for keys
 */
inline ExecutorFunc create_seal_abi_export_executor(int mf_nbits) {
    return [mf_nbits](ExecutionContext& /*ctx*/, const std::unordered_map<NodeIndex, std::any>& inputs,
                      std::any& output, const ComputeNode& self) -> void {
        seal::SEALContext* context = g_seal_context;
        uint64_t param_id = g_seal_param_id;
        auto& key_ctx = *context->key_context_data();
        auto ntt_tables = seal::util::iter(key_ctx.small_ntt_tables());
        int N = key_ctx.parms().poly_modulus_degree();
        auto scheme = key_ctx.parms().scheme();

        const DatumNode* input_node = self.input_nodes[0];
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties for SEAL EXPORT_TO_ABI");
        }

        DataType data_type = input_node->datum_type;
        int level = input_node->fhe_prop->level;
        uint64_t galois_element = (data_type == TYPE_GALOIS_KEY && input_node->fhe_prop->p.has_value()) ?
                                      input_node->fhe_prop->p->galois_element :
                                      0;

        auto input_ptr = std::any_cast<std::shared_ptr<void>>(inputs.at(input_node->index));

        switch (data_type) {
            case TYPE_CIPHERTEXT: {
                auto* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                auto* src = static_cast<seal::Ciphertext*>(input_ptr.get());
                _export_ciphertext(param_id, ntt_tables, src, c_ct);
                output = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* p) {
                    free_ciphertext(p, false);
                    free(p);
                });
                break;
            }
            case TYPE_PLAINTEXT: {
                auto* src = static_cast<seal::Plaintext*>(input_ptr.get());
                auto* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                _export_plaintext(param_id, N, ntt_tables, src, c_pt);
                output = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                    free_plaintext(p, false);
                    free(p);
                });
                break;
            }
            case TYPE_RELIN_KEY: {
                auto* src = static_cast<seal::RelinKeys*>(input_ptr.get());
                auto* c_rlk = (CRelinKey*)malloc(sizeof(CRelinKey));
                _export_relin_key(param_id, scheme, ntt_tables, src, c_rlk, level, mf_nbits);
                output = std::shared_ptr<CRelinKey>(c_rlk, [](CRelinKey* p) {
                    free_relin_key(p, false);
                    free(p);
                });
                break;
            }
            case TYPE_GALOIS_KEY: {
                auto* src = static_cast<seal::GaloisKeys*>(input_ptr.get());
                auto* c_glk = (CGaloisKey*)malloc(sizeof(CGaloisKey));
                set_galois_key_steps(c_glk, &galois_element, 1);
                _export_galois_key(param_id, scheme, ntt_tables, src, c_glk, level, mf_nbits);
                output = std::shared_ptr<CGaloisKey>(c_glk, [](CGaloisKey* p) {
                    free_galois_key(p, false);
                    free(p);
                });
                break;
            }
            default: throw std::runtime_error("Unsupported data type in SEAL EXPORT_TO_ABI");
        }
    };
}

/**
 * @brief Create SEAL ABI import executor
 *
 * Reads CCiphertext* from the c_struct input node and imports it into the
 * pre-allocated seal::Ciphertext output handle provided via ctx.other_args[0].
 * The dest pointer is supplied by the runner's get_other_args callback using
 * extract_output_handle_map (same pattern as cxx_abi_bridge_executors.h).
 */
inline ExecutorFunc create_seal_abi_import_executor() {
    return [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
              const ComputeNode& self) -> void {
        seal::SEALContext* context = g_seal_context;
        uint64_t param_id = g_seal_param_id;
        auto& key_ctx = *context->key_context_data();
        auto ntt_tables = seal::util::iter(key_ctx.small_ntt_tables());

        const DatumNode* input_node = self.input_nodes[0];
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties");
        }

        if (ctx.other_args.empty()) {
            throw std::runtime_error("SEAL IMPORT_FROM_ABI requires pre-allocated dest via other_args");
        }

        DataType data_type = input_node->datum_type;

        switch (data_type) {
            case TYPE_CIPHERTEXT: {
                auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(inputs.at(input_node->index));
                void* dest_raw = ctx.get_other_arg<void>(0);
                auto* dest = static_cast<seal::Ciphertext*>(dest_raw);
                _import_ciphertext(param_id, ntt_tables, c_ct_ptr.get(), dest);
                output = std::shared_ptr<void>(dest_raw, [](void*) {});
                break;
            }
            default: throw std::runtime_error("Unsupported data type in SEAL IMPORT_FROM_ABI");
        }
    };
}

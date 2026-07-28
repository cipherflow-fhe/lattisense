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
 * @file abi_bridge_executors.cc
 * @brief Lattigo plug-in ↔ ABI layer bridge executor for heterogeneous computing
 *
 * Mirrors cxx_sdk_v2/cxx_abi_bridge_executors.h but for the external Lattigo
 * plug-in. The EXPORT_TO_ABI executor reads uintptr_t handles from CArgument.data
 * and calls the per-type Export* Go callbacks to perform Lattigo → C struct conversion.
 *
 * params_handle is read from the global g_lattigo_params_handle, which is set
 * by the Go runner (via SetLattigoParamsHandle) before each run_fhe_gpu_task call
 * and is cleared by ClearLattigoParamsHandle afterwards. The handle itself is
 * pinned in Go's pinnedHandles registry and released by clearPinnedHandles() on Free().
 */

#include <any>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include "wrapper.h"
#include "mega_ag.h"

extern "C" {
#include "c_types.h"
#include "c_structs.h"
#include "c_argument.h"

// Go callbacks implemented in c_struct_import_export.go
void ExportLattigoBfvCiphertext(uintptr_t src_handle, CCiphertext* dest);
void ExportLattigoCkksCiphertext(uintptr_t src_handle, CCiphertext* dest);
void ExportLattigoBfvPlaintext(uintptr_t src_handle, CPlaintext* dest);
void ExportLattigoCkksPlaintext(uintptr_t src_handle, CPlaintext* dest);
void ExportLattigoBfvPlaintextRingT(uintptr_t src_handle, CPlaintext* dest);
void ExportLattigoBfvPlaintextMul(uintptr_t params_handle, uintptr_t src_handle, int mf_nbits, CPlaintext* dest);
void ExportLattigoRelinKey(uintptr_t params_handle, uintptr_t src_handle, int level, int key_mf_nbits, CRelinKey* dest);
void ExportLattigoGaloisKey(uintptr_t params_handle,
                            uintptr_t src_handle,
                            uint64_t galois_element,
                            int level,
                            int key_mf_nbits,
                            CGaloisKey* dest);

// Go callbacks for import
void ImportLattigoBfvCiphertext(uintptr_t dest_handle, CCiphertext* src);
void ImportLattigoCkksCiphertext(uintptr_t dest_handle, CCiphertext* src);
}

// Global params handle set by Go before each run and cleared after.
// Accessed only from the CPU thread pool (EXPORT_TO_ABI nodes run on CPU).
static uintptr_t g_lattigo_params_handle = 0;

extern "C" void set_lattigo_params_handle(uintptr_t h) {
    g_lattigo_params_handle = h;
}

extern "C" void* create_lattigo_abi_export_executor(int algo, int mf_nbits, int key_mf_nbits) {
    auto* fn = new ExecutorFunc([algo, mf_nbits, key_mf_nbits](ExecutionContext& ctx,
                                                               const std::unordered_map<NodeIndex, std::any>& inputs,
                                                               std::any& output, const ComputeNode& self) -> void {
        const DatumNode* input_node = self.input_nodes[0];
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties for EXPORT_TO_ABI");
        }

        DataType data_type = input_node->datum_type;

        int level = input_node->fhe_prop->level;
        bool is_ringt = input_node->fhe_prop->p.has_value() && input_node->fhe_prop->p->is_ringt;
        bool is_mul = input_node->fhe_prop->is_ntt && input_node->fhe_prop->is_mform;
        uint64_t galois_element = (data_type == TYPE_GALOIS_KEY && input_node->fhe_prop->p.has_value()) ?
                                      input_node->fhe_prop->p->galois_element :
                                      0;

        uintptr_t params_handle = g_lattigo_params_handle;
        auto input_sptr = std::any_cast<std::shared_ptr<void>>(inputs.at(input_node->index));
        uintptr_t input_handle = (uintptr_t)input_sptr.get();

        switch (data_type) {
            case TYPE_CIPHERTEXT: {
                auto* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                if (algo == ALGO_BFV)
                    ExportLattigoBfvCiphertext(input_handle, c_ct);
                else
                    ExportLattigoCkksCiphertext(input_handle, c_ct);

                output = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* p) {
                    free_ciphertext(p);
                    free(p);
                });
                break;
            }
            case TYPE_PLAINTEXT: {
                auto* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                if (is_ringt)
                    ExportLattigoBfvPlaintextRingT(input_handle, c_pt);
                else if (is_mul)
                    ExportLattigoBfvPlaintextMul(params_handle, input_handle, mf_nbits, c_pt);
                else if (algo == ALGO_BFV)
                    ExportLattigoBfvPlaintext(input_handle, c_pt);
                else
                    ExportLattigoCkksPlaintext(input_handle, c_pt);

                output = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                    free_plaintext(p);
                    free(p);
                });
                break;
            }
            case TYPE_RELIN_KEY: {
                auto* c_rlk = (CRelinKey*)malloc(sizeof(CRelinKey));
                ExportLattigoRelinKey(params_handle, input_handle, level, key_mf_nbits, c_rlk);
                output = std::shared_ptr<CRelinKey>(c_rlk, [](CRelinKey* p) {
                    free_relin_key(p);
                    free(p);
                });
                break;
            }
            case TYPE_GALOIS_KEY: {
                auto* c_glk = (CGaloisKey*)malloc(sizeof(CGaloisKey));
                ExportLattigoGaloisKey(params_handle, input_handle, galois_element, level, key_mf_nbits, c_glk);

                output = std::shared_ptr<CGaloisKey>(c_glk, [](CGaloisKey* p) {
                    free_galois_key(p);
                    free(p);
                });
                break;
            }
            default: throw std::runtime_error("Unsupported data type in Lattigo EXPORT_TO_ABI");
        }
    });

    return static_cast<void*>(fn);
}

extern "C" void* create_lattigo_abi_import_executor(int algo) {
    auto* fn = new ExecutorFunc([algo](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                       std::any& output, const ComputeNode& self) -> void {
        const DatumNode* input_node = self.input_nodes[0];
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties for IMPORT_FROM_ABI");
        }

        if (ctx.other_args.empty())
            throw std::runtime_error("Lattigo IMPORT_FROM_ABI requires pre-allocated dest via other_args");

        DataType data_type = input_node->datum_type;

        switch (data_type) {
            case TYPE_CIPHERTEXT: {
                auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(inputs.at(input_node->index));

                uintptr_t dest_handle = (uintptr_t)ctx.get_other_arg<void>(0);
                if (algo == ALGO_BFV)
                    ImportLattigoBfvCiphertext(dest_handle, c_ct_ptr.get());
                else
                    ImportLattigoCkksCiphertext(dest_handle, c_ct_ptr.get());
                output = std::shared_ptr<void>((void*)dest_handle, [](void*) {});
                break;
            }
            default: throw std::runtime_error("Unsupported data type in Lattigo IMPORT_FROM_ABI");
        }
    });

    return static_cast<void*>(fn);
}

extern "C" void release_lattigo_executor(void* executor) {
    delete static_cast<ExecutorFunc*>(executor);
}

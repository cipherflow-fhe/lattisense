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
 * @file cxx_abi_bridge_executors.h
 * @brief Frontend library ↔ ABI layer bridge executors for heterogeneous computing
 *
 * This module provides ABI bridge executors between frontend library types
 * (fhe_ops_lib Handle, SEAL types, lattigo types, etc.) and the unified ABI layer
 * (C struct types: CCiphertext, CPlaintext, etc.).
 *
 * Architecture:
 *   Frontend Libraries (fhe_ops_lib/SEAL/lattigo) ↔ ABI Layer (C Structs) ↔ Backend (GPU/FPGA/CPU)
 *
 * Bridge operations:
 * - EXPORT_TO_ABI: fhe_ops_lib::Handle → CCiphertext/CPlaintext (ABI layer)
 * - IMPORT_FROM_ABI: CCiphertext/CPlaintext → fhe_ops_lib::Handle (ABI layer)
 *
 * These executors are bound to ABI bridge nodes in the MegaAG graph during
 * the from_json phase for heterogeneous computing mode.
 */

#ifndef CXX_ABI_BRIDGE_EXECUTORS_H
#define CXX_ABI_BRIDGE_EXECUTORS_H

#include "../mega_ag_runners/mega_ag.h"
#include "../fhe_ops_lib/fhe_lib_v2.h"
#include "cxx_argument.h"
#include <stdexcept>
#include <memory>
#include <any>
#include <unordered_map>

extern "C" {
#include "../abi/c_structs.h"
#include "../mega_ag_runners/c_argument.h"
}

namespace lattisense {

using namespace fhe_ops_lib;

/**
 * @brief Create ABI export executor
 *
 * Creates an executor that analyzes the compute node's input at runtime
 * and exports Handle to C struct based on data type and format:
 * - BfvCiphertext/CkksCiphertext → CCiphertext
 * - BfvPlaintext/CkksPlaintext → CPlaintext (ringt/mul/normal)
 * - RelinKey/GaloisKey → CRelinKey/CGaloisKey
 * - KeySwitchKey → CKeySwitchKey (CKKS only)
 *
 * @param algorithm FHE algorithm (ALGO_BFV or ALGO_CKKS)
 * @param heterogeneous_mode true to convert to C structs (GPU/FPGA), false to pass through native handles (CPU)
 * @param mf_nbits Montgomery form bits for plaintext mul preprocessing
 *                 (GPU_MFORM_BITS for GPU, V2_FPGA_MFORM_BITS for FPGA)
 * @param key_mf_nbits Montgomery form bits for keys (rlk/glk)
 *                     (typically mf_nbits - log2(n) for FPGA)
 *
 * @return ExecutorFunc that performs the export operation
 *
 * @note This executor runs in CPU thread pool (custom nodes)
 * @note Input: std::shared_ptr<fhe_ops_lib::Handle> from available_data
 * @note Output: std::shared_ptr<CCiphertext/CPlaintext/etc> stored in std::any
 */
inline ExecutorFunc
create_abi_export_executor(Algo algorithm, bool heterogeneous_mode = true, int mf_nbits = 64, int key_mf_nbits = 64) {
    if (algorithm == Algo::ALGO_BFV) {
        return [heterogeneous_mode, mf_nbits, key_mf_nbits](ExecutionContext& ctx,
                                                            const std::unordered_map<NodeIndex, std::any>& inputs,
                                                            std::any& output, const ComputeNode& self) -> void {
            const DatumNode* input_node = self.input_nodes[0];
            DataType data_type = input_node->datum_type;

            std::any input_any = inputs.at(input_node->index);
            std::shared_ptr<void> input_ptr;
            if (input_node->is_input) {
                input_ptr = std::any_cast<std::shared_ptr<void>>(input_any);
            }

            BfvContext* bfv_ctx = ctx.get_arithmetic_context<BfvContext>();
            if (!bfv_ctx)
                throw std::runtime_error("BFV context not found for ABI export executor");

            const BfvParameter& param = bfv_ctx->get_parameter();
            int level = input_node->fhe_prop.has_value() ? input_node->fhe_prop->level : -1;
            bool is_ringt = input_node->fhe_prop.has_value() && input_node->fhe_prop->p.has_value() &&
                            input_node->fhe_prop->p->is_ringt;
            bool is_mul =
                input_node->fhe_prop.has_value() && input_node->fhe_prop->is_ntt && input_node->fhe_prop->is_mform;

            switch (data_type) {
                case DataType::TYPE_CIPHERTEXT: {
                    BfvCiphertext* ct = input_node->is_input ?
                                            static_cast<BfvCiphertext*>(input_ptr.get()) :
                                            std::any_cast<std::shared_ptr<BfvCiphertext>>(input_any).get();
                    if (!heterogeneous_mode) {
                        output = input_node->is_input ? std::shared_ptr<BfvCiphertext>(input_ptr, ct) :
                                                        std::any_cast<std::shared_ptr<BfvCiphertext>>(input_any);
                        break;
                    }
                    CCiphertext* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                    export_bfv_ciphertext(ct->get(), c_ct);

                    output = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* p) {
                        free_ciphertext(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_PLAINTEXT:
                    if (is_ringt) {
                        BfvPlaintextRingt* pt = input_node->is_input ?
                                                    static_cast<BfvPlaintextRingt*>(input_ptr.get()) :
                                                    std::any_cast<std::shared_ptr<BfvPlaintextRingt>>(input_any).get();
                        if (!heterogeneous_mode) {
                            output = input_node->is_input ?
                                         std::shared_ptr<BfvPlaintextRingt>(input_ptr, pt) :
                                         std::any_cast<std::shared_ptr<BfvPlaintextRingt>>(input_any);
                            break;
                        }
                        CPlaintext* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                        export_bfv_plaintext_ringt(pt->get(), c_pt);
                        output = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                            free_plaintext(p);
                            free(p);
                        });
                    } else if (is_mul) {
                        BfvPlaintextMul* pt = input_node->is_input ?
                                                  static_cast<BfvPlaintextMul*>(input_ptr.get()) :
                                                  std::any_cast<std::shared_ptr<BfvPlaintextMul>>(input_any).get();
                        if (!heterogeneous_mode) {
                            output = input_node->is_input ? std::shared_ptr<BfvPlaintextMul>(input_ptr, pt) :
                                                            std::any_cast<std::shared_ptr<BfvPlaintextMul>>(input_any);
                            break;
                        }

                        CPlaintext* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                        export_bfv_plaintext_mul(param.get(), pt->get(), mf_nbits, c_pt);
                        output = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                            free_plaintext(p);
                            free(p);
                        });
                    } else {
                        BfvPlaintext* pt = input_node->is_input ?
                                               static_cast<BfvPlaintext*>(input_ptr.get()) :
                                               std::any_cast<std::shared_ptr<BfvPlaintext>>(input_any).get();
                        if (!heterogeneous_mode) {
                            output = input_node->is_input ? std::shared_ptr<BfvPlaintext>(input_ptr, pt) :
                                                            std::any_cast<std::shared_ptr<BfvPlaintext>>(input_any);
                            break;
                        }
                        CPlaintext* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                        export_bfv_plaintext(pt->get(), c_pt);
                        output = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                            free_plaintext(p);
                            free(p);
                        });
                    }
                    break;

                case DataType::TYPE_RELIN_KEY: {
                    if (!heterogeneous_mode)
                        break;
                    RelinKey* rlk = static_cast<RelinKey*>(input_ptr.get());

                    CRelinKey* c_rlk = (CRelinKey*)malloc(sizeof(CRelinKey));
                    export_bfv_relin_key(param.get(), rlk->get(), level, key_mf_nbits, c_rlk);
                    output = std::shared_ptr<CRelinKey>(c_rlk, [](CRelinKey* p) {
                        free_relin_key(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_GALOIS_KEY: {
                    if (!heterogeneous_mode)
                        break;
                    // Get galois element from DatumNode
                    uint64_t galois_element =
                        input_node->fhe_prop->p.has_value() ? input_node->fhe_prop->p->galois_element : 0;

                    GaloisKey* glk = static_cast<GaloisKey*>(input_ptr.get());

                    CGaloisKey* c_glk = (CGaloisKey*)malloc(sizeof(CGaloisKey));
                    set_galois_key_steps(c_glk, &galois_element, 1);

                    export_bfv_galois_key(param.get(), glk->get(), level, key_mf_nbits, c_glk);
                    output = std::shared_ptr<CGaloisKey>(c_glk, [](CGaloisKey* p) {
                        free_galois_key(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_CUSTOM: {
                    CustomData* raw = input_node->is_input ?
                                          static_cast<CustomData*>(input_ptr.get()) :
                                          std::any_cast<std::shared_ptr<CustomData>>(input_any).get();
                    output = std::shared_ptr<CustomData>(raw, [input_any](CustomData*) {});
                    break;
                }

                default: throw std::runtime_error("Unsupported data type for BFV EXPORT_TO_ABI");
            }
        };
    } else if (algorithm == Algo::ALGO_CKKS) {
        return [mf_nbits, key_mf_nbits, heterogeneous_mode](ExecutionContext& ctx,
                                                            const std::unordered_map<NodeIndex, std::any>& inputs,
                                                            std::any& output, const ComputeNode& self) -> void {
            const DatumNode* input_node = self.input_nodes[0];
            DataType data_type = input_node->datum_type;

            std::any input_any = inputs.at(input_node->index);
            std::shared_ptr<void> input_ptr;
            if (input_node->is_input) {
                input_ptr = std::any_cast<std::shared_ptr<void>>(input_any);
            }

            // Get CKKS context
            CkksContext* ckks_ctx = nullptr;
            if (auto* c = ctx.get_arithmetic_context<CkksContext>()) {
                ckks_ctx = c;
            } else if (auto* c = ctx.get_arithmetic_context<CkksBtpContext>()) {
                ckks_ctx = c;
            } else {
                throw std::runtime_error("Invalid context type for CKKS EXPORT_TO_ABI");
            }

            const CkksParameter& param = ckks_ctx->get_parameter();

            int level = input_node->fhe_prop.has_value() ? input_node->fhe_prop->level : -1;
            int sp_level = input_node->fhe_prop.has_value() ? input_node->fhe_prop->sp_level : -1;
            bool is_ringt = input_node->fhe_prop.has_value() && input_node->fhe_prop->p.has_value() &&
                            input_node->fhe_prop->p->is_ringt;
            bool is_mul =
                input_node->fhe_prop.has_value() && input_node->fhe_prop->is_ntt && input_node->fhe_prop->is_mform;

            switch (data_type) {
                case DataType::TYPE_CIPHERTEXT: {
                    CkksCiphertext* ct = input_node->is_input ?
                                             static_cast<CkksCiphertext*>(input_ptr.get()) :
                                             std::any_cast<std::shared_ptr<CkksCiphertext>>(input_any).get();
                    if (!heterogeneous_mode) {
                        output = input_node->is_input ? std::shared_ptr<CkksCiphertext>(input_ptr, ct) :
                                                        std::any_cast<std::shared_ptr<CkksCiphertext>>(input_any);
                        break;
                    }
                    CCiphertext* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                    export_ckks_ciphertext(ct->get(), c_ct);
                    output = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* p) {
                        free_ciphertext(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_PLAINTEXT:
                    if (is_ringt) {
                        CkksPlaintextRingt* pt =
                            input_node->is_input ? static_cast<CkksPlaintextRingt*>(input_ptr.get()) :
                                                   std::any_cast<std::shared_ptr<CkksPlaintextRingt>>(input_any).get();
                        if (!heterogeneous_mode) {
                            output = input_node->is_input ?
                                         std::shared_ptr<CkksPlaintextRingt>(input_ptr, pt) :
                                         std::any_cast<std::shared_ptr<CkksPlaintextRingt>>(input_any);
                            break;
                        }
                        CPlaintext* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                        export_ckks_plaintext_ringt(pt->get(), c_pt);
                        output = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                            free_plaintext(p);
                            free(p);
                        });
                    } else if (is_mul) {
                        CkksPlaintextMul* pt = input_node->is_input ?
                                                   static_cast<CkksPlaintextMul*>(input_ptr.get()) :
                                                   std::any_cast<std::shared_ptr<CkksPlaintextMul>>(input_any).get();
                        if (!heterogeneous_mode) {
                            output = input_node->is_input ? std::shared_ptr<CkksPlaintextMul>(input_ptr, pt) :
                                                            std::any_cast<std::shared_ptr<CkksPlaintextMul>>(input_any);
                            break;
                        }

                        CPlaintext* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                        export_ckks_plaintext_mul(param.get(), pt->get(), mf_nbits, c_pt);
                        output = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                            free_plaintext(p);
                            free(p);
                        });
                    } else {
                        CkksPlaintext* pt = input_node->is_input ?
                                                static_cast<CkksPlaintext*>(input_ptr.get()) :
                                                std::any_cast<std::shared_ptr<CkksPlaintext>>(input_any).get();
                        if (!heterogeneous_mode) {
                            output = input_node->is_input ? std::shared_ptr<CkksPlaintext>(input_ptr, pt) :
                                                            std::any_cast<std::shared_ptr<CkksPlaintext>>(input_any);
                            break;
                        }
                        CPlaintext* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                        export_ckks_plaintext(pt->get(), c_pt);
                        output = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                            free_plaintext(p);
                            free(p);
                        });
                    }
                    break;

                case DataType::TYPE_RELIN_KEY: {
                    if (!heterogeneous_mode)
                        break;
                    RelinKey* rlk = static_cast<RelinKey*>(input_ptr.get());

                    CRelinKey* c_rlk = (CRelinKey*)malloc(sizeof(CRelinKey));
                    export_ckks_relin_key(param.get(), rlk->get(), level, key_mf_nbits, c_rlk);
                    output = std::shared_ptr<CRelinKey>(c_rlk, [](CRelinKey* p) {
                        free_relin_key(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_GALOIS_KEY: {
                    if (!heterogeneous_mode)
                        break;
                    uint64_t galois_element =
                        input_node->fhe_prop->p.has_value() ? input_node->fhe_prop->p->galois_element : 0;

                    GaloisKey* glk = static_cast<GaloisKey*>(input_ptr.get());

                    CGaloisKey* c_glk = (CGaloisKey*)malloc(sizeof(CGaloisKey));
                    set_galois_key_steps(c_glk, &galois_element, 1);

                    export_ckks_galois_key(param.get(), glk->get(), level, key_mf_nbits, c_glk);
                    output = std::shared_ptr<CGaloisKey>(c_glk, [](CGaloisKey* p) {
                        free_galois_key(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_SWITCH_KEY: {
                    if (!heterogeneous_mode)
                        break;
                    KeySwitchKey* swk = static_cast<KeySwitchKey*>(input_ptr.get());

                    CKeySwitchKey* c_swk = (CKeySwitchKey*)malloc(sizeof(CKeySwitchKey));
                    export_ckks_switching_key(param.get(), swk->get(), level, sp_level, key_mf_nbits, c_swk);
                    output = std::shared_ptr<CKeySwitchKey>(c_swk, [](CKeySwitchKey* p) {
                        free_relin_key(p);  // CKeySwitchKey is typedef of CRelinKey
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_CUSTOM: {
                    CustomData* raw = input_node->is_input ?
                                          static_cast<CustomData*>(input_ptr.get()) :
                                          std::any_cast<std::shared_ptr<CustomData>>(input_any).get();
                    output = std::shared_ptr<CustomData>(raw, [input_any](CustomData*) {});
                    break;
                }

                default: throw std::runtime_error("Unsupported data type for CKKS EXPORT_TO_ABI");
            }
        };
    }

    throw std::runtime_error("Unsupported algorithm for EXPORT_TO_ABI");
}

/**
 * @brief Create ABI import executor
 *
 * Creates an executor that imports C struct to Handle based on data type:
 * - CCiphertext → BfvCiphertext/CkksCiphertext
 * - CPlaintext → BfvPlaintext/CkksPlaintext
 *
 * @param algorithm FHE algorithm (ALGO_BFV or ALGO_CKKS)
 * @param heterogeneous_mode true for GPU/FPGA (input is CCiphertext), false for CPU (input is Handle)
 *
 * @return ExecutorFunc that performs the import operation
 *
 * @note This executor runs in CPU thread pool (custom nodes)
 * @note Input: std::shared_ptr<CCiphertext> (heterogeneous) or std::shared_ptr<Handle> (CPU)
 * @note Output: if pre-allocated (shared_ptr<void>), write-back to dest; otherwise store new shared_ptr<Handle>
 */
inline ExecutorFunc create_abi_import_executor(Algo algorithm, bool heterogeneous_mode = true) {
    if (algorithm == Algo::ALGO_BFV) {
        return [heterogeneous_mode](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                    std::any& output, const ComputeNode& self) -> void {
            const DatumNode* input_node = self.input_nodes[0];
            DataType data_type = input_node->datum_type;

            BfvContext* bfv_ctx = ctx.get_arithmetic_context<BfvContext>();
            if (!bfv_ctx)
                throw std::runtime_error("BFV context not found for IMPORT_FROM_ABI");

            switch (data_type) {
                case DataType::TYPE_CIPHERTEXT: {
                    if (heterogeneous_mode) {
                        const std::any& input_any = inputs.at(input_node->index);
                        if (input_any.type() == typeid(std::shared_ptr<CCiphertext>)) {
                            auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(input_any);
                            if (!ctx.other_args.empty()) {
                                // output node: import (copy) into pre-allocated dest handle
                                void* dest_raw = ctx.get_other_arg<void>(0);
                                import_bfv_ciphertext(static_cast<BfvCiphertext*>(dest_raw)->get(), c_ct_ptr.get());
                                output = std::shared_ptr<void>(dest_raw, [](void*) {});
                            } else {
                                // intermediate data: create new handle then import inplace
                                int level = input_node->fhe_prop->level;
                                auto* bfv_ct = new BfvCiphertext(bfv_ctx->new_ciphertext(level));
                                import_bfv_ciphertext(bfv_ct->get(), c_ct_ptr.get());
                                output = std::shared_ptr<BfvCiphertext>(bfv_ct, [](BfvCiphertext* p) { delete p; });
                            }
                        } else {
                            // native handle (BfvCiphertext from custom node): copy to pre-allocated dest
                            if (ctx.other_args.empty())
                                throw std::runtime_error(
                                    "Handle IMPORT_FROM_ABI requires pre-allocated dest via other_args");
                            void* dest_raw = ctx.get_other_arg<void>(0);
                            if (input_node->fhe_prop->degree == 2) {
                                auto sp = std::any_cast<std::shared_ptr<BfvCiphertext3>>(input_any);
                                sp->copy_to(*static_cast<BfvCiphertext3*>(dest_raw));
                            } else {
                                auto sp = std::any_cast<std::shared_ptr<BfvCiphertext>>(input_any);
                                sp->copy_to(*static_cast<BfvCiphertext*>(dest_raw));
                            }
                            output = std::shared_ptr<void>(dest_raw, [](void*) {});
                        }
                    } else {
                        // CPU mode: other_args must supply pre-allocated dest
                        if (ctx.other_args.empty())
                            throw std::runtime_error("CPU IMPORT_FROM_ABI requires pre-allocated dest via other_args");
                        Handle* dest = static_cast<Handle*>(ctx.get_other_arg<void>(0));
                        if (input_node->fhe_prop->degree == 2) {
                            auto sp = std::any_cast<std::shared_ptr<BfvCiphertext3>>(inputs.at(input_node->index));
                            sp->copy_to(*static_cast<BfvCiphertext3*>(dest));
                        } else {
                            auto sp = std::any_cast<std::shared_ptr<BfvCiphertext>>(inputs.at(input_node->index));
                            sp->copy_to(*static_cast<BfvCiphertext*>(dest));
                        }
                    }
                    break;
                }

                default: throw std::runtime_error("Unsupported data type for BFV IMPORT_FROM_ABI");
            }
        };
    } else if (algorithm == Algo::ALGO_CKKS) {
        return [heterogeneous_mode](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                    std::any& output, const ComputeNode& self) -> void {
            const DatumNode* input_node = self.input_nodes[0];
            DataType data_type = input_node->datum_type;

            CkksContext* ckks_ctx = nullptr;
            if (auto* c = ctx.get_arithmetic_context<CkksContext>()) {
                ckks_ctx = c;
            } else if (auto* c = ctx.get_arithmetic_context<CkksBtpContext>()) {
                ckks_ctx = c;
            } else {
                throw std::runtime_error("Invalid context type for CKKS IMPORT_FROM_ABI");
            }

            switch (data_type) {
                case DataType::TYPE_CIPHERTEXT: {
                    if (heterogeneous_mode) {
                        const std::any& input_any = inputs.at(input_node->index);
                        if (input_any.type() == typeid(std::shared_ptr<CCiphertext>)) {
                            auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(input_any);
                            if (!ctx.other_args.empty()) {
                                // output node: import (copy) into pre-allocated dest handle
                                void* dest_raw = ctx.get_other_arg<void>(0);
                                import_ckks_ciphertext(static_cast<CkksCiphertext*>(dest_raw)->get(), c_ct_ptr.get());
                                output = std::shared_ptr<void>(dest_raw, [](void*) {});
                            } else {
                                // intermediate data: create new handle then import inplace
                                int level = input_node->fhe_prop->level;
                                double scale = ckks_ctx->get_parameter().get_default_scale();
                                auto* ckks_ct = new CkksCiphertext(ckks_ctx->new_ciphertext(level, scale));
                                import_ckks_ciphertext(ckks_ct->get(), c_ct_ptr.get());
                                output = std::shared_ptr<CkksCiphertext>(ckks_ct, [](CkksCiphertext* p) { delete p; });
                            }
                        } else {
                            // native handle (CkksCiphertext from custom node): copy to pre-allocated dest
                            if (ctx.other_args.empty())
                                throw std::runtime_error(
                                    "Handle IMPORT_FROM_ABI requires pre-allocated dest via other_args");
                            void* dest_raw = ctx.get_other_arg<void>(0);
                            if (input_node->fhe_prop->degree == 2) {
                                auto sp = std::any_cast<std::shared_ptr<CkksCiphertext3>>(input_any);
                                sp->copy_to(*static_cast<CkksCiphertext3*>(dest_raw));
                            } else {
                                auto sp = std::any_cast<std::shared_ptr<CkksCiphertext>>(input_any);
                                sp->copy_to(*static_cast<CkksCiphertext*>(dest_raw));
                            }
                            output = std::shared_ptr<void>(dest_raw, [](void*) {});
                        }
                    } else {
                        // CPU mode: other_args must supply pre-allocated dest
                        if (ctx.other_args.empty())
                            throw std::runtime_error("CPU IMPORT_FROM_ABI requires pre-allocated dest via other_args");
                        Handle* dest = static_cast<Handle*>(ctx.get_other_arg<void>(0));
                        if (input_node->fhe_prop->degree == 2) {
                            auto sp = std::any_cast<std::shared_ptr<CkksCiphertext3>>(inputs.at(input_node->index));
                            sp->copy_to(*static_cast<CkksCiphertext3*>(dest));
                        } else {
                            auto sp = std::any_cast<std::shared_ptr<CkksCiphertext>>(inputs.at(input_node->index));
                            sp->copy_to(*static_cast<CkksCiphertext*>(dest));
                        }
                    }
                    break;
                }

                default: throw std::runtime_error("Unsupported data type for CKKS IMPORT_FROM_ABI");
            }
        };
    }

    throw std::runtime_error("Unsupported algorithm for IMPORT_FROM_ABI");
}

}  // namespace lattisense

#endif  // CXX_ABI_BRIDGE_EXECUTORS_H

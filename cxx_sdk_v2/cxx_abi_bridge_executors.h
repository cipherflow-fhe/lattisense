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
#include "../fhe_ops_lib/schemes/base/custom_data.h"
#include "../fhe_ops_lib/schemes/base/internal.h"
#include "../fhe_ops_lib/schemes/bfv/bfv.h"
#include "../fhe_ops_lib/schemes/ckks/ckks.h"
#include "cxx_argument.h"
#include <stdexcept>
#include <memory>
#include <any>
#include <cstdio>
#include <mutex>
#include <string>
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
 * - RelinKey/GaloisKey/EvaluationKey → CEvaluationKey
 *
 * @param algorithm FHE algorithm (ALGO_BFV or ALGO_CKKS)
 * @param heterogeneous_mode true to convert to C structs (GPU/FPGA), false to pass through native handles (CPU)
 *
 * @return ExecutorFunc that performs the export operation
 *
 * @note This executor runs in CPU thread pool (custom nodes)
 * @note Input: std::shared_ptr<fhe_ops_lib::Handle> from available_data
 * @note Output: std::shared_ptr<CCiphertext/CPlaintext/etc> stored in std::any
 */
inline ExecutorFunc create_abi_export_executor(Algo algorithm, bool heterogeneous_mode = true) {
    if (algorithm == Algo::ALGO_BFV) {
        return [heterogeneous_mode](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                    const ComputeNode& self) -> void {
            const DatumNode* input_node = self.input_nodes[0];
            DataType data_type = input_node->datum_type;

            std::any input_any = local_data.at(input_node->id);
            std::shared_ptr<void> input_ptr;
            if (input_node->is_input) {
                input_ptr = std::any_cast<std::shared_ptr<void>>(input_any);
            }

            BfvContext* bfv_ctx = ctx.get_arithmetic_context<BfvContext>();
            if (!bfv_ctx)
                throw std::runtime_error("BFV context not found for ABI export executor");

            const BfvParameter& param = bfv_ctx->parameter();
            Metadata source_metadata = input_node->metadata();
            Metadata target_metadata = self.output_nodes[0]->metadata();
            switch (data_type) {
                case DataType::TYPE_CIPHERTEXT: {
                    BfvCiphertext* ct = input_node->is_input ?
                                            static_cast<BfvCiphertext*>(input_ptr.get()) :
                                            std::any_cast<std::shared_ptr<BfvCiphertext>>(input_any).get();
                    if (!heterogeneous_mode) {
                        local_data[self.output_nodes[0]->id] =
                            input_node->is_input ? std::shared_ptr<BfvCiphertext>(input_ptr, ct) :
                                                   std::any_cast<std::shared_ptr<BfvCiphertext>>(input_any);
                        break;
                    }
                    Metadata local_metadata = ct->metadata();
                    if (local_metadata != source_metadata) {
                        printf("ABI export input metadata mismatch for data node %s\n"
                               "local_metadata={is_ringt=%d, is_batched=%d, degree=%d, level=%d, log_slots=%d, "
                               "scale=%f, is_ntt=%d, mform_bits=%d}\n"
                               "source_metadata={is_ringt=%d, is_batched=%d, degree=%d, level=%d, log_slots=%d, "
                               "scale=%f, is_ntt=%d, mform_bits=%d}\n",
                               input_node->id.c_str(), static_cast<int>(local_metadata.is_ringt),
                               static_cast<int>(local_metadata.is_batched), local_metadata.degree, local_metadata.level,
                               local_metadata.log_slots, local_metadata.scale, static_cast<int>(local_metadata.is_ntt),
                               local_metadata.mform_bits, static_cast<int>(source_metadata.is_ringt),
                               static_cast<int>(source_metadata.is_batched), source_metadata.degree,
                               source_metadata.level, source_metadata.log_slots, source_metadata.scale,
                               static_cast<int>(source_metadata.is_ntt), source_metadata.mform_bits);
                        throw std::runtime_error("ABI export input metadata mismatch for data node " + input_node->id);
                    }
                    CCiphertext* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                    export_ciphertext(param.get(), ct->get(), &target_metadata, c_ct);

                    local_data[self.output_nodes[0]->id] = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* p) {
                        free_ciphertext(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_PLAINTEXT: {
                    BfvPlaintext* pt = input_node->is_input ?
                                           static_cast<BfvPlaintext*>(input_ptr.get()) :
                                           std::any_cast<std::shared_ptr<BfvPlaintext>>(input_any).get();
                    if (!heterogeneous_mode) {
                        local_data[self.output_nodes[0]->id] =
                            input_node->is_input ? std::shared_ptr<BfvPlaintext>(input_ptr, pt) :
                                                   std::any_cast<std::shared_ptr<BfvPlaintext>>(input_any);
                        break;
                    }
                    if (pt->metadata() != source_metadata) {
                        throw std::runtime_error("ABI export input metadata mismatch for data node " + input_node->id);
                    }
                    CPlaintext* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                    export_plaintext(param.get(), pt->get(), &target_metadata, c_pt);
                    local_data[self.output_nodes[0]->id] = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                        free_plaintext(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_RELIN_KEY: {
                    RelinKey* rlk = input_node->is_input ? static_cast<RelinKey*>(input_ptr.get()) :
                                                           std::any_cast<std::shared_ptr<RelinKey>>(input_any).get();
                    if (!heterogeneous_mode) {
                        local_data[self.output_nodes[0]->id] = input_node->is_input ?
                                                                   std::shared_ptr<RelinKey>(input_ptr, rlk) :
                                                                   std::any_cast<std::shared_ptr<RelinKey>>(input_any);
                        auto* abi_export_mutex = ctx.get_other_arg<std::mutex>();
                        if (abi_export_mutex == nullptr)
                            throw std::runtime_error("ABI export mutex not found");
                        std::lock_guard<std::mutex> lock(*abi_export_mutex);
                        bfv_ctx->set_relin_key(*rlk);
                        break;
                    }

                    CEvaluationKey* c_rlk = (CEvaluationKey*)malloc(sizeof(CEvaluationKey));
                    export_evaluation_key(param.get(), rlk->get(), -1, &target_metadata, c_rlk);
                    local_data[self.output_nodes[0]->id] =
                        std::shared_ptr<CEvaluationKey>(c_rlk, [](CEvaluationKey* p) {
                            free_evaluation_key(p);
                            free(p);
                        });
                    break;
                }

                case DataType::TYPE_GALOIS_KEY: {
                    GaloisKey* glk = input_node->is_input ? static_cast<GaloisKey*>(input_ptr.get()) :
                                                            std::any_cast<std::shared_ptr<GaloisKey>>(input_any).get();
                    if (!heterogeneous_mode) {
                        local_data[self.output_nodes[0]->id] = input_node->is_input ?
                                                                   std::shared_ptr<GaloisKey>(input_ptr, glk) :
                                                                   std::any_cast<std::shared_ptr<GaloisKey>>(input_any);
                        auto* abi_export_mutex = ctx.get_other_arg<std::mutex>();
                        if (abi_export_mutex == nullptr)
                            throw std::runtime_error("ABI export mutex not found");
                        std::lock_guard<std::mutex> lock(*abi_export_mutex);
                        bfv_ctx->set_galois_key(*glk);
                        break;
                    }
                    CEvaluationKey* c_glk = (CEvaluationKey*)malloc(sizeof(CEvaluationKey));
                    export_evaluation_key(param.get(), glk->get(), -1, &target_metadata, c_glk);
                    local_data[self.output_nodes[0]->id] =
                        std::shared_ptr<CEvaluationKey>(c_glk, [](CEvaluationKey* p) {
                            free_evaluation_key(p);
                            free(p);
                        });
                    break;
                }

                case DataType::TYPE_CUSTOM: {
                    CustomData* raw = input_node->is_input ?
                                          static_cast<CustomData*>(input_ptr.get()) :
                                          std::any_cast<std::shared_ptr<CustomData>>(input_any).get();
                    local_data[self.output_nodes[0]->id] =
                        std::shared_ptr<CustomData>(raw, [input_any](CustomData*) {});
                    break;
                }

                default: throw std::runtime_error("Unsupported data type for BFV EXPORT_TO_ABI");
            }
        };
    } else if (algorithm == Algo::ALGO_CKKS) {
        return [heterogeneous_mode](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                    const ComputeNode& self) -> void {
            const DatumNode* input_node = self.input_nodes[0];
            DataType data_type = input_node->datum_type;

            std::any input_any = local_data.at(input_node->id);
            std::shared_ptr<void> input_ptr;
            if (input_node->is_input) {
                input_ptr = std::any_cast<std::shared_ptr<void>>(input_any);
            }

            auto* ckks_ctx = ctx.get_arithmetic_context<CkksContext>();
            if (!ckks_ctx) {
                throw std::runtime_error("CKKS context not found for ABI export executor");
            }

            const CkksParameter& param = ckks_ctx->parameter();
            Metadata source_metadata = input_node->metadata();
            Metadata target_metadata = self.output_nodes[0]->metadata();

            int sp_level = input_node->fhe_prop.has_value() && input_node->fhe_prop->p.has_value() ?
                               input_node->fhe_prop->p->sp_level :
                               -1;
            switch (data_type) {
                case DataType::TYPE_CIPHERTEXT: {
                    CkksCiphertext* ct = input_node->is_input ?
                                             static_cast<CkksCiphertext*>(input_ptr.get()) :
                                             std::any_cast<std::shared_ptr<CkksCiphertext>>(input_any).get();
                    if (!heterogeneous_mode) {
                        local_data[self.output_nodes[0]->id] =
                            input_node->is_input ? std::shared_ptr<CkksCiphertext>(input_ptr, ct) :
                                                   std::any_cast<std::shared_ptr<CkksCiphertext>>(input_any);
                        break;
                    }
                    if (ct->metadata() != source_metadata) {
                        throw std::runtime_error("ABI export input metadata mismatch for data node " + input_node->id);
                    }
                    CCiphertext* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                    export_ciphertext(param.get(), ct->get(), &target_metadata, c_ct);
                    local_data[self.output_nodes[0]->id] = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* p) {
                        free_ciphertext(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_PLAINTEXT: {
                    CkksPlaintext* pt = input_node->is_input ?
                                            static_cast<CkksPlaintext*>(input_ptr.get()) :
                                            std::any_cast<std::shared_ptr<CkksPlaintext>>(input_any).get();
                    if (!heterogeneous_mode) {
                        local_data[self.output_nodes[0]->id] =
                            input_node->is_input ? std::shared_ptr<CkksPlaintext>(input_ptr, pt) :
                                                   std::any_cast<std::shared_ptr<CkksPlaintext>>(input_any);
                        break;
                    }
                    if (pt->metadata() != source_metadata) {
                        throw std::runtime_error("ABI export input metadata mismatch for data node " + input_node->id);
                    }
                    CPlaintext* c_pt = (CPlaintext*)malloc(sizeof(CPlaintext));
                    export_plaintext(param.get(), pt->get(), &target_metadata, c_pt);
                    local_data[self.output_nodes[0]->id] = std::shared_ptr<CPlaintext>(c_pt, [](CPlaintext* p) {
                        free_plaintext(p);
                        free(p);
                    });
                    break;
                }

                case DataType::TYPE_RELIN_KEY: {
                    RelinKey* rlk = input_node->is_input ? static_cast<RelinKey*>(input_ptr.get()) :
                                                           std::any_cast<std::shared_ptr<RelinKey>>(input_any).get();
                    if (!heterogeneous_mode) {
                        local_data[self.output_nodes[0]->id] = input_node->is_input ?
                                                                   std::shared_ptr<RelinKey>(input_ptr, rlk) :
                                                                   std::any_cast<std::shared_ptr<RelinKey>>(input_any);
                        auto* abi_export_mutex = ctx.get_other_arg<std::mutex>();
                        if (abi_export_mutex == nullptr)
                            throw std::runtime_error("ABI export mutex not found");
                        std::lock_guard<std::mutex> lock(*abi_export_mutex);
                        bool is_bootstrap_key = input_node->fhe_prop.has_value() &&
                                                input_node->fhe_prop->p.has_value() &&
                                                input_node->fhe_prop->p->key_role == "bootstrap";
                        if (is_bootstrap_key) {
                            ckks_ctx->set_enable_bootstrapping(true);
                            ckks_ctx->set_bootstrapping_relin_key(*rlk);
                        } else {
                            ckks_ctx->set_relin_key(*rlk);
                        }
                        break;
                    }

                    CEvaluationKey* c_rlk = (CEvaluationKey*)malloc(sizeof(CEvaluationKey));
                    export_evaluation_key(param.get(), rlk->get(), -1, &target_metadata, c_rlk);
                    local_data[self.output_nodes[0]->id] =
                        std::shared_ptr<CEvaluationKey>(c_rlk, [](CEvaluationKey* p) {
                            free_evaluation_key(p);
                            free(p);
                        });
                    break;
                }

                case DataType::TYPE_GALOIS_KEY: {
                    GaloisKey* glk = input_node->is_input ? static_cast<GaloisKey*>(input_ptr.get()) :
                                                            std::any_cast<std::shared_ptr<GaloisKey>>(input_any).get();
                    if (!heterogeneous_mode) {
                        local_data[self.output_nodes[0]->id] = input_node->is_input ?
                                                                   std::shared_ptr<GaloisKey>(input_ptr, glk) :
                                                                   std::any_cast<std::shared_ptr<GaloisKey>>(input_any);
                        auto* abi_export_mutex = ctx.get_other_arg<std::mutex>();
                        if (abi_export_mutex == nullptr)
                            throw std::runtime_error("ABI export mutex not found");
                        std::lock_guard<std::mutex> lock(*abi_export_mutex);
                        bool is_bootstrap_key = input_node->fhe_prop.has_value() &&
                                                input_node->fhe_prop->p.has_value() &&
                                                input_node->fhe_prop->p->key_role == "bootstrap";
                        if (is_bootstrap_key) {
                            ckks_ctx->set_enable_bootstrapping(true);
                            ckks_ctx->set_bootstrapping_galois_key(*glk);
                        } else {
                            ckks_ctx->set_galois_key(*glk);
                        }
                        break;
                    }
                    CEvaluationKey* c_glk = (CEvaluationKey*)malloc(sizeof(CEvaluationKey));
                    export_evaluation_key(param.get(), glk->get(), -1, &target_metadata, c_glk);
                    local_data[self.output_nodes[0]->id] =
                        std::shared_ptr<CEvaluationKey>(c_glk, [](CEvaluationKey* p) {
                            free_evaluation_key(p);
                            free(p);
                        });
                    break;
                }

                case DataType::TYPE_EVALUATION_KEY: {
                    EvaluationKey* evk = input_node->is_input ?
                                             static_cast<EvaluationKey*>(input_ptr.get()) :
                                             std::any_cast<std::shared_ptr<EvaluationKey>>(input_any).get();
                    if (!heterogeneous_mode) {
                        local_data[self.output_nodes[0]->id] =
                            input_node->is_input ? std::shared_ptr<EvaluationKey>(input_ptr, evk) :
                                                   std::any_cast<std::shared_ptr<EvaluationKey>>(input_any);
                        auto* abi_export_mutex = ctx.get_other_arg<std::mutex>();
                        if (abi_export_mutex == nullptr)
                            throw std::runtime_error("ABI export mutex not found");
                        std::lock_guard<std::mutex> lock(*abi_export_mutex);
                        bool is_bootstrap_key = input_node->fhe_prop.has_value() &&
                                                input_node->fhe_prop->p.has_value() &&
                                                input_node->fhe_prop->p->key_role == "bootstrap";
                        if (is_bootstrap_key) {
                            ckks_ctx->set_enable_bootstrapping(true);
                            if (input_node->id == "evk_n1_to_n2") {
                                ckks_ctx->set_evk_n1_to_n2(*evk);
                            } else if (input_node->id == "evk_n2_to_n1") {
                                ckks_ctx->set_evk_n2_to_n1(*evk);
                            } else if (input_node->id == "evk_dense_to_sparse") {
                                ckks_ctx->set_evk_dense_to_sparse(*evk);
                            } else if (input_node->id == "evk_sparse_to_dense") {
                                ckks_ctx->set_evk_sparse_to_dense(*evk);
                            }
                        }
                        break;
                    }

                    CEvaluationKey* c_evk = (CEvaluationKey*)malloc(sizeof(CEvaluationKey));
                    export_evaluation_key(param.get(), evk->get(), sp_level, &target_metadata, c_evk);
                    local_data[self.output_nodes[0]->id] =
                        std::shared_ptr<CEvaluationKey>(c_evk, [](CEvaluationKey* p) {
                            free_evaluation_key(p);
                            free(p);
                        });
                    break;
                }

                case DataType::TYPE_CUSTOM: {
                    CustomData* raw = input_node->is_input ?
                                          static_cast<CustomData*>(input_ptr.get()) :
                                          std::any_cast<std::shared_ptr<CustomData>>(input_any).get();
                    local_data[self.output_nodes[0]->id] =
                        std::shared_ptr<CustomData>(raw, [input_any](CustomData*) {});
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
    auto get_import_dest_handle = [](ExecutionContext& ctx, const ComputeNode& self) -> void* {
        if (ctx.other_args.empty()) {
            return nullptr;
        }
        auto* output_handle_map = ctx.get_other_arg<std::unordered_map<NodeId, void*>>(0);
        if (!output_handle_map) {
            return nullptr;
        }
        auto it = output_handle_map->find(self.output_nodes[0]->id);
        return it == output_handle_map->end() ? nullptr : it->second;
    };

    if (algorithm == Algo::ALGO_BFV) {
        return [heterogeneous_mode, get_import_dest_handle](ExecutionContext& ctx,
                                                            std::unordered_map<NodeId, std::any>& local_data,
                                                            const ComputeNode& self) -> void {
            const DatumNode* input_node = self.input_nodes[0];
            DataType data_type = input_node->datum_type;

            BfvContext* bfv_ctx = ctx.get_arithmetic_context<BfvContext>();
            if (!bfv_ctx)
                throw std::runtime_error("BFV context not found for IMPORT_FROM_ABI");

            Metadata source_metadata = input_node->metadata();
            Metadata target_metadata = self.output_nodes[0]->metadata();

            switch (data_type) {
                case DataType::TYPE_CIPHERTEXT: {
                    if (heterogeneous_mode) {
                        const std::any& input_any = local_data.at(input_node->id);
                        if (input_any.type() == typeid(std::shared_ptr<CCiphertext>)) {
                            auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(input_any);
                            void* dest_raw = get_import_dest_handle(ctx, self);
                            if (dest_raw) {
                                // output node: import (copy) into pre-allocated dest handle
                                auto* dest = static_cast<BfvCiphertext*>(dest_raw);
                                CHECK(import_ciphertext(bfv_ctx->parameter().get(), dest->get(), &source_metadata,
                                                        &target_metadata, c_ct_ptr.get()));
                                local_data[self.output_nodes[0]->id] = std::shared_ptr<void>(dest_raw, [](void*) {});
                            } else {
                                // intermediate data: create new handle then import inplace
                                int level = input_node->fhe_prop->level;
                                int degree = input_node->fhe_prop->degree;
                                auto* bfv_ct = new BfvCiphertext(bfv_ctx->parameter(), level, degree);
                                CHECK(import_ciphertext(bfv_ctx->parameter().get(), bfv_ct->get(), &source_metadata,
                                                        &target_metadata, c_ct_ptr.get()));
                                local_data[self.output_nodes[0]->id] =
                                    std::shared_ptr<BfvCiphertext>(bfv_ct, [](BfvCiphertext* p) { delete p; });
                            }
                        } else {
                            // native handle (BfvCiphertext from custom node): copy to pre-allocated dest
                            void* dest_raw = get_import_dest_handle(ctx, self);
                            if (!dest_raw)
                                throw std::runtime_error(
                                    "Handle IMPORT_FROM_ABI requires pre-allocated dest via other_args");
                            auto sp = std::any_cast<std::shared_ptr<BfvCiphertext>>(input_any);
                            sp->copy(*static_cast<BfvCiphertext*>(dest_raw));
                            local_data[self.output_nodes[0]->id] = std::shared_ptr<void>(dest_raw, [](void*) {});
                        }
                    } else {
                        // CPU mode: other_args must supply pre-allocated dest
                        void* dest_raw = get_import_dest_handle(ctx, self);
                        if (!dest_raw)
                            throw std::runtime_error("CPU IMPORT_FROM_ABI requires pre-allocated dest via other_args");
                        auto sp = std::any_cast<std::shared_ptr<BfvCiphertext>>(local_data.at(input_node->id));
                        sp->copy(*static_cast<BfvCiphertext*>(dest_raw));
                        local_data[self.output_nodes[0]->id] = std::shared_ptr<void>(dest_raw, [](void*) {});
                    }
                    break;
                }

                default: throw std::runtime_error("Unsupported data type for BFV IMPORT_FROM_ABI");
            }
        };
    } else if (algorithm == Algo::ALGO_CKKS) {
        return [heterogeneous_mode, get_import_dest_handle](ExecutionContext& ctx,
                                                            std::unordered_map<NodeId, std::any>& local_data,
                                                            const ComputeNode& self) -> void {
            const DatumNode* input_node = self.input_nodes[0];
            DataType data_type = input_node->datum_type;

            auto* ckks_ctx = ctx.get_arithmetic_context<CkksContext>();
            if (!ckks_ctx) {
                throw std::runtime_error("CKKS context not found for IMPORT_FROM_ABI");
            }

            Metadata source_metadata = input_node->metadata();
            Metadata target_metadata = self.output_nodes[0]->metadata();

            switch (data_type) {
                case DataType::TYPE_CIPHERTEXT: {
                    if (heterogeneous_mode) {
                        const std::any& input_any = local_data.at(input_node->id);
                        if (input_any.type() == typeid(std::shared_ptr<CCiphertext>)) {
                            auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(input_any);
                            void* dest_raw = get_import_dest_handle(ctx, self);
                            if (dest_raw) {
                                // output node: import (copy) into pre-allocated dest handle
                                auto* dest = static_cast<CkksCiphertext*>(dest_raw);
                                CHECK(import_ciphertext(ckks_ctx->parameter().get(), dest->get(), &source_metadata,
                                                        &target_metadata, c_ct_ptr.get()));
                                local_data[self.output_nodes[0]->id] = std::shared_ptr<void>(dest_raw, [](void*) {});
                            } else {
                                // intermediate data: create new handle then import inplace
                                int level = input_node->fhe_prop->level;
                                int degree = input_node->fhe_prop->degree;
                                auto* ckks_ct = new CkksCiphertext(ckks_ctx->parameter(), level, degree);
                                CHECK(import_ciphertext(ckks_ctx->parameter().get(), ckks_ct->get(), &source_metadata,
                                                        &target_metadata, c_ct_ptr.get()));
                                local_data[self.output_nodes[0]->id] =
                                    std::shared_ptr<CkksCiphertext>(ckks_ct, [](CkksCiphertext* p) { delete p; });
                            }
                        } else {
                            // native handle (CkksCiphertext from custom node): copy to pre-allocated dest
                            void* dest_raw = get_import_dest_handle(ctx, self);
                            if (!dest_raw)
                                throw std::runtime_error(
                                    "Handle IMPORT_FROM_ABI requires pre-allocated dest via other_args");
                            auto sp = std::any_cast<std::shared_ptr<CkksCiphertext>>(input_any);
                            sp->copy(*static_cast<CkksCiphertext*>(dest_raw));
                            local_data[self.output_nodes[0]->id] = std::shared_ptr<void>(dest_raw, [](void*) {});
                        }
                    } else {
                        // CPU mode: other_args must supply pre-allocated dest
                        void* dest_raw = get_import_dest_handle(ctx, self);
                        if (!dest_raw)
                            throw std::runtime_error("CPU IMPORT_FROM_ABI requires pre-allocated dest via other_args");
                        auto sp = std::any_cast<std::shared_ptr<CkksCiphertext>>(local_data.at(input_node->id));
                        sp->copy(*static_cast<CkksCiphertext*>(dest_raw));
                        local_data[self.output_nodes[0]->id] = std::shared_ptr<void>(dest_raw, [](void*) {});
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

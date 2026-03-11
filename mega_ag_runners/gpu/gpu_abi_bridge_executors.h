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
 * @file gpu_abi_bridge_executors.h
 * @brief ABI layer ↔ GPU backend bridge executors for heterogeneous computing
 *
 * This module provides ABI bridge executors between ABI layer (C struct types)
 * and GPU backend types (heongpu types):
 * - LOAD_TO_BACKEND: C struct (CCiphertext/CPlaintext/etc.) → GPU types (heongpu::Ciphertext/Plaintext/etc.)
 * - STORE_FROM_BACKEND: GPU types → C struct
 *
 * These executors handle data transfer for GPU acceleration.
 */

#ifndef GPU_ABI_BRIDGE_EXECUTORS_H
#define GPU_ABI_BRIDGE_EXECUTORS_H

#include "../mega_ag.h"
#include "../cpu_task_utils.h"
#include <memory>
#include <stdexcept>
#include <any>
#include <mutex>

#include "heongpu.hpp"

extern "C" {
#include "../../fhe_ops_lib/fhe_types_v2.h"
#include "../../fhe_ops_lib/structs_v2.h"
}

/**
 * @brief Check CUDA error and throw exception if error occurred
 */
inline void CHECK(cudaError_t err) {
    if (err != cudaSuccess) {
        throw std::runtime_error(cudaGetErrorString(err));
    }
}

/**
 * @brief Export plaintext from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_plaintext(const CPlaintext& src, heongpu::Plaintext<SchemeType>& dest) {
    int N = src.poly.components->n;
    for (int i = 0; i < src.poly.n_component; i++) {
        CHECK(cudaMemcpyAsync(&(dest.data()[i * N]), src.poly.components[i].data, N * sizeof(uint64_t),
                              cudaMemcpyHostToDevice, dest.stream()));
    }
}

/**
 * @brief Export ciphertext from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_ciphertext(const CCiphertext& src, heongpu::Ciphertext<SchemeType>& dest) {
    int N = src.polys->components->n;
    int n_component = src.polys->n_component;
    for (int i = 0; i < src.degree + 1; i++) {
        for (int j = 0; j < n_component; j++) {
            CHECK(cudaMemcpyAsync(&(dest.data()[i * n_component * N + j * N]), src.polys[i].components[j].data,
                                  N * sizeof(uint64_t), cudaMemcpyHostToDevice, dest.stream()));
        }
    }
}

/**
 * @brief Export relinearization key from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_relin_key(const CRelinKey& src,
                      heongpu::Relinkey<SchemeType>& dest,
                      int first_Q_size,
                      int first_Qprime_size) {
    int N = src.public_keys->polys->components->n;
    int n_public_key = src.n_public_key;
    int level = src.public_keys->level;
    int n_component = src.public_keys->polys->n_component;

    for (int i = 0; i < n_public_key; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < n_component; k++) {
                int k_ = (k < level + 1) ? k : k - (level + 1) + first_Q_size;
                CHECK(
                    cudaMemcpyAsync(&(dest.data()[i * 2 * first_Qprime_size * N + j * first_Qprime_size * N + k_ * N]),
                                    src.public_keys[i].polys[j].components[k].data, N * sizeof(uint64_t),
                                    cudaMemcpyHostToDevice, dest.stream()));
            }
        }
    }
}

/**
 * @brief Export Galois key from C struct to GPU device memory (specific galois element)
 */
template <heongpu::Scheme SchemeType>
void export_galois_key(const CGaloisKey& src,
                       heongpu::Galoiskey<SchemeType>& dest,
                       uint32_t galois_element,
                       int first_Q_size,
                       int first_Qprime_size) {
    int N = src.key_switch_keys->public_keys->polys->components->n;
    int n_public_key = src.key_switch_keys->n_public_key;
    int level = src.key_switch_keys->public_keys->level;
    int n_component = src.key_switch_keys->public_keys->polys->n_component;
    int n_key_switch_key = src.n_key_switch_key;

    for (int i = 0; i < n_key_switch_key; i++) {
        if (src.galois_elements[i] != galois_element) {
            continue;
        }

        for (int j = 0; j < n_public_key; j++) {
            for (int k = 0; k < 2; k++) {
                for (int l = 0; l < n_component; l++) {
                    int l_ = (l < level + 1) ? l : l - (level + 1) + first_Q_size;
                    if (galois_element != 2 * N - 1) {
                        CHECK(cudaMemcpyAsync(
                            &(dest.data(
                                galois_element)[j * 2 * first_Qprime_size * N + k * first_Qprime_size * N + l_ * N]),
                            src.key_switch_keys[i].public_keys[j].polys[k].components[l].data, N * sizeof(uint64_t),
                            cudaMemcpyHostToDevice, dest.stream()));
                    } else {
                        CHECK(cudaMemcpyAsync(
                            &(dest.c_data()[j * 2 * first_Qprime_size * N + k * first_Qprime_size * N + l_ * N]),
                            src.key_switch_keys[i].public_keys[j].polys[k].components[l].data, N * sizeof(uint64_t),
                            cudaMemcpyHostToDevice, dest.stream()));
                    }
                }
            }
        }
    }
}

/**
 * @brief Export switching key from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_switching_key(const ::CKeySwitchKey& src,
                          heongpu::Switchkey<SchemeType>& dest,
                          int first_Q_size,
                          int first_Qprime_size) {
    int N = src.public_keys->polys->components->n;
    int n_public_key = src.n_public_key;
    int level = src.public_keys->level;
    int n_component = src.public_keys->polys->n_component;

    for (int i = 0; i < n_public_key; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < n_component; k++) {
                int k_ = (k < level + 1) ? k : k - (level + 1) + first_Q_size;
                CHECK(
                    cudaMemcpyAsync(&(dest.data()[i * 2 * first_Qprime_size * N + j * first_Qprime_size * N + k_ * N]),
                                    src.public_keys[i].polys[j].components[k].data, N * sizeof(uint64_t),
                                    cudaMemcpyHostToDevice, dest.stream()));
            }
        }
    }
}

/**
 * @brief Import ciphertext from GPU device memory to C struct
 */
template <heongpu::Scheme SchemeType> void import_ciphertext(heongpu::Ciphertext<SchemeType>& src, CCiphertext* dest) {
    int N = src.ring_size();
    int n_component = src.level() + 1;

    for (int i = 0; i < src.size(); i++) {
        for (int j = 0; j < n_component; j++) {
            CHECK(cudaMemcpyAsync(dest->polys[i].components[j].data, &src.data()[i * n_component * N + j * N],
                                  N * sizeof(uint64_t), cudaMemcpyDeviceToHost, src.stream()));
        }
    }
}

/**
 * @brief Create executor for loading ABI data to GPU (H2D transfer)
 *
 * Converts C struct to GPU types:
 * - CCiphertext → heongpu::Ciphertext
 * - CPlaintext → heongpu::Plaintext
 * - CRelinKey → heongpu::Relinkey
 * - CGaloisKey → heongpu::Galoiskey
 * - CKeySwitchKey → heongpu::Switchkey
 *
 * @tparam SchemeType GPU scheme type (heongpu::Scheme::BFV or heongpu::Scheme::CKKS)
 * @return ExecutorFunc that performs H2D transfer
 *
 * @note Input: std::shared_ptr<C struct> from available_data
 * @note Output: std::shared_ptr<GPU type> stored in std::any
 * @note Requires heongpu::HEContext in ExecutionContext other_args[0]
 * @note Requires heongpu::ExecutionOptions in ExecutionContext other_args[1]
 * @note Requires galois_key shared_ptr in ExecutionContext other_args[2]
 * @note Requires galois_key_mutex in ExecutionContext other_args[3]
 */
template <heongpu::Scheme SchemeType> ExecutorFunc create_load_to_gpu_executor() {
    return [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
              const ComputeNode& self) -> void {
        // Get GPU context and options from execution context
        auto* operators = ctx.get_arithmetic_context<heongpu::HEArithmeticOperator<SchemeType>>();
        auto* stream_option = ctx.get_other_arg<heongpu::ExecutionOptions>(0);
        auto* context = ctx.get_other_arg<heongpu::HEContext<SchemeType>>(1);
        auto* galois_key_ptr = ctx.get_other_arg<std::shared_ptr<heongpu::Galoiskey<SchemeType>>>(2);
        auto* galois_key_mutex = ctx.get_other_arg<std::mutex>(3);
        auto* all_galois_elts = ctx.get_other_arg<std::vector<uint32_t>>(4);

        if (!stream_option || !context) {
            throw std::runtime_error("GPU stream options or context not found in execution context");
        }

        // Get input node and data
        const DatumNode* input_node = self.input_nodes[0];
        // Determine data type and galois element
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties");
        }

        DataType data_type = input_node->datum_type;

        std::any c_struct = inputs.at(input_node->index);

        uint32_t galois_element = 0;
        if (data_type == TYPE_GALOIS_KEY && input_node->fhe_prop->p.has_value()) {
            galois_element = input_node->fhe_prop->p->galois_element;
        }

        // Perform H2D transfer based on data type
        std::any gpu_data = std::any{};

        switch (data_type) {
            case TYPE_PLAINTEXT: {
                auto c_pt_ptr = std::any_cast<std::shared_ptr<CPlaintext>>(c_struct);
                const CPlaintext* c_pt = c_pt_ptr.get();
                auto output_ptr =
                    std::make_shared<heongpu::Plaintext<SchemeType>>(*context, c_pt->level, *stream_option);
                export_plaintext(*c_pt, *output_ptr);
                gpu_data = output_ptr;
                break;
            }
            case TYPE_CIPHERTEXT: {
                auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(c_struct);
                const CCiphertext* c_ct = c_ct_ptr.get();
                auto output_ptr =
                    std::make_shared<heongpu::Ciphertext<SchemeType>>(*context, c_ct->level, *stream_option);
                export_ciphertext(*c_ct, *output_ptr);
                gpu_data = output_ptr;
                break;
            }
            case TYPE_RELIN_KEY: {
                auto c_rlk_ptr = std::any_cast<std::shared_ptr<CRelinKey>>(c_struct);
                const CRelinKey* c_rlk = c_rlk_ptr.get();
                auto rlk_ptr = std::make_shared<heongpu::Relinkey<SchemeType>>(*context, *stream_option);
                export_relin_key(*c_rlk, *rlk_ptr, context->get_ciphertext_modulus_count(),
                                 context->get_key_modulus_count());
                gpu_data = rlk_ptr;
                break;
            }
            case TYPE_GALOIS_KEY: {
                auto c_glk_ptr = std::any_cast<std::shared_ptr<CGaloisKey>>(c_struct);
                const CGaloisKey* c_glk = c_glk_ptr.get();

                // Initialize galois_key_ptr once with mutex protection
                {
                    std::lock_guard<std::mutex> lock(*galois_key_mutex);
                    if (!(*galois_key_ptr)) {
                        // Initialize with all galois elements from mega_ag
                        *galois_key_ptr = std::make_shared<heongpu::Galoiskey<SchemeType>>(*context, *all_galois_elts,
                                                                                           *stream_option);
                    }
                }

                // Export data without holding the mutex
                export_galois_key(*c_glk, **galois_key_ptr, galois_element, context->get_ciphertext_modulus_count(),
                                  context->get_key_modulus_count());
                gpu_data = *galois_key_ptr;
                break;
            }
            case TYPE_SWITCH_KEY: {
                auto c_swk_ptr = std::any_cast<std::shared_ptr<CKeySwitchKey>>(c_struct);
                const CKeySwitchKey* c_swk = c_swk_ptr.get();
                auto swk_ptr = std::make_shared<heongpu::Switchkey<SchemeType>>(*context, *stream_option);
                export_switching_key(*c_swk, *swk_ptr, context->get_ciphertext_modulus_count(),
                                     context->get_key_modulus_count());
                gpu_data = swk_ptr;
                break;
            }
            default: throw std::runtime_error("Unsupported data type in H2D transfer");
        }

        // Output is the GPU data
        output = gpu_data;
    };
}

/**
 * @brief Create executor for storing GPU data to ABI (D2H transfer)
 *
 * Converts GPU types to C struct:
 * - heongpu::Ciphertext → CCiphertext
 * - heongpu::Plaintext → CPlaintext
 *
 * @tparam SchemeType GPU scheme type (heongpu::Scheme::BFV or heongpu::Scheme::CKKS)
 * @return ExecutorFunc that performs D2H transfer
 *
 * @note Input: std::shared_ptr<GPU type> from available_data
 * @note Output: std::shared_ptr<C struct> stored in std::any
 * @note C struct memory is allocated here and freed by shared_ptr deleter
 */
template <heongpu::Scheme SchemeType> ExecutorFunc create_store_from_gpu_executor() {
    return [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
              const ComputeNode& self) -> void {
        // Get input node and GPU data
        const DatumNode* input_node = self.input_nodes[0];
        // Determine data type
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties");
        }

        DataType data_type = input_node->datum_type;

        std::any gpu_data = inputs.at(input_node->index);

        // Perform D2H transfer and allocate C struct
        std::any c_struct;

        switch (data_type) {
            case TYPE_CIPHERTEXT: {
                auto gpu_ct = std::any_cast<std::shared_ptr<heongpu::Ciphertext<SchemeType>>>(gpu_data);

                auto* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                alloc_ciphertext(c_ct, gpu_ct->size() - 1, gpu_ct->level(), gpu_ct->ring_size());
                c_struct = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* ptr) {
                    free_ciphertext(ptr, false);
                    free(ptr);
                });

                import_ciphertext(*gpu_ct, c_ct);
                break;
            }
            default: throw std::runtime_error("Unsupported data type for D2H transfer");
        }

        // Output is the allocated C struct
        output = c_struct;
    };
}

#endif  // GPU_ABI_BRIDGE_EXECUTORS_H

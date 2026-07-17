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
#include <vector>
#include <limits>

#include <heongpu/heongpu.hpp>

extern "C" {
#include "../../abi/c_types.h"
#include "../../abi/c_structs.h"
}

/**
 * @brief Check CUDA error and throw exception if error occurred
 */
inline void CHECK(cudaError_t err) {
    if (err != cudaSuccess) {
        throw std::runtime_error(cudaGetErrorString(err));
    }
}

struct GpuTransferEntry {
    void* dst;
    void* src;
    size_t size;
};

inline void append_gpu_transfer(std::vector<GpuTransferEntry>& entries, void* dst, const void* src, size_t size) {
    if (size == 0) {
        return;
    }
    entries.push_back({dst, const_cast<void*>(src), size});
}

inline void submit_gpu_transfer_batch(const std::vector<GpuTransferEntry>& entries,
                                      cudaMemcpyKind fallback_kind,
                                      cudaStream_t stream) {
    if (entries.empty()) {
        return;
    }

#if 0
    if (entries.size() > 1) {
        std::vector<void*> dsts;
        std::vector<void*> srcs;
        std::vector<size_t> sizes;
        dsts.reserve(entries.size());
        srcs.reserve(entries.size());
        sizes.reserve(entries.size());

        for (const auto& entry : entries) {
            dsts.push_back(entry.dst);
            srcs.push_back(entry.src);
            sizes.push_back(entry.size);
        }

        cudaMemcpyAttributes attr{};
        attr.srcAccessOrder = cudaMemcpySrcAccessOrderStream;
        size_t attr_idx = 0;
        size_t fail_idx = std::numeric_limits<size_t>::max();
        CHECK(cudaMemcpyBatchAsync(dsts.data(), srcs.data(), sizes.data(), entries.size(), &attr, &attr_idx, 1,
                                   &fail_idx, stream));
        return;
    }
#endif

    for (const auto& entry : entries) {
        CHECK(cudaMemcpyAsync(entry.dst, entry.src, entry.size, fallback_kind, stream));
    }
}

struct H2DBatch {
    std::vector<GpuTransferEntry> entries;

    void append(void* dst, const void* src, size_t size) {
        append_gpu_transfer(entries, dst, src, size);
    }

    void submit(cudaStream_t stream) const {
        submit_gpu_transfer_batch(entries, cudaMemcpyHostToDevice, stream);
    }
};

struct D2HBatch {
    std::vector<GpuTransferEntry> entries;

    void append(void* dst, const void* src, size_t size) {
        append_gpu_transfer(entries, dst, src, size);
    }

    void submit(cudaStream_t stream) const {
        submit_gpu_transfer_batch(entries, cudaMemcpyDeviceToHost, stream);
    }
};

/**
 * @brief Export plaintext from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_plaintext(const CPlaintext& src, heongpu::Plaintext<SchemeType>& dest, H2DBatch& batch) {
    batch.append(dest.data(), src.data, c_plaintext_rns_size(&src) * src.ring_degree * sizeof(uint64_t));
}

/**
 * @brief Export ciphertext from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_ciphertext(const CCiphertext& src, heongpu::Ciphertext<SchemeType>& dest, H2DBatch& batch) {
    batch.append(dest.data(), src.data,
                 src.cipher_size * c_ciphertext_rns_size(&src) * src.ring_degree * sizeof(uint64_t));
}

/**
 * @brief Export relinearization key from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_relin_key(const CRelinKey& src, heongpu::Relinkey<SchemeType>& dest, H2DBatch& batch) {
    size_t element_count = (size_t)c_relin_key_decomp_rns(&src) * 2 * c_relin_key_rns_size(&src) * src.ring_degree;
    batch.append(dest.data(), src.data, element_count * sizeof(uint64_t));
}

/**
 * @brief Export Galois key from C struct to GPU device memory (specific galois element)
 */
inline const CSwitchingKey* find_galois_switching_key(const CGaloisKey& src, uint32_t galois_element) {
    for (int i = 0; i < src.n_switching_key; i++) {
        if (src.galois_elements[i] == galois_element) {
            return &src.switching_keys[i];
        }
    }
    return nullptr;
}

template <heongpu::Scheme SchemeType>
void export_galois_key(const CGaloisKey& src,
                       heongpu::Galoiskey<SchemeType>& dest,
                       uint32_t galois_element,
                       int dest_level_q,
                       H2DBatch& batch) {
    const CSwitchingKey* switching_key = find_galois_switching_key(src, galois_element);
    if (!switching_key) {
        throw std::runtime_error("Galois key missing requested galois element");
    }
    if (dest_level_q < switching_key->level_q) {
        throw std::runtime_error("GPU Galois key destination level is smaller than source level");
    }

    const int ring_degree = switching_key->ring_degree;
    const int src_q_size = switching_key->level_q + 1;
    const int src_p_size = switching_key->level_p + 1;
    const int src_decomp_count = c_switching_key_decomp_rns(switching_key);
    const int dst_q_size = dest_level_q + 1;
    const int dst_rns_size = dst_q_size + src_p_size;
    auto* dest_data =
        galois_element != static_cast<uint32_t>(2 * ring_degree - 1) ? dest.data(galois_element) : dest.c_data();

    for (int decomp_idx = 0; decomp_idx < src_decomp_count; decomp_idx++) {
        for (int poly_idx = 0; poly_idx < 2; poly_idx++) {
            for (int q_idx = 0; q_idx < src_q_size; q_idx++) {
                auto* dst = dest_data + (((size_t)decomp_idx * 2 + poly_idx) * dst_rns_size + q_idx) * ring_degree;
                const uint64_t* src_limb = c_switching_key_const_rns_limb(switching_key, decomp_idx, poly_idx, q_idx);
                batch.append(dst, src_limb, ring_degree * sizeof(uint64_t));
            }
            for (int p_idx = 0; p_idx < src_p_size; p_idx++) {
                auto* dst =
                    dest_data + (((size_t)decomp_idx * 2 + poly_idx) * dst_rns_size + dst_q_size + p_idx) * ring_degree;
                const uint64_t* src_limb =
                    c_switching_key_const_rns_limb(switching_key, decomp_idx, poly_idx, src_q_size + p_idx);
                batch.append(dst, src_limb, ring_degree * sizeof(uint64_t));
            }
        }
    }
}

/**
 * @brief Export switching key from C struct to GPU device memory
 */
template <heongpu::Scheme SchemeType>
void export_switching_key(const ::CSwitchingKey& src, heongpu::Switchkey<SchemeType>& dest, H2DBatch& batch) {
    size_t element_count =
        (size_t)c_switching_key_decomp_rns(&src) * 2 * c_switching_key_rns_size(&src) * src.ring_degree;
    batch.append(dest.data(), src.data, element_count * sizeof(uint64_t));
}

/**
 * @brief Import ciphertext from GPU device memory to C struct
 */
template <heongpu::Scheme SchemeType>
void import_ciphertext(heongpu::Ciphertext<SchemeType>& src, CCiphertext* dest, D2HBatch& batch) {
    batch.append(dest->data, src.data(),
                 dest->cipher_size * c_ciphertext_rns_size(dest) * dest->ring_degree * sizeof(uint64_t));
}

/**
 * @brief Create executor for loading ABI data to GPU (H2D transfer)
 *
 * Converts C struct to GPU types:
 * - CCiphertext → heongpu::Ciphertext
 * - CPlaintext → heongpu::Plaintext
 * - CRelinKey → heongpu::Relinkey
 * - CGaloisKey → heongpu::Galoiskey
 * - CSwitchingKey → heongpu::Switchkey
 *
 * @tparam SchemeType GPU scheme type (heongpu::Scheme::BFV or heongpu::Scheme::CKKS)
 * @return ExecutorFunc that performs H2D transfer
 *
 * @note Input: std::shared_ptr<C struct> from available_data
 * @note Output: std::shared_ptr<GPU type> stored in std::any
 * @note Requires heongpu::ExecutionOptions in ExecutionContext other_args[0]
 * @note Requires heongpu::HEContext in ExecutionContext other_args[1]
 * @note Requires galois_key shared_ptr in ExecutionContext other_args[2]
 * @note Requires galois_key_mutex in ExecutionContext other_args[3]
 * @note Requires all_galois_elts in ExecutionContext other_args[4]
 * @note Requires galois_key_level in ExecutionContext other_args[5]
 * @note Requires H2DBatch in ExecutionContext other_args[6]
 */
template <heongpu::Scheme SchemeType> ExecutorFunc create_load_to_gpu_executor() {
    return [](ExecutionContext& ctx, std::unordered_map<NodeIndex, std::any>& local_data,
              const ComputeNode& self) -> void {
        // Get GPU context and options from execution context
        auto* operators = ctx.get_arithmetic_context<heongpu::HEArithmeticOperator<SchemeType>>();
        auto* stream_option = ctx.get_other_arg<heongpu::ExecutionOptions>(0);
        auto* context = ctx.get_other_arg<heongpu::HEContext<SchemeType>>(1);
        auto* galois_key_ptr = ctx.get_other_arg<std::shared_ptr<heongpu::Galoiskey<SchemeType>>>(2);
        auto* galois_key_mutex = ctx.get_other_arg<std::mutex>(3);
        auto* all_galois_elts = ctx.get_other_arg<std::vector<uint32_t>>(4);
        auto* galois_key_level = ctx.get_other_arg<int>(5);
        auto* h2d_batch = ctx.get_other_arg<H2DBatch>(6);

        if (!stream_option || !context) {
            throw std::runtime_error("GPU stream options or context not found in execution context");
        }
        if (!h2d_batch) {
            throw std::runtime_error("GPU H2D batch not found in execution context");
        }

        // Get input node and data
        const DatumNode* input_node = self.input_nodes[0];
        // Determine data type and galois element
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties");
        }

        DataType data_type = input_node->datum_type;

        std::any c_struct = local_data.at(input_node->index);

        uint32_t galois_element = 0;
        if (data_type == TYPE_GALOIS_KEY && input_node->fhe_prop->p.has_value()) {
            galois_element = input_node->fhe_prop->p->galois_element;
        }

        NodeIndex output_index = self.output_nodes[0]->index;

        switch (data_type) {
            case TYPE_PLAINTEXT: {
                auto c_pt_ptr = std::any_cast<std::shared_ptr<CPlaintext>>(c_struct);
                const CPlaintext* c_pt = c_pt_ptr.get();
                auto gpu_plaintext =
                    std::make_shared<heongpu::Plaintext<SchemeType>>(*context, c_pt->level, *stream_option);
                export_plaintext(*c_pt, *gpu_plaintext, *h2d_batch);
                local_data[output_index] = gpu_plaintext;
                break;
            }
            case TYPE_CIPHERTEXT: {
                auto c_ct_ptr = std::any_cast<std::shared_ptr<CCiphertext>>(c_struct);
                const CCiphertext* c_ct = c_ct_ptr.get();
                auto gpu_ciphertext =
                    std::make_shared<heongpu::Ciphertext<SchemeType>>(*context, c_ct->level, *stream_option);
                export_ciphertext(*c_ct, *gpu_ciphertext, *h2d_batch);
                local_data[output_index] = gpu_ciphertext;
                break;
            }
            case TYPE_RELIN_KEY: {
                auto c_rlk_ptr = std::any_cast<std::shared_ptr<CRelinKey>>(c_struct);
                const CRelinKey* c_rlk = c_rlk_ptr.get();
                auto gpu_relin_key =
                    std::make_shared<heongpu::Relinkey<SchemeType>>(*context, c_rlk->level_q, *stream_option);
                export_relin_key(*c_rlk, *gpu_relin_key, *h2d_batch);
                local_data[output_index] = gpu_relin_key;
                break;
            }
            case TYPE_GALOIS_KEY: {
                auto c_glk_ptr = std::any_cast<std::shared_ptr<CGaloisKey>>(c_struct);
                const CGaloisKey* c_glk = c_glk_ptr.get();

                {
                    std::lock_guard<std::mutex> lock(*galois_key_mutex);
                    if (!(*galois_key_ptr)) {
                        *galois_key_ptr = std::make_shared<heongpu::Galoiskey<SchemeType>>(
                            *context, *all_galois_elts, *galois_key_level, *stream_option);
                    }

                    export_galois_key(*c_glk, **galois_key_ptr, galois_element, *galois_key_level, *h2d_batch);
                }
                local_data[output_index] = *galois_key_ptr;
                break;
            }
            case TYPE_SWITCH_KEY: {
                if constexpr (SchemeType == heongpu::Scheme::CKKS) {
                    auto c_swk_ptr = std::any_cast<std::shared_ptr<CSwitchingKey>>(c_struct);
                    const CSwitchingKey* c_swk = c_swk_ptr.get();
                    auto gpu_switch_key =
                        std::make_shared<heongpu::Switchkey<SchemeType>>(*context, c_swk->level_q, *stream_option);
                    export_switching_key(*c_swk, *gpu_switch_key, *h2d_batch);
                    local_data[output_index] = gpu_switch_key;
                } else {
                    throw std::runtime_error("Switch keys are only supported for CKKS GPU ABI transfers");
                }
                break;
            }
            default: throw std::runtime_error("Unsupported data type in H2D transfer");
        }
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
    return [](ExecutionContext& ctx, std::unordered_map<NodeIndex, std::any>& local_data,
              const ComputeNode& self) -> void {
        auto* d2h_batch = ctx.get_other_arg<D2HBatch>(2);
        if (!d2h_batch) {
            throw std::runtime_error("GPU D2H batch not found in execution context");
        }

        // Get input node and GPU data
        const DatumNode* input_node = self.input_nodes[0];
        // Determine data type
        if (!input_node->fhe_prop.has_value()) {
            throw std::runtime_error("Input node missing FHE properties");
        }

        DataType data_type = input_node->datum_type;

        std::any gpu_data = local_data.at(input_node->index);

        // Perform D2H transfer and allocate C struct
        std::any c_struct;

        switch (data_type) {
            case TYPE_CIPHERTEXT: {
                auto gpu_ct = std::any_cast<std::shared_ptr<heongpu::Ciphertext<SchemeType>>>(gpu_data);

                auto* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                alloc_ciphertext(c_ct, gpu_ct->size(), gpu_ct->level(), gpu_ct->ring_size());
                c_struct = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* ptr) {
                    free_ciphertext(ptr);
                    free(ptr);
                });

                import_ciphertext(*gpu_ct, c_ct, *d2h_batch);
                break;
            }
            default: throw std::runtime_error("Unsupported data type for D2H transfer");
        }

        // Output is the allocated C struct
        local_data[self.output_nodes[0]->index] = c_struct;
    };
}

#endif  // GPU_ABI_BRIDGE_EXECUTORS_H

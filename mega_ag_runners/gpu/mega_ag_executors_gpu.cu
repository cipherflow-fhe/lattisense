// Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/** @file mega_ag_executors_gpu.cu
 * @brief GPU executor implementations for MegaAG compute nodes
 */

#include "../mega_ag_executors.h"
#include <HEonGPU-1.1/heongpu.hpp>
#include <memory>
#include <stdexcept>

// Helper macro to extract common executor setup with typed input vectors
#define GPU_EXECUTOR_SETUP(SchemeType)                                                                                 \
    auto* operators = std::any_cast<heongpu::HEArithmeticOperator<SchemeType>*>(ctx.context);                          \
    if (!operators) {                                                                                                  \
        throw std::runtime_error("Operators not found in GPU Execution context");                                      \
    }                                                                                                                  \
    auto* stream_option = ctx.get_other_arg<heongpu::ExecutionOptions>(0);                                             \
    if (!stream_option) {                                                                                              \
        throw std::runtime_error("Stream Options not provided in Execution context");                                  \
    }                                                                                                                  \
    auto output_ptr = std::any_cast<std::shared_ptr<heongpu::Ciphertext<SchemeType>>>(output);                         \
    heongpu::Ciphertext<SchemeType>& output_ref = *output_ptr;                                                         \
    std::vector<heongpu::Ciphertext<SchemeType>*> ciphertexts;                                                         \
    std::vector<heongpu::Plaintext<SchemeType>*> plaintexts;                                                           \
    std::vector<heongpu::Relinkey<SchemeType>*> relinkeys;                                                             \
    std::vector<heongpu::Galoiskey<SchemeType>*> galoiskeys;                                                           \
    std::vector<heongpu::Switchkey<SchemeType>*> switchkeys;                                                           \
    for (size_t i = 0; i < self.input_nodes.size(); i++) {                                                             \
        auto* input_node = self.input_nodes[i];                                                                        \
        auto input_any = inputs.at(input_node->index);                                                                 \
        if (input_node->datum_type == TYPE_CIPHERTEXT) {                                                               \
            auto input_shared_ptr = std::any_cast<std::shared_ptr<heongpu::Ciphertext<SchemeType>>>(input_any);        \
            ciphertexts.push_back(input_shared_ptr.get());                                                             \
        } else if (input_node->datum_type == TYPE_PLAINTEXT) {                                                         \
            auto input_shared_ptr = std::any_cast<std::shared_ptr<heongpu::Plaintext<SchemeType>>>(input_any);         \
            plaintexts.push_back(input_shared_ptr.get());                                                              \
        } else if (input_node->datum_type == TYPE_RELIN_KEY) {                                                         \
            auto input_shared_ptr = std::any_cast<std::shared_ptr<heongpu::Relinkey<SchemeType>>>(input_any);          \
            relinkeys.push_back(input_shared_ptr.get());                                                               \
        } else if (input_node->datum_type == TYPE_GALOIS_KEY) {                                                        \
            auto input_shared_ptr = std::any_cast<std::shared_ptr<heongpu::Galoiskey<SchemeType>>>(input_any);         \
            galoiskeys.push_back(input_shared_ptr.get());                                                              \
        } else if (input_node->datum_type == TYPE_SWITCH_KEY) {                                                        \
            auto input_shared_ptr = std::any_cast<std::shared_ptr<heongpu::Switchkey<SchemeType>>>(input_any);         \
            switchkeys.push_back(input_shared_ptr.get());                                                              \
        } else {                                                                                                       \
            throw std::runtime_error("Unknown input datum type");                                                      \
        }                                                                                                              \
    }

// Helper function to find plaintext node in inputs
// Returns the 2nd input node (index 1) as the plaintext node when there are exactly 2 inputs
static DatumNode* find_plaintext_node(const ComputeNode& node) {
    if (node.input_nodes.size() == 2) {
        auto* datum_node = node.input_nodes[1];
        if (datum_node->datum_type == DataType::TYPE_PLAINTEXT) {
            return datum_node;  // 2nd input node is plaintext
        }
    }
    return nullptr;
}

template <heongpu::Scheme SchemeType> void bind_gpu_add(ComputeNode& node) {
    if (node.input_nodes.size() == 1) {
        // Single input: ct + ct (same input)
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            GPU_EXECUTOR_SETUP(SchemeType);
            operators->add(*ciphertexts[0], *ciphertexts[0], output_ref, *stream_option);
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if (pt_node->p && pt_node->p->is_ringt) {
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    GPU_EXECUTOR_SETUP(SchemeType);
                    plaintexts[0]->set_ringt(true);
                    operators->add_plain(*ciphertexts[0], *plaintexts[0], output_ref, *stream_option);
                };
            } else {
                // ct + pt (normal plaintext)
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    GPU_EXECUTOR_SETUP(SchemeType);
                    operators->add_plain(*ciphertexts[0], *plaintexts[0], output_ref, *stream_option);
                };
            }
        } else {
            // ct + ct
            node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                               std::any& output, const ComputeNode& self) -> void {
                GPU_EXECUTOR_SETUP(SchemeType);
                operators->add(*ciphertexts[0], *ciphertexts[1], output_ref, *stream_option);
            };
        }
    }
}

template <heongpu::Scheme SchemeType> void bind_gpu_sub(ComputeNode& node) {
    if (node.input_nodes.size() == 1) {
        // Single input: ct - ct (same input)
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            GPU_EXECUTOR_SETUP(SchemeType);
            operators->sub(*ciphertexts[0], *ciphertexts[0], output_ref, *stream_option);
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if (pt_node->p && pt_node->p->is_ringt) {
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    GPU_EXECUTOR_SETUP(SchemeType);
                    plaintexts[0]->set_ringt(true);
                    operators->sub_plain(*ciphertexts[0], *plaintexts[0], output_ref, *stream_option);
                };
            } else {
                // ct - pt (normal plaintext)
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    GPU_EXECUTOR_SETUP(SchemeType);
                    operators->sub_plain(*ciphertexts[0], *plaintexts[0], output_ref, *stream_option);
                };
            }
        } else {
            // ct - ct
            node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                               std::any& output, const ComputeNode& self) -> void {
                GPU_EXECUTOR_SETUP(SchemeType);
                operators->sub(*ciphertexts[0], *ciphertexts[1], output_ref, *stream_option);
            };
        }
    }
}

template <heongpu::Scheme SchemeType> void bind_gpu_neg(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        GPU_EXECUTOR_SETUP(SchemeType);
        operators->negate(*ciphertexts[0], output_ref, *stream_option);
    };
}

template <heongpu::Scheme SchemeType> void bind_gpu_mult(ComputeNode& node) {
    if (node.input_nodes.size() == 1) {
        // Single input: ct * ct (same input)
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            GPU_EXECUTOR_SETUP(SchemeType);
            operators->multiply(*ciphertexts[0], *ciphertexts[0], output_ref, *stream_option);
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if (pt_node->p && pt_node->p->is_ringt) {
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    GPU_EXECUTOR_SETUP(SchemeType);
                    plaintexts[0]->set_ringt(true);
                    operators->multiply_plain(*ciphertexts[0], *plaintexts[0], output_ref, *stream_option);
                };
            } else {
                // ct * pt (normal plaintext)
                if constexpr (SchemeType == heongpu::Scheme::CKKS) {
                    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                       std::any& output, const ComputeNode& self) -> void {
                        GPU_EXECUTOR_SETUP(SchemeType);
                        operators->multiply_plain(*ciphertexts[0], *plaintexts[0], output_ref, *stream_option);
                    };
                } else {
                    throw std::runtime_error("Multiply with plaintext only supported for CKKS scheme");
                }
            }
        } else {
            // ct * ct
            node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                               std::any& output, const ComputeNode& self) -> void {
                GPU_EXECUTOR_SETUP(SchemeType);
                operators->multiply(*ciphertexts[0], *ciphertexts[1], output_ref, *stream_option);
            };
        }
    }
}

template <heongpu::Scheme SchemeType> void bind_gpu_relin(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        GPU_EXECUTOR_SETUP(SchemeType);
        operators->relinearize(*ciphertexts[0], output_ref, *relinkeys[0], *stream_option);
    };
}

template <heongpu::Scheme SchemeType> void bind_gpu_rescale(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        GPU_EXECUTOR_SETUP(SchemeType);
        operators->rescale(*ciphertexts[0], output_ref, *stream_option);
    };
}

template <heongpu::Scheme SchemeType> void bind_gpu_drop_level(ComputeNode& node) {
    if constexpr (SchemeType == heongpu::Scheme::CKKS) {
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            GPU_EXECUTOR_SETUP(SchemeType);
            operators->mod_drop(*ciphertexts[0], output_ref, *stream_option);
        };
    } else {
        throw std::runtime_error("DROP_LEVEL only supported for CKKS scheme");
    }
}

template <heongpu::Scheme SchemeType> void bind_gpu_rotate_col(ComputeNode& node) {
    int step = node.p->rotation_step;
    node.executor = [step](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
        GPU_EXECUTOR_SETUP(SchemeType);
        operators->rotate_rows(*ciphertexts[0], output_ref, *galoiskeys[0], step, *stream_option);
    };
}

template <heongpu::Scheme SchemeType> void bind_gpu_rotate_row(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        GPU_EXECUTOR_SETUP(SchemeType);
        if constexpr (SchemeType == heongpu::Scheme::BFV) {
            operators->rotate_columns(*ciphertexts[0], output_ref, *galoiskeys[0], *stream_option);
        } else {
            operators->conjugate(*ciphertexts[0], output_ref, *galoiskeys[0], *stream_option);
        }
    };
}

template <heongpu::Scheme SchemeType> void bind_gpu_cmpac_sum(ComputeNode& node) {
    int n = node.p->sum_cnt;
    // Find the first plaintext node to determine type (plaintext nodes start at index n+1)
    DatumNode* pt_node = node.input_nodes[n + 1];
    if (pt_node->p && pt_node->p->is_ringt) {
        node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                            std::any& output, const ComputeNode& self) -> void {
            GPU_EXECUTOR_SETUP(SchemeType);
            std::vector<heongpu::Ciphertext<SchemeType>> products(n);
            for (int i = 0; i < n; i++) {
                plaintexts[i]->set_ringt(true);
                operators->multiply_plain(*ciphertexts[i], *plaintexts[i], products[i], *stream_option);
            }
            auto sum = std::move(products[0]);
            for (int i = 0; i < n - 1; i++) {
                operators->add_inplace(sum, products[i + 1], *stream_option);
            }
            operators->add(sum, *ciphertexts[n], output_ref, *stream_option);
        };
    } else {
        // ct * pt (normal)
        if constexpr (SchemeType == heongpu::Scheme::CKKS) {
            node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                std::any& output, const ComputeNode& self) -> void {
                GPU_EXECUTOR_SETUP(SchemeType);
                std::vector<heongpu::Ciphertext<SchemeType>> products(n);
                for (int i = 0; i < n; i++) {
                    operators->multiply_plain(*ciphertexts[i], *plaintexts[i], products[i], *stream_option);
                }
                auto sum = std::move(products[0]);
                for (int i = 0; i < n - 1; i++) {
                    operators->add_inplace(sum, products[i + 1], *stream_option);
                }
                operators->add(sum, *ciphertexts[n], output_ref, *stream_option);
            };
        } else {
            throw std::runtime_error("Multiply with plaintext only supported for CKKS scheme");
        }
    }
}

template <heongpu::Scheme SchemeType> void bind_gpu_cmp_sum(ComputeNode& node) {
    int n = node.p->sum_cnt;
    // Find the first plaintext node to determine type (plaintext nodes start at index n)
    DatumNode* pt_node = node.input_nodes[n];

    if (pt_node->p && pt_node->p->is_ringt) {
        node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                            std::any& output, const ComputeNode& self) -> void {
            GPU_EXECUTOR_SETUP(SchemeType);
            std::vector<heongpu::Ciphertext<SchemeType>> products(n);
            for (int i = 0; i < n; i++) {
                plaintexts[i]->set_ringt(true);
                operators->multiply_plain(*ciphertexts[i], *plaintexts[i], products[i], *stream_option);
            }
            auto sum = std::move(products[0]);
            for (int i = 0; i < n - 1; i++) {
                operators->add_inplace(sum, products[i + 1], *stream_option);
            }
            output_ref = std::move(sum);
        };
    } else {
        // ct * pt (normal)
        if constexpr (SchemeType == heongpu::Scheme::CKKS) {
            node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                std::any& output, const ComputeNode& self) -> void {
                GPU_EXECUTOR_SETUP(SchemeType);
                std::vector<heongpu::Ciphertext<SchemeType>> products(n);
                for (int i = 0; i < n; i++) {
                    operators->multiply_plain(*ciphertexts[i], *plaintexts[i], products[i], *stream_option);
                }
                auto sum = std::move(products[0]);
                for (int i = 0; i < n - 1; i++) {
                    operators->add_inplace(sum, products[i + 1], *stream_option);
                }
                output_ref = std::move(sum);
            };
        } else {
            throw std::runtime_error("Multiply with plaintext only supported for CKKS scheme");
        }
    }
}

template <heongpu::Scheme SchemeType> void bind_gpu_bootstrap(ComputeNode& node) {
    if constexpr (SchemeType == heongpu::Scheme::CKKS) {
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            GPU_EXECUTOR_SETUP(SchemeType);
            output_ref = operators->regular_bootstrapping_v2(*ciphertexts[0], *galoiskeys[0], *relinkeys[0],
                                                             switchkeys[0], switchkeys[1], *stream_option);
        };
    } else {
        throw std::runtime_error("BOOTSTRAP only supported for CKKS scheme");
    }
}

// Explicit template instantiations
template void bind_gpu_add<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_add<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_sub<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_sub<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_neg<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_neg<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_mult<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_mult<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_relin<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_relin<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_rescale<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_drop_level<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_rotate_col<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_rotate_col<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_rotate_row<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_rotate_row<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_cmpac_sum<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_cmpac_sum<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_cmp_sum<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_cmp_sum<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_bootstrap<heongpu::Scheme::CKKS>(ComputeNode& node);

// Wrapper function for ExecutorBinder (callable from non-CUDA code)
void bind_gpu_executor(ComputeNode& node, Algo algorithm) {
    switch (algorithm) {
        case ALGO_BFV:
            switch (node.op_type) {
                case OperationType::ADD: bind_gpu_add<heongpu::Scheme::BFV>(node); break;
                case OperationType::SUB: bind_gpu_sub<heongpu::Scheme::BFV>(node); break;
                case OperationType::NEGATE: bind_gpu_neg<heongpu::Scheme::BFV>(node); break;
                case OperationType::MULTIPLY: bind_gpu_mult<heongpu::Scheme::BFV>(node); break;
                case OperationType::RELINEARIZE: bind_gpu_relin<heongpu::Scheme::BFV>(node); break;
                case OperationType::RESCALE: bind_gpu_rescale<heongpu::Scheme::BFV>(node); break;
                case OperationType::ROTATE_COL: bind_gpu_rotate_col<heongpu::Scheme::BFV>(node); break;
                case OperationType::ROTATE_ROW: bind_gpu_rotate_row<heongpu::Scheme::BFV>(node); break;
                case OperationType::MAC_W_PARTIAL_SUM: bind_gpu_cmpac_sum<heongpu::Scheme::BFV>(node); break;
                case OperationType::MAC_WO_PARTIAL_SUM: bind_gpu_cmp_sum<heongpu::Scheme::BFV>(node); break;
                default: throw std::runtime_error("Unsupported operation type for GPU BFV");
            }
            break;
        case ALGO_CKKS:
            switch (node.op_type) {
                case OperationType::ADD: bind_gpu_add<heongpu::Scheme::CKKS>(node); break;
                case OperationType::SUB: bind_gpu_sub<heongpu::Scheme::CKKS>(node); break;
                case OperationType::NEGATE: bind_gpu_neg<heongpu::Scheme::CKKS>(node); break;
                case OperationType::MULTIPLY: bind_gpu_mult<heongpu::Scheme::CKKS>(node); break;
                case OperationType::RELINEARIZE: bind_gpu_relin<heongpu::Scheme::CKKS>(node); break;
                case OperationType::RESCALE: bind_gpu_rescale<heongpu::Scheme::CKKS>(node); break;
                case OperationType::DROP_LEVEL: bind_gpu_drop_level<heongpu::Scheme::CKKS>(node); break;
                case OperationType::ROTATE_COL: bind_gpu_rotate_col<heongpu::Scheme::CKKS>(node); break;
                case OperationType::ROTATE_ROW: bind_gpu_rotate_row<heongpu::Scheme::CKKS>(node); break;
                case OperationType::MAC_W_PARTIAL_SUM: bind_gpu_cmpac_sum<heongpu::Scheme::CKKS>(node); break;
                case OperationType::MAC_WO_PARTIAL_SUM: bind_gpu_cmp_sum<heongpu::Scheme::CKKS>(node); break;
                case OperationType::BOOTSTRAP: bind_gpu_bootstrap<heongpu::Scheme::CKKS>(node); break;
                default: throw std::runtime_error("Unsupported operation type for GPU CKKS");
            }
            break;
        default: throw std::runtime_error("Unknown algorithm type for GPU");
    }
}

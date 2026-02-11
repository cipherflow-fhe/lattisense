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

#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <tuple>
#include <typeindex>
#include <HEonGPU-1.1/heongpu.hpp>
#include "../mega_ag_executors.h"

template <heongpu::Scheme S> using Ct = heongpu::Ciphertext<S>;
template <heongpu::Scheme S> using Pt = heongpu::Plaintext<S>;
template <heongpu::Scheme S> using Rlk = heongpu::Relinkey<S>;
template <heongpu::Scheme S> using Glk = heongpu::Galoiskey<S>;
template <heongpu::Scheme S> using Swk = heongpu::Switchkey<S>;

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

std::unordered_map<std::type_index, DataType> _type_map = {
    {std::type_index(typeid(Ct<heongpu::Scheme::BFV>)), DataType::TYPE_CIPHERTEXT},
    {std::type_index(typeid(Ct<heongpu::Scheme::CKKS>)), DataType::TYPE_CIPHERTEXT},
    {std::type_index(typeid(Pt<heongpu::Scheme::BFV>)), DataType::TYPE_PLAINTEXT},
    {std::type_index(typeid(Pt<heongpu::Scheme::CKKS>)), DataType::TYPE_PLAINTEXT},
    {std::type_index(typeid(Rlk<heongpu::Scheme::BFV>)), DataType::TYPE_RELIN_KEY},
    {std::type_index(typeid(Rlk<heongpu::Scheme::CKKS>)), DataType::TYPE_RELIN_KEY},
    {std::type_index(typeid(Glk<heongpu::Scheme::BFV>)), DataType::TYPE_GALOIS_KEY},
    {std::type_index(typeid(Glk<heongpu::Scheme::CKKS>)), DataType::TYPE_GALOIS_KEY},
    {std::type_index(typeid(Swk<heongpu::Scheme::BFV>)), DataType::TYPE_SWITCH_KEY},
    {std::type_index(typeid(Swk<heongpu::Scheme::CKKS>)), DataType::TYPE_SWITCH_KEY},
};

template <heongpu::Scheme S>
std::tuple<heongpu::HEArithmeticOperator<S>&, heongpu::ExecutionOptions&>
_get_operator_and_stream_option(ExecutionContext& ctx) {
    auto* operators = std::any_cast<heongpu::HEArithmeticOperator<S>*>(ctx.context);
    if (!operators) {
        throw std::runtime_error("Operators not found in GPU Execution context");
    }
    auto* stream_option = ctx.get_other_arg<heongpu::ExecutionOptions>(0);
    if (!stream_option) {
        throw std::runtime_error("Stream Options not provided in Execution context");
    }
    return {*operators, *stream_option};
}

template <typename T> T& _get_input_data(const std::unordered_map<NodeIndex, std::any>& inputs, const DatumNode& node) {
    assert(node.datum_type == _type_map[std::type_index(typeid(T))]);
    T& data = *std::any_cast<std::shared_ptr<T>>(inputs.at(node.index));
    return data;
}

template <heongpu::Scheme S> void bind_gpu_add(ComputeNode& node) {
    if (node.input_nodes.size() == 1) {
        // Single input: ct + ct (same input)
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
            auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
            operators.add(input0, input0, output0, stream_option);
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if (pt_node->p && pt_node->p->is_ringt) {
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                    auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
                    auto& input1 = _get_input_data<Pt<S>>(inputs, *self.input_nodes[1]);
                    auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                    input1.set_ringt(true);
                    operators.add_plain(input0, input1, output0, stream_option);
                };
            } else {
                // ct + pt (normal plaintext)
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                    auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
                    auto& input1 = _get_input_data<Pt<S>>(inputs, *self.input_nodes[1]);
                    auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                    operators.add_plain(input0, input1, output0, stream_option);
                };
            }
        } else {
            // ct + ct
            node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                               std::any& output, const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
                auto& input1 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[1]);
                auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                operators.add(input0, input1, output0, stream_option);
            };
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_sub(ComputeNode& node) {
    if (node.input_nodes.size() == 1) {
        // Single input: ct - ct (same input)
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
            auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
            operators.sub(input0, input0, output0, stream_option);
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if (pt_node->p && pt_node->p->is_ringt) {
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                    auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
                    auto& input1 = _get_input_data<Pt<S>>(inputs, *self.input_nodes[1]);
                    auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                    input1.set_ringt(true);
                    operators.sub_plain(input0, input1, output0, stream_option);
                };
            } else {
                // ct - pt (normal plaintext)
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                    auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
                    auto& input1 = _get_input_data<Pt<S>>(inputs, *self.input_nodes[1]);
                    auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                    operators.sub_plain(input0, input1, output0, stream_option);
                };
            }
        } else {
            // ct - ct
            node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                               std::any& output, const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
                auto& input1 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[1]);
                auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                operators.sub(input0, input1, output0, stream_option);
            };
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_neg(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
        auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
        auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
        operators.negate(input0, output0, stream_option);
    };
}

template <heongpu::Scheme S> void bind_gpu_mult(ComputeNode& node) {
    if (node.input_nodes.size() == 1) {
        // Single input: ct * ct (same input)
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
            auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
            operators.multiply(input0, input0, output0, stream_option);
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if (pt_node->p && pt_node->p->is_ringt) {
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                    auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
                    auto& input1 = _get_input_data<Pt<S>>(inputs, *self.input_nodes[1]);
                    auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                    input1.set_ringt(true);
                    operators.multiply_plain(input0, input1, output0, stream_option);
                };
            } else {
                // ct * pt (normal plaintext)
                if constexpr (S == heongpu::Scheme::CKKS) {
                    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                       std::any& output, const ComputeNode& self) -> void {
                        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                        auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
                        auto& input1 = _get_input_data<Pt<S>>(inputs, *self.input_nodes[1]);
                        auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                        operators.multiply_plain(input0, input1, output0, stream_option);
                    };
                } else {
                    throw std::runtime_error("Multiply with plaintext only supported for CKKS scheme");
                }
            }
        } else {
            // ct * ct
            node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                               std::any& output, const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
                auto& input1 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[1]);
                auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                operators.multiply(input0, input1, output0, stream_option);
            };
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_relin(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
        auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
        auto& rlk = _get_input_data<Rlk<S>>(inputs, *self.input_nodes[1]);
        auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
        operators.relinearize(input0, output0, rlk, stream_option);
    };
}

template <heongpu::Scheme S> void bind_gpu_rescale(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
        auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
        auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
        operators.rescale(input0, output0, stream_option);
    };
}

template <heongpu::Scheme S> void bind_gpu_drop_level(ComputeNode& node) {
    if constexpr (S == heongpu::Scheme::CKKS) {
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
            auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
            operators.mod_drop(input0, output0, stream_option);
        };
    } else {
        throw std::runtime_error("DROP_LEVEL only supported for CKKS scheme");
    }
}

template <heongpu::Scheme S> void bind_gpu_rotate_col(ComputeNode& node) {
    int step = node.p->rotation_step;
    node.executor = [step](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
        auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
        auto& glk = _get_input_data<Glk<S>>(inputs, *self.input_nodes[1]);
        auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
        operators.rotate_rows(input0, output0, glk, step, stream_option);
    };
}

template <heongpu::Scheme S> void bind_gpu_rotate_row(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
        auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
        auto& glk = _get_input_data<Glk<S>>(inputs, *self.input_nodes[1]);
        auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
        if constexpr (S == heongpu::Scheme::BFV) {
            operators.rotate_columns(input0, output0, glk, stream_option);
        } else {
            operators.conjugate(input0, output0, glk, stream_option);
        }
    };
}

template <heongpu::Scheme S> void bind_gpu_cmpac_sum(ComputeNode& node) {
    int n = node.p->sum_cnt;
    // Find the first plaintext node to determine type (plaintext nodes start at index n+1)
    DatumNode* pt_node = node.input_nodes[n + 1];
    if (pt_node->p && pt_node->p->is_ringt) {
        node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                            std::any& output, const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            std::vector<heongpu::Ciphertext<S>> products(n);
            for (int i = 0; i < n; i++) {
                auto& input_ct_i = _get_input_data<Ct<S>>(inputs, *self.input_nodes[i]);
                auto& input_pt_i = _get_input_data<Pt<S>>(inputs, *self.input_nodes[n + 1 + i]);
                input_pt_i.set_ringt(true);
                operators.multiply_plain(input_ct_i, input_pt_i, products[i], stream_option);
            }
            auto sum = std::move(products[0]);
            for (int i = 1; i < n; i++) {
                operators.add_inplace(sum, products[i], stream_option);
            }
            auto& input_ct_n = _get_input_data<Ct<S>>(inputs, *self.input_nodes[n]);
            auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
            operators.add(sum, input_ct_n, output0, stream_option);
        };
    } else {
        // ct * pt (normal)
        if constexpr (S == heongpu::Scheme::CKKS) {
            node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                std::any& output, const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                std::vector<heongpu::Ciphertext<S>> products(n);
                for (int i = 0; i < n; i++) {
                    auto& input_ct_i = _get_input_data<Ct<S>>(inputs, *self.input_nodes[i]);
                    auto& input_pt_i = _get_input_data<Pt<S>>(inputs, *self.input_nodes[n + 1 + i]);
                    operators.multiply_plain(input_ct_i, input_pt_i, products[i], stream_option);
                }
                auto sum = std::move(products[0]);
                for (int i = 1; i < n; i++) {
                    operators.add_inplace(sum, products[i], stream_option);
                }
                auto& input_ct_n = _get_input_data<Ct<S>>(inputs, *self.input_nodes[n]);
                auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                operators.add(sum, input_ct_n, output0, stream_option);
            };
        } else {
            throw std::runtime_error("Multiply with plaintext only supported for CKKS scheme");
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_cmp_sum(ComputeNode& node) {
    int n = node.p->sum_cnt;
    // Find the first plaintext node to determine type (plaintext nodes start at index n)
    DatumNode* pt_node = node.input_nodes[n];

    if (pt_node->p && pt_node->p->is_ringt) {
        node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                            std::any& output, const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            std::vector<Ct<S>> products(n);
            for (int i = 0; i < n; i++) {
                auto& input_ct_i = _get_input_data<Ct<S>>(inputs, *self.input_nodes[i]);
                auto& input_pt_i = _get_input_data<Pt<S>>(inputs, *self.input_nodes[n + i]);
                input_pt_i.set_ringt(true);
                operators.multiply_plain(input_ct_i, input_pt_i, products[i], stream_option);
            }
            auto sum = std::move(products[0]);
            for (int i = 1; i < n; i++) {
                operators.add_inplace(sum, products[i], stream_option);
            }
            auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
            output0 = std::move(sum);
        };
    } else {
        // ct * pt (normal)
        if constexpr (S == heongpu::Scheme::CKKS) {
            node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                std::any& output, const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                std::vector<heongpu::Ciphertext<S>> products(n);
                for (int i = 0; i < n; i++) {
                    auto& input_ct_i = _get_input_data<Ct<S>>(inputs, *self.input_nodes[i]);
                    auto& input_pt_i = _get_input_data<Pt<S>>(inputs, *self.input_nodes[n + i]);
                    operators.multiply_plain(input_ct_i, input_pt_i, products[i], stream_option);
                }
                auto sum = std::move(products[0]);
                for (int i = 1; i < n; i++) {
                    operators.add_inplace(sum, products[i], stream_option);
                }
                auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
                output0 = std::move(sum);
            };
        } else {
            throw std::runtime_error("Multiply with plaintext only supported for CKKS scheme");
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_bootstrap(ComputeNode& node) {
    if constexpr (S == heongpu::Scheme::CKKS) {
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(inputs, *self.input_nodes[0]);
            auto& rlk = _get_input_data<Rlk<S>>(inputs, *self.input_nodes[1]);
            auto& glk = _get_input_data<Glk<S>>(inputs, *self.input_nodes[2]);
            auto& swk0 = _get_input_data<Swk<S>>(inputs, *self.input_nodes[self.input_nodes.size() - 2]);
            auto& swk1 = _get_input_data<Swk<S>>(inputs, *self.input_nodes[self.input_nodes.size() - 1]);
            auto& output0 = *std::any_cast<std::shared_ptr<Ct<S>>>(output);
            output0 = operators.regular_bootstrapping_v2(input0, glk, rlk, &swk0, &swk1, stream_option);
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

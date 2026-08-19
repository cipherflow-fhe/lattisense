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

#include <cmath>
#include <complex>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <tuple>
#include <variant>
#include <vector>
#include <HEonGPU-1.1/heongpu/heongpu.hpp>
#include "../mega_ag_executors.h"
#include "../../fhe_ops_lib/schemes/base/custom_data.h"

using fhe_ops_lib::CustomData;

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
        if (!datum_node->fhe_prop.has_value()) {
            throw std::runtime_error("FHE property not found for compute node");
        }
        if (datum_node->datum_type == DataType::TYPE_PLAINTEXT) {
            return datum_node;  // 2nd input node is plaintext
        }
    }
    return nullptr;
}

template <heongpu::Scheme S>
std::tuple<heongpu::HEArithmeticOperator<S>&, heongpu::ExecutionOptions&>
_get_operator_and_stream_option(ExecutionContext& ctx) {
    auto* operators = ctx.get_arithmetic_context<heongpu::HEArithmeticOperator<S>>();
    if (!operators) {
        throw std::runtime_error("Operators not found in GPU Execution context");
    }
    auto* stream_option = ctx.get_other_arg<heongpu::ExecutionOptions>(0);
    if (!stream_option) {
        throw std::runtime_error("Stream Options not provided in Execution context");
    }
    return {*operators, *stream_option};
}

template <typename T> T& _get_input_data(std::unordered_map<NodeId, std::any>& local_data, const DatumNode& node) {
    if (!node.fhe_prop.has_value()) {
        throw std::runtime_error("FHE property not found for input node " + node.id);
    }
    T& data = *std::any_cast<std::shared_ptr<T>>(local_data.at(node.id));
    return data;
}

template <>
CustomData& _get_input_data<CustomData>(std::unordered_map<NodeId, std::any>& local_data, const DatumNode& node) {
    if (!node.custom_prop.has_value()) {
        throw std::runtime_error("CustomData property not found for input node " + node.id);
    }

    auto& input_any = local_data.at(node.id);
    if (auto* custom_ptr = std::any_cast<std::shared_ptr<CustomData>>(&input_any)) {
        if (!*custom_ptr) {
            throw std::runtime_error("CustomData input is null for node " + node.id);
        }
        return **custom_ptr;
    }

    if (auto* void_ptr = std::any_cast<std::shared_ptr<void>>(&input_any)) {
        if (!*void_ptr) {
            throw std::runtime_error("CustomData input is null for node " + node.id);
        }
        return *static_cast<CustomData*>(void_ptr->get());
    }

    throw std::runtime_error("CustomData input has unexpected storage type for node " + node.id);
}

template <heongpu::Scheme S>
Ct<S>&
_create_output_data(ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data, const DatumNode& node) {
    if (!node.fhe_prop.has_value()) {
        throw std::runtime_error("FHE property not found for output node " + node.id);
    }
    auto* context = ctx.get_other_arg<heongpu::HEContext<S>>(1);
    auto* stream_option = ctx.get_other_arg<heongpu::ExecutionOptions>(0);
    if (!context || !stream_option) {
        throw std::runtime_error("GPU output allocation requires HEContext and stream options");
    }
    auto output = std::make_shared<Ct<S>>(*context, node.fhe_prop->level, *stream_option);
    output->set_log_slot_count(node.fhe_prop->log_slots);
    output->set_scale(node.fhe_prop->scale);
    local_data[node.id] = output;
    return *output;
}

static std::vector<int32_t> get_default_rotation_substeps(int32_t step) {
    const bool negative_step = step < 0;
    uint32_t abs_step =
        negative_step ? static_cast<uint32_t>(-static_cast<int64_t>(step)) : static_cast<uint32_t>(step);
    uint32_t half = abs_step >> 1;
    uint32_t triple_half = abs_step + half;
    uint32_t changed_bits = half ^ triple_half;
    uint32_t pos_bits = triple_half & changed_bits;
    uint32_t neg_bits = half & changed_bits;

    std::vector<int32_t> substeps;
    for (int idx = 30; idx >= 0; --idx) {
        uint32_t bit = 1u << idx;
        if ((pos_bits & bit) != 0) {
            int32_t substep = static_cast<int32_t>(bit);
            substeps.push_back(negative_step ? -substep : substep);
        }
    }
    for (int idx = 30; idx >= 0; --idx) {
        uint32_t bit = 1u << idx;
        if ((neg_bits & bit) != 0) {
            int32_t substep = -static_cast<int32_t>(bit);
            substeps.push_back(negative_step ? -substep : substep);
        }
    }
    return substeps;
}

// @company CipherFlow
template <heongpu::Scheme S>
void add_scalar_gpu(heongpu::HEArithmeticOperator<S>& operators,
                    Ct<S>& input,
                    Ct<S>& output,
                    const ScalarType& scalar,
                    heongpu::ExecutionOptions& options) {
    std::visit(
        [&](auto&& scalar_value) {
            using T = std::decay_t<decltype(scalar_value)>;
            if constexpr (S == heongpu::Scheme::BFV) {
                if constexpr (std::is_integral_v<T>) {
                    operators.add_plain(input, scalar_value, output, options);
                } else {
                    throw std::runtime_error("Unsupported BFV scalar type for add");
                }
            } else if constexpr (S == heongpu::Scheme::CKKS) {
                if constexpr (std::is_same_v<T, std::complex<double>>) {
                    operators.add_plain(input, Complex64(scalar_value.real(), scalar_value.imag()), output, options);
                } else if constexpr (std::is_arithmetic_v<T>) {
                    operators.add_plain(input, static_cast<double>(scalar_value), output, options);
                } else {
                    throw std::runtime_error("Unsupported CKKS scalar type for add");
                }
            } else {
                throw std::runtime_error("Unsupported scheme for scalar add");
            }
        },
        scalar);
}

// @company CipherFlow
template <heongpu::Scheme S>
void sub_scalar_gpu(heongpu::HEArithmeticOperator<S>& operators,
                    Ct<S>& input,
                    Ct<S>& output,
                    const ScalarType& scalar,
                    heongpu::ExecutionOptions& options) {
    std::visit(
        [&](auto&& scalar_value) {
            using T = std::decay_t<decltype(scalar_value)>;
            if constexpr (S == heongpu::Scheme::BFV) {
                if constexpr (std::is_integral_v<T>) {
                    operators.sub_plain(input, scalar_value, output, options);
                } else {
                    throw std::runtime_error("Unsupported BFV scalar type for sub");
                }
            } else if constexpr (S == heongpu::Scheme::CKKS) {
                if constexpr (std::is_same_v<T, std::complex<double>>) {
                    operators.sub_plain(input, Complex64(scalar_value.real(), scalar_value.imag()), output, options);
                } else if constexpr (std::is_arithmetic_v<T>) {
                    operators.sub_plain(input, static_cast<double>(scalar_value), output, options);
                } else {
                    throw std::runtime_error("Unsupported CKKS scalar type for sub");
                }
            } else {
                throw std::runtime_error("Unsupported scheme for scalar sub");
            }
        },
        scalar);
}

// @company CipherFlow
template <heongpu::Scheme S>
void mult_scalar_gpu(heongpu::HEArithmeticOperator<S>& operators,
                     Ct<S>& input,
                     Ct<S>& output,
                     const ScalarType& scalar,
                     heongpu::ExecutionOptions& options) {
    std::visit(
        [&](auto&& scalar_value) {
            using T = std::decay_t<decltype(scalar_value)>;
            if constexpr (S == heongpu::Scheme::BFV) {
                if constexpr (std::is_integral_v<T>) {
                    operators.multiply_plain(input, scalar_value, output, options);
                } else {
                    throw std::runtime_error("Unsupported BFV scalar type for mult");
                }
            } else if constexpr (S == heongpu::Scheme::CKKS) {
                if constexpr (std::is_same_v<T, std::complex<double>>) {
                    operators.multiply_plain(input, Complex64(scalar_value.real(), scalar_value.imag()), output,
                                             options);
                } else if constexpr (std::is_arithmetic_v<T>) {
                    operators.multiply_plain(input, Complex64(static_cast<double>(scalar_value), 0.0), output, options);
                } else {
                    throw std::runtime_error("Unsupported CKKS scalar type for mult");
                }
            } else {
                throw std::runtime_error("Unsupported scheme for scalar mult");
            }
        },
        scalar);
}

template <heongpu::Scheme S> void bind_gpu_add(ComputeNode& node) {
    if (node.fhe_prop->p.has_value() && node.fhe_prop->p->has_scalar) {
        auto scalar = node.fhe_prop->p->scalar;
        node.executor = [scalar](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                 const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            add_scalar_gpu<S>(operators, input0, output0, scalar, stream_option);
        };
    } else if (node.input_nodes.size() == 1) {
        // Single input: ct + ct (same input)
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            operators.add(input0, input0, output0, stream_option);
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                               const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
                auto& input1 = _get_input_data<Pt<S>>(local_data, *self.input_nodes[1]);
                auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
                operators.add_plain(input0, input1, output0, stream_option);
            };
        } else {
            // ct + ct
            node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                               const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
                auto& input1 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[1]);
                auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
                operators.add(input0, input1, output0, stream_option);
            };
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_sub(ComputeNode& node) {
    if (node.fhe_prop->p.has_value() && node.fhe_prop->p->has_scalar) {
        auto scalar = node.fhe_prop->p->scalar;
        node.executor = [scalar](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                 const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            sub_scalar_gpu<S>(operators, input0, output0, scalar, stream_option);
        };
    } else if (node.input_nodes.size() == 1) {
        // Single input: ct - ct (same input)
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            operators.sub(input0, input0, output0, stream_option);
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                               const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
                auto& input1 = _get_input_data<Pt<S>>(local_data, *self.input_nodes[1]);
                auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
                operators.sub_plain(input0, input1, output0, stream_option);
            };
        } else {
            // ct - ct
            node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                               const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
                auto& input1 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[1]);
                auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
                operators.sub(input0, input1, output0, stream_option);
            };
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_mult(ComputeNode& node) {
    if (node.fhe_prop->p.has_value() && node.fhe_prop->p->has_scalar) {
        auto scalar = node.fhe_prop->p->scalar;
        node.executor = [scalar](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                 const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            mult_scalar_gpu<S>(operators, input0, output0, scalar, stream_option);
        };
    } else if (node.input_nodes.size() == 1) {
        // Single input: ct * ct (same input)
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            operators.multiply(input0, input0, output0, stream_option);
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if constexpr (S != heongpu::Scheme::CKKS) {
                if (!pt_node->fhe_prop->is_ringt) {
                    throw std::runtime_error(
                        "Multiply with plaintext only supported for CKKS scheme or BFV RingT plaintext");
                }
            }
            node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                               const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
                auto& input1 = _get_input_data<Pt<S>>(local_data, *self.input_nodes[1]);
                auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
                operators.multiply_plain(input0, input1, output0, stream_option);
            };
        } else {
            // ct * ct
            node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                               const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
                auto& input1 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[1]);
                auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
                operators.multiply(input0, input1, output0, stream_option);
            };
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_relin(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                       const ComputeNode& self) -> void {
        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
        auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
        auto& rlk = _get_input_data<Rlk<S>>(local_data, *self.input_nodes[1]);
        auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
        operators.relinearize(input0, output0, rlk, stream_option);
    };
}

template <heongpu::Scheme S> void bind_gpu_rescale(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                       const ComputeNode& self) -> void {
        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
        auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
        auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
        operators.rescale(input0, output0, stream_option);
    };
}

template <heongpu::Scheme S> void bind_gpu_drop_level(ComputeNode& node) {
    if (!node.fhe_prop->p.has_value()) {
        throw std::runtime_error("DROP_LEVEL requires drop_level property");
    }
    auto drop_level = node.fhe_prop->p->drop_level;
    node.executor = [drop_level](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                 const ComputeNode& self) -> void {
        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
        auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
        auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
        operators.mod_drop(input0, output0, drop_level, stream_option);
    };
}

template <heongpu::Scheme S> void bind_gpu_rotate_col(ComputeNode& node) {
    if (!node.fhe_prop->p.has_value() || node.fhe_prop->p->rotation_steps.empty()) {
        throw std::runtime_error("Rotation step not found in FHE property");
    }
    auto steps = node.fhe_prop->p->rotation_steps;
    auto use_default_rotation_keys = node.fhe_prop->p->use_default_rotation_keys;
    node.executor = [steps, use_default_rotation_keys](ExecutionContext& ctx,
                                                       std::unordered_map<NodeId, std::any>& local_data,
                                                       const ComputeNode& self) -> void {
        auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
        auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
        if (steps.size() != self.output_nodes.size()) {
            throw std::runtime_error("ROTATE_COL output count does not match rotation_steps count");
        }
        if (self.input_nodes.size() < 2) {
            throw std::runtime_error("ROTATE_COL requires at least one Galois key input");
        }

        if (use_default_rotation_keys) {
            auto& glk = _get_input_data<Glk<S>>(local_data, *self.input_nodes[1]);
            for (size_t i = 0; i < steps.size(); ++i) {
                auto& output = _create_output_data<S>(ctx, local_data, *self.output_nodes[i]);
                auto substeps = get_default_rotation_substeps(steps[i]);
                if (substeps.empty()) {
                    throw std::runtime_error("ROTATE_COL step 0 is not supported on GPU");
                }
                operators.rotate_rows(input0, output, glk, substeps[0], stream_option);
                for (size_t j = 1; j < substeps.size(); ++j) {
                    operators.rotate_rows(output, output, glk, substeps[j], stream_option);
                }
            }
            return;
        }

        if (self.input_nodes.size() < steps.size() + 1) {
            throw std::runtime_error("ROTATE_COL non-default key count does not match rotation_steps count");
        }
        for (size_t i = 0; i < steps.size(); ++i) {
            auto& glk = _get_input_data<Glk<S>>(local_data, *self.input_nodes[i + 1]);
            auto& output = _create_output_data<S>(ctx, local_data, *self.output_nodes[i]);
            operators.rotate_rows(input0, output, glk, steps[i], stream_option);
        }
    };
}

template <heongpu::Scheme S> void bind_gpu_rotate_row(ComputeNode& node) {
    if constexpr (S == heongpu::Scheme::BFV) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& glk = _get_input_data<Glk<S>>(local_data, *self.input_nodes[1]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            operators.rotate_columns(input0, output0, glk, stream_option);
        };
    } else {
        throw std::runtime_error("ROTATE_ROW only supported for BFV scheme");
    }
}

// @company CipherFlow
template <heongpu::Scheme S> void bind_gpu_conjugate(ComputeNode& node) {
    if constexpr (S == heongpu::Scheme::CKKS) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& glk = _get_input_data<Glk<S>>(local_data, *self.input_nodes[1]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            operators.conjugate(input0, output0, glk, stream_option);
        };
    } else {
        throw std::runtime_error("CONJUGATE only supported for CKKS scheme");
    }
}

template <heongpu::Scheme S> void bind_gpu_cmpac_sum(ComputeNode& node) {
    if (!node.fhe_prop->p.has_value()) {
        throw std::runtime_error("Sum count not found in FHE property");
    }
    int n = node.fhe_prop->p->sum_cnt;
    // Find the first plaintext node to determine type (plaintext nodes start at index n+1)
    DatumNode* pt_node = node.input_nodes[n + 1];
    if (!pt_node->fhe_prop.has_value()) {
        throw std::runtime_error("FHE property not found for compute node");
    }

    if (pt_node->fhe_prop->is_ringt) {
        node.executor = [n](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                            const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input_ct_0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& input_pt_0 = _get_input_data<Pt<S>>(local_data, *self.input_nodes[n + 1]);
            Ct<S> sum;
            operators.multiply_plain(input_ct_0, input_pt_0, sum, stream_option);
            for (int i = 1; i < n; i++) {
                auto& input_ct_i = _get_input_data<Ct<S>>(local_data, *self.input_nodes[i]);
                auto& input_pt_i = _get_input_data<Pt<S>>(local_data, *self.input_nodes[n + 1 + i]);
                Ct<S> product;
                operators.multiply_plain(input_ct_i, input_pt_i, product, stream_option);
                operators.add_inplace(sum, product, stream_option);
            }
            auto& input_ct_n = _get_input_data<Ct<S>>(local_data, *self.input_nodes[n]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            operators.add(sum, input_ct_n, output0, stream_option);
        };
    } else {
        // ct * pt (normal)
        if constexpr (S == heongpu::Scheme::CKKS) {
            node.executor = [n](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input_ct_0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
                auto& input_pt_0 = _get_input_data<Pt<S>>(local_data, *self.input_nodes[n + 1]);
                Ct<S> sum;
                operators.multiply_plain(input_ct_0, input_pt_0, sum, stream_option);
                for (int i = 1; i < n; i++) {
                    auto& input_ct_i = _get_input_data<Ct<S>>(local_data, *self.input_nodes[i]);
                    auto& input_pt_i = _get_input_data<Pt<S>>(local_data, *self.input_nodes[n + 1 + i]);
                    Ct<S> product;
                    operators.multiply_plain(input_ct_i, input_pt_i, product, stream_option);
                    operators.add_inplace(sum, product, stream_option);
                }
                auto& input_ct_n = _get_input_data<Ct<S>>(local_data, *self.input_nodes[n]);
                auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
                operators.add(sum, input_ct_n, output0, stream_option);
            };
        } else {
            throw std::runtime_error("Multiply with plaintext only supported for CKKS scheme");
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_cmp_sum(ComputeNode& node) {
    if (!node.fhe_prop->p.has_value()) {
        throw std::runtime_error("Sum count not found in FHE property");
    }
    int n = node.fhe_prop->p->sum_cnt;
    // Find the first plaintext node to determine type (plaintext nodes start at index n)
    DatumNode* pt_node = node.input_nodes[n];
    if (!pt_node->fhe_prop.has_value()) {
        throw std::runtime_error("FHE property not found for compute node");
    }

    if (pt_node->fhe_prop->is_ringt) {
        node.executor = [n](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                            const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input_ct_0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& input_pt_0 = _get_input_data<Pt<S>>(local_data, *self.input_nodes[n]);
            Ct<S> sum;
            operators.multiply_plain(input_ct_0, input_pt_0, sum, stream_option);
            for (int i = 1; i < n; i++) {
                auto& input_ct_i = _get_input_data<Ct<S>>(local_data, *self.input_nodes[i]);
                auto& input_pt_i = _get_input_data<Pt<S>>(local_data, *self.input_nodes[n + i]);
                Ct<S> product;
                operators.multiply_plain(input_ct_i, input_pt_i, product, stream_option);
                operators.add_inplace(sum, product, stream_option);
            }
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            output0 = std::move(sum);
        };
    } else {
        // ct * pt (normal)
        if constexpr (S == heongpu::Scheme::CKKS) {
            node.executor = [n](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                const ComputeNode& self) -> void {
                auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
                auto& input_ct_0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
                auto& input_pt_0 = _get_input_data<Pt<S>>(local_data, *self.input_nodes[n]);
                Ct<S> sum;
                operators.multiply_plain(input_ct_0, input_pt_0, sum, stream_option);
                for (int i = 1; i < n; i++) {
                    auto& input_ct_i = _get_input_data<Ct<S>>(local_data, *self.input_nodes[i]);
                    auto& input_pt_i = _get_input_data<Pt<S>>(local_data, *self.input_nodes[n + i]);
                    Ct<S> product;
                    operators.multiply_plain(input_ct_i, input_pt_i, product, stream_option);
                    operators.add_inplace(sum, product, stream_option);
                }
                auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
                output0 = std::move(sum);
            };
        } else {
            throw std::runtime_error("Multiply with plaintext only supported for CKKS scheme");
        }
    }
}

template <heongpu::Scheme S> void bind_gpu_bootstrap(ComputeNode& node) {
    if constexpr (S == heongpu::Scheme::CKKS) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto [operators, stream_option] = _get_operator_and_stream_option<S>(ctx);
            auto& input0 = _get_input_data<Ct<S>>(local_data, *self.input_nodes[0]);
            auto& rlk = _get_input_data<Rlk<S>>(local_data, *self.input_nodes[1]);
            auto& glk = _get_input_data<Glk<S>>(local_data, *self.input_nodes[2]);
            auto& swk0 = _get_input_data<Swk<S>>(local_data, *self.input_nodes[self.input_nodes.size() - 2]);
            auto& swk1 = _get_input_data<Swk<S>>(local_data, *self.input_nodes[self.input_nodes.size() - 1]);
            auto& output0 = _create_output_data<S>(ctx, local_data, *self.output_nodes[0]);
            output0 = operators.regular_bootstrapping_v2(input0, glk, rlk, &swk0, &swk1, stream_option);
        };
    } else {
        throw std::runtime_error("BOOTSTRAP only supported for CKKS scheme");
    }
}

template <heongpu::Scheme S> void bind_gpu_encode_ringt(ComputeNode& node) {
    if constexpr (S == heongpu::Scheme::CKKS) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            if (!self.fhe_prop.has_value() || !self.output_nodes[0]->fhe_prop.has_value()) {
                throw std::runtime_error("GPU CKKS encode_ringt missing FHE properties");
            }

            auto* stream_option = ctx.get_other_arg<heongpu::ExecutionOptions>(0);
            auto* context = ctx.get_other_arg<heongpu::HEContext<heongpu::Scheme::CKKS>>(1);
            auto* encoder = ctx.get_other_arg<heongpu::HEEncoder<heongpu::Scheme::CKKS>>(2);
            if (!stream_option || !context || !encoder) {
                throw std::runtime_error("GPU CKKS encode_ringt requires HEContext, encoder, and stream options");
            }

            double scale = self.output_nodes[0]->fhe_prop->scale;
            auto& custom_data = _get_input_data<CustomData>(local_data, *self.input_nodes[0]);
            auto* msg_vec = custom_data.get_typed_data<std::vector<double>>();
            if (!msg_vec) {
                throw std::runtime_error("GPU CKKS encode_ringt expects std::vector<double> CustomData");
            }

            auto output = std::make_shared<heongpu::Plaintext<heongpu::Scheme::CKKS>>(*context, *stream_option);
            encoder->encode_ringt(*output, *msg_vec, scale, *stream_option);
            local_data[self.output_nodes[0]->id] = output;
        };
    } else {
        node.executor = [](ExecutionContext&, std::unordered_map<NodeId, std::any>&, const ComputeNode&) -> void {
            throw std::runtime_error("GPU encode_ringt is only supported for CKKS");
        };
    }
}

// Explicit template instantiations
template void bind_gpu_add<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_add<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_sub<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_sub<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_mult<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_mult<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_relin<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_relin<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_rescale<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_rescale<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_drop_level<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_drop_level<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_rotate_col<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_rotate_col<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_rotate_row<heongpu::Scheme::BFV>(ComputeNode& node);

template void bind_gpu_conjugate<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_cmpac_sum<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_cmpac_sum<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_cmp_sum<heongpu::Scheme::BFV>(ComputeNode& node);
template void bind_gpu_cmp_sum<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_bootstrap<heongpu::Scheme::CKKS>(ComputeNode& node);

template void bind_gpu_encode_ringt<heongpu::Scheme::CKKS>(ComputeNode& node);

// Wrapper function for ExecutorBinder (callable from non-CUDA code)
void bind_gpu_executor(ComputeNode& node, Algo algorithm) {
    if (!node.fhe_prop.has_value()) {
        throw std::runtime_error("FHE property not found for compute node");
    }

    switch (algorithm) {
        case ALGO_BFV:
            switch (node.fhe_prop->op_type) {
                case OperationType::ADD: bind_gpu_add<heongpu::Scheme::BFV>(node); break;
                case OperationType::SUB: bind_gpu_sub<heongpu::Scheme::BFV>(node); break;
                case OperationType::MULTIPLY: bind_gpu_mult<heongpu::Scheme::BFV>(node); break;
                case OperationType::RELINEARIZE: bind_gpu_relin<heongpu::Scheme::BFV>(node); break;
                case OperationType::RESCALE: bind_gpu_rescale<heongpu::Scheme::BFV>(node); break;
                case OperationType::DROP_LEVEL: bind_gpu_drop_level<heongpu::Scheme::BFV>(node); break;
                case OperationType::ROTATE_COL: bind_gpu_rotate_col<heongpu::Scheme::BFV>(node); break;
                case OperationType::ROTATE_ROW: bind_gpu_rotate_row<heongpu::Scheme::BFV>(node); break;
                case OperationType::MAC_W_PARTIAL_SUM: bind_gpu_cmpac_sum<heongpu::Scheme::BFV>(node); break;
                case OperationType::MAC_WO_PARTIAL_SUM: bind_gpu_cmp_sum<heongpu::Scheme::BFV>(node); break;
                default: throw std::runtime_error("Unsupported operation type for GPU BFV");
            }
            break;
        case ALGO_CKKS:
            switch (node.fhe_prop->op_type) {
                case OperationType::ADD: bind_gpu_add<heongpu::Scheme::CKKS>(node); break;
                case OperationType::SUB: bind_gpu_sub<heongpu::Scheme::CKKS>(node); break;
                case OperationType::MULTIPLY: bind_gpu_mult<heongpu::Scheme::CKKS>(node); break;
                case OperationType::RELINEARIZE: bind_gpu_relin<heongpu::Scheme::CKKS>(node); break;
                case OperationType::RESCALE: bind_gpu_rescale<heongpu::Scheme::CKKS>(node); break;
                case OperationType::DROP_LEVEL: bind_gpu_drop_level<heongpu::Scheme::CKKS>(node); break;
                case OperationType::ROTATE_COL: bind_gpu_rotate_col<heongpu::Scheme::CKKS>(node); break;
                case OperationType::CONJUGATE: bind_gpu_conjugate<heongpu::Scheme::CKKS>(node); break;
                case OperationType::MAC_W_PARTIAL_SUM: bind_gpu_cmpac_sum<heongpu::Scheme::CKKS>(node); break;
                case OperationType::MAC_WO_PARTIAL_SUM: bind_gpu_cmp_sum<heongpu::Scheme::CKKS>(node); break;
                case OperationType::BOOTSTRAP: bind_gpu_bootstrap<heongpu::Scheme::CKKS>(node); break;
                default: throw std::runtime_error("Unsupported operation type for GPU CKKS");
            }
            break;
        default: throw std::runtime_error("Unknown algorithm type for GPU");
    }
}

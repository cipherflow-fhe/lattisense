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

/** @file mega_ag_executors_cpu.cpp
 * @brief CPU executor implementations for MegaAG compute nodes
 */

#include <any>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../mega_ag_executors.h"
#include "schemes/bfv/bfv.h"
#include "schemes/ckks/ckks.h"

using namespace fhe_ops_lib;

template <HEScheme SchemeType> struct CpuSchemeTypes;

template <> struct CpuSchemeTypes<HEScheme::BFV> {
    using Context = BfvContext;
    using Ciphertext = BfvCiphertext;
    using Plaintext = BfvPlaintext;
};

template <> struct CpuSchemeTypes<HEScheme::CKKS> {
    using Context = CkksContext;
    using Ciphertext = CkksCiphertext;
    using Plaintext = CkksPlaintext;
};

static DatumNode* find_plaintext_node(const ComputeNode& node) {
    if (node.input_nodes.size() == 2) {
        auto* datum_node = node.input_nodes[1];
        if (!datum_node->fhe_prop.has_value()) {
            throw std::runtime_error("FHE property not found for input node " + datum_node->id);
        }
        if (datum_node->datum_type == DataType::TYPE_PLAINTEXT) {
            return datum_node;
        }
    }
    return nullptr;
}

template <HEScheme SchemeType> typename CpuSchemeTypes<SchemeType>::Context& _get_context(ExecutionContext& ctx) {
    using ContextType = typename CpuSchemeTypes<SchemeType>::Context;
    auto* context = ctx.get_arithmetic_context<ContextType>();
    if (!context) {
        throw std::runtime_error("CPU FHE context not found");
    }
    return *context;
}

template <typename T> T& _get_input_data(std::unordered_map<NodeId, std::any>& local_data, const DatumNode& node) {
    if (!node.fhe_prop.has_value()) {
        throw std::runtime_error("FHE property not found for input node " + node.id);
    }
    return *std::any_cast<std::shared_ptr<T>>(local_data.at(node.id));
}

template <HEScheme SchemeType, typename ContextType, typename CiphertextType>
CiphertextType add_scalar(ContextType& context, const CiphertextType& input, const ScalarType& scalar) {
    return std::visit(
        [&](auto&& scalar_value) -> CiphertextType {
            using T = std::decay_t<decltype(scalar_value)>;
            if constexpr (SchemeType == HEScheme::BFV) {
                if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) {
                    return context.add(input, scalar_value);
                } else {
                    throw std::runtime_error("Unsupported BFV scalar type for add");
                }
            } else {
                if constexpr (std::is_same_v<T, std::complex<double>>) {
                    return context.add(input, scalar_value);
                } else {
                    return context.add(input, static_cast<double>(scalar_value));
                }
            }
        },
        scalar);
}

template <HEScheme SchemeType, typename ContextType, typename CiphertextType>
CiphertextType sub_scalar(ContextType& context, const CiphertextType& input, const ScalarType& scalar) {
    return std::visit(
        [&](auto&& scalar_value) -> CiphertextType {
            using T = std::decay_t<decltype(scalar_value)>;
            if constexpr (SchemeType == HEScheme::BFV) {
                if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) {
                    return context.sub(input, scalar_value);
                } else {
                    throw std::runtime_error("Unsupported BFV scalar type for sub");
                }
            } else {
                if constexpr (std::is_same_v<T, std::complex<double>>) {
                    return context.sub(input, scalar_value);
                } else {
                    return context.sub(input, static_cast<double>(scalar_value));
                }
            }
        },
        scalar);
}

template <HEScheme SchemeType, typename ContextType, typename CiphertextType>
CiphertextType mult_scalar(ContextType& context, const CiphertextType& input, const ScalarType& scalar) {
    return std::visit(
        [&](auto&& scalar_value) -> CiphertextType {
            using T = std::decay_t<decltype(scalar_value)>;
            if constexpr (SchemeType == HEScheme::BFV) {
                if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) {
                    return context.mult(input, scalar_value);
                } else {
                    throw std::runtime_error("Unsupported BFV scalar type for mult");
                }
            } else {
                if constexpr (std::is_same_v<T, std::complex<double>>) {
                    return context.mult(input, scalar_value);
                } else {
                    return context.mult(input, static_cast<double>(scalar_value));
                }
            }
        },
        scalar);
}

template <HEScheme SchemeType> void bind_cpu_add(ComputeNode& node) {
    using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;

    if (node.fhe_prop->p.has_value() && node.fhe_prop->p->has_scalar) {
        auto scalar = node.fhe_prop->p->scalar;
        node.executor = [scalar](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                 const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            local_data[self.output_nodes[0]->id] =
                std::make_shared<CiphertextType>(add_scalar<SchemeType>(context, input0, scalar));
        };
    } else if (node.input_nodes.size() == 1) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.add(input0, input0));
        };
    } else if (find_plaintext_node(node)) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            using PlaintextType = typename CpuSchemeTypes<SchemeType>::Plaintext;
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            auto& input1 = _get_input_data<PlaintextType>(local_data, *self.input_nodes[1]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.add(input0, input1));
        };
    } else {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            auto& input1 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[1]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.add(input0, input1));
        };
    }
}

template <HEScheme SchemeType> void bind_cpu_sub(ComputeNode& node) {
    using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;

    if (node.fhe_prop->p.has_value() && node.fhe_prop->p->has_scalar) {
        auto scalar = node.fhe_prop->p->scalar;
        node.executor = [scalar](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                 const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            local_data[self.output_nodes[0]->id] =
                std::make_shared<CiphertextType>(sub_scalar<SchemeType>(context, input0, scalar));
        };
    } else if (node.input_nodes.size() == 1) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.sub(input0, input0));
        };
    } else if (find_plaintext_node(node)) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            using PlaintextType = typename CpuSchemeTypes<SchemeType>::Plaintext;
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            auto& input1 = _get_input_data<PlaintextType>(local_data, *self.input_nodes[1]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.sub(input0, input1));
        };
    } else {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            auto& input1 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[1]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.sub(input0, input1));
        };
    }
}

template <HEScheme SchemeType> void bind_cpu_mult(ComputeNode& node) {
    using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;

    if (node.fhe_prop->p.has_value() && node.fhe_prop->p->has_scalar) {
        auto scalar = node.fhe_prop->p->scalar;
        node.executor = [scalar](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                 const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            local_data[self.output_nodes[0]->id] =
                std::make_shared<CiphertextType>(mult_scalar<SchemeType>(context, input0, scalar));
        };
    } else if (node.input_nodes.size() == 1) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.mult(input0, input0));
        };
    } else if (find_plaintext_node(node)) {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            using PlaintextType = typename CpuSchemeTypes<SchemeType>::Plaintext;
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            auto& input1 = _get_input_data<PlaintextType>(local_data, *self.input_nodes[1]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.mult(input0, input1));
        };
    } else {
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            auto& input1 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[1]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.mult(input0, input1));
        };
    }
}

template <HEScheme SchemeType> void bind_cpu_relin(ComputeNode& node) {
    using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;
    node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                       const ComputeNode& self) -> void {
        auto& context = _get_context<SchemeType>(ctx);
        auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
        local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.relinearize(input0));
    };
}

template <HEScheme SchemeType> void bind_cpu_rescale(ComputeNode& node) {
    using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;
    node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                       const ComputeNode& self) -> void {
        auto& context = _get_context<SchemeType>(ctx);
        auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
        local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.rescale(input0));
    };
}

template <HEScheme SchemeType> void bind_cpu_drop_level(ComputeNode& node) {
    using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;
    if (!node.fhe_prop->p.has_value()) {
        throw std::runtime_error("DROP_LEVEL requires drop_level property");
    }
    auto drop_level = node.fhe_prop->p->drop_level;
    node.executor = [drop_level](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                                 const ComputeNode& self) -> void {
        auto& context = _get_context<SchemeType>(ctx);
        auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
        local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.drop_level(input0, drop_level));
    };
}

template <HEScheme SchemeType> void bind_cpu_rotate_col(ComputeNode& node) {
    if (!node.fhe_prop->p.has_value() || node.fhe_prop->p->rotation_steps.empty()) {
        throw std::runtime_error("ROTATE_COL requires rotation_steps property");
    }
    auto steps = node.fhe_prop->p->rotation_steps;
    auto use_default_rotation_keys = node.fhe_prop->p->use_default_rotation_keys;
    node.executor = [steps, use_default_rotation_keys](ExecutionContext& ctx,
                                                       std::unordered_map<NodeId, std::any>& local_data,
                                                       const ComputeNode& self) -> void {
        using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;
        auto& context = _get_context<SchemeType>(ctx);
        context.set_use_default_rotation_keys(use_default_rotation_keys);
        auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
        if (steps.size() != self.output_nodes.size()) {
            throw std::runtime_error("ROTATE_COL output count does not match rotation_steps count");
        }
        if constexpr (SchemeType == HEScheme::BFV) {
            auto results = context.rotate_cols(input0, steps);
            for (size_t i = 0; i < steps.size(); ++i) {
                local_data[self.output_nodes[i]->id] =
                    std::make_shared<CiphertextType>(std::move(results.at(steps[i])));
            }
        } else {
            auto results = context.rotate(input0, steps);
            for (size_t i = 0; i < steps.size(); ++i) {
                local_data[self.output_nodes[i]->id] =
                    std::make_shared<CiphertextType>(std::move(results.at(steps[i])));
            }
        }
    };
}

template <HEScheme SchemeType> void bind_cpu_rotate_row(ComputeNode& node) {
    using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;
    node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                       const ComputeNode& self) -> void {
        auto& context = _get_context<SchemeType>(ctx);
        auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
        if constexpr (SchemeType == HEScheme::BFV) {
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.rotate_rows(input0));
        } else {
            throw std::runtime_error("ROTATE_ROW only supported for BFV scheme");
        }
    };
}

template <HEScheme SchemeType> void bind_cpu_conjugate(ComputeNode& node) {
    using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;
    node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                       const ComputeNode& self) -> void {
        auto& context = _get_context<SchemeType>(ctx);
        auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
        if constexpr (SchemeType == HEScheme::CKKS) {
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.conjugate(input0));
        } else {
            throw std::runtime_error("CONJUGATE only supported for CKKS scheme");
        }
    };
}

template <HEScheme SchemeType> void bind_cpu_cmpac_sum(ComputeNode& node) {
    if (!node.fhe_prop->p.has_value()) {
        throw std::runtime_error("MAC_W_PARTIAL_SUM requires sum_cnt property");
    }
    int n = node.fhe_prop->p->sum_cnt;
    node.executor = [n](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                        const ComputeNode& self) -> void {
        using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;
        using PlaintextType = typename CpuSchemeTypes<SchemeType>::Plaintext;
        auto& context = _get_context<SchemeType>(ctx);
        std::vector<CiphertextType> products(n);
        for (int i = 0; i < n; i++) {
            auto& ct = _get_input_data<CiphertextType>(local_data, *self.input_nodes[i]);
            auto& pt = _get_input_data<PlaintextType>(local_data, *self.input_nodes[n + 1 + i]);
            products[i] = context.mult(ct, pt);
        }
        CiphertextType sum = std::move(products[0]);
        for (int i = 1; i < n; i++) {
            sum = context.add(sum, products[i]);
        }
        auto& accum = _get_input_data<CiphertextType>(local_data, *self.input_nodes[n]);
        local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.add(sum, accum));
    };
}

template <HEScheme SchemeType> void bind_cpu_cmp_sum(ComputeNode& node) {
    if (!node.fhe_prop->p.has_value()) {
        throw std::runtime_error("MAC_WO_PARTIAL_SUM requires sum_cnt property");
    }
    int n = node.fhe_prop->p->sum_cnt;
    node.executor = [n](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                        const ComputeNode& self) -> void {
        using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;
        using PlaintextType = typename CpuSchemeTypes<SchemeType>::Plaintext;
        auto& context = _get_context<SchemeType>(ctx);
        std::vector<CiphertextType> products(n);
        for (int i = 0; i < n; i++) {
            auto& ct = _get_input_data<CiphertextType>(local_data, *self.input_nodes[i]);
            auto& pt = _get_input_data<PlaintextType>(local_data, *self.input_nodes[n + i]);
            products[i] = context.mult(ct, pt);
        }
        CiphertextType sum = std::move(products[0]);
        for (int i = 1; i < n; i++) {
            sum = context.add(sum, products[i]);
        }
        local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(std::move(sum));
    };
}

template <HEScheme SchemeType> void bind_cpu_bootstrap(ComputeNode& node) {
    if constexpr (SchemeType == HEScheme::CKKS) {
        using CiphertextType = typename CpuSchemeTypes<SchemeType>::Ciphertext;
        node.executor = [](ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data,
                           const ComputeNode& self) -> void {
            auto& context = _get_context<SchemeType>(ctx);
            auto& input0 = _get_input_data<CiphertextType>(local_data, *self.input_nodes[0]);
            local_data[self.output_nodes[0]->id] = std::make_shared<CiphertextType>(context.bootstrap(input0));
        };
    } else {
        throw std::runtime_error("BOOTSTRAP only supported for CKKS scheme");
    }
}

// Explicit template instantiations
template void bind_cpu_add<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_add<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_sub<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_sub<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_mult<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_mult<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_relin<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_relin<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_rescale<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_rescale<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_drop_level<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_drop_level<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_rotate_col<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_rotate_col<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_rotate_row<HEScheme::BFV>(ComputeNode& node);

template void bind_cpu_conjugate<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_cmpac_sum<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_cmpac_sum<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_cmp_sum<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_cmp_sum<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_bootstrap<HEScheme::CKKS>(ComputeNode& node);

// Wrapper function for ExecutorBinder (callable from mega_ag.cpp)
void bind_cpu_executor(ComputeNode& node, Algo algorithm) {
    if (!node.fhe_prop.has_value()) {
        throw std::runtime_error("FHE property not found for compute node " + node.id);
    }

    switch (algorithm) {
        case ALGO_BFV:
            switch (node.fhe_prop->op_type) {
                case OperationType::ADD: bind_cpu_add<HEScheme::BFV>(node); break;
                case OperationType::SUB: bind_cpu_sub<HEScheme::BFV>(node); break;
                case OperationType::MULTIPLY: bind_cpu_mult<HEScheme::BFV>(node); break;
                case OperationType::RELINEARIZE: bind_cpu_relin<HEScheme::BFV>(node); break;
                case OperationType::RESCALE: bind_cpu_rescale<HEScheme::BFV>(node); break;
                case OperationType::DROP_LEVEL: bind_cpu_drop_level<HEScheme::BFV>(node); break;
                case OperationType::ROTATE_COL: bind_cpu_rotate_col<HEScheme::BFV>(node); break;
                case OperationType::ROTATE_ROW: bind_cpu_rotate_row<HEScheme::BFV>(node); break;
                case OperationType::MAC_W_PARTIAL_SUM: bind_cpu_cmpac_sum<HEScheme::BFV>(node); break;
                case OperationType::MAC_WO_PARTIAL_SUM: bind_cpu_cmp_sum<HEScheme::BFV>(node); break;
                default: throw std::runtime_error("Unsupported operation type for CPU BFV");
            }
            break;
        case ALGO_CKKS:
            switch (node.fhe_prop->op_type) {
                case OperationType::ADD: bind_cpu_add<HEScheme::CKKS>(node); break;
                case OperationType::SUB: bind_cpu_sub<HEScheme::CKKS>(node); break;
                case OperationType::MULTIPLY: bind_cpu_mult<HEScheme::CKKS>(node); break;
                case OperationType::RELINEARIZE: bind_cpu_relin<HEScheme::CKKS>(node); break;
                case OperationType::RESCALE: bind_cpu_rescale<HEScheme::CKKS>(node); break;
                case OperationType::DROP_LEVEL: bind_cpu_drop_level<HEScheme::CKKS>(node); break;
                case OperationType::ROTATE_COL: bind_cpu_rotate_col<HEScheme::CKKS>(node); break;
                case OperationType::CONJUGATE: bind_cpu_conjugate<HEScheme::CKKS>(node); break;
                case OperationType::MAC_W_PARTIAL_SUM: bind_cpu_cmpac_sum<HEScheme::CKKS>(node); break;
                case OperationType::MAC_WO_PARTIAL_SUM: bind_cpu_cmp_sum<HEScheme::CKKS>(node); break;
                case OperationType::BOOTSTRAP: bind_cpu_bootstrap<HEScheme::CKKS>(node); break;
                default: throw std::runtime_error("Unsupported operation type for CPU CKKS");
            }
            break;
        default: throw std::runtime_error("Unknown algorithm type for CPU");
    }
}

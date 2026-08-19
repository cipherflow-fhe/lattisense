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

#pragma once

#include <any>
#include <atomic>
#include <cstdint>
#include <complex>
#include <functional>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>
#include "nlohmann/json.hpp"
#include "c_argument.h"
#include "../abi/c_types.h"

using NodeId = std::string;
using ScalarType = std::variant<int64_t, uint64_t, double, std::complex<double>>;

/// Progress callback for tracking mega_ag execution.
/// @param completed Number of compute nodes completed so far.
/// @param total Total number of compute nodes.
using ProgressCallback = std::function<void(int completed, int total)>;

// Forward declarations
struct ComputeNode;
struct CompoundComputeNode;

enum class Processor { CPU, GPU };

// Unified execution context for both CPU and GPU
struct ExecutionContext {
    std::any context;                  // BfvContext* | CkksContext* | CkksBtpContext* (CPU)
                                       // HEArithmeticOperator* (GPU)
    std::vector<std::any> other_args;  // Additional backend-specific arguments
                                       // e.g., ExecutionOptions* (GPU), thread pool, polyvec_64* (FPGA), etc.

    template <typename T> T* get_arithmetic_context() {
        auto* p = std::any_cast<T*>(&context);
        return p ? *p : nullptr;
    }

    template <typename T> T* get_other_arg(size_t index = 0) {
        if (index >= other_args.size() || !other_args[index].has_value()) {
            return nullptr;
        }
        return std::any_cast<T*>(other_args[index]);
    }
};

// Unified executor function signature
using ExecutorFunc = std::function<
    void(ExecutionContext& ctx, std::unordered_map<NodeId, std::any>& local_data, const ComputeNode& self)>;

enum class OperationType {
    UNKNOWN,
    ADD,
    SUB,
    MULTIPLY,
    RELINEARIZE,
    RESCALE,
    DROP_LEVEL,
    ROTATE_COL,
    ROTATE_ROW,
    CONJUGATE,
    MAC_WO_PARTIAL_SUM,
    MAC_W_PARTIAL_SUM,
    BOOTSTRAP,

    // ABI bridge operations (inserted by the Python linker for heterogeneous mode)
    EXPORT_TO_ABI,       // Frontend Handle → ABI C struct (defined in cxx_sdk)
    IMPORT_FROM_ABI,     // ABI C struct → Frontend Handle (defined in cxx_sdk)
    LOAD_TO_BACKEND,     // ABI C struct → Backend device (GPU/FPGA, defined in mega_ag_runners)
    STORE_FROM_BACKEND,  // Backend device → ABI C struct (GPU/FPGA, defined in mega_ag_runners)
};

/**
 * @brief Unified data node for both FHE and custom types.
 */
struct DatumNode {
    std::string id;
    std::vector<CompoundComputeNode*> predecessors;  // Producer top-level compute nodes
    std::vector<CompoundComputeNode*> successors;    // Consumer top-level compute nodes
    bool is_input = false;
    bool is_output = false;
    DataType datum_type = TYPE_CUSTOM;  // Unified data type (TYPE_CUSTOM for custom nodes)

    // FHE-specific metadata. These fields mirror frontend.types.Metadata.
    struct FheProperty {
        bool is_ringt = false;
        bool is_batched = true;
        int32_t degree = 0;
        int32_t level = 0;
        int32_t log_slots = -1;
        double scale = 1.0;
        bool is_ntt = true;
        int32_t mform_bits = 0;

        struct ExtraProperty {
            int32_t sp_level = -1;
            uint32_t galois_element = 0;
            std::string key_role;
        };
        std::optional<ExtraProperty> p;
    };
    std::optional<FheProperty> fhe_prop;

    // Custom-specific properties (if has value, this is a custom node)
    struct CustomProperty {
        std::string type;           // Custom datum type (e.g., "msg", "custom_encoded_data")
        nlohmann::json attributes;  // Custom attributes from JSON
    };
    std::optional<CustomProperty> custom_prop;

    Metadata metadata() const {
        if (datum_type == DataType::TYPE_CUSTOM) {
            return Metadata{};
        }
        if (!fhe_prop.has_value()) {
            throw std::runtime_error("Data node missing FHE metadata");
        }
        const auto& prop = *fhe_prop;
        return Metadata{static_cast<uint8_t>(prop.is_ringt),
                        static_cast<uint8_t>(prop.is_batched),
                        prop.degree,
                        prop.level,
                        prop.log_slots,
                        prop.scale,
                        static_cast<uint8_t>(prop.is_ntt),
                        prop.mform_bits};
    }
};

/**
 * @brief Unified compute node for both FHE and custom operations.
 */
struct ComputeNode {
    std::string id;

    std::vector<DatumNode*> input_nodes;
    std::vector<DatumNode*> output_nodes;

    // Unified executor function (CPU and GPU)
    ExecutorFunc executor;

    // FHE-specific properties
    struct FheProperty {
        OperationType op_type = OperationType::UNKNOWN;

        struct ExtraProperty {
            std::vector<int32_t> rotation_steps;
            bool use_default_rotation_keys = true;
            int32_t sum_cnt = 0;
            int32_t drop_level = 1;
            ScalarType scalar;
            bool has_scalar = false;
        };
        std::optional<ExtraProperty> p;
    };
    std::optional<FheProperty> fhe_prop;

    // Custom-specific properties (opaque user-bound operation)
    struct CustomProperty {
        std::string type;           // Custom operation type
        nlohmann::json attributes;  // Custom attributes from JSON
    };
    std::optional<CustomProperty> custom_prop;
};

struct CompoundComputeNode {
    std::string id;

    std::vector<DatumNode*> input_nodes;
    std::vector<DatumNode*> output_nodes;
    std::vector<ComputeNode> ops;

    bool on_cpu = true;
    int priority = 0;

    void execute(ExecutionContext& exec_ctx, std::unordered_map<NodeId, std::any>& data_cache) const {
        for (const auto& op : ops) {
            op.executor(exec_ctx, data_cache, op);
        }
    }
};

inline bool compute_contains_operation(const CompoundComputeNode& node, OperationType op_type) {
    for (const auto& op : node.ops) {
        if (op.fhe_prop.has_value() && op.fhe_prop->op_type == op_type) {
            return true;
        }
    }
    return false;
}

struct MegaAG {
    std::unordered_map<NodeId, DatumNode> data;
    std::unordered_map<NodeId, CompoundComputeNode> computes;
    std::vector<NodeId> inputs;
    std::vector<NodeId> outputs;
    nlohmann::json parameter;
    Processor processor = Processor::CPU;
    Algo algo;

    /**
     * @brief Load compiled_mega_ag.json and fhe_parameter.json from a task project directory.
     */
    static MegaAG load(const std::string& project_path, Processor processor);

    void bind_abi_bridge_executors(const ExecutorFunc& abi_export,
                                   const ExecutorFunc& abi_import,
                                   const ExecutorFunc& backend_load = {},
                                   const ExecutorFunc& backend_store = {}) {
        for (auto& item : computes) {
            auto& compute = item.second;
            for (auto& op : compute.ops) {
                if (!op.fhe_prop.has_value()) {
                    continue;
                }
                switch (op.fhe_prop->op_type) {
                    case OperationType::EXPORT_TO_ABI: op.executor = abi_export; break;
                    case OperationType::IMPORT_FROM_ABI: op.executor = abi_import; break;
                    case OperationType::LOAD_TO_BACKEND: op.executor = backend_load; break;
                    case OperationType::STORE_FROM_BACKEND: op.executor = backend_store; break;
                    default: break;
                }
            }
        }
    }

    /**
     * @brief Bind custom executors for custom operation types.
     * @param custom_executors Map of custom operation type to executor function.
     */
    void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) {
        for (auto& item : computes) {
            auto& compute = item.second;
            for (auto& op : compute.ops) {
                if (!op.custom_prop.has_value()) {
                    continue;
                }
                auto it = custom_executors.find(op.custom_prop->type);
                if (it != custom_executors.end()) {
                    op.executor = it->second;
                }
            }
        }
    }

    template <typename T>
    std::unordered_set<NodeId> get_available_computes(const std::unordered_map<NodeId, T>& available_data) const {
        std::unordered_set<NodeId> available_computes;
        for (const auto& item : this->computes) {
            const auto& compute_id = item.first;
            const auto& compute_node = item.second;
            bool input_missing = false;

            for (auto* compute_input_node : compute_node.input_nodes) {
                if (available_data.find(compute_input_node->id) == available_data.end()) {
                    input_missing = true;
                    break;
                }
            }

            if (!input_missing) {
                available_computes.insert(compute_id);
            }
        }
        return available_computes;
    }

    template <typename T>
    std::unordered_set<NodeId> step_available_computes(const CompoundComputeNode& completed_compute,
                                                       const std::unordered_map<NodeId, T>& available_data) const {
        std::unordered_set<NodeId> newly_available_computes;

        for (const auto* output_node : completed_compute.output_nodes) {
            for (auto* compute_node : output_node->successors) {
                bool input_missing = false;
                for (const auto* required_node : compute_node->input_nodes) {
                    if (available_data.find(required_node->id) == available_data.end()) {
                        input_missing = true;
                        break;
                    }
                }

                if (!input_missing) {
                    newly_available_computes.insert(compute_node->id);
                }
            }
        }

        return newly_available_computes;
    }

    template <typename T>
    void purge_unused_data(const CompoundComputeNode& compute_node,
                           std::unordered_map<NodeId, std::atomic<int>>& data_ref_counts,
                           std::unordered_map<NodeId, T>& available_data) const {
        for (const auto* input_node : compute_node.input_nodes) {
            int remaining_use = data_ref_counts[input_node->id].fetch_sub(1) - 1;
            if (remaining_use <= 0) {
                available_data.erase(input_node->id);
            }
        }
    }
};

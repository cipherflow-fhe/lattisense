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

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <set>
#include <string>
#include <functional>
#include <any>
#include <atomic>
#include <optional>
#include "nlohmann/json.hpp"
#include "c_argument.h"
#include "../fhe_ops_lib/fhe_lib_v2.h"

using NodeIndex = uint64_t;

// Forward declarations
struct ComputeNode;

enum class Processor { CPU, FPGA, GPU };

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
using ExecutorFunc = std::function<void(ExecutionContext& ctx,
                                        const std::unordered_map<NodeIndex, std::any>& inputs,
                                        std::any& output,
                                        const ComputeNode& self)>;

enum class OperationType {
    UNKNOWN,
    ADD,
    SUB,
    NEGATE,
    MULTIPLY,
    RELINEARIZE,
    RESCALE,
    DROP_LEVEL,
    ROTATE_COL,
    ROTATE_ROW,
    MAC_WO_PARTIAL_SUM,
    MAC_W_PARTIAL_SUM,
    BOOTSTRAP,

    FPGA_KERNEL,  // Composite FPGA sub-project operator (heterogeneous mode)

    // ABI bridge operations (inserted automatically by from_json for heterogeneous mode)
    EXPORT_TO_ABI,       // Frontend Handle → ABI C struct (defined in cxx_sdk)
    IMPORT_FROM_ABI,     // ABI C struct → Frontend Handle (defined in cxx_sdk)
    LOAD_TO_BACKEND,     // ABI C struct → Backend device (GPU/FPGA, defined in mega_ag_runners)
    STORE_FROM_BACKEND,  // Backend device → ABI C struct (GPU/FPGA, defined in mega_ag_runners)
};

// Forward declaration
struct ComputeNode;

/**
 * @brief Unified data node for both FHE and custom types
 */
struct DatumNode {
    NodeIndex index;
    std::string id;
    std::vector<ComputeNode*> predecessors;  // Producer compute nodes (both FHE and custom)
    std::vector<ComputeNode*> successors;    // Consumer compute nodes (both FHE and custom)
    bool is_input = false;
    bool is_output = false;
    DataType datum_type = TYPE_CUSTOM;  // Unified data type (TYPE_CUSTOM for custom nodes)

    // FHE-specific properties (use custom_prop.has_value() to check if custom node)
    struct FheProperty {
        int32_t level = 0;
        int32_t degree = 0;
        bool is_ntt = false;
        bool is_mform = false;

        struct ExtraProperty {
            bool is_ringt = false;
            bool is_compressed = false;
            uint32_t galois_element = 0;
        };
        std::optional<ExtraProperty> p;

        int32_t sp_level = 0;
    };
    std::optional<FheProperty> fhe_prop;

    // Custom-specific properties (if has value, this is a custom node)
    struct CustomProperty {
        std::string type;           // Custom datum type (e.g., "msg", "custom_encoded_data")
        nlohmann::json attributes;  // Custom attributes from JSON
    };
    std::optional<CustomProperty> custom_prop;
};

/**
 * @brief Unified compute node for both FHE and custom operations
 */
struct ComputeNode {
    NodeIndex index;
    std::string id;

    std::vector<DatumNode*> input_nodes;
    std::vector<DatumNode*> output_nodes;

    // Unified executor function (CPU and GPU)
    ExecutorFunc executor;

    // Execution target: true if this node runs on CPU
    bool on_cpu = false;

    // Scheduling priority: higher value runs first
    int priority = 0;

    // Graph structural properties for scheduling, computed by MegaAG::compute_graph_properties()
    struct ScheduleMeta {
        int top_level = 0;     // longest path from any source compute node to this node
        int bottom_level = 0;  // longest path from this node to any sink compute node
    };
    ScheduleMeta sched_meta;

    // FHE-specific properties (use custom_prop.has_value() to check if custom node)
    struct FheProperty {
        OperationType op_type = OperationType::UNKNOWN;

        struct ExtraProperty {
            int32_t rotation_step = 0;
            int32_t sum_cnt = 0;
        };
        std::optional<ExtraProperty> p;
    };
    std::optional<FheProperty> fhe_prop;

    // Custom-specific properties (if has value, this is a custom node)
    struct CustomProperty {
        std::string type;           // Custom operation type (e.g., "encode", "decode")
        nlohmann::json attributes;  // Custom attributes from JSON (e.g., level, scale)
    };
    std::optional<CustomProperty> custom_prop;
};

/**
 * @brief Scheduling mode for compute node priority computation.
 *
 * MAKESPAN_FIRST: bottom_level (longest path to sink) — minimizes makespan.
 * MEMORY_FIRST:  -bottom_level (prefer nodes closer to sink) — reduces peak memory by completing in-flight paths first.
 */
enum class ScheduleMode {
    MAKESPAN_FIRST,
    MEMORY_FIRST,
};

struct MegaAG {
    std::unordered_map<NodeIndex, DatumNode> data;
    std::unordered_map<NodeIndex, ComputeNode> computes;
    std::vector<NodeIndex> inputs;
    std::vector<NodeIndex> outputs;
    std::vector<NodeIndex> offline_inputs;
    nlohmann::json parameter;
    Processor processor = Processor::CPU;
    Algo algo = ALGO_BFV;

    /**
     * @brief Load a MegaAG from JSON, apply processor layout, and compute scheduling priorities.
     *        This is the primary entry point for constructing a ready-to-run MegaAG.
     */
    static MegaAG
    load(const std::string& json_path, Processor processor, ScheduleMode mode = ScheduleMode::MEMORY_FIRST);

    void bind_abi_bridge_executors(const ExecutorFunc& abi_export,
                                   const ExecutorFunc& abi_import,
                                   const ExecutorFunc& backend_load = {},
                                   const ExecutorFunc& backend_store = {}) {
        for (auto& [index, compute] : computes) {
            if (compute.fhe_prop.has_value()) {
                switch (compute.fhe_prop->op_type) {
                    case OperationType::EXPORT_TO_ABI: compute.executor = abi_export; break;
                    case OperationType::IMPORT_FROM_ABI: compute.executor = abi_import; break;
                    case OperationType::LOAD_TO_BACKEND: compute.executor = backend_load; break;
                    case OperationType::STORE_FROM_BACKEND: compute.executor = backend_store; break;
                    default: break;
                }
            }
        }
    }

    /**
     * @brief Bind custom executors for custom operation types
     * @param custom_executors Map of custom operation type to executor function
     */
    void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) {
        for (auto& [index, compute] : computes) {
            if (compute.custom_prop.has_value()) {
                auto it = custom_executors.find(compute.custom_prop->type);
                if (it != custom_executors.end()) {
                    compute.executor = it->second;
                }
            }
        }
    }

    template <typename T>
    std::unordered_set<NodeIndex> get_available_computes(const std::unordered_map<NodeIndex, T>& available_data) const {
        std::unordered_set<NodeIndex> available_computes;
        for (const auto& [compute_index, compute_node] : this->computes) {
            bool input_missing = false;

            for (auto* compute_input_node : compute_node.input_nodes) {
                if (available_data.find(compute_input_node->index) == available_data.end()) {
                    input_missing = true;
                    break;
                }
            }

            if (!input_missing) {
                available_computes.insert(compute_index);
            }
        }
        return available_computes;
    }

    template <typename T>
    std::unordered_set<NodeIndex>
    step_available_computes(const DatumNode& newly_available_datum,
                            const std::unordered_map<NodeIndex, T>& available_data) const {
        std::unordered_set<NodeIndex> newly_available_computes;

        for (auto* compute_node : newly_available_datum.successors) {
            bool input_missing = false;
            for (const auto* required_node : compute_node->input_nodes) {
                if (available_data.find(required_node->index) == available_data.end()) {
                    input_missing = true;
                    break;
                }
            }

            if (!input_missing) {
                newly_available_computes.insert(compute_node->index);
            }
        }

        return newly_available_computes;
    }

    template <typename T>
    void purge_unused_data(const ComputeNode& compute_node,
                           std::unordered_map<NodeIndex, std::atomic<int>>& data_ref_counts,
                           std::unordered_map<NodeIndex, T>& available_data) const {
        for (const auto* input_node : compute_node.input_nodes) {
            int remaining_use = data_ref_counts[input_node->index].fetch_sub(1) - 1;
            if (remaining_use <= 0 && !input_node->is_output && !input_node->is_input) {
                available_data.erase(input_node->index);
            }
        }
    }

    /**
     * @brief Compute top_level/bottom_level for each compute node, then set priority by ScheduleMode.
     *
     * MAKESPAN_FIRST: priority = bottom_level (longer remaining critical path runs first).
     * MEMORY_FIRST:  priority = -bottom_level (prefer nodes closer to sink, completing in-flight paths to free memory).
     */
    void compute_properties(ScheduleMode mode);

private:
    static MegaAG from_json(const std::string& json_path, Processor processor);

    // Inserts ABI bridge nodes for the target processor and sets on_cpu for all compute nodes.
    void apply_processor_layout();

    std::pair<NodeIndex, NodeIndex> get_next_indices() const;
    void rebuild_bridge_relationships(std::initializer_list<OperationType> bridge_ops);
    void insert_backend_abi_bridge_nodes();
    void insert_cpu_abi_bridge_nodes();

    void compute_top_levels();
    void compute_bottom_levels();
};

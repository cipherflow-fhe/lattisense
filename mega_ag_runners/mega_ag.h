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
#include <vector>
#include <set>
#include <string>
#include <functional>
#include <any>
#include <atomic>
#include <variant>
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
        return std::any_cast<T*>(context);
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

    // FHE-specific properties (use custom_prop.has_value() to check if custom node)
    struct FheProperty {
        DataType datum_type;
        int32_t level;
        int32_t degree;
        bool is_ntt;
        bool is_mform;

        struct ExtraProperty {
            bool is_ringt;
            bool is_compressed;
            uint32_t galois_element;
        };
        std::optional<ExtraProperty> p;

        int32_t sp_level;
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
    bool on_cpu;

    // Data flow reverse: true if executor produces data for input_nodes instead of output_nodes
    // (e.g., IMPORT_FROM_ABI bound to abi_export: handle → c_struct, where c_struct is input_nodes[0])
    bool flow_reverse = false;

    // FHE-specific properties (use custom_prop.has_value() to check if custom node)
    struct FheProperty {
        OperationType op_type;

        struct ExtraProperty {
            int32_t rotation_step;
            int32_t sum_cnt;
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

struct MegaAG {
    std::unordered_map<NodeIndex, DatumNode> data;
    std::unordered_map<NodeIndex, ComputeNode> computes;
    std::vector<NodeIndex> inputs;
    std::vector<NodeIndex> outputs;
    std::vector<NodeIndex> offline_inputs;
    nlohmann::json parameter;
    Processor processor = Processor::CPU;

    static MegaAG from_json(const std::string& json_path, Processor processor);

    template <typename T>
    std::set<NodeIndex> get_available_computes(const std::unordered_map<NodeIndex, T>& available_data) const {
        std::set<NodeIndex> available_computes;
        for (const auto& [compute_index, compute_node] : this->computes) {
            bool input_missing = false;

            if (!compute_node.flow_reverse) {
                // Normal flow: check if all input_nodes are available
                for (auto* compute_input_node : compute_node.input_nodes) {
                    if (available_data.find(compute_input_node->index) == available_data.end()) {
                        input_missing = true;
                        break;
                    }
                }
            } else {
                // Reverse flow: check if all output_nodes are available
                for (auto* compute_output_node : compute_node.output_nodes) {
                    if (available_data.find(compute_output_node->index) == available_data.end()) {
                        input_missing = true;
                        break;
                    }
                }
            }

            if (!input_missing) {
                available_computes.insert(compute_index);
            }
        }
        return available_computes;
    }

    template <typename T>
    std::set<NodeIndex> step_available_computes(const DatumNode& newly_available_datum,
                                                const std::unordered_map<NodeIndex, T>& available_data) const {
        std::set<uint64_t> newly_available_computes;

        // Check successors with flow_reverse=false (normal forward consumption)
        for (auto* compute_node : newly_available_datum.successors) {
            // Skip if this is a reverse operation (it doesn't consume from successors)
            if (compute_node->flow_reverse) {
                continue;
            }

            bool input_missing = false;
            // Check if all input nodes are available
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

        // Check predecessors with flow_reverse=true (reverse operations that need this output)
        for (auto* compute_node : newly_available_datum.predecessors) {
            // Skip if this is not a reverse operation
            if (!compute_node->flow_reverse) {
                continue;
            }

            bool input_missing = false;
            // For reverse operations, check if all output nodes are available
            for (const auto* required_node : compute_node->output_nodes) {
                if (!required_node) {
                    input_missing = true;
                    break;
                }
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
        // Determine which nodes were consumed based on flow_reverse
        const std::vector<DatumNode*>& input_nodes =
            !compute_node.flow_reverse ? compute_node.input_nodes : compute_node.output_nodes;

        for (const auto* input_node : input_nodes) {
            int remaining_use = data_ref_counts[input_node->index].fetch_sub(1) - 1;
            if (remaining_use <= 0 && !input_node->is_output && !input_node->is_input) {
                available_data.erase(input_node->index);
            }
        }
    }
};

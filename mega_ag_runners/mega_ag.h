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
                                       // e.g., ExecutionOptions* (GPU), thread pool, etc.
    Processor processor;

    template <typename T> T& get_context() {
        return *std::any_cast<T*>(context);
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

struct DatumNode {
    NodeIndex index = 0;
    std::string id;
    std::vector<ComputeNode*> successors;
    bool is_output = false;

    DataType datum_type = DataType::TYPE_CIPHERTEXT;
    int32_t level = 0;
    int32_t degree = 0;
    bool is_ntt = false;
    bool is_mform = false;
    int32_t sp_level = 0;

    struct ExtraProperty {
        bool is_ringt = false;
        bool is_compressed = false;
        uint32_t galois_element = 0;
    };
    std::optional<ExtraProperty> p;
};

struct ComputeNode {
    NodeIndex index;
    std::string id;

    std::vector<DatumNode*> input_nodes;
    std::vector<DatumNode*> output_nodes;

    // Unified executor function (CPU and GPU)
    ExecutorFunc executor;

    OperationType op_type;

    struct ExtraProperty {
        int32_t rotation_step = 0;
        int32_t sum_cnt = 0;
    };
    std::optional<ExtraProperty> p;
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
            const std::vector<DatumNode*>& compute_input_nodes = compute_node.input_nodes;
            bool input_missing = false;
            for (auto* compute_input_node : compute_input_nodes) {
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
    std::set<NodeIndex> step_available_computes(const DatumNode& newly_available_datum,
                                                const std::unordered_map<NodeIndex, T>& available_data) const {
        std::set<uint64_t> newly_available_computes;

        for (auto* compute_node : newly_available_datum.successors) {
            bool input_missing = false;
            for (const auto* compute_input_node : compute_node->input_nodes) {
                if (available_data.find(compute_input_node->index) == available_data.end()) {
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
            if (remaining_use <= 0 && !input_node->is_output) {
                available_data.erase(input_node->index);
            }
        }
    }
};

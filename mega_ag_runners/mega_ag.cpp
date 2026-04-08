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

#include <fstream>
#include <queue>
#include <string>
#include "nlohmann/json.hpp"

#include "mega_ag.h"
#include "mega_ag_executors.h"

const std::unordered_map<std::string, DataType> str_to_datum_type = {
    {"ct", DataType::TYPE_CIPHERTEXT},    {"ct3", DataType::TYPE_CIPHERTEXT},     {"pt", DataType::TYPE_PLAINTEXT},
    {"pt_mul", DataType::TYPE_PLAINTEXT}, {"pt_ringt", DataType::TYPE_PLAINTEXT}, {"rlk", DataType::TYPE_RELIN_KEY},
    {"glk", DataType::TYPE_GALOIS_KEY},   {"swk", DataType::TYPE_SWITCH_KEY},
};

const std::unordered_map<std::string, OperationType> str_to_operation_type = {
    {"add", OperationType::ADD},
    {"sub", OperationType::SUB},
    {"neg", OperationType::NEGATE},
    {"mult", OperationType::MULTIPLY},
    {"relin", OperationType::RELINEARIZE},
    {"rescale", OperationType::RESCALE},
    {"drop_level", OperationType::DROP_LEVEL},
    {"rotate_row", OperationType::ROTATE_ROW},
    {"rotate_col", OperationType::ROTATE_COL},
    {"cmp_sum", OperationType::MAC_WO_PARTIAL_SUM},
    {"cmpac_sum", OperationType::MAC_W_PARTIAL_SUM},
    {"bootstrap", OperationType::BOOTSTRAP},
    {"fpga_kernel", OperationType::FPGA_KERNEL},
};

// =============================================================================
// Static utility functions
// =============================================================================

// Creates a fresh data node cloned from `src`, assigned `new_idx` and `new_id`,
// with successors/predecessors cleared and optional flag overrides.
static DatumNode make_data_node(const DatumNode& src,
                                NodeIndex new_idx,
                                const std::string& new_id,
                                bool is_input = false,
                                bool is_output = false) {
    DatumNode node = src;
    node.index = new_idx;
    node.id = new_id;
    node.is_input = is_input;
    node.is_output = is_output;
    node.successors.clear();
    node.predecessors.clear();
    return node;
}

// Creates and inserts a bridge FHE compute node (EXPORT_TO_ABI / LOAD_TO_BACKEND /
// STORE_FROM_BACKEND / IMPORT_FROM_ABI) into mega_ag.computes.
// Returns a reference to the newly inserted node.
static ComputeNode& make_bridge_compute_node(MegaAG& mega_ag,
                                             NodeIndex compute_idx,
                                             const std::string& id,
                                             OperationType op,
                                             DatumNode* input,
                                             DatumNode* output) {
    ComputeNode node;
    node.index = compute_idx;
    node.id = id;
    ComputeNode::FheProperty prop;
    prop.op_type = op;
    node.fhe_prop = prop;
    if (input)
        node.input_nodes.push_back(input);
    if (output)
        node.output_nodes.push_back(output);
    mega_ag.computes.emplace(compute_idx, std::move(node));
    return mega_ag.computes.at(compute_idx);
}

// Redirects all successors of `old_data` to point to `new_data` instead,
// and moves them into new_data's successor list. Clears old_data's successors.
static void redirect_consumers(DatumNode& old_data, DatumNode& new_data) {
    for (ComputeNode* successor : old_data.successors) {
        for (auto& in_ptr : successor->input_nodes) {
            if (in_ptr == &old_data)
                in_ptr = &new_data;
        }
        new_data.successors.push_back(successor);
    }
    old_data.successors.clear();
}

// Redirects all FHE predecessors of `old_data` to point to `new_data` instead,
// and moves them into new_data's predecessor list. Clears old_data's predecessors.
static void redirect_producers(DatumNode& old_data, DatumNode& new_data) {
    for (ComputeNode* predecessor : old_data.predecessors) {
        if (!predecessor->fhe_prop.has_value())
            continue;
        for (auto& out_ptr : predecessor->output_nodes) {
            if (out_ptr == &old_data)
                out_ptr = &new_data;
        }
        new_data.predecessors.push_back(predecessor);
    }
    old_data.predecessors.clear();
}

// =============================================================================
// MegaAG member functions — main
// =============================================================================

MegaAG MegaAG::load(const std::string& json_path, Processor processor, ScheduleMode mode) {
    MegaAG mega_ag = from_json(json_path, processor);
    mega_ag.apply_processor_layout();
    mega_ag.compute_properties(mode);
    return mega_ag;
}

MegaAG MegaAG::from_json(const std::string& json_path, Processor processor) {
    std::ifstream json_fs;
    json_fs.open(json_path);
    if (!json_fs.is_open()) {
        throw std::runtime_error("Cannot open MegaAG file " + json_path);
    }
    nlohmann::json mega_ag_json = nlohmann::json::parse(json_fs);
    json_fs.close();

    MegaAG mega_ag;
    mega_ag.processor = processor;
    nlohmann::json& data_json = mega_ag_json["data"];
    nlohmann::json& computes_json = mega_ag_json["compute"];

    // Parse algorithm from JSON
    std::string algo_str = mega_ag_json["algorithm"].get<std::string>();
    if (algo_str == "BFV") {
        mega_ag.algo = ALGO_BFV;
    } else if (algo_str == "CKKS") {
        mega_ag.algo = ALGO_CKKS;
    } else {
        throw std::runtime_error("Unknown algorithm: " + algo_str);
    }

    for (auto& [key, value] : data_json.items()) {
        const std::string& json_type = value["type"].get<std::string>();
        NodeIndex index = std::stoull(key);

        DatumNode node;
        node.index = index;
        node.id = value["id"].get<std::string>();

        if (value.contains("is_custom") && value["is_custom"].get<bool>()) {
            // Custom data node
            DatumNode::CustomProperty custom_prop;
            custom_prop.type = json_type;
            if (value.contains("attributes")) {
                custom_prop.attributes = value["attributes"];
            }
            node.custom_prop = custom_prop;
        } else {
            // FHE data node
            auto datum_type = str_to_datum_type.at(json_type);
            if (processor == Processor::CPU) {
                if (datum_type == DataType::TYPE_RELIN_KEY || datum_type == DataType::TYPE_GALOIS_KEY ||
                    datum_type == DataType::TYPE_SWITCH_KEY) {
                    continue;
                }
            }

            DatumNode::FheProperty fhe_prop;
            fhe_prop.level = value["level"].get<int32_t>();
            fhe_prop.is_ntt = value["is_ntt"].get<bool>();
            fhe_prop.is_mform = value["is_mform"].get<bool>();
            fhe_prop.degree = value["degree"].get<int32_t>();

            // Set sp_level if present in JSON
            if (value.contains("sp_level")) {
                fhe_prop.sp_level = value["sp_level"].get<int32_t>();
            } else {
                fhe_prop.sp_level = -1;  // Default value
            }

            if (datum_type == DataType::TYPE_GALOIS_KEY) {
                DatumNode::FheProperty::ExtraProperty extra_prop;
                extra_prop.galois_element = value["galois_element"].get<uint32_t>();
                fhe_prop.p = extra_prop;
            } else if (json_type == "pt_ringt") {
                DatumNode::FheProperty::ExtraProperty extra_prop;
                extra_prop.is_ringt = true;
                fhe_prop.p = extra_prop;
            }

            node.datum_type = datum_type;
            node.fhe_prop = fhe_prop;
        }

        mega_ag.data.emplace(index, std::move(node));
    }

    for (auto& [key, value] : computes_json.items()) {
        NodeIndex index = std::stoull(key);
        const std::string& json_type = value["type"].get<std::string>();

        ComputeNode node;
        node.index = index;
        node.id = value["id"].get<std::string>();

        auto input_indices = value["inputs"].get<std::vector<NodeIndex>>();
        auto output_indices = value["outputs"].get<std::vector<NodeIndex>>();

        if (value.contains("is_custom") && value["is_custom"].get<bool>()) {
            // Custom compute node
            ComputeNode::CustomProperty custom_prop;
            custom_prop.type = json_type;
            if (value.contains("attributes")) {
                custom_prop.attributes = value["attributes"];
            }
            node.custom_prop = custom_prop;
        } else {
            // FHE compute node
            ComputeNode::FheProperty fhe_prop;
            fhe_prop.op_type = str_to_operation_type.at(json_type);

            if (fhe_prop.op_type == OperationType::ROTATE_COL) {
                ComputeNode::FheProperty::ExtraProperty extra_prop;
                extra_prop.rotation_step = value["step"].get<int32_t>();
                fhe_prop.p = extra_prop;
            } else if (fhe_prop.op_type == OperationType::MAC_WO_PARTIAL_SUM ||
                       fhe_prop.op_type == OperationType::MAC_W_PARTIAL_SUM) {
                ComputeNode::FheProperty::ExtraProperty extra_prop;
                extra_prop.sum_cnt = value["sum_cnt"].get<int32_t>();
                fhe_prop.p = extra_prop;
            }

            node.fhe_prop = fhe_prop;
        }

        // Add input/output nodes (common for both custom and FHE)
        for (NodeIndex i : input_indices) {
            if (processor == Processor::CPU && mega_ag.data.find(i) == mega_ag.data.end()) {
                continue;
            }
            node.input_nodes.push_back(&mega_ag.data.at(i));
        }

        for (NodeIndex i : output_indices) {
            node.output_nodes.push_back(&mega_ag.data.at(i));
        }

        // Bind executor for FHE nodes
        if (!node.custom_prop.has_value() && processor != Processor::FPGA) {
            ExecutorBinder::bind_executor(node, processor, mega_ag.algo);
        }

        mega_ag.computes.emplace(index, std::move(node));
    }

    // Build successor and predecessor relationships after all ComputeNodes are in the map
    for (auto& [compute_index, compute_node] : mega_ag.computes) {
        for (auto* input_node : compute_node.input_nodes) {
            // Add to successor list (unified for both FHE and custom)
            input_node->successors.push_back(&compute_node);
        }
        for (auto* output_node : compute_node.output_nodes) {
            // Add to predecessor list (unified for both FHE and custom)
            output_node->predecessors.push_back(&compute_node);
        }
    }

    std::vector<NodeIndex> input_indices = mega_ag_json["inputs"].get<std::vector<NodeIndex>>();
    if (processor == Processor::CPU) {
        for (auto& index : input_indices) {
            if (mega_ag.data.find(index) != mega_ag.data.end()) {
                mega_ag.inputs.push_back(index);
                mega_ag.data.at(index).is_input = true;
            }
        }
    } else {
        mega_ag.inputs = input_indices;
        for (auto i : mega_ag.inputs) {
            mega_ag.data.at(i).is_input = true;
        }
    }

    mega_ag.outputs = mega_ag_json["outputs"].get<std::vector<NodeIndex>>();
    for (auto i : mega_ag.outputs) {
        mega_ag.data.at(i).is_output = true;
    }

    mega_ag.parameter = mega_ag_json["parameter"];

    return mega_ag;
}

void MegaAG::apply_processor_layout() {
    if (processor == Processor::GPU || processor == Processor::FPGA) {
        insert_backend_abi_bridge_nodes();
    } else if (processor == Processor::CPU) {
        insert_cpu_abi_bridge_nodes();
    }

    for (auto& [compute_index, compute_node] : computes) {
        if (processor == Processor::CPU) {
            compute_node.on_cpu = true;
        } else if (processor == Processor::FPGA) {
            if (compute_node.custom_prop.has_value()) {
                compute_node.on_cpu = true;
            } else if (compute_node.fhe_prop.has_value()) {
                compute_node.on_cpu = (compute_node.fhe_prop->op_type != OperationType::FPGA_KERNEL);
            }
        } else if (processor == Processor::GPU) {
            if (compute_node.custom_prop.has_value()) {
                compute_node.on_cpu = true;
            } else if (compute_node.fhe_prop.has_value()) {
                OperationType op = compute_node.fhe_prop->op_type;
                compute_node.on_cpu = (op == OperationType::EXPORT_TO_ABI || op == OperationType::IMPORT_FROM_ABI);
            } else {
                compute_node.on_cpu = false;
            }
        }
    }
}

void MegaAG::compute_properties(ScheduleMode mode) {
    compute_top_levels();
    compute_bottom_levels();

    for (auto& [idx, node] : computes) {
        switch (mode) {
            case ScheduleMode::MAKESPAN_FIRST: node.priority = node.sched_meta.bottom_level; break;
            case ScheduleMode::MEMORY_FIRST: {
                // Secondary: among same bottom_level, prefer consuming the highest-level
                // (most expensive) CT input first — frees costly memory sooner.
                int max_in_level = 0;
                for (const DatumNode* d : node.input_nodes) {
                    if (d->fhe_prop.has_value() && d->datum_type != DataType::TYPE_RELIN_KEY &&
                        d->datum_type != DataType::TYPE_GALOIS_KEY && d->datum_type != DataType::TYPE_SWITCH_KEY) {
                        max_in_level = std::max(max_in_level, d->fhe_prop->level);
                    }
                }
                constexpr int level_bound = 32;  // > max CT level, keeps bottom_level dominant
                node.priority = node.sched_meta.bottom_level * level_bound + max_in_level;
                break;
            }
        }
    }
}

// =============================================================================
// MegaAG member functions — helpers
// =============================================================================

std::pair<NodeIndex, NodeIndex> MegaAG::get_next_indices() const {
    NodeIndex next_data = 0;
    NodeIndex next_compute = 0;
    for (const auto& [idx, _] : data) {
        if (idx >= next_data)
            next_data = idx + 1;
    }
    for (const auto& [idx, _] : computes) {
        if (idx >= next_compute)
            next_compute = idx + 1;
    }
    return {next_data, next_compute};
}

// Rebuilds successor/predecessor relationships for newly inserted bridge compute nodes
void MegaAG::rebuild_bridge_relationships(std::initializer_list<OperationType> bridge_ops) {
    for (auto& [compute_index, compute_node] : computes) {
        if (!compute_node.fhe_prop.has_value())
            continue;
        OperationType op = compute_node.fhe_prop->op_type;
        for (OperationType bridge_op : bridge_ops) {
            if (op == bridge_op) {
                for (auto* input_node : compute_node.input_nodes)
                    input_node->successors.push_back(&compute_node);
                for (auto* output_node : compute_node.output_nodes)
                    output_node->predecessors.push_back(&compute_node);
                break;
            }
        }
    }
}

void MegaAG::insert_backend_abi_bridge_nodes() {
    const std::string backend = (processor == Processor::GPU) ? "gpu" : "fpga";

    auto [next_data_index, next_compute_index] = get_next_indices();

    // Collect all data indices to process (to avoid iterator invalidation)
    std::vector<NodeIndex> data_indices_to_process;
    for (const auto& [data_idx, _] : data) {
        data_indices_to_process.push_back(data_idx);
    }

    // For each data node, determine its native type and insert conversion if needed
    for (NodeIndex data_idx : data_indices_to_process) {
        DatumNode& data_node = data.at(data_idx);

        // Determine native type of this data node (based on producer)
        bool is_native = true;  // Default for inputs
        if (!data_node.is_input) {
            ComputeNode* producer = data_node.predecessors[0];
            is_native = producer->custom_prop.has_value();  // Custom produces Handle, backend produces device data
        }

        // Group consumers by their type
        std::vector<ComputeNode*> backend_consumers;
        std::vector<ComputeNode*> custom_consumers;

        for (auto* successor : data_node.successors) {
            if (successor->custom_prop.has_value()) {
                custom_consumers.push_back(successor);
            } else {
                backend_consumers.push_back(successor);
            }
        }

        // Case 0: Custom DATA input node → EXPORT_TO_ABI only (runs on CPU, not sent to backend)
        // custom_input → EXPORT_TO_ABI → c_struct (shared_ptr<CustomData>) → custom consumers
        if (data_node.is_input && data_node.custom_prop.has_value()) {
            NodeIndex c_struct_idx = next_data_index++;
            data.emplace(c_struct_idx, make_data_node(data_node, c_struct_idx, data_node.id + "_concrete"));

            make_bridge_compute_node(*this, next_compute_index++, "export_to_abi_" + std::to_string(data_idx),
                                     OperationType::EXPORT_TO_ABI, &data_node, &data.at(c_struct_idx));

            redirect_consumers(data_node, data.at(c_struct_idx));
            continue;
        }

        // Case 1: Native is Handle, but has backend consumers → need H2D conversion
        // handle → EXPORT_TO_ABI → c_struct → LOAD_TO_BACKEND → backend_data → backend consumers
        if (is_native && !backend_consumers.empty()) {
            NodeIndex c_struct_idx = next_data_index++;
            data.emplace(c_struct_idx, make_data_node(data_node, c_struct_idx, data_node.id + "_c_struct_h2d"));

            make_bridge_compute_node(*this, next_compute_index++, "export_to_abi_" + std::to_string(data_idx),
                                     OperationType::EXPORT_TO_ABI, &data_node, &data.at(c_struct_idx));

            NodeIndex backend_data_idx = next_data_index++;
            data.emplace(backend_data_idx,
                         make_data_node(data.at(c_struct_idx), backend_data_idx, data_node.id + "_" + backend));

            make_bridge_compute_node(*this, next_compute_index++, "load_to_" + backend + "_" + std::to_string(data_idx),
                                     OperationType::LOAD_TO_BACKEND, &data.at(c_struct_idx),
                                     &data.at(backend_data_idx));

            // Redirect backend consumers to consume backend_data instead of data_node
            DatumNode& backend_data = data.at(backend_data_idx);
            for (auto* consumer : backend_consumers) {
                for (auto& input_ptr : consumer->input_nodes) {
                    if (input_ptr == &data_node)
                        input_ptr = &backend_data;
                }
                backend_data.successors.push_back(consumer);
            }
            data_node.successors.clear();
        }

        // Case 2: Native is backend data, but has Custom consumers (or is output) → need D2H conversion
        // backend_data → STORE_FROM_BACKEND → c_struct → IMPORT_FROM_ABI → handle (output/custom)
        if (!is_native && (!custom_consumers.empty() || data_node.is_output)) {
            NodeIndex backend_data_idx = next_data_index++;
            data.emplace(backend_data_idx,
                         make_data_node(data_node, backend_data_idx, data_node.id + "_" + backend, false, false));

            NodeIndex c_struct_idx = next_data_index++;
            data.emplace(c_struct_idx,
                         make_data_node(data_node, c_struct_idx, data_node.id + "_c_struct_d2h", false, false));

            make_bridge_compute_node(
                *this, next_compute_index++, "store_from_" + backend + "_" + std::to_string(data_idx),
                OperationType::STORE_FROM_BACKEND, &data.at(backend_data_idx), &data.at(c_struct_idx));

            ComputeNode& import_node =
                make_bridge_compute_node(*this, next_compute_index++, "import_from_abi_" + std::to_string(data_idx),
                                         OperationType::IMPORT_FROM_ABI, &data.at(c_struct_idx), nullptr);

            if (data_node.is_output) {
                // For output: IMPORT points to the predefined output node (data_node itself)
                import_node.output_nodes.push_back(&data_node);
            } else {
                // For intermediate data: Create new handle node for custom consumers
                NodeIndex handle_data_idx = next_data_index++;
                data.emplace(handle_data_idx, make_data_node(data.at(c_struct_idx), handle_data_idx,
                                                             data_node.id + "_handle", false, false));
                import_node.output_nodes.push_back(&data.at(handle_data_idx));

                // Redirect Custom consumers to consume handle_data
                DatumNode& handle_data = data.at(handle_data_idx);
                for (auto* consumer : custom_consumers) {
                    for (auto& input_ptr : consumer->input_nodes) {
                        if (input_ptr == &data_node)
                            input_ptr = &handle_data;
                    }
                    handle_data.successors.push_back(consumer);
                }
            }

            // Redirect backend producers and backend consumers from data_node to backend_data
            redirect_producers(data_node, data.at(backend_data_idx));

            DatumNode& backend_data = data.at(backend_data_idx);
            for (auto* consumer : backend_consumers) {
                for (auto& input_ptr : consumer->input_nodes) {
                    if (input_ptr == &data_node)
                        input_ptr = &backend_data;
                }
                backend_data.successors.push_back(consumer);
            }
            data_node.successors.clear();
        }

        // Case 3: Native is Handle (produced by custom node) and is_output → copy to pre-allocated output handle
        // custom → new_data → IMPORT_FROM_ABI → output_node
        if (is_native && data_node.is_output && !data_node.is_input) {
            NodeIndex new_data_idx = next_data_index++;
            data.emplace(new_data_idx,
                         make_data_node(data_node, new_data_idx, data_node.id + "_concrete", false, false));

            make_bridge_compute_node(*this, next_compute_index++, "import_from_abi_" + std::to_string(data_idx),
                                     OperationType::IMPORT_FROM_ABI, &data.at(new_data_idx), &data_node);

            // Redirect all predecessors (including custom nodes) from data_node to new_data
            DatumNode& new_data = data.at(new_data_idx);
            for (ComputeNode* predecessor : data_node.predecessors) {
                for (auto& out_ptr : predecessor->output_nodes) {
                    if (out_ptr == &data_node)
                        out_ptr = &new_data;
                }
                new_data.predecessors.push_back(predecessor);
            }
            data_node.predecessors.clear();
        }
    }

    // Rebuild predecessor and successor relationships for ABI bridge nodes
    rebuild_bridge_relationships({OperationType::EXPORT_TO_ABI, OperationType::IMPORT_FROM_ABI,
                                  OperationType::LOAD_TO_BACKEND, OperationType::STORE_FROM_BACKEND});
}

void MegaAG::insert_cpu_abi_bridge_nodes() {
    auto [next_data_index, next_compute_index] = get_next_indices();

    // Insert EXPORT_TO_ABI after each input node:
    // input_node → EXPORT_TO_ABI → new_data_node → original compute consumers
    for (NodeIndex input_idx : inputs) {
        DatumNode& input_node = data.at(input_idx);

        NodeIndex new_data_idx = next_data_index++;
        data.emplace(new_data_idx, make_data_node(input_node, new_data_idx, input_node.id + "_concrete"));

        make_bridge_compute_node(*this, next_compute_index++, "export_to_abi_" + std::to_string(input_idx),
                                 OperationType::EXPORT_TO_ABI, &input_node, &data.at(new_data_idx));

        // Redirect input_node's compute consumers to new_data_node
        redirect_consumers(input_node, data.at(new_data_idx));
    }

    // Insert IMPORT_FROM_ABI before each output node:
    // original compute producers → new_data_node → IMPORT_FROM_ABI → output_node
    for (NodeIndex output_idx : outputs) {
        DatumNode& output_node = data.at(output_idx);

        NodeIndex new_data_idx = next_data_index++;
        data.emplace(new_data_idx,
                     make_data_node(output_node, new_data_idx, output_node.id + "_concrete", false, false));

        make_bridge_compute_node(*this, next_compute_index++, "import_from_abi_" + std::to_string(output_idx),
                                 OperationType::IMPORT_FROM_ABI, &data.at(new_data_idx), &output_node);

        // Redirect output_node's compute producers to new_data_node
        redirect_producers(output_node, data.at(new_data_idx));
        // Redirect output_node's consumers (e.g. next ROTATE_COL) to new_data_node,
        // so they read from the concrete intermediate rather than the ABI-import destination.
        redirect_consumers(output_node, data.at(new_data_idx));
    }

    // Rebuild successor/predecessor relationships for inserted bridge nodes
    rebuild_bridge_relationships({OperationType::EXPORT_TO_ABI, OperationType::IMPORT_FROM_ABI});
}

// Propagates top_level forward using topological order (Kahn's algorithm): O(V+E)
void MegaAG::compute_top_levels() {
    std::unordered_map<NodeIndex, int> in_degree;
    for (auto& [idx, node] : computes) {
        node.sched_meta.top_level = 0;
        in_degree[idx] = 0;
    }

    for (auto& [idx, node] : computes) {
        for (auto* input_datum : node.input_nodes) {
            in_degree[idx] += static_cast<int>(input_datum->predecessors.size());
        }
    }

    std::queue<NodeIndex> q;
    for (auto& [idx, deg] : in_degree) {
        if (deg == 0)
            q.push(idx);
    }

    while (!q.empty()) {
        NodeIndex u_idx = q.front();
        q.pop();
        ComputeNode& u = computes.at(u_idx);
        for (auto* output_datum : u.output_nodes) {
            for (auto* downstream : output_datum->successors) {
                int candidate = u.sched_meta.top_level + 1;
                if (downstream->sched_meta.top_level < candidate)
                    downstream->sched_meta.top_level = candidate;
                if (--in_degree[downstream->index] == 0)
                    q.push(downstream->index);
            }
        }
    }
}

// Propagates bottom_level backward using reverse topological order (Kahn's algorithm): O(V+E)
void MegaAG::compute_bottom_levels() {
    std::unordered_map<NodeIndex, int> out_degree;
    for (auto& [idx, node] : computes) {
        node.sched_meta.bottom_level = 0;
        out_degree[idx] = 0;
    }

    for (auto& [idx, node] : computes) {
        for (auto* output_datum : node.output_nodes) {
            out_degree[idx] += static_cast<int>(output_datum->successors.size());
        }
    }

    std::queue<NodeIndex> q;
    for (auto& [idx, deg] : out_degree) {
        if (deg == 0)
            q.push(idx);
    }

    while (!q.empty()) {
        NodeIndex v_idx = q.front();
        q.pop();
        ComputeNode& v = computes.at(v_idx);
        for (auto* input_datum : v.input_nodes) {
            for (auto* upstream : input_datum->predecessors) {
                int candidate = v.sched_meta.bottom_level + 1;
                if (upstream->sched_meta.bottom_level < candidate)
                    upstream->sched_meta.bottom_level = candidate;
                if (--out_degree[upstream->index] == 0)
                    q.push(upstream->index);
            }
        }
    }
}

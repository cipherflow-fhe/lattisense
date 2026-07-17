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
#include <stdexcept>
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
    {"mult_by_i", OperationType::MULT_BY_I},
    {"div_by_i", OperationType::DIV_BY_I},
    {"rotate_row", OperationType::ROTATE_ROW},
    {"rotate_col", OperationType::ROTATE_COL},
    {"cmp_sum", OperationType::MAC_WO_PARTIAL_SUM},
    {"cmpac_sum", OperationType::MAC_W_PARTIAL_SUM},
    {"bootstrap", OperationType::BOOTSTRAP},
    {"encode_ringt", OperationType::ENCODE_RINGT},
    {"fpga_kernel", OperationType::FPGA_KERNEL},
    {"export_to_abi", OperationType::EXPORT_TO_ABI},
    {"import_from_abi", OperationType::IMPORT_FROM_ABI},
    {"load_to_backend", OperationType::LOAD_TO_BACKEND},
    {"store_from_backend", OperationType::STORE_FROM_BACKEND},
};

static bool is_abi_bridge_operation(OperationType op_type) {
    return op_type == OperationType::EXPORT_TO_ABI || op_type == OperationType::IMPORT_FROM_ABI ||
           op_type == OperationType::LOAD_TO_BACKEND || op_type == OperationType::STORE_FROM_BACKEND;
}

static ComputeNode::FheProperty parse_fhe_property(const nlohmann::json& value, OperationType op_type) {
    ComputeNode::FheProperty fhe_prop;
    fhe_prop.op_type = op_type;

    if (op_type == OperationType::ROTATE_COL) {
        ComputeNode::FheProperty::ExtraProperty extra_prop;
        extra_prop.rotation_step = value["step"].get<int32_t>();
        fhe_prop.p = extra_prop;
    } else if (op_type == OperationType::MAC_WO_PARTIAL_SUM || op_type == OperationType::MAC_W_PARTIAL_SUM) {
        ComputeNode::FheProperty::ExtraProperty extra_prop;
        extra_prop.sum_cnt = value["sum_cnt"].get<int32_t>();
        fhe_prop.p = extra_prop;
    } else if (op_type == OperationType::ENCODE_RINGT) {
        ComputeNode::FheProperty::ExtraProperty extra_prop;
        extra_prop.scale = value["scale"].get<double>();
        fhe_prop.p = extra_prop;
    }

    return fhe_prop;
}

template <typename NodeType>
static void attach_io_nodes(NodeType& node,
                            MegaAG& mega_ag,
                            const std::vector<NodeIndex>& input_indices,
                            const std::vector<NodeIndex>& output_indices,
                            Processor processor) {
    for (NodeIndex i : input_indices) {
        if (processor == Processor::CPU && mega_ag.data.find(i) == mega_ag.data.end()) {
            continue;
        }
        node.input_nodes.push_back(&mega_ag.data.at(i));
    }

    for (NodeIndex i : output_indices) {
        node.output_nodes.push_back(&mega_ag.data.at(i));
    }
}

static ComputeNode parse_internal_compute_node(const nlohmann::json& value, MegaAG& mega_ag, Processor processor) {
    const std::string& json_type = value["type"].get<std::string>();

    ComputeNode internal;
    internal.index = value["index"].get<NodeIndex>();
    internal.id = value["id"].get<std::string>();

    OperationType op_type = OperationType::UNKNOWN;
    if (value.contains("is_custom") && value["is_custom"].get<bool>()) {
        ComputeNode::CustomProperty custom_prop;
        custom_prop.type = json_type;
        if (value.contains("attributes")) {
            custom_prop.attributes = value["attributes"];
        }
        internal.custom_prop = custom_prop;
    } else {
        op_type = str_to_operation_type.at(json_type);
        internal.fhe_prop = parse_fhe_property(value, op_type);
    }

    auto input_indices = value["inputs"].get<std::vector<NodeIndex>>();
    auto output_indices = value["outputs"].get<std::vector<NodeIndex>>();

    attach_io_nodes(internal, mega_ag, input_indices, output_indices, processor);

    if (internal.fhe_prop.has_value() && !is_abi_bridge_operation(op_type) && processor != Processor::FPGA) {
        ExecutorBinder::bind_executor(internal, processor, mega_ag.algo);
    }

    return internal;
}

// =============================================================================
// MegaAG member functions — main
// =============================================================================

MegaAG MegaAG::load(const std::string& project_path, Processor processor) {
    std::string mega_ag_path = project_path + "/compiled_mega_ag.json";
    std::ifstream json_fs;
    json_fs.open(mega_ag_path);
    if (!json_fs.is_open()) {
        throw std::runtime_error("Cannot open MegaAG file " + mega_ag_path);
    }
    nlohmann::json mega_ag_json = nlohmann::json::parse(json_fs);
    json_fs.close();

    std::string parameter_path = project_path + "/fhe_parameter.json";
    std::ifstream parameter_fs;
    parameter_fs.open(parameter_path);
    if (!parameter_fs.is_open()) {
        throw std::runtime_error("Cannot open FHE parameter file " + parameter_path);
    }
    nlohmann::json parameter_json = nlohmann::json::parse(parameter_fs);
    parameter_fs.close();

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

        CompoundComputeNode node;
        node.index = index;
        node.id = value["id"].get<std::string>();

        auto input_indices = value["inputs"].get<std::vector<NodeIndex>>();
        auto output_indices = value["outputs"].get<std::vector<NodeIndex>>();

        if (!value.contains("ops")) {
            throw std::runtime_error("Compiled compute node is missing ops");
        }
        for (const auto& op_json : value["ops"]) {
            node.ops.push_back(parse_internal_compute_node(op_json, mega_ag, processor));
        }

        attach_io_nodes(node, mega_ag, input_indices, output_indices, processor);

        if (value.contains("on_cpu"))
            node.on_cpu = value["on_cpu"].get<bool>();
        if (value.contains("priority"))
            node.priority = value["priority"].get<int>();

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

    mega_ag.parameter = parameter_json;

    return mega_ag;
}

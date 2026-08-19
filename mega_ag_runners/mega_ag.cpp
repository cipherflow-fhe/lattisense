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
#include <stdexcept>
#include <string>
#include <vector>
#include "nlohmann/json.hpp"

#include "mega_ag.h"
#include "mega_ag_executors.h"

const std::unordered_map<std::string, DataType> str_to_datum_type = {
    {"ct", DataType::TYPE_CIPHERTEXT},  {"pt", DataType::TYPE_PLAINTEXT},       {"rlk", DataType::TYPE_RELIN_KEY},
    {"glk", DataType::TYPE_GALOIS_KEY}, {"evk", DataType::TYPE_EVALUATION_KEY},
};

const std::unordered_map<std::string, OperationType> str_to_operation_type = {
    {"add", OperationType::ADD},
    {"sub", OperationType::SUB},
    {"mult", OperationType::MULTIPLY},
    {"relin", OperationType::RELINEARIZE},
    {"rescale", OperationType::RESCALE},
    {"drop_level", OperationType::DROP_LEVEL},
    {"rotate_row", OperationType::ROTATE_ROW},
    {"rotate_col", OperationType::ROTATE_COL},
    {"conjugate", OperationType::CONJUGATE},
    {"cmp_sum", OperationType::MAC_WO_PARTIAL_SUM},
    {"cmpac_sum", OperationType::MAC_W_PARTIAL_SUM},
    {"bootstrap", OperationType::BOOTSTRAP},
    {"export_to_abi", OperationType::EXPORT_TO_ABI},
    {"import_from_abi", OperationType::IMPORT_FROM_ABI},
    {"load_to_backend", OperationType::LOAD_TO_BACKEND},
    {"store_from_backend", OperationType::STORE_FROM_BACKEND},
};

static bool is_abi_bridge_operation(OperationType op_type) {
    return op_type == OperationType::EXPORT_TO_ABI || op_type == OperationType::IMPORT_FROM_ABI ||
           op_type == OperationType::LOAD_TO_BACKEND || op_type == OperationType::STORE_FROM_BACKEND;
}

static std::vector<NodeId> parse_node_ids(const nlohmann::json& value) {
    std::vector<NodeId> ids;
    ids.reserve(value.size());
    for (const auto& item : value) {
        if (!item.is_string()) {
            throw std::runtime_error("MegaAG node reference must be a string id");
        }
        ids.push_back(item.get<std::string>());
    }
    return ids;
}

static ScalarType parse_scalar_value(const nlohmann::json& value) {
    if (value.is_number_unsigned()) {
        return value.get<uint64_t>();
    }
    if (value.is_number_integer()) {
        return value.get<int64_t>();
    }
    if (value.is_number_float()) {
        return value.get<double>();
    }
    if (value.is_array() && value.size() == 2) {
        return std::complex<double>(value[0].get<double>(), value[1].get<double>());
    }
    if (value.is_object() && value.contains("real") && value.contains("imag")) {
        return std::complex<double>(value["real"].get<double>(), value["imag"].get<double>());
    }
    throw std::runtime_error("Unsupported scalar JSON value");
}

static ComputeNode::FheProperty parse_fhe_property(const nlohmann::json& value, OperationType op_type) {
    ComputeNode::FheProperty fhe_prop;
    fhe_prop.op_type = op_type;

    ComputeNode::FheProperty::ExtraProperty extra_prop;
    bool has_extra_prop = false;

    if (op_type == OperationType::ROTATE_COL) {
        extra_prop.rotation_steps = value["steps"].get<std::vector<int32_t>>();
        extra_prop.use_default_rotation_keys = value.value("use_default_rotation_keys", true);
        has_extra_prop = true;
    } else if (op_type == OperationType::DROP_LEVEL) {
        if (!value.contains("drop_level")) {
            throw std::runtime_error("DROP_LEVEL requires drop_level property");
        }
        extra_prop.drop_level = value["drop_level"].get<int32_t>();
        has_extra_prop = true;
    } else if (op_type == OperationType::MAC_WO_PARTIAL_SUM || op_type == OperationType::MAC_W_PARTIAL_SUM) {
        extra_prop.sum_cnt = value["sum_cnt"].get<int32_t>();
        has_extra_prop = true;
    }

    if (value.contains("scalar")) {
        extra_prop.scalar = parse_scalar_value(value["scalar"]);
        extra_prop.has_scalar = true;
        has_extra_prop = true;
    }

    if (has_extra_prop) {
        fhe_prop.p = extra_prop;
    }

    return fhe_prop;
}

template <typename NodeType>
static void attach_io_nodes(NodeType& node,
                            MegaAG& mega_ag,
                            const std::vector<NodeId>& input_ids,
                            const std::vector<NodeId>& output_ids,
                            Processor) {
    for (const auto& id : input_ids) {
        node.input_nodes.push_back(&mega_ag.data.at(id));
    }

    for (const auto& id : output_ids) {
        node.output_nodes.push_back(&mega_ag.data.at(id));
    }
}

static ComputeNode
parse_internal_compute_node(const nlohmann::json& value, const std::string& id, MegaAG& mega_ag, Processor processor) {
    const std::string json_type = value["type"].get<std::string>();

    ComputeNode internal;
    internal.id = id;

    OperationType op_type = OperationType::UNKNOWN;
    if (value.contains("is_custom") && value["is_custom"].get<bool>()) {
        ComputeNode::CustomProperty custom_prop;
        custom_prop.type = json_type;
        if (value.contains("attributes")) {
            custom_prop.attributes = value["attributes"];
        }
        internal.custom_prop = custom_prop;
    } else {
        auto it = str_to_operation_type.find(json_type);
        if (it == str_to_operation_type.end()) {
            throw std::runtime_error("Unknown operation type: " + json_type);
        }
        op_type = it->second;
        internal.fhe_prop = parse_fhe_property(value, op_type);
    }

    auto input_ids = parse_node_ids(value["inputs"]);
    auto output_ids = parse_node_ids(value["outputs"]);

    attach_io_nodes(internal, mega_ag, input_ids, output_ids, processor);

    if (internal.fhe_prop.has_value() && !is_abi_bridge_operation(op_type)) {
        ExecutorBinder::bind_executor(internal, processor, mega_ag.algo);
    }

    return internal;
}

static DatumNode::FheProperty parse_fhe_data_property(const nlohmann::json& value) {
    DatumNode::FheProperty fhe_prop;
    fhe_prop.is_ringt = value.value("is_ringt", false);
    fhe_prop.is_batched = value.value("is_batched", true);
    fhe_prop.degree = value.value("degree", 0);
    fhe_prop.level = value.value("level", 0);
    fhe_prop.log_slots = value.value("log_slots", -1);
    fhe_prop.scale = value.value("scale", 1.0);
    fhe_prop.is_ntt = value.value("is_ntt", true);
    fhe_prop.mform_bits = value.value("mform_bits", 0);

    DatumNode::FheProperty::ExtraProperty extra_prop;
    bool has_extra_prop = false;
    if (value.contains("sp_level")) {
        extra_prop.sp_level = value["sp_level"].get<int32_t>();
        has_extra_prop = true;
    }
    if (value.contains("galois_element")) {
        extra_prop.galois_element = value["galois_element"].get<uint32_t>();
        has_extra_prop = true;
    }
    if (value.contains("key_role")) {
        extra_prop.key_role = value["key_role"].get<std::string>();
        has_extra_prop = true;
    }
    if (has_extra_prop) {
        fhe_prop.p = extra_prop;
    }

    return fhe_prop;
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

    std::string algo_str = mega_ag_json["algorithm"].get<std::string>();
    if (algo_str == "BFV") {
        mega_ag.algo = ALGO_BFV;
    } else if (algo_str == "CKKS") {
        mega_ag.algo = ALGO_CKKS;
    } else {
        throw std::runtime_error("Unknown algorithm: " + algo_str);
    }

    for (auto& [key, value] : data_json.items()) {
        const std::string json_type = value["type"].get<std::string>();

        DatumNode node;
        node.id = key;

        if (value.contains("is_custom") && value["is_custom"].get<bool>()) {
            DatumNode::CustomProperty custom_prop;
            custom_prop.type = json_type;
            if (value.contains("attributes")) {
                custom_prop.attributes = value["attributes"];
            }
            node.custom_prop = custom_prop;
        } else {
            auto it = str_to_datum_type.find(json_type);
            if (it == str_to_datum_type.end()) {
                throw std::runtime_error("Unknown datum type: " + json_type);
            }
            auto datum_type = it->second;

            node.datum_type = datum_type;
            node.fhe_prop = parse_fhe_data_property(value);
        }

        mega_ag.data.emplace(node.id, std::move(node));
    }

    for (auto& [key, value] : computes_json.items()) {
        CompoundComputeNode node;
        node.id = key;

        auto input_ids = parse_node_ids(value["inputs"]);
        auto output_ids = parse_node_ids(value["outputs"]);

        if (!value.contains("ops")) {
            throw std::runtime_error("Compiled compute node is missing ops: " + node.id);
        }
        size_t op_index = 0;
        for (const auto& op_json : value["ops"]) {
            const std::string op_id = value["ops"].size() == 1 ? node.id : node.id + ":" + std::to_string(op_index);
            node.ops.push_back(parse_internal_compute_node(op_json, op_id, mega_ag, processor));
            op_index++;
        }

        attach_io_nodes(node, mega_ag, input_ids, output_ids, processor);

        if (value.contains("on_cpu")) {
            node.on_cpu = value["on_cpu"].get<bool>();
        }
        if (value.contains("priority")) {
            node.priority = value["priority"].get<int>();
        }

        mega_ag.computes.emplace(node.id, std::move(node));
    }

    for (auto& [compute_id, compute_node] : mega_ag.computes) {
        for (auto* input_node : compute_node.input_nodes) {
            input_node->successors.push_back(&compute_node);
        }
        for (auto* output_node : compute_node.output_nodes) {
            output_node->predecessors.push_back(&compute_node);
        }
    }

    mega_ag.inputs = parse_node_ids(mega_ag_json["inputs"]);
    for (const auto& id : mega_ag.inputs) {
        mega_ag.data.at(id).is_input = true;
    }

    mega_ag.outputs = parse_node_ids(mega_ag_json["outputs"]);
    for (const auto& id : mega_ag.outputs) {
        mega_ag.data.at(id).is_output = true;
    }

    mega_ag.parameter = parameter_json;

    return mega_ag;
}

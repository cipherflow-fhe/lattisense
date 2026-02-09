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
#include <iostream>
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
    {"bootstrap", OperationType::BOOTSTRAP}};

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
    Algo algorithm;
    std::string algo_str = mega_ag_json["algorithm"].get<std::string>();
    if (algo_str == "BFV") {
        algorithm = ALGO_BFV;
    } else if (algo_str == "CKKS") {
        algorithm = ALGO_CKKS;
    } else {
        throw std::runtime_error("Unknown algorithm: " + algo_str);
    }

    for (auto& [key, value] : data_json.items()) {
        const std::string& json_type = value["type"].get<std::string>();

        auto datum_type = str_to_datum_type.at(json_type);
        if (processor == Processor::CPU) {
            if (datum_type == DataType::TYPE_RELIN_KEY || datum_type == DataType::TYPE_GALOIS_KEY ||
                datum_type == DataType::TYPE_SWITCH_KEY) {
                continue;
            }
        }

        DatumNode node;
        node.index = std::stoull(key);
        node.id = value["id"].get<std::string>();
        node.level = value["level"].get<int32_t>();
        node.is_ntt = value["is_ntt"].get<bool>();
        node.is_mform = value["is_mform"].get<bool>();
        node.degree = value["degree"].get<int32_t>();
        node.datum_type = datum_type;

        if (node.datum_type == DataType::TYPE_GALOIS_KEY) {
            DatumNode::ExtraProperty prop;
            prop.galois_element = value["galois_element"].get<uint32_t>();
            node.p = prop;
        } else if (json_type == "pt_ringt") {
            DatumNode::ExtraProperty prop;
            prop.is_ringt = true;
            node.p = prop;
        }

        mega_ag.data.emplace(node.index, std::move(node));
    }

    for (auto& [key, value] : computes_json.items()) {
        ComputeNode node;
        node.index = std::stoull(key);
        node.id = value["id"].get<std::string>();

        const std::string& json_type = value["type"].get<std::string>();
        node.op_type = str_to_operation_type.at(json_type);

        if (node.op_type == OperationType::ROTATE_COL) {
            ComputeNode::ExtraProperty prop;
            prop.rotation_step = value["step"].get<int32_t>();
            node.p = prop;
        } else if (node.op_type == OperationType::MAC_WO_PARTIAL_SUM ||
                   node.op_type == OperationType::MAC_W_PARTIAL_SUM) {
            ComputeNode::ExtraProperty prop;
            prop.sum_cnt = value["sum_cnt"].get<int32_t>();
            node.p = prop;
        }

        auto input_indices = value["inputs"].get<std::vector<NodeIndex>>();

        for (NodeIndex i : input_indices) {
            if (processor == Processor::CPU && mega_ag.data.find(i) == mega_ag.data.end()) {
                continue;
            }
            DatumNode& input_node = mega_ag.data.at(i);
            node.input_nodes.push_back(&input_node);
        }

        auto output_indices = value["outputs"].get<std::vector<NodeIndex>>();
        for (NodeIndex i : output_indices) {
            node.output_nodes.push_back(&mega_ag.data.at(i));
        }

        // Bind executor based on algorithm and processor type
        ExecutorBinder::bind_executor(node, processor, algorithm);

        mega_ag.computes.emplace(node.index, std::move(node));
    }

    for (auto& [compute_index, compute_node] : mega_ag.computes) {
        for (auto* input_node : compute_node.input_nodes) {
            input_node->successors.push_back(&compute_node);
        }
    }

    std::vector<NodeIndex> input_indices = mega_ag_json["inputs"].get<std::vector<NodeIndex>>();
    if (processor == Processor::CPU) {
        for (auto& index : input_indices) {
            if (mega_ag.data.find(index) != mega_ag.data.end()) {
                mega_ag.inputs.push_back(index);
            }
        }
    } else {
        mega_ag.inputs = input_indices;
    }

    mega_ag.outputs = mega_ag_json["outputs"].get<std::vector<NodeIndex>>();
    for (auto i : mega_ag.outputs) {
        mega_ag.data.at(i).is_output = true;
    }

    mega_ag.parameter = mega_ag_json["parameter"];

    return mega_ag;
}

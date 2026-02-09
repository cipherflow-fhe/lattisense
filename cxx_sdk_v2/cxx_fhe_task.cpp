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

#include <unordered_map>
#include "cxx_fhe_task.h"
#include "cxx_fhe_task_common.h"
#include "nlohmann/json.hpp"

extern "C" {
#include "../fhe_ops_lib/structs_v2.h"
}

namespace cxx_sdk_v2 {

FheTask::FheTask(const std::string& project_path) : _project_path{project_path} {
    std::ifstream sig_file;
    std::string sig_file_path = _project_path + "/task_signature.json";
    sig_file.open(sig_file_path);
    if (!sig_file.is_open()) {
        throw std::runtime_error("Cannot open task signature file " + sig_file_path);
    }
    _task_signature = nlohmann::json::parse(sig_file);
    sig_file.close();
}

FheTask::~FheTask() {
    free_args();
}

void FheTask::new_args(int n_in_args, int n_out_args) {
    free_args();
    input_args.resize(n_in_args);
    output_args.resize(n_out_args);
}

void FheTask::free_args() {
    if (!_heterogeneous_mode) {
        input_args.clear();
        output_args.clear();
        return;
    }

    for (int i = 0; i < input_args.size(); i++) {
        for (int j = 0; j < input_args[i].size; j++) {
            switch (input_args[i].type) {
                case DataType::TYPE_CIPHERTEXT: free_ciphertext(&((CCiphertext*)input_args[i].data)[j], false); break;
                case DataType::TYPE_PLAINTEXT: free_plaintext(&((CPlaintext*)input_args[i].data)[j], false); break;
                case DataType::TYPE_RELIN_KEY: free_relin_key(&((CRelinKey*)input_args[i].data)[j], false); break;
                case DataType::TYPE_GALOIS_KEY: free_galois_key(&((CGaloisKey*)input_args[i].data)[j], false); break;
            }
        }
    }
    input_args.clear();

    for (int i = 0; i < output_args.size(); i++) {
        for (int j = 0; j < output_args[i].size; j++) {
            switch (output_args[i].type) {
                case DataType::TYPE_CIPHERTEXT: free_ciphertext(&((CCiphertext*)output_args[i].data)[j], false); break;
                default: throw std::runtime_error("Unsupported output type");
            }
        }
    }
    output_args.clear();
}

std::unordered_map<CxxArgumentType, DataType> type_map = {
    {CxxArgumentType::CIPHERTEXT, DataType::TYPE_CIPHERTEXT},
    {CxxArgumentType::CIPHERTEXT3, DataType::TYPE_CIPHERTEXT},
    {CxxArgumentType::PLAINTEXT, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::PLAINTEXT_RINGT, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::PLAINTEXT_MUL, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::RELIN_KEY, DataType::TYPE_RELIN_KEY},
    {CxxArgumentType::GALOIS_KEY, DataType::TYPE_GALOIS_KEY},
};

std::map<CxxArgumentType, std::string> cxx_argument_type_str_map = {
    {CxxArgumentType::RELIN_KEY, "rlk"},
    {CxxArgumentType::GALOIS_KEY, "glk"},
    {CxxArgumentType::PLAINTEXT_RINGT, "pt_ringt"},
    {CxxArgumentType::PLAINTEXT_MUL, "pt_mul"},
    {CxxArgumentType::PLAINTEXT, "pt"},
    {CxxArgumentType::CIPHERTEXT, "ct"},
    {CxxArgumentType::CIPHERTEXT3, "ct3"},
    {CxxArgumentType::CUSTOM, "custom"},  // Generic name for custom types
};

std::map<std::string, CxxArgumentType> str_cxx_argument_type_map = {
    {"rlk", CxxArgumentType::RELIN_KEY},
    {"glk", CxxArgumentType::GALOIS_KEY},
    {"pt_ringt", CxxArgumentType::PLAINTEXT_RINGT},
    {"pt_mul", CxxArgumentType::PLAINTEXT_MUL},
    {"pt", CxxArgumentType::PLAINTEXT},
    {"ct", CxxArgumentType::CIPHERTEXT},
    {"ct3", CxxArgumentType::CIPHERTEXT3},
};

void check_with_sig(const CxxVectorArgument& cxx_arg,
                    const std::string& expected_id,
                    CxxArgumentType expected_type,
                    const std::vector<size_t>& expected_shape,
                    int expected_level) {
    if (cxx_arg.arg_id != expected_id) {
        std::string message = "For argument " + cxx_arg.arg_id + ", expected id is " + expected_id +
                              ", but input id is " + cxx_arg.arg_id + ".";
        throw std::runtime_error(message);
    }

    if (cxx_arg.type != expected_type) {
        std::string message = "For argument " + cxx_arg.arg_id + ", expected type is " +
                              cxx_argument_type_str_map[expected_type] + ", but input type is " +
                              cxx_argument_type_str_map[cxx_arg.type] + ".";
        throw std::runtime_error(message);
    }

    int expected_size = 1;
    for (auto x : expected_shape) {
        expected_size *= x;
    }
    if (cxx_arg.flat_handles.size() != expected_size) {
        std::string message = "For argument " + cxx_arg.arg_id + ", expected size is " + std::to_string(expected_size) +
                              ", but input size is " + std::to_string(cxx_arg.flat_handles.size()) + ".";
        throw std::runtime_error(message);
    }

    if (cxx_arg.level != expected_level) {
        std::string message = "For argument " + cxx_arg.arg_id + ", expected level is " +
                              std::to_string(expected_level) + ", but input level is " + std::to_string(cxx_arg.level) +
                              ".";
        throw std::runtime_error(message);
    }
}

void check_context_for_key_signatures(const FheContext& context, const nlohmann::json& key_signature) {
    RelinKey rlk = context.extract_relin_key();
    fhe_ops_lib::KeySwitchKey ksk = rlk.extract_key_switch_key();
    int rlk_level_sig = key_signature["rlk"].get<int>();
    if (rlk_level_sig > ksk.get_level()) {
        throw std::runtime_error("Level of relin key is smaller than the expected level.");
    }

    GaloisKey glk = context.extract_galois_key();
    for (auto& item : key_signature["glk"].items()) {
        uint64_t gal_el = stoul(item.key());
        int glk_level_sig = item.value().get<int>();
        fhe_ops_lib::KeySwitchKey ksk = glk.extract_key_switch_key(gal_el);
        if (glk_level_sig > ksk.get_level()) {
            throw std::runtime_error("Level of Galois key is smaller than the expected level.");
        }
    }
}

void check_parameter(FheContext* context, const nlohmann::json& param_json) {
    if (!param_json.contains("n")) {
        throw std::runtime_error("Parameter JSON missing 'n' field");
    }
    if (!param_json.contains("q")) {
        throw std::runtime_error("Parameter JSON missing 'q' field");
    }

    int expected_n = param_json["n"].get<int>();
    std::vector<uint64_t> expected_q = param_json["q"].get<std::vector<uint64_t>>();

    if (typeid(*context) == typeid(BfvContext)) {
        BfvContext* bfv_context = static_cast<BfvContext*>(context);
        const BfvParameter& param = bfv_context->get_parameter();

        if (param.get_n() != expected_n) {
            throw std::runtime_error("BFV parameter N mismatch: expected " + std::to_string(expected_n) + ", got " +
                                     std::to_string(param.get_n()));
        }

        if (param_json.contains("t")) {
            uint64_t expected_t = param_json["t"].get<uint64_t>();
            if (param.get_t() != expected_t) {
                throw std::runtime_error("BFV parameter t mismatch: expected " + std::to_string(expected_t) + ", got " +
                                         std::to_string(param.get_t()));
            }
        }

        if (param.get_q_count() != expected_q.size()) {
            throw std::runtime_error("BFV parameter Q count mismatch: expected " + std::to_string(expected_q.size()) +
                                     ", got " + std::to_string(param.get_q_count()));
        }
        for (int i = 0; i < expected_q.size(); i++) {
            if (param.get_q(i) != expected_q[i]) {
                throw std::runtime_error("BFV parameter Q[" + std::to_string(i) + "] mismatch: expected " +
                                         std::to_string(expected_q[i]) + ", got " + std::to_string(param.get_q(i)));
            }
        }

        if (param_json.contains("p")) {
            std::vector<uint64_t> expected_p = param_json["p"].get<std::vector<uint64_t>>();
            if (param.get_p_count() != expected_p.size()) {
                throw std::runtime_error("BFV parameter P count mismatch: expected " +
                                         std::to_string(expected_p.size()) + ", got " +
                                         std::to_string(param.get_p_count()));
            }
            for (int i = 0; i < expected_p.size(); i++) {
                if (param.get_p(i) != expected_p[i]) {
                    throw std::runtime_error("BFV parameter P[" + std::to_string(i) + "] mismatch: expected " +
                                             std::to_string(expected_p[i]) + ", got " + std::to_string(param.get_p(i)));
                }
            }
        }
    } else if (typeid(*context) == typeid(CkksContext) || typeid(*context) == typeid(CkksBtpContext)) {
        CkksContext* ckks_context = static_cast<CkksContext*>(context);
        const CkksParameter& param = ckks_context->get_parameter();

        if (param.get_n() != expected_n) {
            throw std::runtime_error("CKKS parameter N mismatch: expected " + std::to_string(expected_n) + ", got " +
                                     std::to_string(param.get_n()));
        }

        int q_count = param.get_max_level() + 1;
        if (q_count != expected_q.size()) {
            throw std::runtime_error("CKKS parameter Q count mismatch: expected " + std::to_string(expected_q.size()) +
                                     ", got " + std::to_string(q_count));
        }
        for (int i = 0; i < expected_q.size(); i++) {
            if (param.get_q(i) != expected_q[i]) {
                throw std::runtime_error("CKKS parameter Q[" + std::to_string(i) + "] mismatch: expected " +
                                         std::to_string(expected_q[i]) + ", got " + std::to_string(param.get_q(i)));
            }
        }

        if (param_json.contains("p")) {
            std::vector<uint64_t> expected_p = param_json["p"].get<std::vector<uint64_t>>();
            if (param.get_p_count() != expected_p.size()) {
                throw std::runtime_error("CKKS parameter P count mismatch: expected " +
                                         std::to_string(expected_p.size()) + ", got " +
                                         std::to_string(param.get_p_count()));
            }
            for (int i = 0; i < expected_p.size(); i++) {
                if (param.get_p(i) != expected_p[i]) {
                    throw std::runtime_error("CKKS parameter P[" + std::to_string(i) + "] mismatch: expected " +
                                             std::to_string(expected_p[i]) + ", got " + std::to_string(param.get_p(i)));
                }
            }
        }
    } else {
        throw std::runtime_error("Unknown context type for parameter checking");
    }
}

int check_signatures(FheContext* context,
                     const std::vector<CxxVectorArgument>& cxx_args,
                     const nlohmann::json& task_sig_json,
                     bool online_phase) {
    int algo;
    if (typeid(*context) == typeid(BfvContext)) {
        algo = 0;
        if (task_sig_json["algorithm"] != "BFV") {
            throw std::runtime_error("algo error");
        }
    } else if (typeid(*context) == typeid(CkksContext) || typeid(*context) == typeid(CkksBtpContext)) {
        algo = 1;
        if (task_sig_json["algorithm"] != "CKKS") {
            throw std::runtime_error("algo error");
        }
    } else {
        throw std::runtime_error("context type error");
    }

    check_context_for_key_signatures(*context, task_sig_json["key"]);

    auto data_sig_json = online_phase ? task_sig_json["online"].get<std::vector<nlohmann::json>>() :
                                        task_sig_json["offline"].get<std::vector<nlohmann::json>>();

    int n_in_args = 0;

    for (int i = 0; i < cxx_args.size(); i++) {
        std::string expected_id = data_sig_json[i]["id"].get<std::string>();
        std::string type_str = data_sig_json[i]["type"].get<std::string>();

        std::vector<uint64_t> expected_shape = data_sig_json[i]["size"].get<std::vector<uint64_t>>();

        // Use CUSTOM type for unknown types
        CxxArgumentType expected_type = CxxArgumentType::CUSTOM;
        if (str_cxx_argument_type_map.find(type_str) != str_cxx_argument_type_map.end()) {
            expected_type = str_cxx_argument_type_map[type_str];
        }

        // Level is optional for custom data types
        int expected_level = -1;
        if (data_sig_json[i].contains("level") && !data_sig_json[i]["level"].is_null()) {
            expected_level = data_sig_json[i]["level"].get<int>();
        }

        check_with_sig(cxx_args[i], expected_id, expected_type, expected_shape, expected_level);

        std::string phase = data_sig_json[i]["phase"].get<std::string>();
        if (phase == "in" or phase == "offline") {
            n_in_args++;
        }
    }

    return n_in_args;
}

}  // namespace cxx_sdk_v2

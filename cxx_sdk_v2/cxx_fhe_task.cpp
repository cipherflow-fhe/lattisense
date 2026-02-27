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
#include "cxx_argument.h"
#include "check_sig.h"
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

    std::string algo_str = _task_signature["algorithm"].get<std::string>();
    if (algo_str == "BFV") {
        _algo = Algo::ALGO_BFV;
    } else if (algo_str == "CKKS") {
        _algo = Algo::ALGO_CKKS;
    } else {
        throw std::runtime_error("Unknown algorithm in task_signature: " + algo_str);
    }

    std::ifstream mega_ag_file;
    std::string mega_ag_file_path = _project_path + "/mega_ag.json";
    mega_ag_file.open(mega_ag_file_path);
    if (!mega_ag_file.is_open()) {
        throw std::runtime_error("Cannot open mega_ag file " + mega_ag_file_path);
    }
    nlohmann::json mega_ag_json = nlohmann::json::parse(mega_ag_file);
    mega_ag_file.close();
    _param_json = mega_ag_json["parameter"];
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

}  // namespace cxx_sdk_v2

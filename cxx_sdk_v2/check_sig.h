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

#ifndef CHECK_SIG_H
#define CHECK_SIG_H

#include "cxx_fhe_task.h"
#include "nlohmann/json.hpp"
#include <map>

namespace lattisense {

// Type mapping declarations
inline std::map<CxxArgumentType, std::string> cxx_argument_type_str_map = {
    {CxxArgumentType::RELIN_KEY, "rlk"},      {CxxArgumentType::GALOIS_KEY, "glk"},
    {CxxArgumentType::EVALUATION_KEY, "evk"}, {CxxArgumentType::PLAINTEXT, "pt"},
    {CxxArgumentType::CIPHERTEXT, "ct"},      {CxxArgumentType::CUSTOM, "custom"},  // Generic name for custom types
};

inline std::map<std::string, CxxArgumentType> str_cxx_argument_type_map = {
    {"rlk", CxxArgumentType::RELIN_KEY}, {"glk", CxxArgumentType::GALOIS_KEY}, {"evk", CxxArgumentType::EVALUATION_KEY},
    {"pt", CxxArgumentType::PLAINTEXT},  {"ct", CxxArgumentType::CIPHERTEXT},
};

/**
 * @brief Check if a single argument conforms to signature requirements
 */
inline void check_with_sig(const CxxVectorArgument& cxx_arg,
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

/**
 * @brief Check if context keys conform to signature requirements
 */
inline void check_context_for_key_signatures(const FheContext& context, const nlohmann::json& key_signature) {
    int rlk_level_sig = key_signature["rlk"].get<int>();
    if (rlk_level_sig >= 0) {
        const RelinKey& rlk = context.evaluation_key_set().relin_key();
        if (rlk.is_empty()) {
            throw std::runtime_error("Relinearization key is required by the task signature but is not set.");
        }
        if (rlk.level() < rlk_level_sig) {
            throw std::runtime_error("Level of relin key is smaller than the expected level.");
        }
    }

    if (!key_signature["glk"].empty() && !key_signature.contains("glk_order")) {
        throw std::runtime_error("GLK signature requires glk_order.");
    }

    if (key_signature.contains("glk_order") && key_signature["glk_order"].size() != key_signature["glk"].size()) {
        throw std::runtime_error("GLK signature glk_order size does not match glk map size.");
    }

    if (key_signature.contains("glk_order")) {
        for (auto& item : key_signature["glk_order"]) {
            if (!key_signature["glk"].contains(std::to_string(item.get<uint64_t>()))) {
                throw std::runtime_error("GLK signature glk_order contains an element missing from glk map.");
            }
        }
    }

    const auto& galois_keys = context.evaluation_key_set().galois_keys();
    for (auto& item : key_signature["glk"].items()) {
        uint64_t gal_el = std::stoull(item.key());
        int glk_level_sig = item.value().get<int>();
        auto glk_it = galois_keys.find(gal_el);
        if (glk_it == galois_keys.end() || glk_it->second.is_empty()) {
            throw std::runtime_error("Galois key is required by the task signature but is not set.");
        }
        if (glk_it->second.level() < glk_level_sig) {
            throw std::runtime_error("Level of Galois key is smaller than the expected level.");
        }
    }
}

/**
 * @brief Check if FHE context parameters match JSON configuration
 *
 * @param context Pointer to FHE context object
 * @param param_json Parameter configuration JSON object
 * @throws std::runtime_error When parameters do not match
 */
inline void check_parameter(FheContext* context, const nlohmann::json& param_json) {
    if (!param_json.contains("log_n")) {
        throw std::runtime_error("Parameter JSON missing 'log_n' field");
    }
    if (!param_json.contains("q")) {
        throw std::runtime_error("Parameter JSON missing 'q' field");
    }

    int expected_n = 1 << param_json["log_n"].get<int>();
    std::vector<uint64_t> expected_q = param_json["q"].get<std::vector<uint64_t>>();

    if (typeid(*context) == typeid(BfvContext)) {
        BfvContext* bfv_context = static_cast<BfvContext*>(context);
        const BfvParameter& param = bfv_context->parameter();

        if (param.n() != expected_n) {
            throw std::runtime_error("BFV parameter N mismatch: expected " + std::to_string(expected_n) + ", got " +
                                     std::to_string(param.n()));
        }

        if (!param_json.contains("t")) {
            throw std::runtime_error("BFV parameter JSON missing 't' field");
        }
        uint64_t expected_t = param_json["t"].get<uint64_t>();
        if (param.t() != expected_t) {
            throw std::runtime_error("BFV parameter t mismatch: expected " + std::to_string(expected_t) + ", got " +
                                     std::to_string(param.t()));
        }

        auto actual_q = param.q();
        if (param.max_level() + 1 != expected_q.size()) {
            throw std::runtime_error("BFV parameter Q count mismatch: expected " + std::to_string(expected_q.size()) +
                                     ", got " + std::to_string(param.max_level() + 1));
        }
        for (int i = 0; i < expected_q.size(); i++) {
            if (actual_q[i] != expected_q[i]) {
                throw std::runtime_error("BFV parameter Q[" + std::to_string(i) + "] mismatch: expected " +
                                         std::to_string(expected_q[i]) + ", got " + std::to_string(actual_q[i]));
            }
        }

        if (param_json.contains("p")) {
            std::vector<uint64_t> expected_p = param_json["p"].get<std::vector<uint64_t>>();
            auto actual_p = param.p();
            if (actual_p.size() != expected_p.size()) {
                throw std::runtime_error("BFV parameter P count mismatch: expected " +
                                         std::to_string(expected_p.size()) + ", got " +
                                         std::to_string(actual_p.size()));
            }
            for (int i = 0; i < expected_p.size(); i++) {
                if (actual_p[i] != expected_p[i]) {
                    throw std::runtime_error("BFV parameter P[" + std::to_string(i) + "] mismatch: expected " +
                                             std::to_string(expected_p[i]) + ", got " + std::to_string(actual_p[i]));
                }
            }
        }
    } else if (typeid(*context) == typeid(CkksContext)) {
        CkksContext* ckks_context = static_cast<CkksContext*>(context);
        const CkksParameter& param = ckks_context->parameter();

        if (param.n() != expected_n) {
            throw std::runtime_error("CKKS parameter N mismatch: expected " + std::to_string(expected_n) + ", got " +
                                     std::to_string(param.n()));
        }

        auto actual_q = param.q();
        int q_count = param.max_level() + 1;
        if (q_count != expected_q.size()) {
            throw std::runtime_error("CKKS parameter Q count mismatch: expected " + std::to_string(expected_q.size()) +
                                     ", got " + std::to_string(q_count));
        }
        for (int i = 0; i < expected_q.size(); i++) {
            if (actual_q[i] != expected_q[i]) {
                throw std::runtime_error("CKKS parameter Q[" + std::to_string(i) + "] mismatch: expected " +
                                         std::to_string(expected_q[i]) + ", got " + std::to_string(actual_q[i]));
            }
        }

        if (param_json.contains("p")) {
            std::vector<uint64_t> expected_p = param_json["p"].get<std::vector<uint64_t>>();
            auto actual_p = param.p();
            if (actual_p.size() != expected_p.size()) {
                throw std::runtime_error("CKKS parameter P count mismatch: expected " +
                                         std::to_string(expected_p.size()) + ", got " +
                                         std::to_string(actual_p.size()));
            }
            for (int i = 0; i < expected_p.size(); i++) {
                if (actual_p[i] != expected_p[i]) {
                    throw std::runtime_error("CKKS parameter P[" + std::to_string(i) + "] mismatch: expected " +
                                             std::to_string(expected_p[i]) + ", got " + std::to_string(actual_p[i]));
                }
            }
        }
    } else {
        throw std::runtime_error("Unknown context type for parameter checking");
    }
}

/**
 * @brief Check that the context, arguments, and key signatures all conform to the task signature.
 *
 * Verifies that:
 * - The context type matches the expected algorithm (BFV or CKKS)
 * - The context keys satisfy the key-level requirements in the task signature
 * - Each element of cxx_args matches the expected id, type, shape, and level from the signature
 *
 * @param context       Pointer to the FHE context object
 * @param cxx_args      Array of task input/output arguments to validate
 * @param task_sig_json Task signature JSON object
 * @param expected_algo Expected algorithm (ALGO_BFV or ALGO_CKKS), must match the context type
 * @return Number of input arguments (phase == "in") among cxx_args
 * @throws std::runtime_error if any check fails
 */
inline int check_signatures(FheContext* context,
                            const std::vector<CxxVectorArgument>& cxx_args,
                            const nlohmann::json& task_sig_json,
                            Algo expected_algo) {
    if (expected_algo == Algo::ALGO_BFV) {
        if (typeid(*context) != typeid(BfvContext)) {
            throw std::runtime_error("Algorithm is BFV but context is not BfvContext");
        }
    } else if (expected_algo == Algo::ALGO_CKKS) {
        if (typeid(*context) != typeid(CkksContext)) {
            throw std::runtime_error("Algorithm is CKKS but context is not CkksContext");
        }
    } else {
        throw std::runtime_error("Unknown algorithm type");
    }

    check_context_for_key_signatures(*context, task_sig_json["key"]);

    auto data_sig_json = task_sig_json["online"].get<std::vector<nlohmann::json>>();

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
        if (phase == "in") {
            n_in_args++;
        }
    }

    return n_in_args;
}

}  // namespace lattisense

#endif  // CHECK_SIG_H

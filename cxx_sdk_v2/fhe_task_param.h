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

#ifndef FHE_TASK_PARAM_H
#define FHE_TASK_PARAM_H

#include <variant>
#include "cxx_fhe_task.h"

namespace lattisense {

using namespace fhe_ops_lib;

/**
 * @brief Create a BfvParameter from parameter JSON.
 *
 * Expects param_json to contain: "n", "t", "q", "p".
 *
 * @param param_json Parameter JSON from FheTask::_param_json
 * @return BfvParameter
 */
inline BfvParameter create_bfv_parameter(const nlohmann::json& param_json) {
    auto n = param_json["n"].get<int>();
    auto t = param_json["t"].get<uint64_t>();
    auto q = param_json["q"].get<std::vector<uint64_t>>();
    auto p = param_json["p"].get<std::vector<uint64_t>>();
    return BfvParameter::create_custom_parameter(n, t, q, p);
}

/**
 * @brief Create a CkksParameter from parameter JSON.
 *
 * Expects param_json to contain: "n", "q", "p".
 *
 * @param param_json Parameter JSON from FheTask::_param_json
 * @return CkksParameter
 */
inline CkksParameter create_ckks_parameter(const nlohmann::json& param_json) {
    auto n = param_json["n"].get<int>();
    auto q = param_json["q"].get<std::vector<uint64_t>>();
    auto p = param_json["p"].get<std::vector<uint64_t>>();
    return CkksParameter::create_custom_parameter(n, q, p);
}

/**
 * @brief Create a CkksBtpParameter from parameter JSON.
 *
 * Selects toy (n=2^13) or full (n=2^16) bootstrap parameter set based on "n".
 *
 * @param param_json Parameter JSON from FheTask::_param_json
 * @return CkksBtpParameter
 * @throws std::runtime_error if n is not a supported bootstrap size
 */
inline CkksBtpParameter create_ckks_btp_parameter(const nlohmann::json& param_json) {
    auto n = param_json["n"].get<int>();
    if (n == 1 << 13) {
        return CkksBtpParameter::create_toy_parameter();
    } else if (n == 1 << 16) {
        return CkksBtpParameter::create_parameter();
    } else {
        throw std::runtime_error("Unsupported bootstrap parameter size n=" + std::to_string(n));
    }
}

/**
 * @brief Create the appropriate FHE parameter from an FheTask.
 *
 * Dispatches to create_bfv_parameter, create_ckks_btp_parameter, or create_ckks_parameter
 * based on task.algo() and whether bootstrap fields are present in task.param_json().
 *
 * For CKKS, bootstrap is detected by the presence of "btp_cts_start_level" in param_json.
 *
 * @param task FheTask instance
 * @return std::variant<BfvParameter, CkksParameter, CkksBtpParameter>
 * @throws std::runtime_error on unknown algo
 */
inline std::variant<BfvParameter, CkksParameter, CkksBtpParameter> create_fhe_parameter(const FheTask& task) {
    const auto& param_json = task.param_json();
    const Algo algo = task.algo();

    if (algo == Algo::ALGO_BFV) {
        return create_bfv_parameter(param_json);
    } else if (algo == Algo::ALGO_CKKS) {
        if (param_json.contains("btp_cts_start_level")) {
            return create_ckks_btp_parameter(param_json);
        } else {
            return create_ckks_parameter(param_json);
        }
    } else {
        throw std::runtime_error("create_fhe_parameter: unknown Algo value");
    }
}

}  // namespace lattisense

#endif  // FHE_TASK_PARAM_H

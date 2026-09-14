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
 * Expects param_json to contain: "log_n", "t", "q", "p".
 *
 * @param param_json Parameter JSON from FheTask::_param_json
 * @return BfvParameter
 */
inline BfvParameter create_bfv_parameter(const nlohmann::json& param_json) {
    auto log_n = param_json["log_n"].get<int>();
    auto t = param_json["t"].get<uint64_t>();
    auto q = param_json["q"].get<std::vector<uint64_t>>();
    auto p = param_json["p"].get<std::vector<uint64_t>>();
    return BfvParameter::create_custom_parameter(log_n, t, q, p);
}

/**
 * @brief Create a CkksParameter from parameter JSON.
 *
 * Expects param_json to contain: "log_n", "log_default_scale", "q", "p".
 *
 * @param param_json Parameter JSON from FheTask::_param_json
 * @return CkksParameter
 */
inline CkksParameter create_ckks_parameter(const nlohmann::json& param_json) {
    auto log_n = param_json["log_n"].get<int>();
    auto log_default_scale = param_json["log_default_scale"].get<int>();
    auto q = param_json["q"].get<std::vector<uint64_t>>();
    auto p = param_json["p"].get<std::vector<uint64_t>>();
    return CkksParameter::create_custom_parameter(log_n, log_default_scale, q, p);
}

/**
 * @brief Create the appropriate FHE parameter from an FheTask.
 *
 * Dispatches to create_bfv_parameter or create_ckks_parameter based on task.algo().
 *
 * @param task FheTask instance
 * @return std::variant<BfvParameter, CkksParameter>
 * @throws std::runtime_error on unknown algo
 */
inline std::variant<BfvParameter, CkksParameter> create_fhe_parameter(const FheTask& task) {
    const auto& param_json = task.param_json();
    const Algo algo = task.algo();

    if (algo == Algo::ALGO_BFV) {
        return create_bfv_parameter(param_json);
    } else if (algo == Algo::ALGO_CKKS) {
        return create_ckks_parameter(param_json);
    } else {
        throw std::runtime_error("create_fhe_parameter: unknown Algo value");
    }
}

}  // namespace lattisense

#endif  // FHE_TASK_PARAM_H

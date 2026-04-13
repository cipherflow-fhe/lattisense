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

#ifndef CXX_FHE_TASK_H
#define CXX_FHE_TASK_H

#include <unordered_map>
#include <vector>
#include "nlohmann/json.hpp"
#include "../fhe_ops_lib/fhe_lib_v2.h"

extern "C" {
#include "../mega_ag_runners/wrapper.h"
}

#include "../mega_ag_runners/mega_ag.h"
#include "cxx_argument.h"
#include "check_sig.h"

namespace lattisense {

using namespace fhe_ops_lib;

class FheTask {
public:
    FheTask() = default;

    FheTask(const std::string& project_path);

    FheTask(const FheTask& other) = delete;

    FheTask(FheTask&& other) {
        std::swap(_project_path, other._project_path);
        std::swap(_algo, other._algo);
        std::swap(task_handle, other.task_handle);
    }

    void operator=(const FheTask& other) = delete;

    void operator=(FheTask&& other) {
        std::swap(_project_path, other._project_path);
        std::swap(_algo, other._algo);
        std::swap(task_handle, other.task_handle);
    }

    ~FheTask();

    /**
     * @brief Bind custom executors for specific custom operation types before running the task
     * @param custom_executors Map of custom operation type to executor function
     */
    virtual void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) = 0;

    const nlohmann::json& param_json() const {
        return _param_json;
    }
    Algo algo() const {
        return _algo;
    }

    // virtual uint64_t run(FheContext* context, const std::vector<CxxVectorArgument>& cxx_args) = 0;

protected:
    std::string _project_path = "";
    nlohmann::json _task_signature;
    nlohmann::json _param_json;
    Algo _algo = ALGO_BFV;  // FHE algorithm (ALGO_BFV or ALGO_CKKS), parsed from task_signature

    fhe_task_handle task_handle = nullptr;

    std::vector<CArgument> input_args;
    std::vector<CArgument> output_args;
    PublicKeyStorage _key_storage;

    void new_args(int n_in_args, int n_out_args);
    void free_args();

    /**
     * @brief Bind ABI bridge executors for Frontend Handle ↔ ABI C struct bridging
     *
     * Called automatically in the constructor to bind ABI bridge executors.
     */
    virtual void bind_abi_executors() = 0;
};

class FheTaskCpu : public FheTask {
public:
    using FheTask::FheTask;

    FheTaskCpu(const std::string& project_path);
    ~FheTaskCpu();

    void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) override;
    uint64_t run(FheContext* context, const std::vector<CxxVectorArgument>& cxx_args);

protected:
    void bind_abi_executors() override;
};

class FheTaskGpu : public FheTask {
public:
    using FheTask::FheTask;

    FheTaskGpu(const std::string& project_path);

    ~FheTaskGpu();

    void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) override;
    uint64_t run(FheContext* context, const std::vector<CxxVectorArgument>& cxx_args);

protected:
    void bind_abi_executors() override;
};

class FheTaskFpga : public FheTask {
public:
    FheTaskFpga(const std::string& project_path);

    FheTaskFpga(const FheTaskFpga& other) = delete;

    FheTaskFpga(FheTaskFpga&& other);

    void operator=(const FheTaskFpga& other) = delete;

    void operator=(FheTaskFpga&& other);

    ~FheTaskFpga();

    void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) override;
    uint64_t run(FheContext* context, const std::vector<CxxVectorArgument>& cxx_args);

protected:
    void bind_abi_executors() override;
};

}  // namespace lattisense
#endif  // CXX_FHE_TASK_H

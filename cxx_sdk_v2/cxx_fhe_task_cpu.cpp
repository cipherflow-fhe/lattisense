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
#include <unordered_map>
#include <vector>
#include <typeindex>
#include <set>
#include <unordered_set>
#include <sstream>
#include <thread>
#include <future>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <functional>
#include "../lib/thread_pool/BS_thread_pool.hpp"

#include "cxx_fhe_task.h"
#include "cxx_fhe_task_common.h"

extern "C" {
#include "../mega_ag_runners/wrapper.h"
}

// #define LOG_PARALLEL

namespace cxx_sdk_v2 {
std::unordered_map<std::type_index, CxxArgumentType> _type_map = {
    {std::type_index(typeid(BfvCiphertext)), CxxArgumentType::CIPHERTEXT},
    {std::type_index(typeid(BfvCiphertext3)), CxxArgumentType::CIPHERTEXT3},
    {std::type_index(typeid(BfvPlaintext)), CxxArgumentType::PLAINTEXT},
    {std::type_index(typeid(BfvPlaintextRingt)), CxxArgumentType::PLAINTEXT_RINGT},
    {std::type_index(typeid(BfvPlaintextMul)), CxxArgumentType::PLAINTEXT_MUL},
    {std::type_index(typeid(CkksCiphertext)), CxxArgumentType::CIPHERTEXT},
    {std::type_index(typeid(CkksCiphertext3)), CxxArgumentType::CIPHERTEXT3},
    {std::type_index(typeid(CkksPlaintext)), CxxArgumentType::PLAINTEXT},
    {std::type_index(typeid(CkksPlaintextRingt)), CxxArgumentType::PLAINTEXT_RINGT},
    {std::type_index(typeid(CkksPlaintextMul)), CxxArgumentType::PLAINTEXT_MUL}};

FheTaskCpu::FheTaskCpu(const std::string& project_path) : FheTask{project_path} {
    task_handle = create_fhe_cpu_task(project_path.c_str());
    _heterogeneous_mode = false;  // CPU mode uses homogeneous computation
}

FheTaskCpu::~FheTaskCpu() {
    release_fhe_cpu_task(task_handle);
}

int64_t get_duration_in_us(const std::chrono::_V2::system_clock::time_point& start) {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now - start).count();
}

uint64_t FheTaskCpu::run(FheContext* context, const std::vector<CxxVectorArgument>& cxx_args) {
    auto start = std::chrono::high_resolution_clock::now();

    int n_in_args = 0, n_out_args = 0;
    n_in_args = check_signatures(context, cxx_args, _task_signature);
    n_out_args = cxx_args.size() - n_in_args;

    nlohmann::json key_signature = _task_signature["key"];

    Algo algo = Algo::ALGO_BFV;
    if (typeid(*context) == typeid(BfvContext)) {
        algo = Algo::ALGO_BFV;
    } else if (typeid(*context) == typeid(CkksContext) || typeid(*context) == typeid(CkksBtpContext)) {
        algo = Algo::ALGO_CKKS;
    }

    const Parameter& param = context->get_parameter();

    new_args(n_in_args, n_out_args);

    export_cxx_arguments(cxx_args, input_args, output_args, param, -1, _heterogeneous_mode);

    export_public_key_arguments(key_signature, input_args, context, -1, _heterogeneous_mode);

    // Call CPU runner
    int ret = run_fhe_cpu_task(task_handle, input_args.data(), input_args.size(), output_args.data(),
                               output_args.size(), algo);

    if (ret != 0) {
        throw std::runtime_error("Failed to run CPU project");
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
#ifdef LATTISENSE_DEV
    std::cout << "Run CPU time: " << duration.count() / 1.0e6 << " ms" << std::endl;
#endif

    return duration.count();
}

}  // namespace cxx_sdk_v2

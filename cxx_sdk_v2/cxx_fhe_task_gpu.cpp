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

#include <sys/time.h>
#include <exception>
#include <unordered_map>

#include "cxx_fhe_task.h"
#include "cxx_argument.h"
#include "check_sig.h"
#include "../mega_ag_runners/wrapper.h"

namespace cxx_sdk_v2 {

const int GPU_MFORM_BITS = 0;

FheTaskGpu::FheTaskGpu(const std::string& project_path) : FheTask{project_path} {
    task_handle = create_fhe_gpu_task(project_path.c_str());
    _heterogeneous_mode = true;  // GPU mode uses heterogeneous computation
}

FheTaskGpu::~FheTaskGpu() {
    release_fhe_gpu_task(task_handle);
}

uint64_t FheTaskGpu::run(FheContext* context, const std::vector<CxxVectorArgument>& cxx_args, bool print_time) {
    auto start = std::chrono::high_resolution_clock::now();

    int n_in_args = 0, n_out_args = 0;
    n_in_args = check_signatures(context, cxx_args, _task_signature, _algo);
    n_out_args = cxx_args.size() - n_in_args;

    // Check parameter
    check_parameter(context, _param_json);

    nlohmann::json key_signature = _task_signature["key"];

    const Parameter& param = context->get_parameter();

    new_args(n_in_args, n_out_args);

    export_cxx_arguments(cxx_args, input_args, output_args, param, GPU_MFORM_BITS, _heterogeneous_mode);

    export_public_key_arguments(key_signature, input_args, context, GPU_MFORM_BITS, _heterogeneous_mode);

    // call runner
    int ret = run_fhe_gpu_task(task_handle, input_args.data(), input_args.size(), output_args.data(),
                               output_args.size(), _algo);

    if (ret != 0) {
        throw std::runtime_error("Failed to run GPU project");
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    if (print_time) {
        std::cout << "Run GPU time: " << duration.count() / 1.0e6 << " ms" << std::endl;
    }

    return duration.count();
}
}  // namespace cxx_sdk_v2

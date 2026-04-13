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

/** @file cpu_wrapper.cpp
 * @brief CPU wrapper implementation for MegaAG execution
 */

#include "../mega_ag.h"
#include "../cpu_task_utils.h"
#include "../../fhe_ops_lib/fhe_lib_v2.h"
#include "../../lib/thread_pool/BS_thread_pool.hpp"
#include "../../lib/gsl/span"

#ifdef LATTISENSE_DEV
#    include "../cpu_mem_monitor.h"
#endif

extern "C" {
#include "../wrapper.h"
}

#include <chrono>
#include <iostream>
#include <any>
#include <memory>
#include <thread>

namespace cpu_wrapper {

using namespace fhe_ops_lib;

template <HEScheme SchemeType, typename TContext>
void _run_mega_ag_impl(gsl::span<CArgument> input_args, gsl::span<CArgument> output_args, const MegaAG& mega_ag) {
    std::unique_ptr<TContext> context;
    init_context<SchemeType, TContext>(mega_ag.parameter, input_args, context);

    auto start = std::chrono::high_resolution_clock::now();

    int num_threads = std::min(32, static_cast<int>(std::thread::hardware_concurrency()));
    BS::priority_thread_pool pool(num_threads);

    // Extract input handles and build available_data map
    std::vector<void*> input_handles = extract_input_handles(input_args, false);
    std::unordered_map<NodeIndex, std::any> available_data = init_available_data(mega_ag, input_handles);

    // Build output handle map for IMPORT_FROM_ABI get_other_args
    std::unordered_map<NodeIndex, void*> output_handle_map = extract_output_handle_map(mega_ag, output_args);

    // Provide output dest pointers to IMPORT_FROM_ABI nodes via get_other_args
    auto get_other_args = [&output_handle_map](const ComputeNode& node) -> std::vector<std::any> {
        if (node.fhe_prop.has_value() && node.fhe_prop->op_type == OperationType::IMPORT_FROM_ABI) {
            const DatumNode* output_node = node.output_nodes[0];
            auto it = output_handle_map.find(output_node->index);
            if (it != output_handle_map.end()) {
                return {it->second};
            }
        }
        return {};
    };

    // Run CPU tasks in thread pool
#ifdef LATTISENSE_DEV
    MemoryMonitor mem_monitor(100);  // sample every 100 ms
    mem_monitor.start(MemoryMonitor::next_csv_path("mem_usage_cpu"));
#endif
    run_tasks(mega_ag, pool, context, available_data, get_other_args);
#ifdef LATTISENSE_DEV
    mem_monitor.stop();
#endif

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
#ifdef LATTISENSE_DEV
    std::cout << "Run CPU mega_ag time: " << duration.count() << " milliseconds" << std::endl;
#endif
}

template <HEScheme SchemeType>
void _run_mega_ag(gsl::span<CArgument> input_args, gsl::span<CArgument> output_args, const MegaAG& mega_ag) {
    // Determine TContext based on SchemeType and bootstrap parameters
    if constexpr (SchemeType == HEScheme::CKKS) {
        // Check if bootstrap parameters exist
        if (mega_ag.parameter.contains("btp_output_level")) {
            // Use CkksBtpContext for bootstrap
            using TContext = CkksBtpContext;
            _run_mega_ag_impl<SchemeType, TContext>(input_args, output_args, mega_ag);
        } else {
            // Use regular CkksContext
            using TContext = CkksContext;
            _run_mega_ag_impl<SchemeType, TContext>(input_args, output_args, mega_ag);
        }
    } else {
        // BFV always uses BfvContext
        using TContext = BfvContext;
        _run_mega_ag_impl<SchemeType, TContext>(input_args, output_args, mega_ag);
    }
}

class FheCpuTask {
public:
    FheCpuTask(const std::string& project_path)
        : mega_ag_(MegaAG::load(project_path + "/mega_ag.json", Processor::CPU)) {}

    ~FheCpuTask() {}

    void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) {
        mega_ag_.bind_custom_executors(custom_executors);
    }

    void bind_abi_bridge_executors(const ExecutorFunc& abi_export, const ExecutorFunc& abi_import) {
        mega_ag_.bind_abi_bridge_executors(abi_export, abi_import);
    }

    int run(gsl::span<CArgument> input_args, gsl::span<CArgument> output_args) {
        switch (mega_ag_.algo) {
            case Algo::ALGO_BFV: _run_mega_ag<HEScheme::BFV>(input_args, output_args, mega_ag_); break;
            case Algo::ALGO_CKKS: _run_mega_ag<HEScheme::CKKS>(input_args, output_args, mega_ag_); break;
            default: throw std::invalid_argument("algo not supported"); break;
        }

        return 0;
    }

protected:
    MegaAG mega_ag_;
};
};  // namespace cpu_wrapper

extern "C" {
fhe_task_handle create_fhe_cpu_task(const char* project_path) {
    cpu_wrapper::FheCpuTask* task = new cpu_wrapper::FheCpuTask(project_path);
    return (fhe_task_handle)task;
}

void release_fhe_cpu_task(fhe_task_handle handle) {
    cpu_wrapper::FheCpuTask* task = (cpu_wrapper::FheCpuTask*)handle;
    delete task;
}

void bind_cpu_task_custom_executors(fhe_task_handle handle,
                                    const char** custom_types,
                                    void** executors,
                                    uint64_t n_executors) {
    cpu_wrapper::FheCpuTask* task = (cpu_wrapper::FheCpuTask*)handle;
    std::unordered_map<std::string, ExecutorFunc> custom_executors;
    for (uint64_t i = 0; i < n_executors; i++) {
        ExecutorFunc* executor_ptr = reinterpret_cast<ExecutorFunc*>(executors[i]);
        custom_executors[std::string(custom_types[i])] = *executor_ptr;
    }
    task->bind_custom_executors(custom_executors);
}

void bind_cpu_task_abi_bridge_executors(fhe_task_handle handle, void* abi_export_executor, void* abi_import_executor) {
    cpu_wrapper::FheCpuTask* task = (cpu_wrapper::FheCpuTask*)handle;
    ExecutorFunc* export_executor = reinterpret_cast<ExecutorFunc*>(abi_export_executor);
    ExecutorFunc* import_executor = reinterpret_cast<ExecutorFunc*>(abi_import_executor);
    task->bind_abi_bridge_executors(*export_executor, *import_executor);
}

int run_fhe_cpu_task(fhe_task_handle handle,
                     CArgument* input_args,
                     uint64_t n_in_args,
                     CArgument* output_args,
                     uint64_t n_out_args) {
    cpu_wrapper::FheCpuTask* task = (cpu_wrapper::FheCpuTask*)handle;
    gsl::span<CArgument> input_arg_span{input_args, n_in_args};
    gsl::span<CArgument> output_arg_span{output_args, n_out_args};
    return task->run(input_arg_span, output_arg_span);
}
}  // extern "C"

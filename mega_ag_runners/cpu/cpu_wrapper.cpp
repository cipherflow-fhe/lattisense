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
#include "../../fhe_ops_lib/fhe_lib_v2.h"
#include "../../lib/thread_pool/BS_thread_pool.hpp"
#include "../../lib/gsl/span"

extern "C" {
#include "../wrapper.h"
}

#include <queue>
#include <set>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <iostream>
#include <any>
#include <memory>

namespace cpu_wrapper {

using namespace fhe_ops_lib;

template <typename TContext>
std::vector<Handle*> extract_input_handles(CArgument* input_args, uint64_t n_in_args, TContext& context) {
    std::vector<Handle*> input_handles;
    for (uint64_t i = 0; i < n_in_args; ++i) {
        auto& arg = input_args[i];
        switch (arg.type) {
            case TYPE_PLAINTEXT:
            case TYPE_CIPHERTEXT: {
                Handle** handle_array = static_cast<Handle**>(arg.data);
                for (int j = 0; j < arg.size; ++j) {
                    input_handles.push_back(handle_array[j]);
                }
                break;
            }
            case TYPE_RELIN_KEY: {
                Handle** handle_array = static_cast<Handle**>(arg.data);
                for (int j = 0; j < arg.size; ++j) {
                    RelinKey* rlk_ptr = static_cast<RelinKey*>(handle_array[j]);
                    context.set_context_relin_key(*rlk_ptr);
                }
                break;
            }
            case TYPE_GALOIS_KEY: {
                Handle** handle_array = static_cast<Handle**>(arg.data);
                for (int j = 0; j < arg.size; ++j) {
                    GaloisKey* glk_ptr = static_cast<GaloisKey*>(handle_array[j]);
                    context.set_context_galois_key(*glk_ptr);
                }
                break;
            }
            case TYPE_SWITCH_KEY: {
                if constexpr (std::is_same_v<TContext, CkksBtpContext>) {
                    Handle** handle_array = static_cast<Handle**>(arg.data);
                    std::string key_id(arg.id);
                    for (int j = 0; j < arg.size; ++j) {
                        KeySwitchKey* swk_ptr = static_cast<KeySwitchKey*>(handle_array[j]);
                        if (key_id == "swk_dts") {
                            context.set_context_switch_key_dts(*swk_ptr);
                        } else if (key_id == "swk_std") {
                            context.set_context_switch_key_std(*swk_ptr);
                        }
                    }
                } else {
                    throw std::runtime_error("TYPE_SWITCH_KEY is only supported for CkksBtpContext");
                }
                break;
            }
            default: throw std::runtime_error("Unknown argument type in extract_input_handles");
        }
    }
    return input_handles;
}

std::vector<Handle*> extract_output_handles(CArgument* output_args, uint64_t n_out_args) {
    std::vector<Handle*> output_handles;
    for (uint64_t i = 0; i < n_out_args; ++i) {
        Handle** handle_array = static_cast<Handle**>(output_args[i].data);
        for (int j = 0; j < output_args[i].size; ++j) {
            output_handles.push_back(handle_array[j]);
        }
    }
    return output_handles;
}

template <HEScheme SchemeType, typename TContext>
void init_context(const nlohmann::json& param_json, std::unique_ptr<TContext>& context) {
    auto n = param_json["n"].get<int>();

    auto max_level = param_json["max_level"].get<int>();
    auto q = param_json["q"].get<std::vector<uint64_t>>();
    auto p = param_json["p"].get<std::vector<uint64_t>>();

    if constexpr (SchemeType == HEScheme::CKKS) {
        if constexpr (std::is_same_v<TContext, CkksBtpContext>) {
            // Create CkksBtpContext for bootstrap
            int cts_start_level = param_json["btp_cts_start_level"].get<int>();
            int eval_mod_start_level = param_json["btp_eval_mod_start_level"].get<int>();
            int stc_start_level = param_json["btp_stc_start_level"].get<int>();
            double scale = param_json["scale"].get<double>();

            if (n == 1 << 13) {
                CkksBtpParameter btp_param = CkksBtpParameter::create_toy_parameter();
                context = std::make_unique<TContext>(CkksBtpContext::create_empty_context(btp_param));
            } else if (n == 1 << 16) {
                CkksBtpParameter btp_param = CkksBtpParameter::create_parameter();
                context = std::make_unique<TContext>(CkksBtpContext::create_empty_context(btp_param));
            }
        } else {
            // Create regular CkksContext
            CkksParameter param = CkksParameter::create_custom_parameter(n, q, p);
            context = std::make_unique<TContext>(CkksContext::create_empty_context(param));
        }

    } else if constexpr (SchemeType == HEScheme::BFV) {
        auto t = param_json["t"].get<uint64_t>();
        BfvParameter param = BfvParameter::create_custom_parameter(n, t, q, p);
        context = std::make_unique<TContext>(BfvContext::create_empty_context(param));
    }
}

template <HEScheme SchemeType>
void init_available_data(std::unordered_map<NodeIndex, std::any>& available_data,
                         const std::vector<NodeIndex>& input_indices,
                         const std::vector<Handle*>& input_handles) {
    using CiphertextType = std::conditional_t<SchemeType == HEScheme::BFV, BfvCiphertext, CkksCiphertext>;
    using Ciphertext3Type = std::conditional_t<SchemeType == HEScheme::BFV, BfvCiphertext3, CkksCiphertext3>;
    using PlaintextType = std::conditional_t<SchemeType == HEScheme::BFV, BfvPlaintext, CkksPlaintext>;
    using PlaintextRingtType = std::conditional_t<SchemeType == HEScheme::BFV, BfvPlaintextRingt, CkksPlaintextRingt>;
    using PlaintextMulType = std::conditional_t<SchemeType == HEScheme::BFV, BfvPlaintextMul, CkksPlaintextMul>;

    for (size_t i = 0; i < input_indices.size(); ++i) {
        NodeIndex index = input_indices[i];
        Handle* handle = input_handles[i];
        if (auto* p = dynamic_cast<Ciphertext3Type*>(handle)) {
            available_data[index] = std::shared_ptr<Ciphertext3Type>(std::shared_ptr<Ciphertext3Type>(), p);
        } else if (auto* p = dynamic_cast<CiphertextType*>(handle)) {
            available_data[index] = std::shared_ptr<CiphertextType>(std::shared_ptr<CiphertextType>(), p);
        } else if (auto* p = dynamic_cast<PlaintextRingtType*>(handle)) {
            available_data[index] = std::shared_ptr<PlaintextRingtType>(std::shared_ptr<PlaintextRingtType>(), p);
        } else if (auto* p = dynamic_cast<PlaintextMulType*>(handle)) {
            available_data[index] = std::shared_ptr<PlaintextMulType>(std::shared_ptr<PlaintextMulType>(), p);
        } else if (auto* p = dynamic_cast<PlaintextType*>(handle)) {
            available_data[index] = std::shared_ptr<PlaintextType>(std::shared_ptr<PlaintextType>(), p);
        } else {
            throw std::runtime_error("Unknown input handle type in init_available_data");
        }
    }
}

template <HEScheme SchemeType, typename TContext>
void _run_mega_ag_impl(gsl::span<CArgument> input_args, gsl::span<CArgument> output_args, const MegaAG& mega_ag) {
    std::unique_ptr<TContext> context;
    init_context<SchemeType, TContext>(mega_ag.parameter, context);

    std::vector<Handle*> input_handles = extract_input_handles(input_args.data(), input_args.size(), *context);
    std::vector<Handle*> output_handles = extract_output_handles(output_args.data(), output_args.size());

    if constexpr (std::is_same_v<TContext, CkksBtpContext>) {
        context->create_bootstrapper();
    }

    auto start = std::chrono::high_resolution_clock::now();

    int num_threads = std::min(32, static_cast<int>(std::thread::hardware_concurrency()));
    BS::thread_pool pool(num_threads);

    std::vector<std::unique_ptr<TContext>> fhe_context_ptrs(num_threads);
    for (int i = 0; i < num_threads; ++i) {
        pool.detach_task([&fhe_context_ptrs, &context, i]() {
            fhe_context_ptrs[i] = std::make_unique<TContext>(context->shallow_copy_context());
        });
    }
    pool.wait();

    std::mutex m_mutex;
    std::atomic<size_t> total_tasks(mega_ag.computes.size());
    std::atomic<size_t> completed_tasks(0);
    std::condition_variable completion_cv;
    std::mutex completion_mutex;
    std::queue<NodeIndex> task_queue;
    std::set<NodeIndex> queued_computes;

    std::unordered_map<NodeIndex, std::any> available_handles;
    init_available_data<SchemeType>(available_handles, mega_ag.inputs, input_handles);

    std::unordered_map<NodeIndex, std::atomic<int>> data_ref_counts;
    for (const auto& [data_index, data_info] : mega_ag.data) {
        data_ref_counts[data_index].store(data_info.successors.size());
    }

    std::set<NodeIndex> available_computes = mega_ag.get_available_computes(available_handles);

    for (const auto& task_index : available_computes) {
        task_queue.push(task_index);
        queued_computes.insert(task_index);
    }

    // Define task submission function
    std::function<void(NodeIndex)> submit_task = [&](NodeIndex task_index) {
        pool.detach_task([task_index, &mega_ag, &completed_tasks, &total_tasks, &m_mutex, &completion_mutex,
                          &completion_cv, &available_handles, &fhe_context_ptrs, &task_queue, &queued_computes,
                          &data_ref_counts]() {
            auto thread_id = BS::this_thread::get_index().value();

            const ComputeNode& compute_node = mega_ag.computes.at(task_index);
            const std::vector<DatumNode*>& compute_input_nodes = compute_node.input_nodes;

            // Cache input data for this thread (as std::any wrapping Handle*)
            std::unordered_map<NodeIndex, std::any> thread_input_cache;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                // Cache input handles (store shared_ptr for executor)
                for (const auto* input_node : compute_input_nodes) {
                    thread_input_cache[input_node->index] = available_handles[input_node->index];
                }
            }

            // Prepare execution context
            ExecutionContext exec_ctx;
            exec_ctx.context = fhe_context_ptrs[thread_id].get();

            // Execute the compute node using its bound executor
            std::any output;
            compute_node.executor(exec_ctx, thread_input_cache, output, compute_node);

            NodeIndex output_index = compute_node.output_nodes[0]->index;

            const DatumNode& compute_output_node = *compute_node.output_nodes[0];

            // Update results and find newly available tasks
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                // Store the output
                available_handles[output_index] = output;
                // Clean up unreferenced data
                mega_ag.purge_unused_data(compute_node, data_ref_counts, available_handles);
                // Find newly available computes
                std::set<NodeIndex> newly_available_computes =
                    mega_ag.step_available_computes(compute_output_node, available_handles);

                for (const auto& new_task_index : newly_available_computes) {
                    if (queued_computes.find(new_task_index) == queued_computes.end()) {
                        task_queue.push(new_task_index);
                        queued_computes.insert(new_task_index);
                    }
                }
            }

            // Check if all tasks are completed
            if (completed_tasks.fetch_add(1) + 1 >= total_tasks) {
                std::lock_guard<std::mutex> lock(completion_mutex);
                completion_cv.notify_all();
            }
        });
    };

    // Task dispatcher loop
    while (true) {
        NodeIndex next_task;
        bool has_task = false;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!task_queue.empty()) {
                next_task = task_queue.front();
                task_queue.pop();
                has_task = true;
            }
        }

        if (has_task) {
            submit_task(next_task);
        } else {
            if (completed_tasks.load() >= total_tasks) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Wait for all tasks to complete
    {
        std::unique_lock<std::mutex> lock(completion_mutex);
        completion_cv.wait(lock, [&] { return completed_tasks.load() >= total_tasks; });
    }

    pool.wait();

    // Move results from available_handles back to output_handles
    for (size_t i = 0; i < mega_ag.outputs.size(); ++i) {
        NodeIndex output_index = mega_ag.outputs[i];
        const std::any& result_any = available_handles[output_index];

        Handle* result_handle = nullptr;
        if constexpr (SchemeType == HEScheme::BFV) {
            if (auto* p = std::any_cast<std::shared_ptr<BfvCiphertext>>(&result_any))
                result_handle = p->get();
            else if (auto* p = std::any_cast<std::shared_ptr<BfvCiphertext3>>(&result_any))
                result_handle = p->get();
        } else {
            if (auto* p = std::any_cast<std::shared_ptr<CkksCiphertext>>(&result_any))
                result_handle = p->get();
            else if (auto* p = std::any_cast<std::shared_ptr<CkksCiphertext3>>(&result_any))
                result_handle = p->get();
        }
        if (!result_handle)
            throw std::runtime_error("Cannot extract output ciphertext from result");

        // Move the result into the pre-allocated output Handle
        *output_handles[i] = std::move(*result_handle);
    }

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
        : mega_ag_(MegaAG::from_json(project_path + "/mega_ag.json", Processor::CPU)) {}

    ~FheCpuTask() {}

    int run(gsl::span<CArgument> input_args, gsl::span<CArgument> output_args, Algo algo) {
        switch (algo) {
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

int run_fhe_cpu_task(fhe_task_handle handle,
                     CArgument* input_args,
                     uint64_t n_in_args,
                     CArgument* output_args,
                     uint64_t n_out_args,
                     Algo algo) {
    cpu_wrapper::FheCpuTask* task = (cpu_wrapper::FheCpuTask*)handle;
    gsl::span<CArgument> input_arg_span{input_args, n_in_args};
    gsl::span<CArgument> output_arg_span{output_args, n_out_args};
    return task->run(input_arg_span, output_arg_span, algo);
}
}  // extern "C"
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

/** @file common.h
 * @brief Common utility functions shared across CPU/GPU/FPGA wrappers
 */

#pragma once

#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <any>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <utility>
#include <cstdio>
#include <exception>
#include "nlohmann/json.hpp"
#include "../fhe_ops_lib/schemes/bfv/bfv.h"
#include "../fhe_ops_lib/schemes/ckks/ckks.h"
#include "../lib/thread_pool/BS_thread_pool.hpp"
#include "mega_ag.h"
#include "task_cancellation.h"
#include "../lib/gsl/span"
#include "../tools/task_progress_bar.h"

extern "C" {
#include "../abi/c_structs.h"
}

/// Progress callback for tracking mega_ag execution.
/// @param completed Number of compute nodes completed so far.
/// @param total Total number of compute nodes.
using ProgressCallback = std::function<void(int completed, int total)>;

using namespace fhe_ops_lib;

/**
 * @brief Initialize empty FHE context from parameter JSON
 *
 * This function creates an FHE context from parameter JSON. It supports:
 * - BFV scheme (requires "t" parameter)
 * - CKKS scheme (without "t" parameter)
 *
 * @tparam SchemeType Scheme type (HEScheme::BFV or HEScheme::CKKS)
 * @tparam TContext Context type (BfvContext or CkksContext)
 * @param param_json Parameter JSON containing: log_n, max_level, q, p, and optionally t (BFV only)
 *                   For CKKS: log_default_scale
 *                   For bootstrap: btp_cts_start_level, btp_eval_mod_start_level, btp_stc_start_level, scale
 * @param context Output unique_ptr to store the created context
 *
 * @note This function unifies the following implementations:
 *       - cpu_wrapper::init_context
 *       - gpu_wrapper::init_custom_base_context
 *       - fpga_wrapper::init_bfv_context and init_ckks_context
 */
template <HEScheme SchemeType, typename TContext>
void init_context(const nlohmann::json& param_json, std::unique_ptr<TContext>& context) {
    auto log_n = param_json["log_n"].get<int>();
    auto q = param_json["q"].get<std::vector<uint64_t>>();
    auto p = param_json["p"].get<std::vector<uint64_t>>();

    if constexpr (SchemeType == HEScheme::CKKS) {
        auto log_default_scale = param_json["log_default_scale"].get<int>();
        CkksParameter param = CkksParameter::create_custom_parameter(log_n, log_default_scale, q, p);
        context = std::make_unique<TContext>(CkksContext::create_empty_context(param));

        if (param_json.value("enable_bootstrapping", false)) {
            context->set_enable_bootstrapping(true);
            context->bootstrapping_parameter();
        }

    } else if constexpr (SchemeType == HEScheme::BFV) {
        auto t = param_json["t"].get<uint64_t>();
        BfvParameter param = BfvParameter::create_custom_parameter(log_n, t, q, p);
        context = std::make_unique<TContext>(BfvContext::create_empty_context(param));
    }
}

/**
 * @brief Extract input pointers from CArgument array
 *
 * CArgument.data is treated as a void*[] (array of opaque pointers).
 * Each element is stored as void* in the result; the caller/executor is
 * responsible for interpreting the pointer (e.g. Handle* for fhe_ops_lib,
 * uintptr_t* for Lattigo, or any other plugin-specific type).
 *
 * @param input_args Array of input arguments
 */
inline std::vector<void*> extract_input_handles(gsl::span<CArgument> input_args) {
    std::vector<void*> input_handles;
    for (size_t i = 0; i < input_args.size(); ++i) {
        auto& arg = input_args[i];
        void** ptr_array = static_cast<void**>(arg.data);
        for (int j = 0; j < arg.size; ++j) {
            input_handles.push_back(ptr_array[j]);
        }
    }
    return input_handles;
}

/**
 * @brief Extract output handle map from CArgument array
 *
 * Builds a map from NodeId (mega_ag.outputs[i]) to void* (the pre-allocated
 * output Handle pointer), combining extract_output_handles with output_handle_map
 * construction into a single step.
 *
 * @param mega_ag The computation graph containing output node indices
 * @param output_args Array of output arguments
 * @return Map from NodeId to void* for each output node
 */
inline std::unordered_map<NodeId, void*> extract_output_handle_map(const MegaAG& mega_ag,
                                                                   gsl::span<CArgument> output_args) {
    std::unordered_map<NodeId, void*> output_handle_map;
    size_t output_idx = 0;
    for (size_t i = 0; i < output_args.size(); ++i) {
        auto& arg = output_args[i];
        void** ptr_array = static_cast<void**>(arg.data);
        for (int j = 0; j < arg.size; ++j) {
            output_handle_map[mega_ag.outputs[output_idx]] = ptr_array[j];
            output_idx++;
        }
    }
    return output_handle_map;
}

/**
 * @brief Initialize available_data map from input pointer array
 *
 * Stores each input as shared_ptr<void> in available_data. The executor
 * for each compute node is responsible for interpreting the void* (e.g. casting
 * to Handle* for fhe_ops_lib, uintptr_t* for Lattigo, SealObject* for SEAL, etc.).
 *
 * @param mega_ag The computation graph containing inputs/data
 * @param input_handles Pre-extracted input void* pointers
 * @return Map from NodeId to std::any containing shared_ptr<void>
 */
inline std::unordered_map<NodeId, std::any> init_available_data(const MegaAG& mega_ag,
                                                                const std::vector<void*>& input_handles) {
    std::unordered_map<NodeId, std::any> available_data;

    size_t handle_idx = 0;
    for (NodeId input_id : mega_ag.inputs) {
        available_data[input_id] = std::shared_ptr<void>(input_handles[handle_idx], [](void*) {});
        handle_idx++;
    }

    return available_data;
}

/**
 * @brief Get data reference counts for memory management
 *
 * This function calculates how many times each data node will be consumed
 * (i.e., how many compute nodes have it as an input).
 *
 * @param mega_ag The computation graph containing data nodes
 * @return Map from NodeId to atomic reference count
 */
inline std::unordered_map<NodeId, std::atomic<int>> get_data_ref_counts(const MegaAG& mega_ag) {
    std::unordered_map<NodeId, std::atomic<int>> data_ref_counts;

    for (const auto& [data_id, data_node] : mega_ag.data) {
        int ref_count = static_cast<int>(data_node.successors.size());
        data_ref_counts[data_id].store(ref_count);
    }

    return data_ref_counts;
}

/**
 * @brief Task scheduling entry for the priority queue.
 *
 * Higher priority value runs first.
 */
struct TaskInfo {
    int priority;
    NodeId id;

    bool operator<(const TaskInfo& other) const {
        return priority < other.priority;
    }
};

using OtherArgsCallback = std::function<std::vector<std::any>(const CompoundComputeNode&)>;
using BackendTaskSubmitter = std::function<void(NodeId,
                                                std::mutex&,
                                                std::priority_queue<TaskInfo>&,
                                                std::set<NodeId>&,
                                                std::atomic<size_t>&,
                                                std::atomic<size_t>&,
                                                std::condition_variable&,
                                                std::mutex&,
                                                std::unordered_map<NodeId, std::atomic<int>>&)>;

struct RunTasksOptions {
    OtherArgsCallback get_other_args;
    BackendTaskSubmitter submit_backend_task;
    std::function<void()> cleanup;
    ProgressCallback progress_callback;
    const std::atomic<bool>* cancel_flag = nullptr;
};

/**
 * @brief Run tasks with CPU thread pool and optional backend task submission
 *
 * This function runs the main task dispatcher loop in the calling thread.
 * CPU tasks (on_cpu == true) are submitted to the CPU thread pool.
 * Backend tasks (on_cpu == false) are submitted via the optional callback (for GPU/FPGA).
 *
 * @tparam TContext Context type (BfvContext, CkksContext, or CkksBtpContext)
 * @param mega_ag The computation graph
 * @param pool CPU thread pool for parallel execution
 * @param base_context Shared context used by all CPU tasks
 * @param available_data Map of available data indexed by NodeId
 * @param options Optional callbacks and cancellation flag for backend submission, cleanup, and progress.
 */
template <typename TContext>
void run_tasks(const MegaAG& mega_ag,
               BS::priority_thread_pool& pool,
               const std::unique_ptr<TContext>& base_context,
               std::unordered_map<NodeId, std::any>& available_data,
               const RunTasksOptions& options = {}) {
    // Initialize reference counts for memory management
    std::unordered_map<NodeId, std::atomic<int>> data_ref_counts = get_data_ref_counts(mega_ag);

    size_t task_count(mega_ag.computes.size());

    // Progress bar for task completion tracking
    TaskProgressBar progress_bar(task_count);

    // Task scheduling structures
    std::mutex m_mutex;
    std::mutex abi_export_mutex;
    std::atomic<size_t> total_tasks(task_count);
    std::atomic<size_t> completed_tasks(0);
    std::condition_variable completion_cv;
    std::mutex completion_mutex;
    std::priority_queue<TaskInfo> task_queue;
    std::set<NodeId> queued_computes;
    std::exception_ptr first_exception;
    std::mutex exception_mutex;
    std::atomic<bool> failed(false);

    // Progress callback throttle state (best-effort, no mutex)
    using SteadyClock = std::chrono::steady_clock;
    std::atomic<SteadyClock::rep> last_progress_time{0};
    constexpr auto progress_interval = std::chrono::milliseconds(100);

    // Define CPU task submission function
    std::function<void(NodeId, const std::vector<std::any>&)> submit_task =
        [&](NodeId task_id, const std::vector<std::any>& other_args) {
            const BS::priority_t pool_priority = mega_ag.computes.at(task_id).priority;
            pool.detach_task(
                [task_id, &mega_ag, &completed_tasks, &total_tasks, &m_mutex, &abi_export_mutex, &completion_mutex,
                 &completion_cv, &available_data, &base_context, &task_queue, &queued_computes, &data_ref_counts,
                 other_args, &options, &last_progress_time, progress_interval, &first_exception, &exception_mutex,
                 &failed]() {
                    const CompoundComputeNode& compute_node = mega_ag.computes.at(task_id);
                    const std::vector<DatumNode*>& compute_input_nodes = compute_node.input_nodes;

                    // Cache input data for this thread
                    std::unordered_map<NodeId, std::any> thread_data_cache;
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        for (const auto* input_node : compute_input_nodes) {
                            thread_data_cache[input_node->id] = available_data.at(input_node->id);
                        }
                    }

                    // Prepare execution context
                    std::vector<std::any> exec_other_args = other_args;
                    if (compute_contains_operation(compute_node, OperationType::EXPORT_TO_ABI)) {
                        exec_other_args.push_back(&abi_export_mutex);
                    }

                    ExecutionContext exec_ctx;
                    exec_ctx.context = base_context.get();
                    exec_ctx.other_args = std::move(exec_other_args);

                    try {
                        if (options.cancel_flag && options.cancel_flag->load()) {
                            return;
                        }
                        compute_node.execute(exec_ctx, thread_data_cache);
                    } catch (...) {
                        {
                            std::lock_guard<std::mutex> lock(exception_mutex);
                            if (!first_exception) {
                                first_exception = std::current_exception();
                            }
                        }
                        failed.store(true);
                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            while (!task_queue.empty()) {
                                task_queue.pop();
                            }
                        }
                        completed_tasks.fetch_add(1);
                        std::lock_guard<std::mutex> lock(completion_mutex);
                        completion_cv.notify_all();
                        return;
                    }

                    // Update results and find newly available tasks
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        for (const auto* output_node : compute_node.output_nodes) {
                            available_data[output_node->id] = thread_data_cache.at(output_node->id);
                        }

                        // Clean up unreferenced data
                        mega_ag.purge_unused_data(compute_node, data_ref_counts, available_data);

                        auto newly_available_computes = mega_ag.step_available_computes(compute_node, available_data);

                        for (const auto& new_task_id : newly_available_computes) {
                            if (queued_computes.find(new_task_id) == queued_computes.end()) {
                                int pri = mega_ag.computes.at(new_task_id).priority;
                                task_queue.push({pri, new_task_id});
                                queued_computes.insert(new_task_id);
                            }
                        }
                    }

                    // Check if all tasks are completed
                    size_t prev = completed_tasks.fetch_add(1);
                    if (options.progress_callback) {
                        auto now = SteadyClock::now().time_since_epoch().count();
                        auto last = last_progress_time.load(std::memory_order_relaxed);
                        bool is_final = (prev + 1 >= total_tasks);
                        bool throttle_ok = (now - last) >=
                                           std::chrono::duration_cast<SteadyClock::duration>(progress_interval).count();
                        if (is_final || throttle_ok) {
                            last_progress_time.store(now, std::memory_order_relaxed);
                            options.progress_callback(static_cast<int>(prev + 1), static_cast<int>(total_tasks.load()));
                        }
                    }
                    if (prev + 1 >= total_tasks) {
                        std::lock_guard<std::mutex> lock(completion_mutex);
                        completion_cv.notify_all();
                    }
                },
                pool_priority);
        };

    // Get initial available computes and initialize task queue
    std::unordered_set<NodeId> available_computes = mega_ag.get_available_computes(available_data);
    for (const auto& task_id : available_computes) {
        int pri = mega_ag.computes.at(task_id).priority;
        task_queue.push({pri, task_id});
        queued_computes.insert(task_id);
    }

    bool cancelled = false;

    // Main task dispatcher loop
    while (true) {
        if (failed.load()) {
            std::lock_guard<std::mutex> lock(m_mutex);
            while (!task_queue.empty()) {
                task_queue.pop();
            }
            break;
        }

        if (options.cancel_flag && options.cancel_flag->load()) {
            std::lock_guard<std::mutex> lock(m_mutex);
            while (!task_queue.empty()) {
                task_queue.pop();
            }
            cancelled = true;
            break;
        }

        NodeId next_task;
        bool has_task = false;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!task_queue.empty()) {
                next_task = task_queue.top().id;
                task_queue.pop();
                has_task = true;
            }
        }

        if (has_task) {
            progress_bar.update(completed_tasks.load());

            const CompoundComputeNode& compute_node = mega_ag.computes.at(next_task);
            if (compute_node.on_cpu) {
                // Submit to CPU thread pool
                std::vector<std::any> other_args_vec;
                if (options.get_other_args) {
                    other_args_vec = options.get_other_args(compute_node);
                }
                submit_task(next_task, other_args_vec);
            } else if (options.submit_backend_task) {
                // Submit to backend handler (GPU/FPGA) with shared state references
                options.submit_backend_task(next_task, m_mutex, task_queue, queued_computes, completed_tasks,
                                            total_tasks, completion_cv, completion_mutex, data_ref_counts);
            }
            // else: skip non-CPU tasks if no handler provided (shouldn't happen in well-formed graphs)
        } else {
            if (completed_tasks.load() >= total_tasks) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Wait for all tasks to complete
    if (!cancelled && !failed.load()) {
        std::unique_lock<std::mutex> lock(completion_mutex);
        completion_cv.wait(lock, [&] { return completed_tasks.load() >= total_tasks; });
    }

    pool.wait();

    if (options.cleanup) {
        options.cleanup();
    }

    progress_bar.finalize();

    if (cancelled) {
        throw mega_ag_runner::TaskCancelled();
    }

    if (first_exception) {
        std::rethrow_exception(first_exception);
    }
}

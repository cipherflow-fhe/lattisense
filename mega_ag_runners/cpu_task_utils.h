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
#include <cstdio>
#include "nlohmann/json.hpp"
#include "../fhe_ops_lib/fhe_lib_v2.h"
#include "../lib/thread_pool/BS_thread_pool.hpp"
#include "mega_ag.h"
#include "../lib/gsl/span"

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
 * - Bootstrap contexts (CkksBtpContext when bootstrap parameters present)
 *
 * @tparam SchemeType Scheme type (HEScheme::BFV or HEScheme::CKKS)
 * @tparam TContext Context type (BfvContext, CkksContext, or CkksBtpContext)
 * @param param_json Parameter JSON containing: n, max_level, q, p, and optionally t (BFV only)
 *                   For bootstrap: btp_cts_start_level, btp_eval_mod_start_level, btp_stc_start_level, scale
 * @param context Output unique_ptr to store the created context
 *
 * @note This function unifies the following implementations:
 *       - cpu_wrapper::init_context
 *       - gpu_wrapper::init_custom_base_context
 *       - fpga_wrapper::init_bfv_context and init_ckks_context
 */
template <HEScheme SchemeType, typename TContext>
void init_empty_context(const nlohmann::json& param_json, std::unique_ptr<TContext>& context) {
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

/**
 * @brief Set encryption keys (RLK, GLK, SWK) in context from input arguments
 *
 * This function scans input_args for key types and sets them in the context.
 * Used by CPU/GPU wrappers to initialize context with encryption keys.
 *
 * @tparam TContext Context type (BfvContext, CkksContext, or CkksBtpContext)
 * @param input_args Input arguments array
 * @param context Context to set keys in
 */
template <typename TContext> void set_context_keys(gsl::span<CArgument> input_args, TContext& context) {
    for (size_t i = 0; i < input_args.size(); ++i) {
        auto& arg = input_args[i];
        switch (arg.type) {
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
                }
                break;
            }
            default:
                // Ignore non-key types
                break;
        }
    }
}

/**
 * @brief Initialize context with keys and bootstrapper
 *
 * This function combines three steps:
 * 1. Initialize empty context from parameter JSON
 * 2. Set encryption keys (RLK, GLK, SWK) from input arguments
 * 3. Create bootstrapper if using CkksBtpContext
 *
 * @tparam SchemeType Scheme type (HEScheme::BFV or HEScheme::CKKS)
 * @tparam TContext Context type (BfvContext, CkksContext, or CkksBtpContext)
 * @param param_json Parameter JSON
 * @param input_args Input arguments array containing keys
 * @param context Output unique_ptr to store the initialized context
 */
template <HEScheme SchemeType, typename TContext>
void init_context(const nlohmann::json& param_json,
                  gsl::span<CArgument> input_args,
                  std::unique_ptr<TContext>& context) {
    // Step 1: Initialize empty context
    init_empty_context<SchemeType, TContext>(param_json, context);

    // Step 2: Set keys in context
    set_context_keys(input_args, *context);

    // Step 3: Create bootstrapper if needed
    if constexpr (std::is_same_v<TContext, CkksBtpContext>) {
        context->create_bootstrapper();
    }
}

/**
 * @brief Create shallow copies of context for each thread in the pool
 *
 * This function creates a shallow copy of the given context for each thread
 * in the thread pool, allowing parallel execution with thread-local contexts.
 *
 * @tparam TContext Context type (e.g., BfvContext, CkksContext, CkksBtpContext)
 * @param pool Thread pool for parallel execution
 * @param context Source context to copy from
 * @return Vector of unique_ptrs to context copies, one per thread
 */
template <typename TContext>
std::vector<std::unique_ptr<TContext>> create_thread_contexts(BS::priority_thread_pool& pool,
                                                              const std::unique_ptr<TContext>& context) {
    const size_t num_threads = pool.get_thread_count();
    std::vector<std::unique_ptr<TContext>> context_ptrs(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        pool.detach_task([&context_ptrs, &context, i]() {
            context_ptrs[i] = std::make_unique<TContext>(context->shallow_copy_context());
        });
    }
    pool.wait();

    return context_ptrs;
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
 * @param include_keys Whether to include key arguments (rlk, glk, swk) in the result
 */
inline std::vector<void*> extract_input_handles(gsl::span<CArgument> input_args, bool include_keys = true) {
    std::vector<void*> input_handles;
    for (size_t i = 0; i < input_args.size(); ++i) {
        auto& arg = input_args[i];
        DataType data_type = arg.type;

        // Skip keys if include_keys is false
        if (!include_keys) {
            if (data_type == TYPE_RELIN_KEY || data_type == TYPE_GALOIS_KEY || data_type == TYPE_SWITCH_KEY) {
                continue;
            }
        }

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
 * Builds a map from NodeIndex (mega_ag.outputs[i]) to void* (the pre-allocated
 * output Handle pointer), combining extract_output_handles with output_handle_map
 * construction into a single step.
 *
 * @param mega_ag The computation graph containing output node indices
 * @param output_args Array of output arguments
 * @return Map from NodeIndex to void* for each output node
 */
inline std::unordered_map<NodeIndex, void*> extract_output_handle_map(const MegaAG& mega_ag,
                                                                      gsl::span<CArgument> output_args) {
    std::unordered_map<NodeIndex, void*> output_handle_map;
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
 * For GLK nodes, all galois key nodes share the same shared_ptr<void>.
 *
 * @param mega_ag The computation graph containing inputs/data
 * @param input_handles Pre-extracted input void* pointers
 * @return Map from NodeIndex to std::any containing shared_ptr<void>
 */
inline std::unordered_map<NodeIndex, std::any> init_available_data(const MegaAG& mega_ag,
                                                                   const std::vector<void*>& input_handles) {
    std::unordered_map<NodeIndex, std::any> available_data;

    // Map input pointers
    std::shared_ptr<void> shared_glk_ptr;
    size_t handle_idx = 0;
    for (NodeIndex input_index : mega_ag.inputs) {
        const DatumNode& input_datum = mega_ag.data.at(input_index);

        if (input_datum.datum_type == DataType::TYPE_GALOIS_KEY) {
            // All glk nodes share the same pointer
            if (!shared_glk_ptr) {
                shared_glk_ptr = std::shared_ptr<void>(input_handles[handle_idx], [](void*) {});
                handle_idx++;
            }
            available_data[input_index] = shared_glk_ptr;
        } else {
            available_data[input_index] = std::shared_ptr<void>(input_handles[handle_idx], [](void*) {});
            handle_idx++;
        }
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
 * @return Map from NodeIndex to atomic reference count
 */
inline std::unordered_map<NodeIndex, std::atomic<int>> get_data_ref_counts(const MegaAG& mega_ag) {
    std::unordered_map<NodeIndex, std::atomic<int>> data_ref_counts;

    for (const auto& [data_index, data_node] : mega_ag.data) {
        int ref_count = static_cast<int>(data_node.successors.size());
        data_ref_counts[data_index].store(ref_count);
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
    NodeIndex index;

    bool operator<(const TaskInfo& other) const {
        return priority < other.priority;
    }
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
 * @param base_context Base context to create thread-local copies from
 * @param available_data Map of available data indexed by NodeIndex
 * @param get_other_args Optional callback to get other_args for each CPU task (for FPGA offset_map, etc.)
 * @param submit_backend_task Optional callback to submit backend tasks (for GPU heterogeneous mode)
 *                             Receives: task_index, m_mutex, task_queue, queued_computes,
 *                                      completed_tasks, total_tasks, completion_cv, completion_mutex,
 *                                      data_ref_counts
 *                             If provided, total_tasks = all tasks; otherwise total_tasks = CPU tasks only
 *
 * @note If submit_backend_task is provided, this function handles GPU heterogeneous mode.
 *       Otherwise, it handles pure CPU or FPGA mode (only CPU tasks executed).
 */
template <typename TContext>
void run_tasks(const MegaAG& mega_ag,
               BS::priority_thread_pool& pool,
               const std::unique_ptr<TContext>& base_context,
               std::unordered_map<NodeIndex, std::any>& available_data,
               std::function<std::vector<std::any>(const ComputeNode&)> get_other_args = nullptr,
               std::function<void(NodeIndex,
                                  std::mutex&,
                                  std::priority_queue<TaskInfo>&,
                                  std::set<NodeIndex>&,
                                  std::atomic<size_t>&,
                                  std::atomic<size_t>&,
                                  std::condition_variable&,
                                  std::mutex&,
                                  std::unordered_map<NodeIndex, std::atomic<int>>&)> submit_backend_task = nullptr,
               std::function<void()> cleanup = nullptr,
               ProgressCallback progress_callback = nullptr) {
    // Create thread-local contexts for CPU pool
    std::vector<std::unique_ptr<TContext>> context_ptrs = create_thread_contexts(pool, base_context);

    // Initialize reference counts for memory management
    std::unordered_map<NodeIndex, std::atomic<int>> data_ref_counts = get_data_ref_counts(mega_ag);

    size_t task_count(mega_ag.computes.size());

    // Task scheduling structures
    std::mutex m_mutex;
    std::atomic<size_t> total_tasks(task_count);
    std::atomic<size_t> completed_tasks(0);
    std::condition_variable completion_cv;
    std::mutex completion_mutex;
    std::priority_queue<TaskInfo> task_queue;
    std::set<NodeIndex> queued_computes;

    // Progress callback throttle state (best-effort, no mutex)
    using SteadyClock = std::chrono::steady_clock;
    std::atomic<SteadyClock::rep> last_progress_time{0};
    constexpr auto progress_interval = std::chrono::milliseconds(100);

    // Define CPU task submission function
    std::function<void(NodeIndex, const std::vector<std::any>&)> submit_task =
        [&](NodeIndex task_index, const std::vector<std::any>& other_args) {
            const BS::priority_t pool_priority = mega_ag.computes.at(task_index).priority;
            pool.detach_task(
                [task_index, &mega_ag, &completed_tasks, &total_tasks, &m_mutex, &completion_mutex, &completion_cv,
                 &available_data, &context_ptrs, &task_queue, &queued_computes, &data_ref_counts, other_args,
                 &progress_callback, &last_progress_time, progress_interval]() {
                    auto thread_id = BS::this_thread::get_index().value();

                    const ComputeNode& compute_node = mega_ag.computes.at(task_index);
                    const std::vector<DatumNode*>& compute_input_nodes = compute_node.input_nodes;
                    const DatumNode* compute_output_node = compute_node.output_nodes[0];

                    // Cache input data for this thread
                    std::unordered_map<NodeIndex, std::any> thread_input_cache;
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        for (const auto* input_node : compute_input_nodes) {
                            thread_input_cache[input_node->index] = available_data.at(input_node->index);
                        }
                    }

                    // Prepare execution context
                    ExecutionContext exec_ctx;
                    exec_ctx.context = context_ptrs[thread_id].get();
                    exec_ctx.other_args = other_args;

                    // Execute the compute node using its bound executor
                    std::any output;
                    try {
                        compute_node.executor(exec_ctx, thread_input_cache, output, compute_node);
                    } catch (const std::exception& e) {
                        // Still increment completed_tasks to avoid deadlock
                        if (completed_tasks.fetch_add(1) + 1 >= total_tasks) {
                            std::lock_guard<std::mutex> lock(completion_mutex);
                            completion_cv.notify_all();
                        }
                        return;
                    }

                    // Determine where to store the output
                    NodeIndex output_index = compute_output_node->index;

                    // Update results and find newly available tasks
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        // Store the output
                        available_data[output_index] = output;

                        // Clean up unreferenced data
                        mega_ag.purge_unused_data(compute_node, data_ref_counts, available_data);

                        // Find newly available computes
                        std::unordered_set<NodeIndex> newly_available_computes =
                            mega_ag.step_available_computes(*compute_output_node, available_data);

                        for (const auto& new_task_index : newly_available_computes) {
                            if (queued_computes.find(new_task_index) == queued_computes.end()) {
                                int pri = mega_ag.computes.at(new_task_index).priority;
                                task_queue.push({pri, new_task_index});
                                queued_computes.insert(new_task_index);
                            }
                        }
                    }

                    // Check if all tasks are completed
                    size_t prev = completed_tasks.fetch_add(1);
                    if (progress_callback) {
                        auto now = SteadyClock::now().time_since_epoch().count();
                        auto last = last_progress_time.load(std::memory_order_relaxed);
                        bool is_final = (prev + 1 >= total_tasks);
                        bool throttle_ok = (now - last) >=
                                           std::chrono::duration_cast<SteadyClock::duration>(progress_interval).count();
                        if (is_final || throttle_ok) {
                            last_progress_time.store(now, std::memory_order_relaxed);
                            progress_callback(static_cast<int>(prev + 1), static_cast<int>(total_tasks.load()));
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
    std::unordered_set<NodeIndex> available_computes = mega_ag.get_available_computes(available_data);
    for (const auto& task_index : available_computes) {
        int pri = mega_ag.computes.at(task_index).priority;
        task_queue.push({pri, task_index});
        queued_computes.insert(task_index);
    }

    // Main task dispatcher loop
    while (true) {
        NodeIndex next_task;
        bool has_task = false;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!task_queue.empty()) {
                next_task = task_queue.top().index;
                task_queue.pop();
                has_task = true;
            }
        }

        if (has_task) {
            const ComputeNode& compute_node = mega_ag.computes.at(next_task);
            if (compute_node.on_cpu) {
                // Submit to CPU thread pool
                std::vector<std::any> other_args_vec;
                if (get_other_args) {
                    other_args_vec = get_other_args(compute_node);
                }
                submit_task(next_task, other_args_vec);
            } else if (submit_backend_task) {
                // Submit to backend handler (GPU/FPGA) with shared state references
                submit_backend_task(next_task, m_mutex, task_queue, queued_computes, completed_tasks, total_tasks,
                                    completion_cv, completion_mutex, data_ref_counts);
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
    {
        std::unique_lock<std::mutex> lock(completion_mutex);
        completion_cv.wait(lock, [&] { return completed_tasks.load() >= total_tasks; });
    }

    pool.wait();

    // Call cleanup function if provided (e.g., gpu_pool.wait() for GPU mode)
    if (cleanup) {
        cleanup();
    }
}

// Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include <unordered_map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <set>
#include <memory>
#include <algorithm>
#include <HEonGPU-1.1/heongpu/heongpu.hpp>

#include "nlohmann/json.hpp"
#include "../lib/thread_pool/BS_thread_pool.hpp"
#include "../lib/gsl/span"

#include "../wrapper.h"
#include "../mega_ag.h"
#include "gpu_abi_bridge_executors.h"
#include "../cpu_task_utils.h"
#include "../../fhe_ops_lib/fhe_lib_v2.h"

#ifdef LATTISENSE_DEV
#    include "gpu_mem_monitor.h"
#    include "../cpu_mem_monitor.h"
#endif

extern "C" {
#include "../../abi/c_types.h"
#include "../../abi/c_structs.h"
}

namespace gpu_wrapper {
using namespace fhe_ops_lib;

template <heongpu::Scheme SchemeType>
void init_gpu_context(const nlohmann::json& param_json,
                      heongpu::HEContext<SchemeType>& context,
                      std::unique_ptr<heongpu::HEEncoder<SchemeType>>& encoder,
                      std::unique_ptr<heongpu::HEArithmeticOperator<SchemeType>>& operators) {
    auto n = param_json["n"].get<int>();

    auto max_level = param_json["max_level"].get<int>();
    auto q = param_json["q"].get<std::vector<uint64_t>>();
    auto p = param_json["p"].get<std::vector<uint64_t>>();

    heongpu::MemoryPoolConfig pool_config = heongpu::MemoryPoolConfig::Defaults();

    if constexpr (SchemeType == heongpu::Scheme::CKKS) {
        context = heongpu::GenHEContext<SchemeType>(heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(n);

        int slots = param_json["slots"].get<int>();
        context->set_slot_count(slots);

        std::vector<Data64> Q, P;
        for (int i = 0; i <= max_level; i++) {
            Q.push_back(Data64(q[i]));
        }

        for (int i = 0; i < p.size(); i++) {
            P.push_back(Data64(p[i]));
        }
        context->set_coeff_modulus_values(Q, P);
        context->generate(pool_config);

        encoder = std::make_unique<heongpu::HEEncoder<SchemeType>>(context);
        operators = std::make_unique<heongpu::HEArithmeticOperator<SchemeType>>(context, *encoder);

        if (param_json.contains("btp_output_level")) {
            int cts_start_level = param_json["btp_cts_start_level"].get<int>();
            int cts_depth = param_json["btp_cts_depth"].get<int>();
            double cts_bsgs_ratio = param_json["btp_cts_bsgs_ratio"].get<double>();

            uint64_t eval_mod_q = param_json["btp_eval_mod_q"].get<uint64_t>();
            int eval_mod_start_level = param_json["btp_eval_mod_start_level"].get<int>();
            double eval_mod_scaling_factor = param_json["btp_eval_mod_scaling_factor"].get<double>();
            double eval_mod_message_ratio = param_json["btp_eval_mod_message_ratio"].get<double>();
            int eval_mod_k = param_json["btp_eval_mod_k"].get<int>();
            int eval_mod_sine_deg = param_json["btp_eval_mod_sine_deg"].get<int>();
            int eval_mod_double_angle = param_json["btp_eval_mod_double_angle"].get<int>();
            int eval_mod_arcsine_deg = param_json["btp_eval_mod_arcsine_deg"].get<int>();

            int stc_start_level = param_json["btp_stc_start_level"].get<int>();
            int stc_depth = param_json["btp_stc_depth"].get<int>();
            double stc_bsgs_ratio = param_json["btp_stc_bsgs_ratio"].get<double>();

            double scale = param_json["scale"].get<double>();

            heongpu::EncodingMatrixConfig cts_config(heongpu::LinearTransformType::COEFFS_TO_SLOTS, cts_start_level,
                                                     cts_bsgs_ratio, cts_depth);
            heongpu::EvalModConfig eval_mod_config(eval_mod_q, eval_mod_start_level, eval_mod_message_ratio, eval_mod_k,
                                                   eval_mod_sine_deg, eval_mod_double_angle, eval_mod_arcsine_deg,
                                                   eval_mod_scaling_factor);
            heongpu::EncodingMatrixConfig stc_config(heongpu::LinearTransformType::SLOTS_TO_COEFFS, stc_start_level,
                                                     stc_bsgs_ratio, stc_depth);

            heongpu::BootstrappingConfigV2 boot_config(stc_config, eval_mod_config, cts_config);

            operators->generate_bootstrapping_params_v2(scale, boot_config);
        }

    } else {
        int t = param_json["t"].get<uint64_t>();
        context = heongpu::GenHEContext<SchemeType>(heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(n);

        std::vector<Data64> Q, P;
        for (int i = 0; i <= max_level; i++) {
            Q.push_back(Data64(q[i]));
        }
        for (int i = 0; i < p.size(); i++) {
            P.push_back(Data64(p[i]));
        }
        context->set_coeff_modulus_values(Q, P);
        context->set_plain_modulus(t);
        context->generate(pool_config);

        encoder = std::make_unique<heongpu::HEEncoder<SchemeType>>(context);
        operators = std::make_unique<heongpu::HEArithmeticOperator<SchemeType>>(context, *encoder);
    }
}

template <heongpu::Scheme SchemeType, typename TContext>
void _run_mega_ag_impl(gsl::span<CArgument> input_args,
                       gsl::span<CArgument> output_args,
                       const MegaAG& mega_ag,
                       ProgressCallback progress_cb = nullptr,
                       int gpu_device = 0,
                       const std::atomic<bool>* cancel_flag = nullptr) {
    // cudaSetDevice is thread-local; new threads in the pool default to device 0.
    // Use the runtime-specified device so all worker threads bind to the same device.
    const int device = gpu_device;
    CHECK(cudaSetDevice(device));

    // Initialize GPU context and operators for GPU FHE operations
    heongpu::HEContext<SchemeType> context;
    std::unique_ptr<heongpu::HEEncoder<SchemeType>> encoder;
    std::unique_ptr<heongpu::HEArithmeticOperator<SchemeType>> operators;

    init_gpu_context<SchemeType>(mega_ag.parameter, context, encoder, operators);

    // GPU streams for FHE computations
    const int num_streams = 2;
    std::vector<cudaStream_t> streams(num_streams);
    std::vector<heongpu::ExecutionOptions> stream_options(num_streams);

    // GPU thread pool for GPU FHE operations (priority-enabled to avoid high-priority tasks being starved)
    BS::priority_thread_pool gpu_pool(num_streams);

    for (int i = 0; i < num_streams; i++) {
        CHECK(cudaStreamCreate(&streams[i]));
        stream_options[i] = heongpu::ExecutionOptions().set_stream(streams[i]);
    }

    // CPU thread pool for CPU tasks (custom nodes + ABI bridge nodes)
    const int num_cpu_threads = std::min(16, static_cast<int>(std::thread::hardware_concurrency())) - num_streams;
    BS::priority_thread_pool cpu_pool(num_cpu_threads > 0 ? num_cpu_threads : 1);

    // Create CPU contexts for CPU nodes (ABI bridge only, no keys needed)
    constexpr HEScheme cpu_scheme = (SchemeType == heongpu::Scheme::BFV) ? HEScheme::BFV : HEScheme::CKKS;
    std::unique_ptr<TContext> base_cpu_context;
    init_empty_context<cpu_scheme, TContext>(mega_ag.parameter, base_cpu_context);

    std::vector<void*> input_handles = extract_input_handles(input_args);

    std::unordered_map<NodeIndex, std::any> available_data = init_available_data(mega_ag, input_handles);

    // Build output handle map: output NodeIndex -> void* handle pointer
    std::unordered_map<NodeIndex, void*> output_handle_map = extract_output_handle_map(mega_ag, output_args);

    // GPU-specific data structures
    std::unordered_map<NodeIndex, cudaEvent_t> data_ready_events;
    std::shared_ptr<heongpu::Galoiskey<SchemeType>> galois_key;
    std::mutex galois_key_mutex;

    // Collect all galois elements and the shared maximum GLK level from data nodes
    std::vector<uint32_t> all_galois_elts;
    int galois_key_level = -1;
    for (const auto& [data_index, data_node] : mega_ag.data) {
        if (data_node.datum_type == DataType::TYPE_GALOIS_KEY && data_node.fhe_prop.has_value()) {
            galois_key_level = std::max(galois_key_level, data_node.fhe_prop->level);
            if (data_node.fhe_prop->p.has_value()) {
                all_galois_elts.push_back(data_node.fhe_prop->p->galois_element);
            }
        }
    }

    // Define GPU task submission function
    // This receives shared state from run_tasks
    std::function<void(NodeIndex, std::mutex&, std::priority_queue<TaskInfo>&, std::set<NodeIndex>&,
                       std::atomic<size_t>&, std::atomic<size_t>&, std::condition_variable&, std::mutex&,
                       std::unordered_map<NodeIndex, std::atomic<int>>&)>
        submit_gpu_task = [&](NodeIndex task_index, std::mutex& m_mutex, std::priority_queue<TaskInfo>& task_queue,
                              std::set<NodeIndex>& queued_computes, std::atomic<size_t>& completed_tasks,
                              std::atomic<size_t>& total_tasks, std::condition_variable& completion_cv,
                              std::mutex& completion_mutex,
                              std::unordered_map<NodeIndex, std::atomic<int>>& data_ref_counts) {
            const BS::priority_t pool_priority = mega_ag.computes.at(task_index).priority;
            gpu_pool.detach_task(
                [task_index, pool_priority, device, &gpu_pool, &mega_ag, &m_mutex, &task_queue, &queued_computes,
                 &completed_tasks, &total_tasks, &completion_cv, &completion_mutex, &available_data, &operators,
                 &encoder, &data_ready_events, &stream_options, &streams, &context, &galois_key, &galois_key_mutex,
                 &data_ref_counts, &all_galois_elts, &galois_key_level, cancel_flag]() {
                    CHECK(cudaSetDevice(device));
                    if (cancel_flag && cancel_flag->load()) {
                        return;
                    }
                    auto stream_id = BS::this_thread::get_index().value();

                    const CompoundComputeNode& compute_node = mega_ag.computes.at(task_index);

                    const std::vector<DatumNode*>& compute_input_nodes = compute_node.input_nodes;
                    const bool has_load_to_backend =
                        compute_contains_operation(compute_node, OperationType::LOAD_TO_BACKEND);
                    const bool has_store_from_backend =
                        compute_contains_operation(compute_node, OperationType::STORE_FROM_BACKEND);
                    const bool has_encode_ringt = compute_contains_operation(compute_node, OperationType::ENCODE_RINGT);

                    std::vector<cudaEvent_t> events_to_wait;
                    std::unordered_map<NodeIndex, std::any> thread_data_cache;
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        // Check if all BACKEND input events are available.
                        // ABI inputs for LOAD_TO_BACKEND don't have events.
                        bool events_ready = true;
                        if (!has_load_to_backend && !has_encode_ringt) {
                            for (const auto* input_node : compute_input_nodes) {
                                auto event_it = data_ready_events.find(input_node->index);
                                if (event_it == data_ready_events.end()) {
                                    events_ready = false;
                                    break;
                                }
                            }
                        }

                        if (!events_ready) {
                            queued_computes.erase(task_index);
                            task_queue.push({compute_node.priority, task_index});
                            return;
                        }

                        // Collect events to wait for and cache data pointers.
                        for (const auto* input_node : compute_input_nodes) {
                            thread_data_cache[input_node->index] = available_data[input_node->index];

                            if (!has_load_to_backend && !has_encode_ringt) {
                                events_to_wait.push_back(data_ready_events.at(input_node->index));
                            }
                        }
                    }

                    // Wait for all required events outside of locks
                    for (auto& event : events_to_wait) {
                        CHECK(cudaStreamWaitEvent(streams[stream_id], event, 0));
                    }

                    // Execute computation using unified executor
                    H2DBatch h2d_batch;
                    D2HBatch d2h_batch;
                    ExecutionContext exec_ctx;
                    exec_ctx.context = operators.get();
                    exec_ctx.other_args.push_back(&stream_options[stream_id]);
                    exec_ctx.other_args.push_back(&context);
                    if (has_encode_ringt) {
                        exec_ctx.other_args.push_back(encoder.get());
                    }

                    if (has_load_to_backend) {
                        exec_ctx.other_args.push_back(&galois_key);
                        exec_ctx.other_args.push_back(&galois_key_mutex);
                        exec_ctx.other_args.push_back(&all_galois_elts);
                        exec_ctx.other_args.push_back(&galois_key_level);
                        exec_ctx.other_args.push_back(&h2d_batch);
                    }
                    if (has_store_from_backend) {
                        exec_ctx.other_args.push_back(&d2h_batch);
                    }

                    compute_node.execute(exec_ctx, thread_data_cache);
                    if (has_load_to_backend) {
                        h2d_batch.submit(streams[stream_id]);
                    }
                    if (has_store_from_backend) {
                        d2h_batch.submit(streams[stream_id]);
                    }

                    // Create events for GPU backend outputs (not STORE_FROM_BACKEND which outputs to C struct)
                    std::vector<cudaEvent_t> output_events;
                    if (!has_store_from_backend) {
                        output_events.reserve(compute_node.output_nodes.size());
                        for (size_t i = 0; i < compute_node.output_nodes.size(); ++i) {
                            cudaEvent_t output_event;
                            CHECK(cudaEventCreate(&output_event));
                            CHECK(cudaEventRecord(output_event, streams[stream_id]));
                            output_events.push_back(output_event);
                        }
                    }

                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        for (const auto* output_node : compute_node.output_nodes) {
                            available_data[output_node->index] = thread_data_cache.at(output_node->index);
                        }
                        auto newly_available_computes = mega_ag.step_available_computes(compute_node, available_data);

                        for (size_t i = 0; i < output_events.size(); ++i) {
                            data_ready_events[compute_node.output_nodes[i]->index] = output_events[i];
                        }

                        for (const auto& new_task_index : newly_available_computes) {
                            if (queued_computes.find(new_task_index) == queued_computes.end()) {
                                task_queue.push({mega_ag.computes.at(new_task_index).priority, new_task_index});
                                queued_computes.insert(new_task_index);
                            }
                        }
                    }

                    gpu_pool.detach_task(
                        [compute_node, output_events, device, &mega_ag, &m_mutex, &available_data, &data_ref_counts]() {
                            CHECK(cudaSetDevice(device));
                            for (auto& output_event : output_events) {
                                CHECK(cudaEventSynchronize(output_event));
                            }

                            {
                                std::lock_guard<std::mutex> lock(m_mutex);
                                mega_ag.purge_unused_data(compute_node, data_ref_counts, available_data);
                            }
                        },
                        pool_priority);

                    // Check if all tasks are completed (in this thread, not async lambda)
                    if (completed_tasks.fetch_add(1) + 1 >= total_tasks) {
                        std::lock_guard<std::mutex> lock(completion_mutex);
                        completion_cv.notify_all();
                    }
                },
                pool_priority);
        };

    // Define get_other_args for IMPORT_FROM_ABI nodes: pass all output Handle* entries.
    auto get_other_args = [&](const CompoundComputeNode& compute_node) -> std::vector<std::any> {
        if (compute_contains_operation(compute_node, OperationType::IMPORT_FROM_ABI)) {
            return {&output_handle_map};
        }
        return {};
    };

#ifdef LATTISENSE_DEV
    MemoryMonitor cpu_mem_monitor(100);  // sample every 100 ms
    cpu_mem_monitor.start(MemoryMonitor::next_csv_path(".", "mem_usage_cpu"));
    GpuMemoryMonitor gpu_mem_monitor(100);  // sample every 100 ms
    gpu_mem_monitor.start(GpuMemoryMonitor::next_csv_path("mem_usage_gpu"));
#endif
    RunTasksOptions options;
    options.get_other_args = get_other_args;
    options.submit_backend_task = submit_gpu_task;
    options.cleanup = [&gpu_pool, &data_ready_events, &streams]() {
        gpu_pool.wait();
        for (auto stream : streams) {
            CHECK(cudaStreamSynchronize(stream));
        }
        for (auto& pair : data_ready_events) {
            cudaEvent_t event = pair.second;
            gpu_pool.detach_task([event]() { CHECK(cudaEventDestroy(event)); });
        }
        gpu_pool.wait();
    };
    options.progress_callback = progress_cb;
    options.cancel_flag = cancel_flag;

#ifdef LATTISENSE_DEV
    try {
#endif
        run_tasks(mega_ag, cpu_pool, base_cpu_context, available_data, options);
#ifdef LATTISENSE_DEV
    } catch (...) {
        cpu_mem_monitor.stop();
        gpu_mem_monitor.stop();
        throw;
    }
    cpu_mem_monitor.stop();
    gpu_mem_monitor.stop();
#endif
}

// Dispatch function to call _run_mega_ag_impl with appropriate TContext
template <heongpu::Scheme SchemeType>
void _run_mega_ag(gsl::span<CArgument> input_args,
                  gsl::span<CArgument> output_args,
                  const MegaAG& mega_ag,
                  ProgressCallback progress_cb = nullptr,
                  int gpu_device = 0,
                  const std::atomic<bool>* cancel_flag = nullptr) {
    if constexpr (SchemeType == heongpu::Scheme::CKKS) {
        if (mega_ag.parameter.contains("btp_output_level")) {
            _run_mega_ag_impl<SchemeType, CkksBtpContext>(input_args, output_args, mega_ag, progress_cb, gpu_device,
                                                          cancel_flag);
        } else {
            _run_mega_ag_impl<SchemeType, CkksContext>(input_args, output_args, mega_ag, progress_cb, gpu_device,
                                                       cancel_flag);
        }
    } else {
        _run_mega_ag_impl<SchemeType, BfvContext>(input_args, output_args, mega_ag, progress_cb, gpu_device,
                                                  cancel_flag);
    }
}

class FheGpuTask {
public:
    FheGpuTask(const std::string& project_path) {
        mega_ag_ = MegaAG::load(project_path, Processor::GPU);

        cudaSetDevice(0);  // Warm up default device; actual device is selected at run time

        // Warm up the CUDA context, so that the computation time measurment is more accurate.
        heongpu::HEContext<heongpu::Scheme::BFV> context =
            heongpu::GenHEContext<heongpu::Scheme::BFV>(heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(8192);
        context->set_coeff_modulus_values({18014398508400641, 18014398510645249, 18014398510661633},
                                          {36028797018652673});
        context->set_plain_modulus(65537);
        heongpu::MemoryPoolConfig pool_config = heongpu::MemoryPoolConfig::Defaults();
        context->generate(pool_config);
        heongpu::HEKeyGenerator<heongpu::Scheme::BFV> keygen(context);
        heongpu::Secretkey<heongpu::Scheme::BFV> secret_key(context);
        keygen.generate_secret_key(secret_key);
    }

    ~FheGpuTask() {}

    void bind_abi_bridge_executors(const ExecutorFunc& abi_export, const ExecutorFunc& abi_import) {
        // Create GPU backend bridge executors based on algorithm
        ExecutorFunc load_to_gpu;
        ExecutorFunc store_from_gpu;

        if (mega_ag_.algo == ALGO_BFV) {
            load_to_gpu = create_load_to_gpu_executor<heongpu::Scheme::BFV>();
            store_from_gpu = create_store_from_gpu_executor<heongpu::Scheme::BFV>();
        } else if (mega_ag_.algo == ALGO_CKKS) {
            load_to_gpu = create_load_to_gpu_executor<heongpu::Scheme::CKKS>();
            store_from_gpu = create_store_from_gpu_executor<heongpu::Scheme::CKKS>();
        } else {
            throw std::runtime_error("Unsupported algorithm for GPU bridge executors");
        }

        // Bind ABI bridge executors (export, import, load, store)
        mega_ag_.bind_abi_bridge_executors(abi_export, abi_import, load_to_gpu, store_from_gpu);
    }

    void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) {
        mega_ag_.bind_custom_executors(custom_executors);
    }

    void request_cancel() noexcept {
        std::lock_guard<std::mutex> lock(cancel_mutex_);
        if (cancel_flag_) {
            cancel_flag_->store(true);
        }
    }

    int run(gsl::span<CArgument> input_args,
            gsl::span<CArgument> output_args,
            ProgressCallback progress_cb = nullptr,
            int gpu_device = 0) {
        std::lock_guard<std::mutex> run_lock(run_mutex_);
        auto cancel_flag = std::make_shared<std::atomic<bool>>(false);
        {
            std::lock_guard<std::mutex> lock(cancel_mutex_);
            cancel_flag_ = cancel_flag;
        }

        try {
            switch (mega_ag_.algo) {
                case Algo::ALGO_BFV:
                    _run_mega_ag<heongpu::Scheme::BFV>(input_args, output_args, mega_ag_, progress_cb, gpu_device,
                                                       cancel_flag.get());
                    break;
                case Algo::ALGO_CKKS:
                    _run_mega_ag<heongpu::Scheme::CKKS>(input_args, output_args, mega_ag_, progress_cb, gpu_device,
                                                        cancel_flag.get());
                    break;
                default: throw std::invalid_argument("algo not supported"); break;
            }
            CHECK(cudaDeviceSynchronize());
        } catch (const mega_ag_runner::TaskCancelled&) {
            CHECK(cudaDeviceSynchronize());
            clear_cancel_flag(cancel_flag);
            return FHE_TASK_CANCELLED;
        } catch (...) {
            clear_cancel_flag(cancel_flag);
            throw;
        }

        clear_cancel_flag(cancel_flag);
        return FHE_TASK_OK;
    }

protected:
    void clear_cancel_flag(const std::shared_ptr<std::atomic<bool>>& cancel_flag) noexcept {
        std::lock_guard<std::mutex> lock(cancel_mutex_);
        if (cancel_flag_ == cancel_flag) {
            cancel_flag_.reset();
        }
    }

    MegaAG mega_ag_;
    std::shared_ptr<std::atomic<bool>> cancel_flag_;
    std::mutex cancel_mutex_;
    std::mutex run_mutex_;
};
};  // namespace gpu_wrapper

extern "C" {
fhe_task_handle create_fhe_gpu_task(const char* project_path) {
    gpu_wrapper::FheGpuTask* task = new gpu_wrapper::FheGpuTask(project_path);
    return (fhe_task_handle)task;
}

void release_fhe_gpu_task(fhe_task_handle handle) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    delete task;
}

void cancel_fhe_gpu_task(fhe_task_handle handle) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    if (task) {
        task->request_cancel();
    }
}

void bind_gpu_task_abi_bridge_executors(fhe_task_handle handle, void* abi_export_executor, void* abi_import_executor) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    ExecutorFunc* export_executor = reinterpret_cast<ExecutorFunc*>(abi_export_executor);
    ExecutorFunc* import_executor = reinterpret_cast<ExecutorFunc*>(abi_import_executor);
    task->bind_abi_bridge_executors(*export_executor, *import_executor);
}

void bind_gpu_task_custom_executors(fhe_task_handle handle,
                                    const char** custom_types,
                                    void** executors,
                                    uint64_t n_executors) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    std::unordered_map<std::string, ExecutorFunc> custom_executors;
    for (uint64_t i = 0; i < n_executors; i++) {
        ExecutorFunc* executor_ptr = reinterpret_cast<ExecutorFunc*>(executors[i]);
        custom_executors[std::string(custom_types[i])] = *executor_ptr;
    }
    task->bind_custom_executors(custom_executors);
}

int run_fhe_gpu_task(fhe_task_handle handle,
                     CArgument* input_args,
                     uint64_t n_in_args,
                     CArgument* output_args,
                     uint64_t n_out_args,
                     progress_callback_t progress_cb,
                     void* user_data,
                     int gpu_device) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    gsl::span<CArgument> input_arg_span{input_args, n_in_args};
    gsl::span<CArgument> output_arg_span{output_args, n_out_args};

    ProgressCallback cb;
    if (progress_cb) {
        cb = [progress_cb, user_data](int completed, int total) { progress_cb(completed, total, user_data); };
    }
    return task->run(input_arg_span, output_arg_span, cb, gpu_device);
}
}  // extern "C"

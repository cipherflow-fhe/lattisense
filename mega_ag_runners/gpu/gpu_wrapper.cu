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
#include <cstdlib>
#include <cstring>
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
#include "gpu_plaintext_bulk_loader.h"
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

static bool env_flag_enabled(const char* name, bool default_value) {
    const char* value = std::getenv(name);
    if (!value) {
        return default_value;
    }
    if (std::strcmp(value, "0") == 0 || std::strcmp(value, "false") == 0 || std::strcmp(value, "FALSE") == 0 ||
        std::strcmp(value, "off") == 0 || std::strcmp(value, "OFF") == 0) {
        return false;
    }
    return true;
}

static size_t env_size_or_default(const char* name, size_t default_value) {
    const char* value = std::getenv(name);
    if (!value) {
        return default_value;
    }
    char* end = nullptr;
    unsigned long parsed = std::strtoul(value, &end, 10);
    if (end == value || parsed == 0) {
        return default_value;
    }
    return static_cast<size_t>(parsed);
}

struct CudaHostDeleter {
    void operator()(void* ptr) const {
        if (ptr) {
            cudaFreeHost(ptr);
        }
    }
};

struct CudaDeviceDeleter {
    void operator()(void* ptr) const {
        if (ptr) {
            cudaFree(ptr);
        }
    }
};

struct BulkPlaintextRingtTransferResources {
    std::unique_ptr<void, CudaHostDeleter> host_staging;
    std::unique_ptr<void, CudaDeviceDeleter> device_staging;
    std::unique_ptr<void, CudaDeviceDeleter> device_destinations;
    std::vector<uint64_t*> host_destinations;
};

__global__ void scatter_plaintext_ringt_batch_kernel(uint64_t** destinations,
                                                     const uint64_t* packed_src,
                                                     size_t words_per_plaintext,
                                                     size_t count) {
    size_t total_words = words_per_plaintext * count;
    for (size_t linear = blockIdx.x * blockDim.x + threadIdx.x; linear < total_words;
         linear += blockDim.x * gridDim.x) {
        size_t item = linear / words_per_plaintext;
        size_t word = linear - item * words_per_plaintext;
        destinations[item][word] = packed_src[linear];
    }
}

class CudaEventPool {
public:
    CudaEventPool(int device, size_t initial_size) : device_(device) {
        CHECK(cudaSetDevice(device_));
        for (size_t i = 0; i < initial_size; ++i) {
            free_events_.push_back(create_event());
        }
    }

    ~CudaEventPool() {
        cudaSetDevice(device_);
        for (cudaEvent_t event : all_events_) {
            cudaEventDestroy(event);
        }
    }

    CudaEventPool(const CudaEventPool&) = delete;
    CudaEventPool& operator=(const CudaEventPool&) = delete;

    cudaEvent_t acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (free_events_.empty()) {
            return create_event();
        }

        cudaEvent_t event = free_events_.back();
        free_events_.pop_back();
        return event;
    }

    void release(cudaEvent_t event) {
        if (!event) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        free_events_.push_back(event);
    }

private:
    cudaEvent_t create_event() {
        cudaEvent_t event;
        CHECK(cudaEventCreateWithFlags(&event, cudaEventDisableTiming));
        all_events_.push_back(event);
        return event;
    }

    int device_;
    std::mutex mutex_;
    std::vector<cudaEvent_t> free_events_;
    std::vector<cudaEvent_t> all_events_;
};

struct PooledCudaEvent {
    PooledCudaEvent(CudaEventPool& pool, cudaEvent_t event) : pool(&pool), event(event) {}

    ~PooledCudaEvent() {
        if (pool && event) {
            pool->release(event);
        }
    }

    cudaEvent_t get() const {
        return event;
    }

    CudaEventPool* pool;
    cudaEvent_t event;
};

using PooledCudaEventPtr = std::shared_ptr<PooledCudaEvent>;

static PooledCudaEventPtr acquire_pooled_event(CudaEventPool& event_pool) {
    return std::make_shared<PooledCudaEvent>(event_pool, event_pool.acquire());
}

template <heongpu::Scheme SchemeType>
bool bulk_load_plaintext_ringt_batch(const std::vector<const ComputeNode*>& compute_nodes,
                                     const std::unordered_map<NodeIndex, std::any>& inputs,
                                     std::vector<std::any>& outputs,
                                     std::shared_ptr<BulkPlaintextRingtTransferResources>& transfer_resources,
                                     heongpu::HEContext<SchemeType>& context,
                                     heongpu::ExecutionOptions& stream_option) {
    if (compute_nodes.size() < 2) {
        return false;
    }

    std::vector<std::shared_ptr<CPlaintext>> c_plaintexts;
    c_plaintexts.reserve(compute_nodes.size());
    for (const ComputeNode* compute_node : compute_nodes) {
        if (!is_bulk_plaintext_ringt_load_node(*compute_node)) {
            return false;
        }
        const DatumNode* input_node = compute_node->input_nodes[0];
        auto c_pt_ptr = std::any_cast<std::shared_ptr<CPlaintext>>(inputs.at(input_node->index));
        if (!is_bulk_plaintext_ringt_payload(*c_pt_ptr)) {
            return false;
        }
        c_plaintexts.push_back(c_pt_ptr);
    }

    const size_t payload_bytes = plaintext_payload_bytes(*c_plaintexts[0]);
    const size_t words_per_plaintext = payload_bytes / sizeof(uint64_t);
    const size_t total_bytes = payload_bytes * c_plaintexts.size();

    void* host_staging_raw = nullptr;
    CHECK(cudaHostAlloc(&host_staging_raw, total_bytes, cudaHostAllocDefault));
    auto resources = std::make_shared<BulkPlaintextRingtTransferResources>();
    resources->host_staging.reset(host_staging_raw);

    auto* host_bytes = static_cast<uint8_t*>(resources->host_staging.get());
    for (size_t i = 0; i < c_plaintexts.size(); ++i) {
        std::memcpy(host_bytes + i * payload_bytes, c_plaintexts[i]->poly.contiguous_data, payload_bytes);
    }

    void* device_staging_raw = nullptr;
    CHECK(cudaMalloc(&device_staging_raw, total_bytes));
    resources->device_staging.reset(device_staging_raw);

    void* device_destinations_raw = nullptr;
    CHECK(cudaMalloc(&device_destinations_raw, c_plaintexts.size() * sizeof(uint64_t*)));
    resources->device_destinations.reset(device_destinations_raw);

    outputs.clear();
    outputs.reserve(c_plaintexts.size());
    resources->host_destinations.reserve(c_plaintexts.size());
    for (const auto& c_pt : c_plaintexts) {
        auto output_ptr = std::make_shared<heongpu::Plaintext<SchemeType>>(context, c_pt->level, stream_option);
        resources->host_destinations.push_back(output_ptr->data());
        outputs.push_back(output_ptr);
    }

    cudaStream_t stream = std::any_cast<std::shared_ptr<heongpu::Plaintext<SchemeType>>>(outputs[0])->stream();
    CHECK(cudaMemcpyAsync(resources->device_destinations.get(), resources->host_destinations.data(),
                          c_plaintexts.size() * sizeof(uint64_t*), cudaMemcpyHostToDevice, stream));
    CHECK(cudaMemcpyAsync(resources->device_staging.get(), resources->host_staging.get(), total_bytes,
                          cudaMemcpyHostToDevice, stream));

    constexpr int threads = 256;
    size_t blocks = (words_per_plaintext * c_plaintexts.size() + threads - 1) / threads;
    blocks = std::min<size_t>(blocks, 65535);
    scatter_plaintext_ringt_batch_kernel<<<static_cast<unsigned int>(blocks), threads, 0, stream>>>(
        static_cast<uint64_t**>(resources->device_destinations.get()),
        static_cast<const uint64_t*>(resources->device_staging.get()), words_per_plaintext, c_plaintexts.size());
    CHECK(cudaGetLastError());

    transfer_resources = resources;
    return true;
}

template <typename T>
void purge_unused_data_and_events(const ComputeNode& compute_node,
                                  std::unordered_map<NodeIndex, std::atomic<int>>& data_ref_counts,
                                  std::unordered_map<NodeIndex, T>& available_data,
                                  std::unordered_map<NodeIndex, PooledCudaEventPtr>& data_ready_events) {
    for (const auto* input_node : compute_node.input_nodes) {
        int remaining_use = data_ref_counts[input_node->index].fetch_sub(1) - 1;
        if (remaining_use <= 0 && !input_node->is_output && !input_node->is_input) {
            available_data.erase(input_node->index);
            data_ready_events.erase(input_node->index);
        }
    }
}

template <heongpu::Scheme SchemeType>
void init_gpu_context(const nlohmann::json& param_json,
                      heongpu::HEContext<SchemeType>& context,
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

        auto gpu_encoder = std::make_unique<heongpu::HEEncoder<SchemeType>>(context);
        operators = std::make_unique<heongpu::HEArithmeticOperator<SchemeType>>(context, *gpu_encoder);

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

        auto gpu_encoder = std::make_unique<heongpu::HEEncoder<SchemeType>>(context);
        operators = std::make_unique<heongpu::HEArithmeticOperator<SchemeType>>(context, *gpu_encoder);
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
    std::unique_ptr<heongpu::HEArithmeticOperator<SchemeType>> operators;

    init_gpu_context<SchemeType>(mega_ag.parameter, context, operators);

    // GPU streams for FHE computations. Defaults to the historical value, with
    // an environment override for profiling stream-count sensitivity.
    int num_streams = 16;
    if (const char* env_streams = std::getenv("LATTISENSE_GPU_NUM_STREAMS")) {
        int parsed_streams = std::atoi(env_streams);
        if (parsed_streams > 0) {
            num_streams = parsed_streams;
        }
    }
    std::cout << "[GPU] num_streams: " << num_streams << std::endl;
    std::vector<cudaStream_t> streams(num_streams);
    std::vector<heongpu::ExecutionOptions> stream_options(num_streams);

    size_t initial_event_pool_size = static_cast<size_t>(num_streams) * 4;
    if (const char* env_event_pool_size = std::getenv("LATTISENSE_GPU_EVENT_POOL_SIZE")) {
        int parsed_event_pool_size = std::atoi(env_event_pool_size);
        if (parsed_event_pool_size > 0) {
            initial_event_pool_size = static_cast<size_t>(parsed_event_pool_size);
        }
    }
    CudaEventPool event_pool(device, initial_event_pool_size);
    std::cout << "[GPU] event_pool_size: " << initial_event_pool_size << std::endl;

    // GPU thread pool for GPU FHE operations (priority-enabled to avoid high-priority tasks being starved)
    BS::priority_thread_pool gpu_pool(num_streams);

    for (int i = 0; i < num_streams; i++) {
        CHECK(cudaStreamCreate(&streams[i]));
        stream_options[i] = heongpu::ExecutionOptions().set_stream(streams[i]);
    }

    // CPU thread pool for CPU tasks (custom nodes + ABI bridge nodes)
    int num_cpu_threads = std::min(16, static_cast<int>(std::thread::hardware_concurrency())) - num_streams;
    if (const char* env_cpu_threads = std::getenv("LATTISENSE_GPU_NUM_CPU_THREADS")) {
        int parsed_cpu_threads = std::atoi(env_cpu_threads);
        if (parsed_cpu_threads > 0) {
            num_cpu_threads = parsed_cpu_threads;
        }
    }
    num_cpu_threads = num_cpu_threads > 0 ? num_cpu_threads : 1;
    std::cout << "[GPU] num_cpu_threads: " << num_cpu_threads << std::endl;
    BS::priority_thread_pool cpu_pool(num_cpu_threads);

    // Create CPU contexts for CPU nodes (ABI bridge only, no keys needed)
    constexpr HEScheme cpu_scheme = (SchemeType == heongpu::Scheme::BFV) ? HEScheme::BFV : HEScheme::CKKS;
    std::unique_ptr<TContext> base_cpu_context;
    init_empty_context<cpu_scheme, TContext>(mega_ag.parameter, base_cpu_context);

    std::vector<void*> input_handles = extract_input_handles(input_args);

    std::unordered_map<NodeIndex, std::any> available_data = init_available_data(mega_ag, input_handles);

    // Build output handle map: output NodeIndex -> void* handle pointer
    std::unordered_map<NodeIndex, void*> output_handle_map = extract_output_handle_map(mega_ag, output_args);

    // GPU-specific data structures
    std::unordered_map<NodeIndex, PooledCudaEventPtr> data_ready_events;
    std::shared_ptr<heongpu::Galoiskey<SchemeType>> galois_key;
    std::mutex galois_key_mutex;

    // Collect all galois elements from data nodes
    std::vector<uint32_t> all_galois_elts;
    for (const auto& [data_index, data_node] : mega_ag.data) {
        if (data_node.datum_type == DataType::TYPE_GALOIS_KEY && data_node.fhe_prop->p.has_value()) {
            all_galois_elts.push_back(data_node.fhe_prop->p->galois_element);
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
            std::vector<NodeIndex> task_indices{task_index};
            const bool bulk_pt_ringt_enabled = env_flag_enabled("LATTISENSE_GPU_BULK_PT_RINGT_H2D", true);
            const size_t bulk_pt_ringt_batch_size =
                env_size_or_default("LATTISENSE_GPU_BULK_PT_RINGT_BATCH_SIZE", 64);

            if (bulk_pt_ringt_enabled && bulk_pt_ringt_batch_size > 1 &&
                is_bulk_plaintext_ringt_load_node(mega_ag.computes.at(task_index))) {
                std::lock_guard<std::mutex> lock(m_mutex);
                while (task_indices.size() < bulk_pt_ringt_batch_size && !task_queue.empty()) {
                    NodeIndex next_task_index = task_queue.top().index;
                    if (!is_bulk_plaintext_ringt_load_node(mega_ag.computes.at(next_task_index))) {
                        break;
                    }
                    task_queue.pop();
                    task_indices.push_back(next_task_index);
                }
            }

            gpu_pool.detach_task(
                [task_indices, pool_priority, device, &gpu_pool, &mega_ag, &m_mutex, &task_queue, &queued_computes,
                 &completed_tasks, &total_tasks, &completion_cv, &completion_mutex, &available_data, &operators,
                 &data_ready_events, &stream_options, &streams, &context, &galois_key, &galois_key_mutex,
                 &data_ref_counts, &all_galois_elts, &event_pool, cancel_flag]() {
                    CHECK(cudaSetDevice(device));
                    if (cancel_flag && cancel_flag->load()) {
                        return;
                    }
                    NodeIndex task_index = task_indices[0];
                    auto stream_id = BS::this_thread::get_index().value();

                    if (task_indices.size() > 1) {
                        std::vector<const ComputeNode*> batch_compute_nodes;
                        batch_compute_nodes.reserve(task_indices.size());
                        std::vector<ComputeNode> batch_compute_node_copies;
                        batch_compute_node_copies.reserve(task_indices.size());
                        std::unordered_map<uint64_t, std::any> thread_input_cache;

                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            for (NodeIndex batch_task_index : task_indices) {
                                const ComputeNode& batch_compute_node = mega_ag.computes.at(batch_task_index);
                                batch_compute_nodes.push_back(&batch_compute_node);
                                batch_compute_node_copies.push_back(batch_compute_node);
                                for (const auto* input_node : batch_compute_node.input_nodes) {
                                    thread_input_cache[input_node->index] = available_data[input_node->index];
                                }
                            }
                        }

                        ExecutionContext exec_ctx;
                        exec_ctx.context = operators.get();
                        exec_ctx.other_args.push_back(&stream_options[stream_id]);
                        exec_ctx.other_args.push_back(&context);
                        exec_ctx.other_args.push_back(&galois_key);
                        exec_ctx.other_args.push_back(&galois_key_mutex);
                        exec_ctx.other_args.push_back(&all_galois_elts);

                        std::vector<std::any> outputs;
                        std::shared_ptr<BulkPlaintextRingtTransferResources> transfer_resources;
                        bool used_bulk_loader = bulk_load_plaintext_ringt_batch<SchemeType>(
                            batch_compute_nodes, thread_input_cache, outputs, transfer_resources, context,
                            stream_options[stream_id]);

                        if (!used_bulk_loader) {
                            outputs.clear();
                            outputs.reserve(batch_compute_nodes.size());
                            for (const ComputeNode* batch_compute_node : batch_compute_nodes) {
                                std::any output;
                                batch_compute_node->executor(exec_ctx, thread_input_cache, output, *batch_compute_node);
                                outputs.push_back(output);
                            }
                        }

                        PooledCudaEventPtr output_event = acquire_pooled_event(event_pool);
                        CHECK(cudaEventRecord(output_event->get(), streams[stream_id]));

                        {
                            std::lock_guard<std::mutex> lock(m_mutex);

                            for (size_t i = 0; i < batch_compute_nodes.size(); ++i) {
                                const DatumNode* compute_output_node = batch_compute_nodes[i]->output_nodes[0];
                                available_data[compute_output_node->index] = outputs[i];
                                data_ready_events[compute_output_node->index] = output_event;

                                std::unordered_set<NodeIndex> newly_available_computes =
                                    mega_ag.step_available_computes(*compute_output_node, available_data);

                                for (const auto& new_task_index : newly_available_computes) {
                                    if (queued_computes.find(new_task_index) == queued_computes.end()) {
                                        task_queue.push({mega_ag.computes.at(new_task_index).priority, new_task_index});
                                        queued_computes.insert(new_task_index);
                                    }
                                }
                            }
                        }

                        gpu_pool.detach_task(
                            [batch_compute_node_copies, output_event, transfer_resources, device, &m_mutex,
                             &available_data, &data_ref_counts, &data_ready_events]() {
                                CHECK(cudaSetDevice(device));
                                CHECK(cudaEventSynchronize(output_event->get()));
                                (void)transfer_resources;

                                {
                                    std::lock_guard<std::mutex> lock(m_mutex);
                                    for (const ComputeNode& batch_compute_node : batch_compute_node_copies) {
                                        purge_unused_data_and_events(batch_compute_node, data_ref_counts, available_data,
                                                                     data_ready_events);
                                    }
                                }
                            },
                            pool_priority);

                        size_t prev = completed_tasks.fetch_add(task_indices.size());
                        if (prev + task_indices.size() >= total_tasks) {
                            std::lock_guard<std::mutex> lock(completion_mutex);
                            completion_cv.notify_all();
                        }
                        return;
                    }

                    const ComputeNode& compute_node = mega_ag.computes.at(task_index);

                    // Get operation type outside lock
                    OperationType op =
                        compute_node.fhe_prop.has_value() ? compute_node.fhe_prop->op_type : OperationType::UNKNOWN;

                    const std::vector<DatumNode*>& compute_input_nodes = compute_node.input_nodes;
                    const DatumNode* compute_output_node = compute_node.output_nodes[0];

                    std::vector<PooledCudaEventPtr> events_to_wait;
                    std::unordered_map<uint64_t, std::any> thread_input_cache;
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        // Check if all BACKEND input events are available
                        // ABI inputs (from CPU via LOAD_TO_BACKEND) don't have events
                        bool events_ready = true;
                        if (op != OperationType::LOAD_TO_BACKEND) {
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
                            task_queue.push({mega_ag.computes.at(task_index).priority, task_index});
                            return;
                        }

                        // Collect events to wait for and cache data pointers
                        for (const auto* input_node : compute_input_nodes) {
                            // Cache input data
                            thread_input_cache[input_node->index] = available_data[input_node->index];

                            // Collect events for GPU backend inputs
                            // LOAD_TO_BACKEND loads from CPU (no events), other ops use GPU inputs (have events)
                            if (op != OperationType::LOAD_TO_BACKEND) {
                                events_to_wait.push_back(data_ready_events[input_node->index]);
                            }
                        }
                    }

                    // Wait for all required events outside of locks
                    for (auto& event : events_to_wait) {
                        CHECK(cudaStreamWaitEvent(streams[stream_id], event->get(), 0));
                    }

                    // Execute computation using unified executor
                    ExecutionContext exec_ctx;
                    exec_ctx.context = operators.get();
                    exec_ctx.other_args.push_back(&stream_options[stream_id]);

                    // LOAD_TO_BACKEND needs HEContext and galois_key parameters
                    if (op == OperationType::LOAD_TO_BACKEND) {
                        exec_ctx.other_args.push_back(&context);
                        exec_ctx.other_args.push_back(&galois_key);
                        exec_ctx.other_args.push_back(&galois_key_mutex);
                        exec_ctx.other_args.push_back(&all_galois_elts);
                    }

                    std::any output;

                    // Allocate output based on operation type
                    // GPU FHE ops: pre-allocate GPU ciphertext (except LOAD and STORE which handle allocation
                    // internally) LOAD_TO_BACKEND: allocates GPU memory internally STORE_FROM_BACKEND: outputs to C
                    // struct (not GPU memory)
                    if (op != OperationType::LOAD_TO_BACKEND && op != OperationType::STORE_FROM_BACKEND) {
                        int output_level = compute_output_node->fhe_prop->level;
                        auto output_ptr = std::make_shared<heongpu::Ciphertext<SchemeType>>(context, output_level,
                                                                                            stream_options[stream_id]);
                        output = output_ptr;
                    }

                    compute_node.executor(exec_ctx, thread_input_cache, output, compute_node);

                    // Create event for GPU backend outputs (not STORE_FROM_BACKEND which outputs to C struct)
                    PooledCudaEventPtr output_event;
                    if (op != OperationType::STORE_FROM_BACKEND) {
                        output_event = acquire_pooled_event(event_pool);
                        CHECK(cudaEventRecord(output_event->get(), streams[stream_id]));
                    }

                    {
                        std::lock_guard<std::mutex> lock(m_mutex);

                        // Store output in available_data
                        available_data[compute_output_node->index] = output;

                        // Store event if created
                        if (output_event) {
                            data_ready_events[compute_output_node->index] = output_event;
                        }

                        // Update available computes
                        std::unordered_set<NodeIndex> newly_available_computes =
                            mega_ag.step_available_computes(*compute_output_node, available_data);

                        for (const auto& new_task_index : newly_available_computes) {
                            if (queued_computes.find(new_task_index) == queued_computes.end()) {
                                task_queue.push({mega_ag.computes.at(new_task_index).priority, new_task_index});
                                queued_computes.insert(new_task_index);
                            }
                        }
                    }

                    gpu_pool.detach_task(
                        [compute_node, output_event, device, &m_mutex, &available_data, &data_ref_counts,
                         &data_ready_events]() {
                            CHECK(cudaSetDevice(device));
                            // Wait for GPU computation to complete if event exists
                            if (output_event) {
                                CHECK(cudaEventSynchronize(output_event->get()));
                            }

                            {
                                std::lock_guard<std::mutex> lock(m_mutex);
                                purge_unused_data_and_events(compute_node, data_ref_counts, available_data,
                                                             data_ready_events);
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

    // Define get_other_args for IMPORT_FROM_ABI nodes: pass output Handle* as other_arg
    auto get_other_args = [&](const ComputeNode& compute_node) -> std::vector<std::any> {
        std::vector<std::any> other_args_vec;
        if (compute_node.fhe_prop.has_value() && compute_node.fhe_prop->op_type == OperationType::IMPORT_FROM_ABI) {
            NodeIndex output_node_index = compute_node.output_nodes[0]->index;
            auto it = output_handle_map.find(output_node_index);
            if (it != output_handle_map.end()) {
                other_args_vec.push_back(it->second);
            }
        }
        return other_args_vec;
    };

#ifdef LATTISENSE_DEV
    MemoryMonitor cpu_mem_monitor(100);  // sample every 100 ms
    cpu_mem_monitor.start(MemoryMonitor::next_csv_path("mem_usage_cpu"));
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
        data_ready_events.clear();
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
        mega_ag_ = MegaAG::load(project_path + "/mega_ag.json", Processor::GPU);
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
        warm_up_device(gpu_device);
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
    void warm_up_device(int gpu_device) {
        CHECK(cudaSetDevice(gpu_device));
        if (warmed_device_ == gpu_device) {
            return;
        }

        // Warm up the selected CUDA context before measuring real computation.
        // This must happen after cudaSetDevice(gpu_device): HEonGPU/RMM memory
        // resources are process-global and bind to the current CUDA device.
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
        warmed_device_ = gpu_device;
    }

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
    int warmed_device_ = -1;
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

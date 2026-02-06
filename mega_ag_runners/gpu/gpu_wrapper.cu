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
#include <fstream>
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
#include <HEonGPU-1.1/heongpu.hpp>

#include "nlohmann/json.hpp"
#include "../lib/thread_pool/BS_thread_pool.hpp"
#include "../lib/gsl/span"

#include "../wrapper.h"
#include "../mega_ag.h"
#include "../../fhe_ops_lib/fhe_lib_v2.h"

extern "C" {
#include "../../fhe_ops_lib/fhe_types_v2.h"
#include "../../fhe_ops_lib/structs_v2.h"
}

namespace gpu_wrapper {

void CHECK(cudaError_t err) {
    if (err != cudaSuccess) {
        throw std::runtime_error(cudaGetErrorString(err));
    }
}

template <heongpu::Scheme SchemeType>
void export_plaintext(const CPlaintext& src, heongpu::Plaintext<SchemeType>& dest) {
    int N = src.poly.components->n;
    for (int i = 0; i < src.poly.n_component; i++) {
        CHECK(cudaMemcpyAsync(&(dest.data()[i * N]), src.poly.components[i].data, N * sizeof(uint64_t),
                              cudaMemcpyHostToDevice, dest.stream()));
    }
}

template <heongpu::Scheme SchemeType>
void export_ciphertext(const CCiphertext& src, heongpu::Ciphertext<SchemeType>& dest) {
    int N = src.polys->components->n;
    int n_component = src.polys->n_component;
    for (int i = 0; i < src.degree + 1; i++) {
        for (int j = 0; j < n_component; j++) {
            CHECK(cudaMemcpyAsync(&(dest.data()[i * n_component * N + j * N]), src.polys[i].components[j].data,
                                  N * sizeof(uint64_t), cudaMemcpyHostToDevice, dest.stream()));
        }
    }
}

template <heongpu::Scheme SchemeType>
void export_relin_key(const CRelinKey& src,
                      heongpu::Relinkey<SchemeType>& dest,
                      int first_Q_size,
                      int first_Qprime_size) {
    int N = src.public_keys->polys->components->n;
    int n_public_key = src.n_public_key;
    int level = src.public_keys->level;
    int n_component = src.public_keys->polys->n_component;

    for (int i = 0; i < n_public_key; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < n_component; k++) {
                int k_ = (k < level + 1) ? k : k - (level + 1) + first_Q_size;
                CHECK(
                    cudaMemcpyAsync(&(dest.data()[i * 2 * first_Qprime_size * N + j * first_Qprime_size * N + k_ * N]),
                                    src.public_keys[i].polys[j].components[k].data, N * sizeof(uint64_t),
                                    cudaMemcpyHostToDevice, dest.stream()));
            }
        }
    }
}

template <heongpu::Scheme SchemeType>
void export_galois_key(const CGaloisKey& src,
                       heongpu::Galoiskey<SchemeType>& dest,
                       uint32_t galois_element,
                       int first_Q_size,
                       int first_Qprime_size) {
    int N = src.key_switch_keys->public_keys->polys->components->n;
    int n_public_key = src.key_switch_keys->n_public_key;
    int level = src.key_switch_keys->public_keys->level;
    int n_component = src.key_switch_keys->public_keys->polys->n_component;
    int n_key_switch_key = src.n_key_switch_key;

    for (int i = 0; i < n_key_switch_key; i++) {
        if (src.galois_elements[i] != galois_element) {
            continue;
        }

        for (int j = 0; j < n_public_key; j++) {
            for (int k = 0; k < 2; k++) {
                for (int l = 0; l < n_component; l++) {
                    int l_ = (l < level + 1) ? l : l - (level + 1) + first_Q_size;
                    if (galois_element != 2 * N - 1) {
                        CHECK(cudaMemcpyAsync(
                            &(dest.data(
                                galois_element)[j * 2 * first_Qprime_size * N + k * first_Qprime_size * N + l_ * N]),
                            src.key_switch_keys[i].public_keys[j].polys[k].components[l].data, N * sizeof(uint64_t),
                            cudaMemcpyHostToDevice, dest.stream()));
                    } else {
                        CHECK(cudaMemcpyAsync(
                            &(dest.c_data()[j * 2 * first_Qprime_size * N + k * first_Qprime_size * N + l_ * N]),
                            src.key_switch_keys[i].public_keys[j].polys[k].components[l].data, N * sizeof(uint64_t),
                            cudaMemcpyHostToDevice, dest.stream()));
                    }
                }
            }
        }
    }
}

template <heongpu::Scheme SchemeType>
void export_galois_key(const CGaloisKey& src,
                       heongpu::Galoiskey<SchemeType>& dest,
                       int first_Q_size,
                       int first_Qprime_size) {
    int N = src.key_switch_keys->public_keys->polys->components->n;
    int n_public_key = src.key_switch_keys->n_public_key;
    int level = src.key_switch_keys->public_keys->level;
    int n_component = src.key_switch_keys->public_keys->polys->n_component;
    int n_key_switch_key = src.n_key_switch_key;

    for (int i = 0; i < n_key_switch_key; i++) {
        for (int j = 0; j < n_public_key; j++) {
            for (int k = 0; k < 2; k++) {
                for (int l = 0; l < n_component; l++) {
                    int l_ = (l < level + 1) ? l : l - (level + 1) + first_Q_size;
                    if (src.galois_elements[i] != 2 * N - 1) {
                        CHECK(cudaMemcpyAsync(&(dest.data(src.galois_elements[i])[j * 2 * first_Qprime_size * N +
                                                                                  k * first_Qprime_size * N + l_ * N]),
                                              src.key_switch_keys[i].public_keys[j].polys[k].components[l].data,
                                              N * sizeof(uint64_t), cudaMemcpyHostToDevice, dest.stream()));
                    } else {
                        CHECK(cudaMemcpyAsync(
                            &(dest.c_data()[j * 2 * first_Qprime_size * N + k * first_Qprime_size * N + l_ * N]),
                            src.key_switch_keys[i].public_keys[j].polys[k].components[l].data, N * sizeof(uint64_t),
                            cudaMemcpyHostToDevice, dest.stream()));
                    }
                }
            }
        }
    }
}

template <heongpu::Scheme SchemeType>
void export_switching_key(const ::CKeySwitchKey& src,
                          heongpu::Switchkey<SchemeType>& dest,
                          int first_Q_size,
                          int first_Qprime_size) {
    int N = src.public_keys->polys->components->n;
    int n_public_key = src.n_public_key;
    int level = src.public_keys->level;
    int n_component = src.public_keys->polys->n_component;

    for (int i = 0; i < n_public_key; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < n_component; k++) {
                int k_ = (k < level + 1) ? k : k - (level + 1) + first_Q_size;
                CHECK(
                    cudaMemcpyAsync(&(dest.data()[i * 2 * first_Qprime_size * N + j * first_Qprime_size * N + k_ * N]),
                                    src.public_keys[i].polys[j].components[k].data, N * sizeof(uint64_t),
                                    cudaMemcpyHostToDevice, dest.stream()));
            }
        }
    }
}

template <heongpu::Scheme SchemeType> void import_ciphertext(CCiphertext& dest, heongpu::Ciphertext<SchemeType>& src) {
    int N = src.ring_size();
    int n_component = src.level() + 1;

    for (int i = 0; i < src.size(); i++) {
        for (int j = 0; j < n_component; j++) {
            CHECK(cudaMemcpyAsync(dest.polys[i].components[j].data, &src.data()[i * n_component * N + j * N],
                                  N * sizeof(uint64_t), cudaMemcpyDeviceToHost, src.stream()));
        }
    }
}

template <heongpu::Scheme SchemeType>
void init_context(const nlohmann::json& param_json,
                  std::unique_ptr<heongpu::HEContext<SchemeType>>& context,
                  std::unique_ptr<heongpu::HEArithmeticOperator<SchemeType>>& operators) {
    auto n = param_json["n"].get<int>();

    auto max_level = param_json["max_level"].get<int>();
    auto q = param_json["q"].get<std::vector<uint64_t>>();
    auto p = param_json["p"].get<std::vector<uint64_t>>();

    if constexpr (SchemeType == heongpu::Scheme::CKKS) {
        context = std::make_unique<heongpu::HEContext<SchemeType>>(heongpu::keyswitching_type::KEYSWITCHING_METHOD_II,
                                                                   heongpu::sec_level_type::none);
        context->set_poly_modulus_degree(n);

        std::vector<Data64> Q, P;
        for (int i = 0; i <= max_level; i++) {
            Q.push_back(Data64(q[i]));
        }

        for (int i = 0; i < p.size(); i++) {
            P.push_back(Data64(p[i]));
        }
        context->set_coeff_modulus_values(Q, P);
        context->generate();

        auto gpu_encoder = std::make_unique<heongpu::HEEncoder<SchemeType>>(*context);
        operators = std::make_unique<heongpu::HEArithmeticOperator<SchemeType>>(*context, *gpu_encoder);

        if (param_json.contains("btp_output_level")) {
            int cts_start_level = param_json["btp_cts_start_level"].get<int>();
            int eval_mod_start_level = param_json["btp_eval_mod_start_level"].get<int>();
            int stc_start_level = param_json["btp_stc_start_level"].get<int>();
            double scale = param_json["scale"].get<double>();

            heongpu::EncodingMatrixConfig cts_config(heongpu::LinearTransformType::COEFFS_TO_SLOTS, cts_start_level);
            heongpu::EvalModConfig eval_mod_config(eval_mod_start_level);
            heongpu::EncodingMatrixConfig stc_config(heongpu::LinearTransformType::SLOTS_TO_COEFFS, stc_start_level);

            heongpu::BootstrappingConfigV2 boot_config(stc_config, eval_mod_config, cts_config);

            operators->generate_bootstrapping_params_v2(scale, boot_config);
        }

    } else {
        int t = param_json["t"].get<uint64_t>();
        context = std::make_unique<heongpu::HEContext<SchemeType>>(heongpu::keyswitching_type::KEYSWITCHING_METHOD_II,
                                                                   heongpu::sec_level_type::none);
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
        context->generate();

        auto gpu_encoder = std::make_unique<heongpu::HEEncoder<SchemeType>>(*context);
        operators = std::make_unique<heongpu::HEArithmeticOperator<SchemeType>>(*context, *gpu_encoder);
    }
}

template <heongpu::Scheme SchemeType>
std::any transfer_input_h2c(const uint64_t& input_index,
                            gsl::span<CArgument> args,
                            heongpu::HEContext<SchemeType>& context,
                            const std::vector<uint64_t>& input_indices,
                            heongpu::ExecutionOptions& options,
                            uint32_t galois_element,
                            std::shared_ptr<heongpu::Galoiskey<SchemeType>>& galois_key,
                            std::mutex& galois_key_mutex) {
    int input_index_offset = 0;
    for (int i = 0; i < args.size(); i++) {
        auto& arg = args[i];
        switch (arg.type) {
            case TYPE_PLAINTEXT:
                for (int j = 0; j < arg.size; j++) {
                    if (input_index_offset < input_indices.size() && input_indices[input_index_offset] == input_index) {
                        auto level = ((CPlaintext*)(arg.data))[j].level;
                        heongpu::Plaintext<SchemeType> pt = heongpu::Plaintext<SchemeType>(context, level, options);
                        export_plaintext(((CPlaintext*)(arg.data))[j], pt);
                        return std::make_shared<heongpu::Plaintext<SchemeType>>(std::move(pt));
                    }
                    input_index_offset++;
                }
                break;
            case TYPE_CIPHERTEXT:
                for (int j = 0; j < arg.size; j++) {
                    if (input_index_offset < input_indices.size() && input_indices[input_index_offset] == input_index) {
                        auto level = ((CCiphertext*)(arg.data))[j].level;
                        heongpu::Ciphertext<SchemeType> ct = heongpu::Ciphertext<SchemeType>(context, level, options);
                        export_ciphertext(((CCiphertext*)(arg.data))[j], ct);
                        return std::make_shared<heongpu::Ciphertext<SchemeType>>(std::move(ct));
                    }
                    input_index_offset++;
                }
                break;
            case TYPE_RELIN_KEY:
                for (int j = 0; j < arg.size; j++) {
                    if (input_index_offset < input_indices.size() && input_indices[input_index_offset] == input_index) {
                        heongpu::Relinkey<SchemeType> rlk = heongpu::Relinkey<SchemeType>(context, options);
                        export_relin_key(((CRelinKey*)(arg.data))[j], rlk, context.get_ciphertext_modulus_count(),
                                         context.get_key_modulus_count());
                        return std::make_shared<heongpu::Relinkey<SchemeType>>(std::move(rlk));
                    }
                    input_index_offset++;
                }
                break;
            case TYPE_GALOIS_KEY:
                for (int j = 0; j < arg.size; j++) {
                    const CGaloisKey& c_glk = ((CGaloisKey*)(arg.data))[j];
                    for (int k = 0; k < c_glk.n_key_switch_key; k++) {
                        if (input_index_offset < input_indices.size() &&
                            input_indices[input_index_offset] == input_index) {
                            {
                                std::lock_guard<std::mutex> lock(galois_key_mutex);
                                if (!galois_key) {
                                    std::vector<uint32_t> all_galois_elts;
                                    for (int m = 0; m < c_glk.n_key_switch_key; m++) {
                                        all_galois_elts.push_back(c_glk.galois_elements[m]);
                                    }
                                    galois_key = std::make_shared<heongpu::Galoiskey<SchemeType>>(
                                        context, all_galois_elts, options);
                                }
                            }

                            export_galois_key(c_glk, *galois_key, galois_element,
                                              context.get_ciphertext_modulus_count(), context.get_key_modulus_count());
                            return galois_key;
                        }

                        input_index_offset++;
                    }
                }
                break;
            case TYPE_SWITCH_KEY:
                for (int j = 0; j < arg.size; j++) {
                    if (input_index_offset < input_indices.size() && input_indices[input_index_offset] == input_index) {
                        const CKeySwitchKey& c_swk = ((CKeySwitchKey*)(arg.data))[j];
                        heongpu::Switchkey<SchemeType> swk(context, options);
                        export_switching_key(c_swk, swk, context.get_ciphertext_modulus_count(),
                                             context.get_key_modulus_count());
                        return std::make_shared<heongpu::Switchkey<SchemeType>>(std::move(swk));
                    }
                    input_index_offset++;
                }
                break;
            default: continue; break;
        }
    }
    return std::any{};
}

template <heongpu::Scheme SchemeType>
void transfer_output_c2h(const NodeIndex& output_index,
                         heongpu::Ciphertext<SchemeType>& output_data,
                         gsl::span<CArgument> args,
                         const std::vector<NodeIndex>& output_indices) {
    int output_index_offset = 0;
    for (int i = 0; i < args.size(); i++) {
        auto& arg = args[i];
        switch (arg.type) {
            case TYPE_CIPHERTEXT:
                for (int j = 0; j < arg.size; j++) {
                    if (output_index_offset < output_indices.size() &&
                        output_indices[output_index_offset] == output_index) {
                        import_ciphertext(((CCiphertext*)(arg.data))[j], output_data);
                        return;
                    }
                    output_index_offset++;
                }
                break;
            default: continue; break;
        }
    }
}

template <heongpu::Scheme SchemeType>
void _run_mega_ag(gsl::span<CArgument> input_args, gsl::span<CArgument> output_args, const MegaAG& mega_ag) {
    std::unique_ptr<heongpu::HEContext<SchemeType>> context;
    std::unique_ptr<heongpu::HEArithmeticOperator<SchemeType>> operators;

    auto init_start = std::chrono::high_resolution_clock::now();
    init_context<SchemeType>(mega_ag.parameter, context, operators);
    auto init_end = std::chrono::high_resolution_clock::now();
    auto init_duration = std::chrono::duration_cast<std::chrono::nanoseconds>(init_end - init_start);

    auto& input_indices = mega_ag.inputs;
    auto& output_indices = mega_ag.outputs;

    int num_data_streams = 2;
    int num_compute_streams = 6;

    if (input_indices.size() >= 8000) {
        num_data_streams = 6;
        num_compute_streams = 2;
    }

    std::vector<cudaStream_t> data_streams(num_data_streams);
    std::vector<cudaStream_t> compute_streams(num_compute_streams);
    std::vector<heongpu::ExecutionOptions> data_stream_options(num_data_streams);
    std::vector<heongpu::ExecutionOptions> compute_stream_options(num_compute_streams);

    const int num_compute_threads = num_compute_streams;  // Thread pool size matches compute streams
    BS::thread_pool pool(num_compute_threads);

    for (int i = 0; i < num_data_streams; i++) {
        CHECK(cudaStreamCreate(&data_streams[i]));
        data_stream_options[i] = heongpu::ExecutionOptions().set_stream(data_streams[i]);
    }

    for (int i = 0; i < num_compute_streams; i++) {
        CHECK(cudaStreamCreate(&compute_streams[i]));
        compute_stream_options[i] = heongpu::ExecutionOptions().set_stream(compute_streams[i]);
    }

    // Thread-safe data structures for task management
    std::mutex m_mutex;
    std::atomic<size_t> total_tasks(mega_ag.computes.size());
    std::atomic<size_t> completed_tasks(0);
    std::condition_variable completion_cv;
    std::mutex completion_mutex;
    std::queue<NodeIndex> task_queue;

    // Final outputs queue for data thread processing
    struct Output {
        NodeIndex index;
        std::shared_ptr<heongpu::Ciphertext<SchemeType>> ptr;
        cudaEvent_t event;
    };
    std::queue<Output> outputs_queue;
    std::mutex outputs_mutex;

    std::unordered_map<NodeIndex, cudaEvent_t> data_ready_events;

    std::unordered_map<NodeIndex, std::any> available_data;
    std::set<NodeIndex> queued_computes;  // Track computes already added to task_queue

    // Reference counting for data handles
    std::unordered_map<NodeIndex, std::atomic<int>> data_ref_counts;
    // Initialize reference counts from JSON once at startup
    for (const auto& [data_index, data_info] : mega_ag.data) {
        data_ref_counts[data_index].store(data_info.successors.size());
    }

    // Global Galoiskey for bootstrap (will be created on first Galois_Key encounter)
    std::shared_ptr<heongpu::Galoiskey<SchemeType>> galois_key;
    std::mutex galois_key_mutex;

    // Create dedicated thread for asynchronous data export
    std::thread data_export_thread([&]() {
        int input_counter = 0;
        for (const auto& input_index : input_indices) {
            int stream_id = input_counter % num_data_streams;
            cudaEvent_t input_event;
            CHECK(cudaEventCreate(&input_event));

            // Get galois_element only if this input is a Galois key
            uint32_t galois_element = 0;
            const DatumNode& input_node = mega_ag.data.at(input_index);
            if (input_node.datum_type == TYPE_GALOIS_KEY && input_node.p.has_value()) {
                galois_element = input_node.p->galois_element;
            }

            auto exported_data = transfer_input_h2c<SchemeType>(input_index, input_args, *context, input_indices,
                                                                data_stream_options[stream_id], galois_element,
                                                                galois_key, galois_key_mutex);

            if (!exported_data.has_value()) {
                std::ostringstream oss;
                oss << "null input for : " << mega_ag.data.at(input_index).id;
                throw std::runtime_error(oss.str());
            }

            CHECK(cudaEventRecord(input_event, data_streams[stream_id]));

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                available_data[input_index] = exported_data;
                data_ready_events[input_index] = input_event;
            }

            if (input_counter % 16 == 0 || input_counter == input_indices.size() - 1) {
                // Wait for some initial data to be exported
                std::lock_guard<std::mutex> lock(m_mutex);
                std::set<NodeIndex> available_computes = mega_ag.get_available_computes(available_data);
                for (const auto& task_index : available_computes) {
                    if (queued_computes.find(task_index) == queued_computes.end()) {
                        task_queue.push(task_index);
                        queued_computes.insert(task_index);
                    }
                }
            }

            input_counter++;
        }
    });

    // Create dedicated thread for final output processing using data streams
    std::thread data_import_thread([&]() {
        int output_counter = 0;
        while (true) {
            Output output;
            bool has_output = false;

            {
                std::lock_guard<std::mutex> output_lock(outputs_mutex);
                if (!outputs_queue.empty()) {
                    output = outputs_queue.front();
                    outputs_queue.pop();
                    has_output = true;
                }
            }

            if (has_output) {
                // Use data stream for output processing
                int stream_id = output_counter % num_data_streams;
                output_counter++;

                // Wait for computation to complete before importing
                CHECK(cudaStreamWaitEvent(data_streams[stream_id], output.event, 0));

                // Switch output to data stream for import
                output.ptr->switch_stream(data_streams[stream_id]);
                // Import output using data stream
                transfer_output_c2h<SchemeType>(output.index, *output.ptr, output_args, output_indices);
            } else {
                // Check if all computations are done
                if (completed_tasks.load() >= total_tasks) {
                    break;
                }
                // Brief sleep to avoid busy waiting
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    });

    // Define task submission function
    std::function<void(uint64_t)> submit_task = [&](uint64_t task_index) {
        pool.detach_task([task_index, &pool, &mega_ag, &completed_tasks, &total_tasks, &m_mutex, &completion_mutex,
                          &completion_cv, &available_data, &operators, &data_ready_events, &compute_stream_options,
                          &compute_streams, &task_queue, &output_args, &context, &outputs_queue, &outputs_mutex,
                          &queued_computes, &data_ref_counts]() {
            auto stream_id = BS::this_thread::get_index().value();

            const ComputeNode& compute_node = mega_ag.computes.at(task_index);
            std::vector<DatumNode*> compute_input_nodes = compute_node.input_nodes;

            std::vector<cudaEvent_t> events_to_wait;
            std::unordered_map<uint64_t, std::any> thread_input_cache;
            {
                std::lock_guard<std::mutex> lock(m_mutex);

                bool events_ready = true;
                for (const auto* input_node : compute_input_nodes) {
                    auto event_it = data_ready_events.find(input_node->index);
                    if (event_it == data_ready_events.end()) {
                        events_ready = false;
                        break;
                    }
                }

                if (!events_ready) {
                    queued_computes.erase(task_index);
                    task_queue.push(task_index);
                    return;
                }

                for (const auto* input_node : compute_input_nodes) {
                    events_to_wait.push_back(data_ready_events[input_node->index]);
                    thread_input_cache[input_node->index] = available_data[input_node->index];
                }
            }

            for (auto& event : events_to_wait) {
                CHECK(cudaStreamWaitEvent(compute_streams[stream_id], event, 0));
            }

            DatumNode* compute_output_node = compute_node.output_nodes[0];

            ExecutionContext exec_ctx;
            exec_ctx.context = operators.get();
            exec_ctx.other_args.push_back(&compute_stream_options[stream_id]);
            exec_ctx.processor = Processor::GPU;

            int output_level = compute_output_node->level;
            auto output_ptr = std::make_shared<heongpu::Ciphertext<SchemeType>>(*context, output_level,
                                                                                compute_stream_options[stream_id]);

            std::any output = output_ptr;
            compute_node.executor(exec_ctx, thread_input_cache, output, compute_node);

            cudaEvent_t output_event;
            CHECK(cudaEventCreate(&output_event));
            CHECK(cudaEventRecord(output_event, compute_streams[stream_id]));

            {
                std::lock_guard<std::mutex> lock(m_mutex);

                available_data[compute_output_node->index] = output_ptr;
                data_ready_events[compute_output_node->index] = output_event;

                std::set<NodeIndex> newly_available_computes =
                    mega_ag.step_available_computes(*compute_output_node, available_data);

                for (const auto& new_task_index : newly_available_computes) {
                    if (queued_computes.find(new_task_index) == queued_computes.end()) {
                        task_queue.push(new_task_index);
                        queued_computes.insert(new_task_index);
                    }
                }
            }

            pool.detach_task([output_event, compute_node, &mega_ag, &m_mutex, &available_data, &data_ref_counts]() {
                CHECK(cudaEventSynchronize(output_event));
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    mega_ag.purge_unused_data(compute_node, data_ref_counts, available_data);
                }
            });

            if (compute_output_node->is_output) {
                std::lock_guard<std::mutex> output_lock(outputs_mutex);
                outputs_queue.push({compute_output_node->index, output_ptr, output_event});
            }

            if (completed_tasks.fetch_add(1) + 1 >= total_tasks) {
                std::lock_guard<std::mutex> lock(completion_mutex);
                completion_cv.notify_all();
            }
        });
    };

    // Task dispatcher loop
    while (true) {
        // Check for available tasks in queue
        uint64_t next_task;
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
            // No tasks available, check if we're done
            if (completed_tasks.load() >= total_tasks) {
                break;
            }
            // Wait briefly for more tasks
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Wait for all tasks to complete
    {
        std::unique_lock<std::mutex> lock(completion_mutex);
        completion_cv.wait(lock, [&] { return completed_tasks.load() >= total_tasks; });
    }

    // Final wait for any remaining tasks
    pool.wait();
    data_export_thread.join();
    data_import_thread.join();

    // Cleanup events asynchronously in thread pool - one event per thread
    for (auto& pair : data_ready_events) {
        cudaEvent_t event = pair.second;
        pool.detach_task([event]() { CHECK(cudaEventDestroy(event)); });
    }
    pool.wait();
}

class FheGpuTask {
public:
    FheGpuTask(const std::string& project_path) {
        mega_ag_ = MegaAG::from_json(project_path + "/mega_ag.json", Processor::GPU);
    }

    ~FheGpuTask() {}

    int run(gsl::span<CArgument> input_args, gsl::span<CArgument> output_args, Algo algo) {
        cudaSetDevice(0);

        switch (algo) {
            case Algo::ALGO_BFV: _run_mega_ag<heongpu::Scheme::BFV>(input_args, output_args, mega_ag_); break;
            case Algo::ALGO_CKKS: _run_mega_ag<heongpu::Scheme::CKKS>(input_args, output_args, mega_ag_); break;
            default: throw std::invalid_argument("algo not supported"); break;
        }

        CHECK(cudaDeviceSynchronize());

        return 0;
    }

protected:
    MegaAG mega_ag_;
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

int run_fhe_gpu_task(fhe_task_handle handle,
                     CArgument* input_args,
                     uint64_t n_in_args,
                     CArgument* output_args,
                     uint64_t n_out_args,
                     Algo algo) {
    gpu_wrapper::FheGpuTask* task = (gpu_wrapper::FheGpuTask*)handle;
    gsl::span<CArgument> input_arg_span{input_args, n_in_args};
    gsl::span<CArgument> output_arg_span{output_args, n_out_args};
    return task->run(input_arg_span, output_arg_span, algo);
}
}  // extern "C"

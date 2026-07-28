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
#include <queue>
#include <set>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <algorithm>
#include <functional>
#include "nlohmann/json.hpp"
#include "cJSON/cJSON.h"

extern "C" {
#include "../wrapper.h"
#include "../../abi/c_types.h"
#include "../../backends/lattisense-fpga/lattisense-fpga-runtime/libbfv2/include/poly.h"
#include "../../backends/lattisense-fpga/lattisense-fpga-runtime/fpga_ops/utils.h"
#include "../../backends/lattisense-fpga/lattisense-fpga-runtime/libbfv2/include/project.h"
#include "../../backends/lattisense-fpga/lattisense-fpga-runtime/fpga_ops/fpga_ops_v2.h"
}
#include "../mega_ag.h"
#include "../cpu_task_utils.h"
#include "fpga_abi_bridge_executors.h"

namespace fpga_wrapper {

using namespace fhe_ops_lib;

/**
 * @brief Get the size (number of offsets) for a data node in FPGA polyvec
 *
 * @param node The data node to get size for
 * @return Number of offsets this node occupies in FPGA polyvec
 */
inline int get_data_node_size(const DatumNode& node) {
    if (!node.fhe_prop.has_value()) {
        throw std::runtime_error("Node missing FHE properties for FPGA size calculation");
    }

    int n_component = node.fhe_prop->level + 1;

    switch (node.datum_type) {
        case TYPE_CIPHERTEXT: return (node.fhe_prop->degree + 1) * n_component;
        case TYPE_PLAINTEXT: return n_component;
        case TYPE_RELIN_KEY: {
            int p_count = node.fhe_prop->sp_level + 1;
            int n_public_key = (n_component + p_count - 1) / p_count;
            return n_public_key * 2 * (n_component + p_count);
        }
        case TYPE_GALOIS_KEY: {
            int p_count = node.fhe_prop->sp_level + 1;
            int n_public_key = (n_component + p_count - 1) / p_count;
            return 1 * n_public_key * 2 * (n_component + p_count);  // One key_switch_key per rotation
        }
        default: throw std::runtime_error("Unsupported data type for FPGA size calculation");
    }
}

// fpga_data (kernel input) → LOAD_TO_BACKEND → c_struct → EXPORT_TO_ABI → handle
inline std::pair<const DatumNode*, const DatumNode*> fpga_input_bridge(const DatumNode* fpga_data) {
    const DatumNode* c_struct = fpga_data->predecessors[0]->input_nodes[0];
    const DatumNode* handle = c_struct->predecessors[0]->input_nodes[0];
    return {c_struct, handle};
}

// fpga_data (kernel output) → STORE_FROM_BACKEND → c_struct → IMPORT_FROM_ABI → handle
inline std::pair<const DatumNode*, const DatumNode*> fpga_output_bridge(const DatumNode* fpga_data) {
    const DatumNode* c_struct = fpga_data->successors[0]->output_nodes[0];
    const DatumNode* handle = c_struct->successors[0]->output_nodes[0];
    return {c_struct, handle};
}

inline std::unordered_map<NodeIndex, int> precompute_kernel_offsets(const ComputeNode& kernel_node) {
    std::unordered_map<NodeIndex, int> offset_map;

    // Gather handle nodes for this kernel's inputs:
    //   fpga_data.predecessors[0] = LOAD_TO_BACKEND
    //   LOAD_TO_BACKEND.input_nodes[0] = c_struct
    //   c_struct.predecessors[0] = EXPORT_TO_ABI
    //   EXPORT_TO_ABI.input_nodes[0] = handle
    std::vector<const DatumNode*> handle_inputs;
    for (const DatumNode* fpga_data : kernel_node.input_nodes) {
        auto [_, handle] = fpga_input_bridge(fpga_data);
        handle_inputs.push_back(handle);
    }

    // Separate into GLK and non-GLK handle nodes (same ordering as linker)
    std::vector<size_t> glk_idxs, non_glk_idxs;
    for (size_t i = 0; i < handle_inputs.size(); i++) {
        if (handle_inputs[i]->datum_type == DataType::TYPE_GALOIS_KEY)
            glk_idxs.push_back(i);
        else
            non_glk_idxs.push_back(i);
    }

    // Sort GLK inputs by galois_element (string order, matching linker)
    std::sort(glk_idxs.begin(), glk_idxs.end(), [&](size_t a, size_t b) {
        auto elem = [&](size_t i) -> uint32_t {
            const auto& p = handle_inputs[i]->fhe_prop->p;
            return p.has_value() ? p->galois_element : 0;
        };
        return std::to_string(elem(a)) < std::to_string(elem(b));
    });

    // Compute input offsets: non-GLK first, then sorted GLK
    int current_offset = 0;

    for (size_t i : non_glk_idxs) {
        auto [c_struct, _] = fpga_input_bridge(kernel_node.input_nodes[i]);
        int size = get_data_node_size(*handle_inputs[i]);
        offset_map[c_struct->index] = current_offset;
        current_offset += size;
    }

    // GLK nodes share the same polyvec size based on the max level across all GLK nodes
    int max_glk_level = -1;
    for (size_t i : glk_idxs) {
        int level = handle_inputs[i]->fhe_prop->level;
        max_glk_level = level > max_glk_level ? level : max_glk_level;
    }
    for (size_t i : glk_idxs) {
        auto [c_struct, _] = fpga_input_bridge(kernel_node.input_nodes[i]);
        DatumNode max_level_node = *handle_inputs[i];
        max_level_node.fhe_prop->level = max_glk_level;
        int size = get_data_node_size(max_level_node);
        offset_map[c_struct->index] = current_offset;
        current_offset += size;
    }

    // Compute output offsets:
    //   fpga_data → STORE_FROM_BACKEND → c_struct → IMPORT_FROM_ABI → handle
    // The handle node holds the final data type/level for size calculation.
    current_offset = 0;
    for (const DatumNode* fpga_data : kernel_node.output_nodes) {
        auto [c_struct, handle] = fpga_output_bridge(fpga_data);
        int size = get_data_node_size(*handle);
        offset_map[c_struct->index] = current_offset;
        current_offset += size;
    }

    return offset_map;
}

struct KernelProject {
    acc_project_st_v2* proj;
    bool online_phase;
};

template <HEScheme SchemeType, typename TContext>
void _run_mega_ag_impl(gsl::span<CArgument> input_args,
                       gsl::span<CArgument> output_args,
                       const MegaAG& mega_ag,
                       const std::unordered_map<NodeIndex, KernelProject>& kernel_projects) {
    // Create FHE context from mega_ag.parameter
    std::unique_ptr<TContext> context;
    init_empty_context<SchemeType, TContext>(mega_ag.parameter, context);

    // Set t for BFV scheme
    if constexpr (SchemeType == HEScheme::BFV) {
        uint64_t t = mega_ag.parameter["t"].get<uint64_t>();
        if (c_set_t_fpga(t) != 0) {
            throw std::runtime_error("fpga set t failed");
        }
    }

    // Extract input and output handles
    std::vector<void*> input_handles = extract_input_handles(input_args);

    // Build available_data map from input handles only (outputs written back via get_other_args)
    std::unordered_map<NodeIndex, std::any> available_data = init_available_data(mega_ag, input_handles);

    // Build output handle map: output NodeIndex -> void* handle pointer
    std::unordered_map<NodeIndex, void*> output_handle_map = extract_output_handle_map(mega_ag, output_args);

    // Pre-compute per-kernel offset maps: kernel NodeIndex -> {c_struct NodeIndex -> polyvec offset}
    std::unordered_map<NodeIndex, std::unordered_map<NodeIndex, int>> kernel_offset_maps;
    for (const auto& [index, compute] : mega_ag.computes) {
        if (compute.fhe_prop.has_value() && compute.fhe_prop->op_type == OperationType::FPGA_KERNEL) {
            kernel_offset_maps[index] = precompute_kernel_offsets(compute);
        }
    }

    // Define callback to get other_args for LOAD_TO_BACKEND and IMPORT_FROM_ABI operations.
    // For LOAD_TO_BACKEND: traverse back through EXPORT_TO_ABI to find the parent FPGA_KERNEL,
    // then use that kernel's project->pvi and offset map.
    auto get_other_args = [&](const ComputeNode& compute_node) -> std::vector<std::any> {
        std::vector<std::any> other_args_vec;
        if (compute_node.fhe_prop.has_value()) {
            if (compute_node.fhe_prop->op_type == OperationType::LOAD_TO_BACKEND) {
                // c_struct -> LOAD_TO_BACKEND -> fpga_data -> FPGA_KERNEL
                const DatumNode* fpga_data = compute_node.output_nodes[0];
                const ComputeNode* kernel = fpga_data->successors[0];
                NodeIndex kernel_idx = kernel->index;
                NodeIndex c_struct_index = compute_node.input_nodes[0]->index;
                int offset = kernel_offset_maps.at(kernel_idx).at(c_struct_index);
                acc_project_st_v2* proj = kernel_projects.at(kernel_idx).proj;
                other_args_vec.push_back(proj->pvi);
                other_args_vec.push_back(offset);
            } else if (compute_node.fhe_prop->op_type == OperationType::IMPORT_FROM_ABI) {
                NodeIndex output_node_index = compute_node.output_nodes[0]->index;
                auto it = output_handle_map.find(output_node_index);
                if (it != output_handle_map.end()) {
                    other_args_vec.push_back(it->second);
                }
            }
        }
        return other_args_vec;
    };

    // Create single-thread pool used for both CPU bridge tasks and async FPGA_KERNEL tasks.
    BS::priority_thread_pool pool(1);

    // Define submit_fpga_task: called by run_tasks when an FPGA_KERNEL node becomes schedulable.
    // Looks up the correct sub-project, pre-allocates output CCiphertexts bound to pvo,
    // runs the project, then injects output data nodes so subsequent IMPORT_FROM_ABI can proceed.
    std::function<void(NodeIndex, std::mutex&, std::priority_queue<TaskInfo>&, std::set<NodeIndex>&,
                       std::atomic<size_t>&, std::atomic<size_t>&, std::condition_variable&, std::mutex&,
                       std::unordered_map<NodeIndex, std::atomic<int>>&)>
        submit_fpga_task = [&](NodeIndex task_index, std::mutex& m_mutex, std::priority_queue<TaskInfo>& task_queue,
                               std::set<NodeIndex>& queued_computes, std::atomic<size_t>& completed_tasks,
                               std::atomic<size_t>& total_tasks, std::condition_variable& completion_cv,
                               std::mutex& completion_mutex,
                               std::unordered_map<NodeIndex, std::atomic<int>>& data_ref_counts) {
            pool.detach_task([&, task_index]() {
                const auto& [proj, online_phase] = kernel_projects.at(task_index);
                const auto& offset_map = kernel_offset_maps.at(task_index);

                // Pre-allocate CCiphertext for each output and bind to pvo BEFORE run_project,
                // so the FPGA can write results there directly.
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    const ComputeNode& kernel = mega_ag.computes.at(task_index);
                    int n = mega_ag.parameter["n"].get<int>();

                    for (const DatumNode* fpga_out : kernel.output_nodes) {
                        auto [c_struct_node, _] = fpga_output_bridge(fpga_out);

                        int offset = offset_map.at(c_struct_node->index);
                        int degree = c_struct_node->fhe_prop->degree;
                        int level = c_struct_node->fhe_prop->level;

                        auto* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                        alloc_ciphertext(c_ct, degree, level, n);
                        export_ct_pointers(c_ct, proj->pvo, offset, false);

                        available_data[c_struct_node->index] = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* p) {
                            free_ciphertext(p);
                            free(p);
                        });

                        // STORE is skipped (c_struct already pre-allocated); count it as completed
                        completed_tasks.fetch_add(1);
                    }
                }

                uint64_t total_proj_time_ns = 0;
                int ret = run_project(&g_fpga_dev, proj, online_phase, &total_proj_time_ns);

                // Free copied input polyvec terms after FPGA run completes
                free_polyvec_64_terms(proj->pvi);

                if (ret) {
                    throw std::runtime_error("Failed to run FPGA task");
                }
#ifdef LATTISENSE_DEV
                fprintf(stderr, "Run FPGA project time: %.3f ms\n", total_proj_time_ns / 1.0e6);
#endif

                {
                    std::lock_guard<std::mutex> lock(m_mutex);

                    const ComputeNode& kernel = mega_ag.computes.at(task_index);
                    for (const DatumNode* fpga_out : kernel.output_nodes) {
                        available_data[fpga_out->index] = std::any{};

                        // c_struct was pre-allocated; schedule IMPORT via step_available_computes
                        auto [c_struct_node, _] = fpga_output_bridge(fpga_out);

                        std::unordered_set<NodeIndex> new_computes =
                            mega_ag.step_available_computes(*c_struct_node, available_data);
                        for (NodeIndex nc : new_computes) {
                            if (queued_computes.find(nc) == queued_computes.end()) {
                                task_queue.push({mega_ag.computes.at(nc).priority, nc});
                                queued_computes.insert(nc);
                            }
                        }
                    }
                }

                size_t after = completed_tasks.fetch_add(1) + 1;
                if (after >= total_tasks) {
                    std::lock_guard<std::mutex> lock(completion_mutex);
                    completion_cv.notify_all();
                }
            });
        };

    run_tasks(mega_ag, pool, context, available_data, get_other_args, submit_fpga_task);
}

template <HEScheme SchemeType>
void _run_mega_ag(gsl::span<CArgument> input_args,
                  gsl::span<CArgument> output_args,
                  const MegaAG& mega_ag,
                  const std::unordered_map<NodeIndex, KernelProject>& kernel_projects) {
    if constexpr (SchemeType == HEScheme::CKKS) {
        if (mega_ag.parameter.contains("btp_output_level")) {
            using TContext = CkksBtpContext;
            _run_mega_ag_impl<SchemeType, TContext>(input_args, output_args, mega_ag, kernel_projects);
        } else {
            using TContext = CkksContext;
            _run_mega_ag_impl<SchemeType, TContext>(input_args, output_args, mega_ag, kernel_projects);
        }
    } else {
        using TContext = BfvContext;
        _run_mega_ag_impl<SchemeType, TContext>(input_args, output_args, mega_ag, kernel_projects);
    }
}

class FheFpgaTask {
public:
    FheFpgaTask(const std::string& project_path)
        : mega_ag_(MegaAG::load(project_path + "/mega_ag.json", Processor::FPGA)) {
        // Load one sub-project per FPGA_KERNEL node; the kernel's NodeIndex is the sub-dir name.
        // online_phase is determined by whether the sub-project's mega_ag.json has offline_inputs.
        for (const auto& [index, compute] : mega_ag_.computes) {
            if (compute.fhe_prop.has_value() && compute.fhe_prop->op_type == OperationType::FPGA_KERNEL) {
                std::string sub_path = project_path + "/" + std::to_string(index);
                std::string sub_mag_path = sub_path + "/mega_ag.json";

                std::ifstream f(sub_mag_path);
                if (!f.is_open()) {
                    throw std::runtime_error("Failed to open sub-project mega_ag.json: " + sub_mag_path);
                }
                nlohmann::json sub_mag = nlohmann::json::parse(f);
                bool online_phase = sub_mag.value("offline_inputs", nlohmann::json::array()).empty();

                acc_project_st_v2* proj = c_load_fpga_project(sub_path.c_str(), online_phase);
                if (proj == nullptr) {
                    throw std::runtime_error("Failed to load FPGA sub-project: " + sub_path);
                }
                kernel_projects_[index] = {proj, online_phase};
            }
        }
    }

    ~FheFpgaTask() {
        for (auto& [_, entry] : kernel_projects_) {
            c_free_project_json(&entry.proj);
        }
    }

    void bind_abi_bridge_executors(const ExecutorFunc& abi_export, const ExecutorFunc& abi_import) {
        ExecutorFunc load_to_fpga = create_load_to_fpga_executor();
        mega_ag_.bind_abi_bridge_executors(abi_export, abi_import, load_to_fpga, {});
    }

    void bind_custom_executors(const std::unordered_map<std::string, ExecutorFunc>& custom_executors) {
        mega_ag_.bind_custom_executors(custom_executors);
    }

    int run(gsl::span<CArgument> input_args, gsl::span<CArgument> output_args) {
        switch (mega_ag_.algo) {
            case Algo::ALGO_BFV:
                _run_mega_ag<HEScheme::BFV>(input_args, output_args, mega_ag_, kernel_projects_);
                break;
            case Algo::ALGO_CKKS:
                _run_mega_ag<HEScheme::CKKS>(input_args, output_args, mega_ag_, kernel_projects_);
                break;
            default: throw std::invalid_argument("algo not supported"); break;
        }

        return 0;
    }

protected:
    MegaAG mega_ag_;
    std::unordered_map<NodeIndex, KernelProject> kernel_projects_;
};

};  // namespace fpga_wrapper

extern "C" {

fhe_task_handle create_fhe_fpga_task(const char* project_path) {
    fpga_wrapper::FheFpgaTask* task = new fpga_wrapper::FheFpgaTask(project_path);
    return (fhe_task_handle)task;
}

void release_fhe_fpga_task(fhe_task_handle handle) {
    fpga_wrapper::FheFpgaTask* task = (fpga_wrapper::FheFpgaTask*)handle;
    delete task;
}

void bind_fpga_task_abi_bridge_executors(fhe_task_handle handle, void* abi_export_executor, void* abi_import_executor) {
    fpga_wrapper::FheFpgaTask* task = (fpga_wrapper::FheFpgaTask*)handle;
    ExecutorFunc* export_executor = reinterpret_cast<ExecutorFunc*>(abi_export_executor);
    ExecutorFunc* import_executor = reinterpret_cast<ExecutorFunc*>(abi_import_executor);

    ExecutorFunc import = import_executor ? *import_executor : ExecutorFunc{};
    task->bind_abi_bridge_executors(*export_executor, import);
}

void bind_fpga_task_custom_executors(fhe_task_handle handle,
                                     const char** custom_types,
                                     void** executors,
                                     uint64_t n_executors) {
    fpga_wrapper::FheFpgaTask* task = (fpga_wrapper::FheFpgaTask*)handle;
    std::unordered_map<std::string, ExecutorFunc> custom_executors;
    for (uint64_t i = 0; i < n_executors; i++) {
        ExecutorFunc* executor_ptr = reinterpret_cast<ExecutorFunc*>(executors[i]);
        custom_executors[std::string(custom_types[i])] = *executor_ptr;
    }
    task->bind_custom_executors(custom_executors);
}

int run_fhe_fpga_task(fhe_task_handle handle,
                      CArgument* input_args,
                      uint64_t n_in_args,
                      CArgument* output_args,
                      uint64_t n_out_args) {
    fpga_wrapper::FheFpgaTask* task = (fpga_wrapper::FheFpgaTask*)handle;
    gsl::span<CArgument> input_arg_span{input_args, n_in_args};
    gsl::span<CArgument> output_arg_span{output_args, n_out_args};
    return task->run(input_arg_span, output_arg_span);
}
}  // extern "C"

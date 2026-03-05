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
#include "../fhe_ops_lib/fhe_types_v2.h"
#include "../../backends/lattisense-fpga/lattisense-fpga-runtime/libbfv2/include/poly.h"
// #include "structs_v2.h"
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

/**
 * @brief Pre-compute input and output offsets for FPGA polyvec
 *
 * @param mega_ag The computation graph
 * @return offset_map: c_struct NodeIndex -> offset in polyvec (inputs use pvi, outputs use pvo)
 */
inline std::unordered_map<NodeIndex, int> precompute_input_output_offsets(const MegaAG& mega_ag) {
    std::unordered_map<NodeIndex, int> offset_map;

    // Separate inputs into GLK and non-GLK nodes
    std::vector<NodeIndex> glk_inputs;
    std::vector<NodeIndex> non_glk_inputs;

    for (NodeIndex input_index : mega_ag.inputs) {
        const DatumNode& input_node = mega_ag.data.at(input_index);
        if (input_node.datum_type == DataType::TYPE_GALOIS_KEY) {
            glk_inputs.push_back(input_index);
        } else {
            non_glk_inputs.push_back(input_index);
        }
    }

    // Sort GLK inputs by galois_element (string order)
    std::sort(glk_inputs.begin(), glk_inputs.end(), [&mega_ag](NodeIndex a, NodeIndex b) {
        const auto& node_a = mega_ag.data.at(a);
        const auto& node_b = mega_ag.data.at(b);
        uint32_t elem_a = node_a.fhe_prop->p.has_value() ? node_a.fhe_prop->p->galois_element : 0;
        uint32_t elem_b = node_b.fhe_prop->p.has_value() ? node_b.fhe_prop->p->galois_element : 0;
        return std::to_string(elem_a) < std::to_string(elem_b);
    });

    // Compute input offsets: non-GLK first, then sorted GLK
    int current_offset = 0;

    // Process non-GLK inputs
    for (NodeIndex input_index : non_glk_inputs) {
        const DatumNode& input_node = mega_ag.data.at(input_index);
        int size = get_data_node_size(input_node);

        // Store offset for c_struct node: handle -> EXPORT_TO_ABI -> c_struct
        NodeIndex c_struct_index = input_node.successors[0]->output_nodes[0]->index;
        offset_map[c_struct_index] = current_offset;
        current_offset += size;
    }

    // Process GLK inputs (sorted by galois_element)
    // All GLK nodes share the same size based on the maximum level across all GLK nodes
    int max_glk_level = -1;
    for (NodeIndex input_index : glk_inputs) {
        int level = mega_ag.data.at(input_index).fhe_prop->level;
        max_glk_level = level > max_glk_level ? level : max_glk_level;
    }
    for (NodeIndex input_index : glk_inputs) {
        const DatumNode& input_node = mega_ag.data.at(input_index);
        DatumNode max_level_node = input_node;
        max_level_node.fhe_prop->level = max_glk_level;
        int size = get_data_node_size(max_level_node);

        NodeIndex c_struct_index = input_node.successors[0]->output_nodes[0]->index;
        offset_map[c_struct_index] = current_offset;
        current_offset += size;
    }

    // Compute output offsets (reset offset counter for output polyvec)
    current_offset = 0;
    for (NodeIndex output_index : mega_ag.outputs) {
        const DatumNode& output_node = mega_ag.data.at(output_index);  // This is handle node
        int size = get_data_node_size(output_node);

        // New flow: fpga_data → STORE → c_struct → IMPORT → handle (output)
        // Get c_struct from: handle.predecessors[0] (IMPORT) -> input_nodes[0] (c_struct)
        NodeIndex c_struct_index = output_node.predecessors[0]->input_nodes[0]->index;
        offset_map[c_struct_index] = current_offset;
        current_offset += size;
    }

    return offset_map;
}

template <HEScheme SchemeType, typename TContext>
void _run_mega_ag_impl(gsl::span<CArgument> input_args,
                       gsl::span<CArgument> output_args,
                       const MegaAG& mega_ag,
                       acc_project_st_v2* project,
                       bool online_phase) {
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

    // Pre-compute offsets for all inputs and outputs
    std::unordered_map<NodeIndex, int> offset_map = precompute_input_output_offsets(mega_ag);

    // Define callback to get other_args for LOAD_TO_BACKEND and IMPORT_FROM_ABI operations
    auto get_other_args = [&](const ComputeNode& compute_node) -> std::vector<std::any> {
        std::vector<std::any> other_args_vec;
        if (compute_node.fhe_prop.has_value()) {
            if (compute_node.fhe_prop->op_type == OperationType::LOAD_TO_BACKEND) {
                NodeIndex c_struct_index = compute_node.input_nodes[0]->index;
                int offset = offset_map[c_struct_index];
                other_args_vec.push_back(project->pvi);
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

    // Create single-thread pool used for both CPU bridge tasks and the async fpga_run task.
    BS::thread_pool pool(1);

    // Define submit_fpga_task: called by run_tasks when the composite "fpga_run" node
    // becomes schedulable (i.e. all LOAD_TO_BACKEND operations have completed).
    // It runs run_project and then injects all fpga_data output nodes into available_data
    // so that the subsequent STORE_FROM_BACKEND operations can be scheduled.
    std::function<void(NodeIndex, std::mutex&, std::queue<NodeIndex>&, std::set<NodeIndex>&, std::atomic<size_t>&,
                       std::atomic<size_t>&, std::condition_variable&, std::mutex&,
                       std::unordered_map<NodeIndex, std::atomic<int>>&)>
        submit_fpga_task = [&](NodeIndex task_index, std::mutex& m_mutex, std::queue<NodeIndex>& task_queue,
                               std::set<NodeIndex>& queued_computes, std::atomic<size_t>& completed_tasks,
                               std::atomic<size_t>& total_tasks, std::condition_variable& completion_cv,
                               std::mutex& completion_mutex,
                               std::unordered_map<NodeIndex, std::atomic<int>>& data_ref_counts) {
            // Submit to pool so the dispatcher thread is not blocked and
            // completion_cv accounting remains consistent.
            pool.detach_task([&, task_index]() {
                // Pre-allocate CCiphertext for each output and bind to pvo BEFORE run_project,
                // so the FPGA can write results there directly.
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    const ComputeNode& fpga_run = mega_ag.computes.at(task_index);
                    int n = mega_ag.parameter["n"].get<int>();

                    for (const DatumNode* fpga_out : fpga_run.output_nodes) {
                        // fpga_out -> STORE_FROM_BACKEND -> c_struct -> IMPORT_FROM_ABI -> handle
                        const ComputeNode* store_node = fpga_out->successors[0];
                        const DatumNode* c_struct_node = store_node->output_nodes[0];

                        int offset = offset_map.at(c_struct_node->index);
                        int degree = c_struct_node->fhe_prop->degree;
                        int level = c_struct_node->fhe_prop->level;

                        auto* c_ct = (CCiphertext*)malloc(sizeof(CCiphertext));
                        alloc_ciphertext(c_ct, degree, level, n);
                        export_ct_pointers(c_ct, project->pvo, offset);

                        available_data[c_struct_node->index] = std::shared_ptr<CCiphertext>(c_ct, [](CCiphertext* p) {
                            free_ciphertext(p, false);
                            free(p);
                        });

                        // STORE is skipped (c_struct already pre-allocated); count it as completed
                        completed_tasks.fetch_add(1);
                    }
                }

                uint64_t total_proj_time_ns = 0;
                int ret = run_project(&g_fpga_dev, project, online_phase, &total_proj_time_ns);
                if (ret) {
                    throw std::runtime_error("Failed to run FPGA task");
                }
#ifdef LATTISENSE_DEV
                fprintf(stderr, "Run FPGA project time: %.3f ms\n", total_proj_time_ns / 1.0e6);
#endif

                {
                    std::lock_guard<std::mutex> lock(m_mutex);

                    const ComputeNode& fpga_run = mega_ag.computes.at(task_index);
                    for (const DatumNode* fpga_out : fpga_run.output_nodes) {
                        available_data[fpga_out->index] = std::any{};

                        // c_struct was pre-allocated; schedule IMPORT via step_available_computes
                        const ComputeNode* store_node = fpga_out->successors[0];
                        const DatumNode* c_struct_node = store_node->output_nodes[0];

                        std::set<NodeIndex> new_computes =
                            mega_ag.step_available_computes(*c_struct_node, available_data);
                        for (NodeIndex nc : new_computes) {
                            if (queued_computes.find(nc) == queued_computes.end()) {
                                task_queue.push(nc);
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
                  acc_project_st_v2* project,
                  bool online_phase) {
    if constexpr (SchemeType == HEScheme::CKKS) {
        if (mega_ag.parameter.contains("btp_output_level")) {
            using TContext = CkksBtpContext;
            _run_mega_ag_impl<SchemeType, TContext>(input_args, output_args, mega_ag, project, online_phase);
        } else {
            using TContext = CkksContext;
            _run_mega_ag_impl<SchemeType, TContext>(input_args, output_args, mega_ag, project, online_phase);
        }
    } else {
        using TContext = BfvContext;
        _run_mega_ag_impl<SchemeType, TContext>(input_args, output_args, mega_ag, project, online_phase);
    }
}

class FheFpgaTask {
public:
    FheFpgaTask(const std::string& project_path, bool online_phase) {
        mega_ag_ = MegaAG::from_json(project_path + "/mega_ag.json", Processor::FPGA);
        online_phase_ = online_phase;
        project_ = c_load_fpga_project(project_path.c_str(), online_phase);
        if (project_ == nullptr) {
            throw std::runtime_error("Failed to load FPGA project");
        }
    }

    ~FheFpgaTask() {
        if (project_ != nullptr) {
            c_free_project_json(&project_);
        }
    }

    void bind_abi_bridge_executors(const ExecutorFunc& abi_export, const ExecutorFunc& abi_import) {
        // Create FPGA backend bridge executor
        ExecutorFunc load_to_fpga = create_load_to_fpga_executor();

        // Bind ABI bridge executors (both export and import, plus load for backend)
        mega_ag_.bind_abi_bridge_executors(abi_export, abi_import, load_to_fpga, {});
    }

    int run(gsl::span<CArgument> input_args, gsl::span<CArgument> output_args) {
        switch (mega_ag_.algo) {
            case Algo::ALGO_BFV:
                _run_mega_ag<HEScheme::BFV>(input_args, output_args, mega_ag_, project_, online_phase_);
                break;
            case Algo::ALGO_CKKS:
                _run_mega_ag<HEScheme::CKKS>(input_args, output_args, mega_ag_, project_, online_phase_);
                break;
            default: throw std::invalid_argument("algo not supported"); break;
        }

        return 0;
    }

protected:
    MegaAG mega_ag_;
    acc_project_st_v2* project_ = nullptr;
    bool online_phase_ = true;
};

};  // namespace fpga_wrapper

extern "C" {

fhe_task_handle create_fhe_fpga_task(const char* project_path, bool online_phase) {
    fpga_wrapper::FheFpgaTask* task = new fpga_wrapper::FheFpgaTask(project_path, online_phase);
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

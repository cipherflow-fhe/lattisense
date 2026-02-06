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

#ifndef CXX_FHE_TASK_H
#define CXX_FHE_TASK_H

#include <fstream>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <typeindex>
#include "nlohmann/json.hpp"
#include "../fhe_ops_lib/fhe_lib_v2.h"

extern "C" {
#include "../mega_ag_runners/wrapper.h"
}
#include "../mega_ag_runners/mega_ag.h"

namespace cxx_sdk_v2 {

using namespace fhe_ops_lib;

enum class CxxArgumentType {
    PLAINTEXT,
    PLAINTEXT_MUL,
    PLAINTEXT_RINGT,
    CIPHERTEXT,
    CIPHERTEXT3,
    RELIN_KEY,
    GALOIS_KEY,
    CUSTOM
};
extern std::unordered_map<CxxArgumentType, DataType> type_map;
extern std::unordered_map<std::type_index, CxxArgumentType> _type_map;

template <typename T> struct is_vector {
    static const bool value = false;
};

template <typename T> struct is_vector<std::vector<T>> {
    static const bool value = true;
};

template <typename T>
void add_flat(T& x,
              std::vector<Handle*>& flat,
              std::vector<CxxArgumentType>& flat_types,
              std::vector<int>& flat_levels) {
    if constexpr (is_vector<T>::value) {
        for (auto& y : x) {
            add_flat(y, flat, flat_types, flat_levels);
        }
    } else {
        flat.push_back(&x);
        flat_types.push_back(_type_map[std::type_index(typeid(T))]);
        flat_levels.push_back(x.get_level());
    }
}

/**
 * @brief Structure describing the information of each input/output argument.
 */
struct CxxVectorArgument {
    /** Argument ID. */
    std::string arg_id;
    /** Argument type. */
    CxxArgumentType type;
    /** Argument level. */
    int level;
    /** Pointers to data handles contained in this argument. */
    std::vector<Handle*> flat_handles;

    template <typename T> CxxVectorArgument(const std::string& id, T* hdl) : arg_id(id) {
        std::vector<CxxArgumentType> flat_types;
        std::vector<int> flat_levels;
        add_flat(*hdl, flat_handles, flat_types, flat_levels);
        type = flat_types[0];
        level = flat_levels[0];
        for (int i = 0; i < flat_handles.size(); i++) {
            if (flat_types[i] != type) {
                throw std::runtime_error("inconsistent types");
            }
            if (flat_levels[i] != level) {
                throw std::runtime_error("inconsistent levels");
            }
        }
    }
};

class FheTask {
public:
    FheTask() = default;

    FheTask(const std::string& project_path);

    FheTask(const FheTask& other) = delete;

    FheTask(FheTask&& other) {
        std::swap(_project_path, other._project_path);
        std::swap(_heterogeneous_mode, other._heterogeneous_mode);
    }

    void operator=(const FheTask& other) = delete;

    void operator=(FheTask&& other) {
        std::swap(_project_path, other._project_path);
        std::swap(_heterogeneous_mode, other._heterogeneous_mode);
    }

    ~FheTask();

    /**
     * @brief Core function for executing Fully Homomorphic Encryption (FHE) tasks.
     *
     * @param context Pointer to the FHE context object containing encryption parameters and public keys required for
     * task execution.
     * @param cxx_args Array of task input/output argument information, where each argument is described by a
     * `CxxVectorArgument` structure.
     *
     * @return Task execution time in microseconds.
     *
     * @note
     * - Derived classes must implement this function to define specific heterogeneous FHE task execution logic.
     * - Each `CxxVectorArgument` object in `cxx_args` contains the argument ID, type, level, and an array of data
     * handle pointers.
     */
    // virtual uint64_t run(FheContext* context, const std::vector<CxxVectorArgument>& cxx_args) = 0;

protected:
    std::string _project_path = "";
    nlohmann::json _task_signature;
    bool _heterogeneous_mode = false;  // false for CPU mode (homogeneous), true for GPU/FPGA mode (heterogeneous)

    std::vector<CArgument> input_args;
    std::vector<CArgument> output_args;

    void new_args(int n_in_args, int n_out_args);
    void free_args();
};

class FheTaskCpu : public FheTask {
public:
    using FheTask::FheTask;

    FheTaskCpu(const std::string& project_path);
    ~FheTaskCpu();

    uint64_t run(FheContext* context, const std::vector<CxxVectorArgument>& cxx_args);

private:
    fhe_task_handle task_handle;
};

class FheTaskGpu : public FheTask {
public:
    using FheTask::FheTask;

    FheTaskGpu(const std::string& project_path);

    ~FheTaskGpu();

    uint64_t run(FheContext* context, const std::vector<CxxVectorArgument>& cxx_args, bool print_time = true);

    fhe_task_handle task_handle;
};

}  // namespace cxx_sdk_v2
#endif  // CXX_FHE_TASK_H

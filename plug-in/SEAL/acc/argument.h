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

#pragma once

extern "C" {
#include "c_types.h"
#include "c_argument.h"
}
#include <stdexcept>
#include <typeindex>
#include <unordered_map>
#include <vector>
#include <seal/seal.h>
#include "nlohmann/json.hpp"
#include "c_struct_import_export.h"

// ---------------------------------------------------------------------------
// SealArgumentType — SEAL analogue of CxxArgumentType in cxx_argument.h
// ---------------------------------------------------------------------------

enum class SealArgumentType { PLAINTEXT, CIPHERTEXT, RELIN_KEY, GALOIS_KEY };

inline std::unordered_map<SealArgumentType, DataType> type_map = {
    {SealArgumentType::CIPHERTEXT, DataType::TYPE_CIPHERTEXT},
    {SealArgumentType::PLAINTEXT, DataType::TYPE_PLAINTEXT},
    {SealArgumentType::RELIN_KEY, DataType::TYPE_RELIN_KEY},
    {SealArgumentType::GALOIS_KEY, DataType::TYPE_GALOIS_KEY},
};

inline std::unordered_map<std::type_index, SealArgumentType> _type_map = {
    {std::type_index(typeid(seal::Ciphertext)), SealArgumentType::CIPHERTEXT},
    {std::type_index(typeid(seal::Plaintext)), SealArgumentType::PLAINTEXT},
};

// ---------------------------------------------------------------------------
// Vector flattening helpers
// ---------------------------------------------------------------------------

template <typename T> struct is_vector {
    static const bool value = false;
};

template <typename T> struct is_vector<std::vector<T>> {
    static const bool value = true;
};

template <typename T>
void get_arg_info(const seal::EncryptionParameters& params,
                  T& x,
                  std::vector<std::any>& flat,
                  std::vector<SealArgumentType>& flat_types,
                  std::vector<int>& flat_levels) {
    flat.push_back(&x);
    flat_types.push_back(_type_map[std::type_index(typeid(T))]);
    flat_levels.push_back(-1);
}

template <>
inline void get_arg_info<seal::Plaintext>(const seal::EncryptionParameters& params,
                                          seal::Plaintext& x,
                                          std::vector<std::any>& flat,
                                          std::vector<SealArgumentType>& flat_types,
                                          std::vector<int>& flat_levels) {
    flat.push_back(&x);
    flat_types.push_back(_type_map[std::type_index(typeid(seal::Plaintext))]);
    flat_levels.push_back(x.coeff_count() / params.poly_modulus_degree() - 1);
}

template <>
inline void get_arg_info<seal::Ciphertext>(const seal::EncryptionParameters& params,
                                           seal::Ciphertext& x,
                                           std::vector<std::any>& flat,
                                           std::vector<SealArgumentType>& flat_types,
                                           std::vector<int>& flat_levels) {
    flat.push_back(&x);
    flat_types.push_back(_type_map[std::type_index(typeid(seal::Ciphertext))]);
    flat_levels.push_back(x.coeff_modulus_size() - 1);
}

template <typename T>
void add_flat(const seal::EncryptionParameters& params,
              T& x,
              std::vector<std::any>& flat,
              std::vector<SealArgumentType>& flat_types,
              std::vector<int>& flat_levels) {
    if constexpr (is_vector<T>::value) {
        for (auto& y : x) {
            add_flat(params, y, flat, flat_types, flat_levels);
        }
    } else {
        get_arg_info(params, x, flat, flat_types, flat_levels);
    }
}

// ---------------------------------------------------------------------------
// SealVectorArgument — SEAL analogue of CxxVectorArgument in cxx_argument.h
// ---------------------------------------------------------------------------

struct SealVectorArgument {
    std::string arg_id;
    const seal::EncryptionParameters& params;
    SealArgumentType type;
    int level;
    std::vector<std::any> flat_data;

    template <typename T>
    SealVectorArgument(const seal::EncryptionParameters& params, std::string id, T* operand)
        : params(params), arg_id(id) {
        std::vector<SealArgumentType> flat_types;
        std::vector<int> flat_levels;
        add_flat(params, *operand, flat_data, flat_types, flat_levels);
        type = flat_types[0];
        level = flat_levels[0];

        for (int i = 0; i < (int)flat_data.size(); i++) {
            if (flat_types[i] != type) {
                throw std::runtime_error("inconsistent types");
            }
            if (flat_levels[i] != level) {
                throw std::runtime_error("inconsistent levels");
            }
        }
    }
};

// ---------------------------------------------------------------------------
// CArgument construction — SealVectorArgument → CArgument (pointer mode)
// Mirrors export_argument / export_arguments / import_arguments /
// export_public_key_arguments in argument.go (lattigo).
// CArgument.data is a malloc'd void*[] of raw SEAL object pointers.
// The actual SEAL ↔ C struct conversion is deferred to the EXPORT_TO_ABI /
// IMPORT_FROM_ABI ABI bridge executors in abi_bridge_executors.h.
// ---------------------------------------------------------------------------

inline CArgument export_argument(const SealVectorArgument& src) {
    CArgument dest;
    dest.id = src.arg_id.c_str();
    dest.type = type_map[src.type];
    dest.size = src.flat_data.size();
    dest.level = src.level;

    void** ptr_arr = (void**)malloc(sizeof(void*) * dest.size);
    for (int i = 0; i < (int)src.flat_data.size(); i++) {
        switch (src.type) {
            case SealArgumentType::CIPHERTEXT: ptr_arr[i] = std::any_cast<seal::Ciphertext*>(src.flat_data[i]); break;
            case SealArgumentType::PLAINTEXT: ptr_arr[i] = std::any_cast<seal::Plaintext*>(src.flat_data[i]); break;
            default: free(ptr_arr); throw std::runtime_error("Unsupported argument type in export_argument");
        }
    }
    dest.data = (void*)ptr_arr;

    return dest;
}

inline void export_arguments(const std::vector<SealVectorArgument>& seal_args,
                             std::vector<CArgument>& input_args,
                             std::vector<CArgument>& output_args) {
    for (int i = 0; i < (int)input_args.size(); i++) {
        input_args[i] = export_argument(seal_args[i]);
    }
    for (int i = 0; i < (int)output_args.size(); i++) {
        output_args[i] = export_argument(seal_args[input_args.size() + i]);
    }
}

// inline void import_arguments(const std::vector<SealVectorArgument>& seal_args,
//                               int arg_idx_offset,
//                               std::vector<CArgument>& output_args) {
//     // No-op: output ciphertexts are written back in-place by the IMPORT_FROM_ABI
//     // executor during run_fhe_gpu_task / run_fhe_fpga_task. The seal::Ciphertext*
//     // pointers stored in CArgument.data already point to the caller's objects.
//     (void)seal_args;
//     (void)arg_idx_offset;
//     (void)output_args;
// }

inline void export_public_keys(const seal::RelinKeys* rlk,
                               const seal::GaloisKeys* glk,
                               nlohmann::json& key_signature,
                               std::vector<CArgument>& input_args) {
    if (key_signature["rlk"].get<int>() >= 0) {
        CArgument rlk_arg;
        int rlk_level = key_signature["rlk"].get<int>();
        rlk_arg.id = "rlk_ntt";
        rlk_arg.type = DataType::TYPE_RELIN_KEY;
        rlk_arg.size = 1;
        rlk_arg.level = rlk_level;

        void** ptr_arr = (void**)malloc(sizeof(void*));
        ptr_arr[0] = const_cast<seal::RelinKeys*>(rlk);
        rlk_arg.data = ptr_arr;

        input_args.push_back(rlk_arg);
    }

    if (!key_signature["glk"].empty()) {
        int glk_level = -1;
        std::vector<uint64_t> galois_elements;
        for (auto& item : key_signature["glk"].items()) {
            int lvl = item.value().get<int>();
            glk_level = glk_level < lvl ? lvl : glk_level;
            galois_elements.push_back(std::stoul(item.key()));
        }

        for (uint64_t galois_element : galois_elements) {
            CArgument glk_arg;
            glk_arg.id = "glk_ntt";
            glk_arg.type = DataType::TYPE_GALOIS_KEY;
            glk_arg.size = 1;
            glk_arg.level = glk_level;

            void** ptr_arr = (void**)malloc(sizeof(void*));
            ptr_arr[0] = const_cast<seal::GaloisKeys*>(glk);
            glk_arg.data = ptr_arr;

            input_args.push_back(glk_arg);
        }
    }
}

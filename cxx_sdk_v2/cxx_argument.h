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

#ifndef CXX_ARGUMENT_H
#define CXX_ARGUMENT_H

#include <vector>
#include <string>
#include <typeindex>
#include <type_traits>
#include <unordered_map>
#include <stdexcept>
#include <utility>
#include "nlohmann/json.hpp"
#include "../fhe_ops_lib/schemes/base/custom_data.h"
#include "../fhe_ops_lib/schemes/bfv/bfv.h"
#include "../fhe_ops_lib/schemes/ckks/ckks.h"

extern "C" {
#include "../abi/c_structs.h"
#include "../mega_ag_runners/wrapper.h"
}

namespace lattisense {

using namespace fhe_ops_lib;

enum class CxxArgumentType { PLAINTEXT, CIPHERTEXT, RELIN_KEY, GALOIS_KEY, EVALUATION_KEY, CUSTOM };

inline std::unordered_map<CxxArgumentType, DataType> type_map = {
    {CxxArgumentType::CIPHERTEXT, DataType::TYPE_CIPHERTEXT},
    {CxxArgumentType::PLAINTEXT, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::RELIN_KEY, DataType::TYPE_RELIN_KEY},
    {CxxArgumentType::GALOIS_KEY, DataType::TYPE_GALOIS_KEY},
    {CxxArgumentType::EVALUATION_KEY, DataType::TYPE_EVALUATION_KEY},
    {CxxArgumentType::CUSTOM, DataType::TYPE_CUSTOM},
};

inline std::unordered_map<std::type_index, CxxArgumentType> _type_map = {
    {std::type_index(typeid(BfvCiphertext)), CxxArgumentType::CIPHERTEXT},
    {std::type_index(typeid(BfvPlaintext)), CxxArgumentType::PLAINTEXT},
    {std::type_index(typeid(CkksCiphertext)), CxxArgumentType::CIPHERTEXT},
    {std::type_index(typeid(CkksPlaintext)), CxxArgumentType::PLAINTEXT},
    {std::type_index(typeid(CustomData)), CxxArgumentType::CUSTOM},
};

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

        if constexpr (std::is_same_v<T, CustomData>) {
            flat_levels.push_back(-1);
        } else {
            flat_levels.push_back(x.level());
        }
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

    CxxVectorArgument(const std::string& id, CxxArgumentType arg_type, int arg_level, std::vector<Handle*>&& handles)
        : arg_id(id), type(arg_type), level(arg_level), flat_handles(std::move(handles)) {}
};

inline CArgument export_cxx_argument(const CxxVectorArgument& src) {
    CArgument dest;
    dest.id = src.arg_id.c_str();
    dest.type = type_map[src.type];
    dest.size = src.flat_handles.size();
    dest.level = src.level;

    // Use Handle* pointers directly; ABI conversion is performed by the EXPORT_TO_ABI node in the MegaAG graph
    dest.data = (void*)src.flat_handles.data();

    return dest;
}

inline void export_cxx_arguments(const std::vector<CxxVectorArgument>& cxx_args,
                                 std::vector<CArgument>& input_args,
                                 std::vector<CArgument>& output_args) {
    for (int i = 0; i < input_args.size(); i++) {
        input_args[i] = export_cxx_argument(cxx_args[i]);
    }

    for (int i = 0; i < output_args.size(); i++) {
        int arg_idx = input_args.size() + i;
        output_args[i] = export_cxx_argument(cxx_args[arg_idx]);
    }
}

inline void append_public_key_arguments(nlohmann::json& key_signature,
                                        std::vector<CxxVectorArgument>& cxx_args,
                                        FheContext* context) {
    if (key_signature["rlk"].get<int>() >= 0) {
        int rlk_level = key_signature["rlk"].get<int>();
        cxx_args.emplace_back("rlk_ntt", CxxArgumentType::RELIN_KEY, rlk_level,
                              std::vector<Handle*>{const_cast<RelinKey*>(&context->evaluation_key_set().relin_key())});
    }

    if (!key_signature["glk"].empty()) {
        if (!key_signature.contains("glk_order")) {
            throw std::runtime_error("GLK signature requires glk_order");
        }

        int glk_level = -1;
        std::vector<Handle*> glk_handles;
        for (auto& item : key_signature["glk_order"]) {
            uint64_t gal_el = item.get<uint64_t>();
            int level = key_signature["glk"].at(std::to_string(gal_el)).get<int>();
            glk_level = glk_level < level ? level : glk_level;
            glk_handles.push_back(const_cast<GaloisKey*>(&context->evaluation_key_set().galois_key(gal_el)));
        }
        cxx_args.emplace_back("glk_ntt", CxxArgumentType::GALOIS_KEY, glk_level, std::move(glk_handles));
    }

    if (key_signature.contains("ckks_btp_evk") && !key_signature["ckks_btp_evk"].empty()) {
        auto* ckks_context = dynamic_cast<CkksContext*>(context);
        if (ckks_context == nullptr) {
            throw std::runtime_error("CKKS bootstrapping evaluation keys require CkksContext");
        }
        const auto& btp_keys = ckks_context->bootstrapping_evaluation_keys();
        const auto& btp_key_set = btp_keys.evaluation_key_set();
        for (auto& item : key_signature["ckks_btp_evk"].items()) {
            const std::string& id = item.key();
            int level = item.value()[0].get<int>();
            if (id == "evk_rlk") {
                cxx_args.emplace_back(id, CxxArgumentType::RELIN_KEY, level,
                                      std::vector<Handle*>{const_cast<RelinKey*>(&btp_key_set.relin_key())});
            } else if (id.rfind("evk_glk_", 0) == 0) {
                uint64_t gal_el = std::stoull(id.substr(std::string("evk_glk_").size()));
                cxx_args.emplace_back(id, CxxArgumentType::GALOIS_KEY, level,
                                      std::vector<Handle*>{const_cast<GaloisKey*>(&btp_key_set.galois_key(gal_el))});
            } else if (id == "evk_n1_to_n2") {
                cxx_args.emplace_back(id, CxxArgumentType::EVALUATION_KEY, level,
                                      std::vector<Handle*>{const_cast<EvaluationKey*>(&btp_keys.evk_n1_to_n2())});
            } else if (id == "evk_n2_to_n1") {
                cxx_args.emplace_back(id, CxxArgumentType::EVALUATION_KEY, level,
                                      std::vector<Handle*>{const_cast<EvaluationKey*>(&btp_keys.evk_n2_to_n1())});
            } else if (id == "evk_dense_to_sparse") {
                cxx_args.emplace_back(
                    id, CxxArgumentType::EVALUATION_KEY, level,
                    std::vector<Handle*>{const_cast<EvaluationKey*>(&btp_keys.evk_dense_to_sparse())});
            } else if (id == "evk_sparse_to_dense") {
                cxx_args.emplace_back(
                    id, CxxArgumentType::EVALUATION_KEY, level,
                    std::vector<Handle*>{const_cast<EvaluationKey*>(&btp_keys.evk_sparse_to_dense())});
            }
        }
    }
}

inline std::vector<CxxVectorArgument> build_runtime_cxx_arguments(const std::vector<CxxVectorArgument>& cxx_args,
                                                                  int n_in_args,
                                                                  nlohmann::json& key_signature,
                                                                  FheContext* context) {
    std::vector<CxxVectorArgument> runtime_args;
    runtime_args.reserve(cxx_args.size() + 2);

    auto output_begin = cxx_args.begin() + n_in_args;
    runtime_args.insert(runtime_args.end(), cxx_args.begin(), output_begin);
    append_public_key_arguments(key_signature, runtime_args, context);
    runtime_args.insert(runtime_args.end(), output_begin, cxx_args.end());

    return runtime_args;
}

inline int get_n_key_arg(nlohmann::json& key_signature, bool online_phase = true) {
    int n_key_arg = 0;
    if (online_phase) {
        if (key_signature["rlk"].get<int>() >= 0) {
            n_key_arg++;
        }
        if (!key_signature["glk"].empty()) {
            n_key_arg++;
        }
        if (key_signature.contains("ckks_btp_evk")) {
            n_key_arg += key_signature["ckks_btp_evk"].size();
        }
    }
    return n_key_arg;
}

}  // namespace lattisense

#endif  // CXX_ARGUMENT_H

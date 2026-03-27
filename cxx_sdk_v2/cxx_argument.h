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
#include <unordered_map>
#include <stdexcept>
#include "nlohmann/json.hpp"
#include "../fhe_ops_lib/fhe_lib_v2.h"

extern "C" {
#include "../fhe_ops_lib/structs_v2.h"
#include "../mega_ag_runners/wrapper.h"
}

namespace lattisense {

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

inline std::unordered_map<CxxArgumentType, DataType> type_map = {
    {CxxArgumentType::CIPHERTEXT, DataType::TYPE_CIPHERTEXT},
    {CxxArgumentType::CIPHERTEXT3, DataType::TYPE_CIPHERTEXT},
    {CxxArgumentType::PLAINTEXT, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::PLAINTEXT_RINGT, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::PLAINTEXT_MUL, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::RELIN_KEY, DataType::TYPE_RELIN_KEY},
    {CxxArgumentType::GALOIS_KEY, DataType::TYPE_GALOIS_KEY},
    {CxxArgumentType::CUSTOM, DataType::TYPE_CUSTOM},
};

inline std::unordered_map<std::type_index, CxxArgumentType> _type_map = {
    {std::type_index(typeid(BfvCiphertext)), CxxArgumentType::CIPHERTEXT},
    {std::type_index(typeid(BfvCiphertext3)), CxxArgumentType::CIPHERTEXT3},
    {std::type_index(typeid(BfvPlaintext)), CxxArgumentType::PLAINTEXT},
    {std::type_index(typeid(BfvPlaintextRingt)), CxxArgumentType::PLAINTEXT_RINGT},
    {std::type_index(typeid(BfvPlaintextMul)), CxxArgumentType::PLAINTEXT_MUL},
    {std::type_index(typeid(CkksCiphertext)), CxxArgumentType::CIPHERTEXT},
    {std::type_index(typeid(CkksCiphertext3)), CxxArgumentType::CIPHERTEXT3},
    {std::type_index(typeid(CkksPlaintext)), CxxArgumentType::PLAINTEXT},
    {std::type_index(typeid(CkksPlaintextRingt)), CxxArgumentType::PLAINTEXT_RINGT},
    {std::type_index(typeid(CkksPlaintextMul)), CxxArgumentType::PLAINTEXT_MUL},
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

        // CustomData doesn't have get_level(), use -1 as default
        if constexpr (std::is_same_v<T, CustomData>) {
            flat_levels.push_back(-1);
        } else {
            flat_levels.push_back(x.get_level());
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

/**
 * @brief Per-instance storage for extracted public keys.
 *
 * Owned by FheTask so that key lifetime is tied to the FheTask instance,
 * avoiding the thread-safety and multi-instance hazards of static locals.
 */
struct PublicKeyStorage {
    RelinKey saved_rlk;
    GaloisKey saved_glk;
    KeySwitchKey saved_swk_dts;
    KeySwitchKey saved_swk_std;
    RelinKey* rlk_handle = nullptr;
    GaloisKey* glk_handle = nullptr;
    KeySwitchKey* swk_dts_handle = nullptr;
    KeySwitchKey* swk_std_handle = nullptr;
};

inline void export_public_key_arguments(nlohmann::json& key_signature,
                                        std::vector<CArgument>& input_args,
                                        FheContext* context,
                                        PublicKeyStorage& keys) {
    if (key_signature["rlk"].get<int>() >= 0) {
        CArgument rlk_arg;
        int rlk_level = key_signature["rlk"].get<int>();
        rlk_arg.id = "rlk_ntt";
        rlk_arg.type = DataType::TYPE_RELIN_KEY;
        rlk_arg.size = 1;
        rlk_arg.level = rlk_level;

        // Use Handle* pointers; ABI conversion is performed by the EXPORT_TO_ABI node in the MegaAG graph
        keys.saved_rlk = context->extract_relin_key();
        keys.rlk_handle = &keys.saved_rlk;
        rlk_arg.data = (void*)&keys.rlk_handle;

        input_args.push_back(rlk_arg);
    }
    if (!key_signature["glk"].empty()) {
        CArgument glk_arg;
        int glk_level = -1;
        for (auto& item : key_signature["glk"].items()) {
            int level = item.value().get<int>();
            glk_level = glk_level < level ? level : glk_level;
        }

        glk_arg.id = "glk_ntt";
        glk_arg.type = DataType::TYPE_GALOIS_KEY;
        glk_arg.size = 1;
        glk_arg.level = glk_level;

        // Use Handle* pointers; ABI conversion is performed by the EXPORT_TO_ABI node in the MegaAG graph
        keys.saved_glk = context->extract_galois_key();
        keys.glk_handle = &keys.saved_glk;
        glk_arg.data = (void*)&keys.glk_handle;

        input_args.push_back(glk_arg);
    }
    if (key_signature.contains("ckks_btp_swk")) {
        auto& swk_sig = key_signature["ckks_btp_swk"];
        CkksBtpContext* btp_context = dynamic_cast<CkksBtpContext*>(context);
        if (btp_context == nullptr) {
            throw std::runtime_error("Context is not CkksBtpContext but ckks_btp_swk is required");
        }

        if (swk_sig.contains("swk_dts")) {
            CArgument swk_dts_arg;
            auto swk_dts_levels = swk_sig["swk_dts"].get<std::vector<int>>();
            int level = swk_dts_levels[0];

            swk_dts_arg.id = "swk_dts";
            swk_dts_arg.type = DataType::TYPE_SWITCH_KEY;
            swk_dts_arg.size = 1;
            swk_dts_arg.level = level;

            // Use Handle* pointers; ABI conversion is performed by the EXPORT_TO_ABI node in the MegaAG graph
            keys.saved_swk_dts = btp_context->extract_swk_dts();
            keys.swk_dts_handle = &keys.saved_swk_dts;
            swk_dts_arg.data = (void*)&keys.swk_dts_handle;

            input_args.push_back(swk_dts_arg);
        }

        if (swk_sig.contains("swk_std")) {
            CArgument swk_std_arg;
            auto swk_std_levels = swk_sig["swk_std"].get<std::vector<int>>();
            int level = swk_std_levels[0];

            swk_std_arg.id = "swk_std";
            swk_std_arg.type = DataType::TYPE_SWITCH_KEY;
            swk_std_arg.size = 1;
            swk_std_arg.level = level;

            // Use Handle* pointers; ABI conversion is performed by the EXPORT_TO_ABI node in the MegaAG graph
            keys.saved_swk_std = btp_context->extract_swk_std();
            keys.swk_std_handle = &keys.saved_swk_std;
            swk_std_arg.data = (void*)&keys.swk_std_handle;

            input_args.push_back(swk_std_arg);
        }
    }
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
        if (key_signature.contains("ckks_btp_swk")) {
            auto& swk = key_signature["ckks_btp_swk"];
            if (swk.contains("swk_dts")) {
                n_key_arg++;
            }
            if (swk.contains("swk_std")) {
                n_key_arg++;
            }
        }
    }
    return n_key_arg;
}

}  // namespace lattisense

#endif  // CXX_ARGUMENT_H

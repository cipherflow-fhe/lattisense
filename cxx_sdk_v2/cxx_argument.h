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

inline std::unordered_map<CxxArgumentType, DataType> type_map = {
    {CxxArgumentType::CIPHERTEXT, DataType::TYPE_CIPHERTEXT},
    {CxxArgumentType::CIPHERTEXT3, DataType::TYPE_CIPHERTEXT},
    {CxxArgumentType::PLAINTEXT, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::PLAINTEXT_RINGT, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::PLAINTEXT_MUL, DataType::TYPE_PLAINTEXT},
    {CxxArgumentType::RELIN_KEY, DataType::TYPE_RELIN_KEY},
    {CxxArgumentType::GALOIS_KEY, DataType::TYPE_GALOIS_KEY},
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

inline void _export_ciphertexts(const std::vector<Handle*>& src, CCiphertext* dest, const Parameter& param) {
    for (int i = 0; i < src.size(); i++) {
        if (typeid(param) == typeid(BfvParameter)) {
            export_bfv_ciphertext(src[i]->get(), &dest[i]);
        } else if (typeid(param) == typeid(CkksParameter)) {
            export_ckks_ciphertext(src[i]->get(), &dest[i]);
        }
    }
}

inline void _import_ciphertexts(CCiphertext* src, const std::vector<Handle*>& dest, const Parameter& param) {
    for (int i = 0; i < dest.size(); i++) {
        if (typeid(param) == typeid(BfvParameter)) {
            *dest[i] = import_bfv_ciphertext(param.get(), &src[i]);
        } else if (typeid(param) == typeid(CkksParameter)) {
            double scale = ((CkksCiphertext*)dest[i])->get_scale();
            *dest[i] = import_ckks_ciphertext(param.get(), &src[i]);
            ((CkksCiphertext*)dest[i])->set_scale(scale);
        }
    }
}

inline void _export_plaintexts(const std::vector<Handle*>& src, CPlaintext* dest, const Parameter& param) {
    for (int i = 0; i < src.size(); i++) {
        if (typeid(param) == typeid(BfvParameter)) {
            export_bfv_plaintext(src[i]->get(), &dest[i]);
        } else if (typeid(param) == typeid(CkksParameter)) {
            export_ckks_plaintext(src[i]->get(), &dest[i]);
        }
    }
}

inline void _export_plaintext_ringts(const std::vector<Handle*>& src, CPlaintext* dest, const Parameter& param) {
    for (int i = 0; i < src.size(); i++) {
        if (typeid(param) == typeid(BfvParameter)) {
            export_bfv_plaintext_ringt(src[i]->get(), &dest[i]);
        } else if (typeid(param) == typeid(CkksParameter)) {
            export_ckks_plaintext_ringt(src[i]->get(), &dest[i]);
        }
    }
}

inline void
_export_plaintext_muls(const std::vector<Handle*>& src, CPlaintext* dest, const Parameter& param, int mf_nbits) {
    if (mf_nbits == 0) {
        throw std::runtime_error("Unsupported mfrom bite");
    }
    for (int i = 0; i < src.size(); i++) {
        if (typeid(param) == typeid(BfvParameter)) {
            bfv_plaintext_mul_inv_mform_and_mul_by_pow2(param.get(), src[i]->get(), mf_nbits);
            export_bfv_plaintext_mul(src[i]->get(), &dest[i]);
        } else if (typeid(param) == typeid(CkksParameter)) {
            ckks_plaintext_mul_inv_mform_and_mul_by_pow2(param.get(), src[i]->get(), mf_nbits);
            export_ckks_plaintext_mul(src[i]->get(), &dest[i]);
        }
    }
}

inline void _export_relin_key(const Handle& src, CRelinKey* dest, int level, const Parameter& param, int mf_nbits) {
    if (typeid(param) == typeid(BfvParameter)) {
        set_bfv_rlk_n_mform_bits(param.get(), src.get(), mf_nbits);
    } else if (typeid(param) == typeid(CkksParameter)) {
        set_ckks_rlk_n_mform_bits(param.get(), src.get(), mf_nbits);
    }
    export_relin_key(src.get(), level, dest);
}

inline void _export_galois_key(const Handle& src, CGaloisKey* dest, int level, const Parameter& param, int mf_nbits) {
    if (typeid(param) == typeid(BfvParameter)) {
        set_bfv_glk_n_mform_bits(param.get(), src.get(), mf_nbits);
    } else if (typeid(param) == typeid(CkksParameter)) {
        set_ckks_glk_n_mform_bits(param.get(), src.get(), mf_nbits);
    }

    export_galois_key(src.get(), level, dest);
}

inline void _export_switching_key(const Handle& src,
                                  CKeySwitchKey* dest,
                                  int level,
                                  int sp_level,
                                  const Parameter& param,
                                  int mf_nbits) {
    if (typeid(param) == typeid(BfvParameter)) {
        throw std::runtime_error("BFV does not support switching key export");
    } else if (typeid(param) == typeid(CkksParameter)) {
        set_ckks_swk_n_mform_bits(param.get(), src.get(), mf_nbits);
    }
    export_switching_key(src.get(), level, sp_level, dest);
}

inline CArgument
export_cxx_argument(const CxxVectorArgument& src, const Parameter& param, int mf_nbits, bool is_heterogeneous = true) {
    CArgument dest;
    dest.id = src.arg_id.c_str();
    dest.type = type_map[src.type];
    dest.size = src.flat_handles.size();
    dest.level = src.level;

    if (!is_heterogeneous) {
        dest.data = (void*)src.flat_handles.data();
        return dest;
    }

    // GPU/FPGA mode: export to C struct (for GPU computation)
    switch (src.type) {
        case CxxArgumentType::CIPHERTEXT: {
            dest.data = (CCiphertext*)malloc(sizeof(CCiphertext) * dest.size);
            _export_ciphertexts(src.flat_handles, (CCiphertext*)dest.data, param);
            break;
        }
        case CxxArgumentType::CIPHERTEXT3: {
            dest.data = (CCiphertext*)malloc(sizeof(CCiphertext) * dest.size);
            _export_ciphertexts(src.flat_handles, (CCiphertext*)dest.data, param);
            break;
        }
        case CxxArgumentType::PLAINTEXT: {
            dest.data = (CPlaintext*)malloc(sizeof(CPlaintext) * dest.size);
            _export_plaintexts(src.flat_handles, (CPlaintext*)dest.data, param);
            break;
        }
        case CxxArgumentType::PLAINTEXT_RINGT: {
            dest.data = (CPlaintext*)malloc(sizeof(CPlaintext) * dest.size);
            _export_plaintext_ringts(src.flat_handles, (CPlaintext*)dest.data, param);
            break;
        }
        case CxxArgumentType::PLAINTEXT_MUL: {
            dest.data = (CPlaintext*)malloc(sizeof(CPlaintext) * dest.size);
            _export_plaintext_muls(src.flat_handles, (CPlaintext*)dest.data, param, mf_nbits);
            break;
        }
        case CxxArgumentType::CUSTOM: {
            break;
        }
        default: throw std::runtime_error("Unsupported argument type");
    }
    return dest;
}

inline void export_cxx_arguments(const std::vector<CxxVectorArgument>& cxx_args,
                                 std::vector<CArgument>& input_args,
                                 std::vector<CArgument>& output_args,
                                 const Parameter& param,
                                 int mf_nbits,
                                 bool is_heterogeneous) {
    for (int i = 0; i < input_args.size(); i++) {
        input_args[i] = export_cxx_argument(cxx_args[i], param, mf_nbits, is_heterogeneous);
    }

    for (int i = 0; i < output_args.size(); i++) {
        output_args[i] = export_cxx_argument(cxx_args[input_args.size() + i], param, mf_nbits, is_heterogeneous);
    }
}

inline void export_public_key_arguments(nlohmann::json& key_signature,
                                        std::vector<CArgument>& input_args,
                                        FheContext* context,
                                        int mf_nbits,
                                        bool is_heterogeneous) {
    if (key_signature["rlk"].get<int>() >= 0) {
        CArgument rlk_arg;
        int rlk_level = key_signature["rlk"].get<int>();
        RelinKey rlk = context->extract_relin_key();
        rlk_arg.id = "rlk_ntt";
        rlk_arg.type = DataType::TYPE_RELIN_KEY;
        rlk_arg.size = 1;
        rlk_arg.level = rlk_level;

        if (!is_heterogeneous) {
            static RelinKey saved_rlk;
            static std::vector<Handle*> rlk_handle_vec(1);
            saved_rlk = std::move(rlk);
            rlk_handle_vec[0] = (Handle*)&saved_rlk;
            rlk_arg.data = (void*)rlk_handle_vec.data();
            input_args.push_back(rlk_arg);
        } else {
            rlk_arg.data = (CRelinKey*)malloc(sizeof(CRelinKey) * rlk_arg.size);
            input_args.push_back(rlk_arg);
            _export_relin_key(rlk, &((CRelinKey*)(rlk_arg.data))[0], rlk_level, context->get_parameter(), mf_nbits);
        }
    }
    if (!key_signature["glk"].empty()) {
        CArgument glk_arg;
        int glk_level = -1;
        std::vector<uint64_t> galois_elements;
        for (auto& item : key_signature["glk"].items()) {
            int level = item.value().get<int>();
            glk_level = glk_level < level ? level : glk_level;
            uint64_t gal_el = std::stoul(item.key());
            galois_elements.push_back(gal_el);
        }

        GaloisKey glk = context->extract_galois_key();
        glk_arg.id = "glk_ntt";
        glk_arg.type = DataType::TYPE_GALOIS_KEY;
        glk_arg.size = 1;
        glk_arg.level = glk_level;

        if (!is_heterogeneous) {
            static GaloisKey saved_glk;
            static std::vector<Handle*> glk_handle_vec(1);
            saved_glk = std::move(glk);
            glk_handle_vec[0] = (Handle*)&saved_glk;
            glk_arg.data = (void*)glk_handle_vec.data();
            input_args.push_back(glk_arg);
        } else {
            CGaloisKey* c_glk = (CGaloisKey*)malloc(sizeof(CGaloisKey) * glk_arg.size);
            set_galois_key_steps(&c_glk[0], galois_elements.data(), galois_elements.size());
            glk_arg.data = c_glk;
            input_args.push_back(glk_arg);
            _export_galois_key(glk, &((CGaloisKey*)(glk_arg.data))[0], glk_level, context->get_parameter(), mf_nbits);
        }
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
            int sp_level = swk_dts_levels[1];

            KeySwitchKey swk_dts = btp_context->extract_swk_dts();
            swk_dts_arg.id = "swk_dts";
            swk_dts_arg.type = DataType::TYPE_SWITCH_KEY;
            swk_dts_arg.size = 1;
            swk_dts_arg.level = level;

            if (!is_heterogeneous) {
                static KeySwitchKey saved_swk_dts;
                static std::vector<Handle*> swk_dts_handle_vec(1);
                saved_swk_dts = std::move(swk_dts);
                swk_dts_handle_vec[0] = (Handle*)&saved_swk_dts;
                swk_dts_arg.data = (void*)swk_dts_handle_vec.data();
                input_args.push_back(swk_dts_arg);
            } else {
                swk_dts_arg.data = (CKeySwitchKey*)malloc(sizeof(CKeySwitchKey) * swk_dts_arg.size);
                input_args.push_back(swk_dts_arg);
                _export_switching_key(swk_dts, &((CKeySwitchKey*)(swk_dts_arg.data))[0], level, sp_level,
                                      context->get_parameter(), mf_nbits);
            }
        }

        if (swk_sig.contains("swk_std")) {
            CArgument swk_std_arg;
            auto swk_std_levels = swk_sig["swk_std"].get<std::vector<int>>();
            int level = swk_std_levels[0];
            int sp_level = swk_std_levels[1];

            KeySwitchKey swk_std = btp_context->extract_swk_std();
            swk_std_arg.id = "swk_std";
            swk_std_arg.type = DataType::TYPE_SWITCH_KEY;
            swk_std_arg.size = 1;
            swk_std_arg.level = level;

            if (!is_heterogeneous) {
                // CPU mode: need to save the swk object itself
                static KeySwitchKey saved_swk_std;
                static std::vector<Handle*> swk_std_handle_vec(1);
                saved_swk_std = std::move(swk_std);
                swk_std_handle_vec[0] = (Handle*)&saved_swk_std;
                swk_std_arg.data = (void*)swk_std_handle_vec.data();
                input_args.push_back(swk_std_arg);
            } else {
                swk_std_arg.data = (CKeySwitchKey*)malloc(sizeof(CKeySwitchKey) * swk_std_arg.size);
                input_args.push_back(swk_std_arg);
                _export_switching_key(swk_std, &((CKeySwitchKey*)(swk_std_arg.data))[0], level, sp_level,
                                      context->get_parameter(), mf_nbits);
            }
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

}  // namespace cxx_sdk_v2

#endif  // CXX_ARGUMENT_H

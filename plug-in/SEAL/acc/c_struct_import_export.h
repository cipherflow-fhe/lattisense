#pragma once

extern "C" {
#include "fhe_types_v2.h"
#include "wrapper.h"
#include "c_argument.h"
}
#include <typeindex>
#include <any>
#include <seal/seal.h>
#include "nlohmann/json.hpp"

void _export_ciphertext(uint64_t param_id,
                        seal::util::ConstNTTTablesIter& ntt_tables,
                        seal::Ciphertext* src,
                        CCiphertext* dest);
void _import_ciphertext(uint64_t param_id,
                        seal::util::ConstNTTTablesIter& ntt_tables,
                        CCiphertext* src,
                        seal::Ciphertext* dest);

void _export_plaintext(uint64_t param_id,
                       int N,
                       seal::util::ConstNTTTablesIter& ntt_tables,
                       seal::Plaintext* src,
                       CPlaintext* dest);

void _export_relin_key(uint64_t param_id,
                       seal::scheme_type scheme,
                       seal::util::ConstNTTTablesIter& ntt_tables,
                       const seal::RelinKeys* src,
                       CRelinKey* dest,
                       int level,
                       int mf_nbits);
void _export_galois_key(uint64_t param_id,
                        seal::scheme_type scheme,
                        seal::util::ConstNTTTablesIter& ntt_tables,
                        const seal::GaloisKeys* src,
                        CGaloisKey* dest,
                        int level,
                        int mf_nbits);

enum class SealArgumentType { PLAINTEXT, CIPHERTEXT, RELIN_KEY, GALOIS_KEY };

extern std::unordered_map<SealArgumentType, DataType> type_map;
extern std::unordered_map<std::type_index, SealArgumentType> _type_map;

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

    int level = -1;
    ;
    SealArgumentType type = _type_map[std::type_index(typeid(T))];

    flat_types.push_back(type);
    flat_levels.push_back(level);
}

template <>
inline void get_arg_info<seal::Plaintext>(const seal::EncryptionParameters& params,
                                          seal::Plaintext& x,
                                          std::vector<std::any>& flat,
                                          std::vector<SealArgumentType>& flat_types,
                                          std::vector<int>& flat_levels) {
    flat.push_back(&x);

    int level = x.coeff_count() / params.poly_modulus_degree() - 1;
    SealArgumentType type = _type_map[std::type_index(typeid(seal::Plaintext))];

    flat_types.push_back(type);
    flat_levels.push_back(level);
}

template <>
inline void get_arg_info<seal::Ciphertext>(const seal::EncryptionParameters& params,
                                           seal::Ciphertext& x,
                                           std::vector<std::any>& flat,
                                           std::vector<SealArgumentType>& flat_types,
                                           std::vector<int>& flat_levels) {
    flat.push_back(&x);

    int level = x.coeff_modulus_size() - 1;
    SealArgumentType type = _type_map[std::type_index(typeid(seal::Ciphertext))];

    flat_types.push_back(type);
    flat_levels.push_back(level);
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

        for (int i = 0; i < flat_data.size(); i++) {
            if (flat_types[i] != type) {
                throw std::runtime_error("inconsistent types");
            }
            if (flat_levels[i] != level) {
                throw std::runtime_error("inconsistent levels");
            }
        }
    }
};

CArgument export_argument(std::string phase,
                          const SealVectorArgument& src,
                          seal::util::ConstNTTTablesIter& ntt_tables,
                          int N,
                          uint64_t param_id);

void export_arguments(const std::vector<SealVectorArgument>& seal_args,
                      std::vector<CArgument>& input_args,
                      std::vector<CArgument>& output_args,
                      seal::util::ConstNTTTablesIter& ntt_tables,
                      int N,
                      uint64_t param_id);

void import_arguments(const std::vector<SealVectorArgument>& seal_args,
                      int arg_idx_offset,
                      std::vector<CArgument>& output_args,
                      seal::util::ConstNTTTablesIter& ntt_tables,
                      int N,
                      uint64_t param_id);

void export_public_keys(const seal::RelinKeys* rlk,
                        const seal::GaloisKeys* glk,
                        nlohmann::json& key_signature,
                        std::vector<CArgument>& input_args,
                        uint64_t param_id,
                        seal::scheme_type scheme,
                        seal::util::ConstNTTTablesIter& ntt_tables,
                        int mf_nbits);

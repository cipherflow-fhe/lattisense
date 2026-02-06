#include "c_struct_import_export.h"
#include <fstream>
#include <algorithm>
#include "nlohmann/json.hpp"

extern "C" {
#include "structs_v2.h"
}

using namespace std;
using namespace seal::util;

void _export_ciphertext(uint64_t param_id, ConstNTTTablesIter& ntt_tables, seal::Ciphertext* src, CCiphertext* dest) {
    dest->level = src->coeff_modulus_size() - 1;
    int N = src->poly_modulus_degree();
    dest->degree = src->size() - 1;
    dest->polys = (CPolynomial*)malloc(sizeof(CPolynomial) * src->size());

    for (int i = 0; i < src->size(); i++) {
        dest->polys[i].n_component = dest->level + 1;
        dest->polys[i].components = (CComponent*)malloc(sizeof(CComponent) * (dest->level + 1));

        for (int j = 0; j < dest->level + 1; j++) {
            dest->polys[i].components[j].n = N;
            dest->polys[i].components[j].data = (uint64_t*)malloc(sizeof(uint64_t) * N);

            if (src->is_ntt_form()) {
                CoeffIter src_coeff(&src->data(i)[j * N]);
                inverse_ntt_negacyclic_harvey(src_coeff, ntt_tables[j]);
            }

            memcpy(dest->polys[i].components[j].data, &src->data(i)[j * N], N * sizeof(uint64_t));

            if (src->is_ntt_form()) {
                ckks_component_ntt(param_id, dest->polys[i].components[j].data, j);
            }
        }
    }
}

void _import_ciphertext(uint64_t param_id, ConstNTTTablesIter& ntt_tables, CCiphertext* src, seal::Ciphertext* dest) {
    int N = src->polys->components->n;
    for (int i = 0; i < src->degree + 1; i++) {
        for (int j = 0; j < src->polys[i].n_component; j++) {
            if (dest->is_ntt_form()) {
                ckks_component_inv_ntt(param_id, src->polys[i].components[j].data, j);
            }
            memcpy(&dest->data(i)[j * N], src->polys[i].components[j].data, N * sizeof(uint64_t));

            if (dest->is_ntt_form()) {
                CoeffIter dest_coeff(&dest->data(i)[j * N]);
                ntt_negacyclic_harvey(dest_coeff, ntt_tables[j]);
            }
        }
    }
}

void _export_plaintext(uint64_t param_id,
                       int N,
                       ConstNTTTablesIter& ntt_tables,
                       seal::Plaintext* src,
                       CPlaintext* dest) {
    dest->level = src->coeff_count() / N - 1;
    dest->poly.n_component = dest->level + 1;
    dest->poly.components = (CComponent*)malloc(sizeof(CComponent) * (dest->level + 1));

    for (int j = 0; j < dest->level + 1; j++) {
        dest->poly.components[j].n = N;
        dest->poly.components[j].data = (uint64_t*)malloc(sizeof(uint64_t) * N);

        if (src->is_ntt_form()) {
            CoeffIter src_coeff(&src->data()[j * N]);
            inverse_ntt_negacyclic_harvey(src_coeff, ntt_tables[j]);
        }
        memcpy(dest->poly.components[j].data, &src->data()[j * N], N * sizeof(uint64_t));

        if (src->is_ntt_form()) {
            ckks_component_ntt(param_id, dest->poly.components[j].data, j);
        }
    }
}

void _export_key_switch_key(uint64_t param_id,
                            seal::scheme_type scheme,
                            ConstNTTTablesIter& ntt_tables,
                            const vector<seal::PublicKey>& src,
                            CKeySwitchKey* dest,
                            int level,
                            int mf_nbits) {
    int n_public_key = level + 1;  // sp_level = 0

    int N = src[0].data().poly_modulus_degree();
    int n_component = src[0].data().coeff_modulus_size();

    dest->n_public_key = n_public_key;
    dest->public_keys = (CPublicKey*)malloc(sizeof(CPublicKey) * n_public_key);

    for (int k = 0; k < n_public_key; k++) {
        dest->public_keys[k].level = level;
        dest->public_keys[k].degree = 1;
        dest->public_keys[k].polys = (CPolynomial*)malloc(sizeof(CPolynomial) * 2);

        for (int i = 0; i < 2; i++) {
            dest->public_keys[k].polys[i].n_component = n_component;
            dest->public_keys[k].polys[i].components = (CComponent*)malloc(sizeof(CComponent) * n_component);

            for (int j = 0; j < n_component; j++) {
                dest->public_keys[k].polys[i].components[j].n = N;
                dest->public_keys[k].polys[i].components[j].data = (uint64_t*)malloc(sizeof(uint64_t) * N);

                CoeffIter ksk_coeff(const_cast<uint64_t*>(&src[k].data().data(i)[j * N]));
                inverse_ntt_negacyclic_harvey(ksk_coeff, ntt_tables[j]);

                memcpy(dest->public_keys[k].polys[i].components[j].data, &src[k].data().data(i)[j * N],
                       N * sizeof(uint64_t));

                if (scheme == seal::scheme_type::bfv) {
                    bfv_component_ntt(param_id, dest->public_keys[k].polys[i].components[j].data, j);
                    if (mf_nbits != 0) {
                        bfv_component_mul_by_pow2(param_id, dest->public_keys[k].polys[i].components[j].data, j,
                                                  mf_nbits);
                    }
                } else {
                    ckks_component_ntt(param_id, dest->public_keys[k].polys[i].components[j].data, j);
                    if (mf_nbits != 0) {
                        ckks_component_mul_by_pow2(param_id, dest->public_keys[k].polys[i].components[j].data, j,
                                                   mf_nbits);
                    }
                }
            }
        }
    }
}

void _export_relin_key(uint64_t param_id,
                       seal::scheme_type scheme,
                       ConstNTTTablesIter& ntt_tables,
                       const seal::RelinKeys* src,
                       CRelinKey* dest,
                       int level,
                       int mf_nbits) {
    _export_key_switch_key(param_id, scheme, ntt_tables, src->key(2), dest, level, mf_nbits);
}

void _export_galois_key(uint64_t param_id,
                        seal::scheme_type scheme,
                        ConstNTTTablesIter& ntt_tables,
                        const seal::GaloisKeys* src,
                        CGaloisKey* dest,
                        int level,
                        int mf_nbits) {
    int n_key_switch_key = dest->n_key_switch_key;
    dest->key_switch_keys = (CKeySwitchKey*)malloc(sizeof(CKeySwitchKey) * n_key_switch_key);

    for (int i = 0; i < n_key_switch_key; i++) {
        _export_key_switch_key(param_id, scheme, ntt_tables, src->key(dest->galois_elements[i]),
                               &(dest->key_switch_keys[i]), level, mf_nbits);
    }
}

unordered_map<type_index, SealArgumentType> _type_map = {
    {type_index(typeid(seal::Ciphertext)), SealArgumentType::CIPHERTEXT},
    {type_index(typeid(seal::Plaintext)), SealArgumentType::PLAINTEXT}};

std::unordered_map<SealArgumentType, DataType> type_map = {
    {SealArgumentType::CIPHERTEXT, DataType::TYPE_CIPHERTEXT},
    {SealArgumentType::PLAINTEXT, DataType::TYPE_PLAINTEXT},
    {SealArgumentType::RELIN_KEY, DataType::TYPE_RELIN_KEY},
    {SealArgumentType::GALOIS_KEY, DataType::TYPE_GALOIS_KEY},
};

CArgument export_argument(std::string phase,
                          const SealVectorArgument& src,
                          ConstNTTTablesIter& ntt_tables,
                          int N,
                          uint64_t param_id) {
    CArgument dest;
    dest.id = src.arg_id.c_str();
    dest.type = type_map[src.type];
    dest.size = src.flat_data.size();
    dest.level = src.level;

    switch (src.type) {
        case SealArgumentType::CIPHERTEXT: {
            dest.data = (CCiphertext*)malloc(sizeof(CCiphertext) * dest.size);
            if (phase == "in") {
                for (int i = 0; i < src.flat_data.size(); i++) {
                    _export_ciphertext(param_id, ntt_tables, std::any_cast<seal::Ciphertext*>(src.flat_data[i]),
                                       &((CCiphertext*)dest.data)[i]);
                }
            } else {
                for (int i = 0; i < src.flat_data.size(); i++) {
                    alloc_ciphertext(&((CCiphertext*)dest.data)[i],
                                     std::any_cast<seal::Ciphertext*>(src.flat_data[i])->size() - 1, src.level, N);
                }
            }
            break;
        }
        case SealArgumentType::PLAINTEXT: {
            dest.data = (CPlaintext*)malloc(sizeof(CPlaintext) * dest.size);
            for (int i = 0; i < src.flat_data.size(); i++) {
                _export_plaintext(param_id, N, ntt_tables, std::any_cast<seal::Plaintext*>(src.flat_data[i]),
                                  &((CPlaintext*)dest.data)[i]);
            }
            break;
        }
        default: throw std::runtime_error("Unsupported argument type");
    }

    return dest;
}

void export_arguments(const std::vector<SealVectorArgument>& seal_args,
                      std::vector<CArgument>& input_args,
                      std::vector<CArgument>& output_args,
                      ConstNTTTablesIter& ntt_tables,
                      int N,
                      uint64_t param_id) {
    for (int i = 0; i < input_args.size(); i++) {
        input_args[i] = export_argument("in", seal_args[i], ntt_tables, N, param_id);
    }

    for (int i = 0; i < output_args.size(); i++) {
        output_args[i] = export_argument("out", seal_args[input_args.size() + i], ntt_tables, N, param_id);
    }
}

void import_arguments(const std::vector<SealVectorArgument>& seal_args,
                      int arg_idx_offset,
                      std::vector<CArgument>& output_args,
                      ConstNTTTablesIter& ntt_tables,
                      int N,
                      uint64_t param_id) {
    for (int i = 0; i < output_args.size(); i++) {
        for (int j = 0; j < seal_args[i + arg_idx_offset].flat_data.size(); j++) {
            _import_ciphertext(param_id, ntt_tables, &((CCiphertext*)output_args[i].data)[j],
                               std::any_cast<seal::Ciphertext*>(seal_args[i + arg_idx_offset].flat_data[j]));
        }
    }
}

void export_public_keys(const seal::RelinKeys* rlk,
                        const seal::GaloisKeys* glk,
                        nlohmann::json& key_signature,
                        std::vector<CArgument>& input_args,
                        uint64_t param_id,
                        seal::scheme_type scheme,
                        ConstNTTTablesIter& ntt_tables,
                        int mf_nbits) {
    if (key_signature["rlk"].get<int>() >= 0) {
        CArgument rlk_arg;
        int rlk_level = key_signature["rlk"].get<int>();
        rlk_arg.id = "rlk_ntt";
        rlk_arg.type = DataType::TYPE_RELIN_KEY;
        rlk_arg.size = 1;
        rlk_arg.level = rlk_level;
        rlk_arg.data = (CRelinKey*)malloc(sizeof(CRelinKey) * rlk_arg.size);

        _export_relin_key(param_id, scheme, ntt_tables, rlk, &((CRelinKey*)rlk_arg.data)[0], rlk_level, mf_nbits);

        input_args.push_back(rlk_arg);
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

        glk_arg.id = "glk_ntt";
        glk_arg.type = DataType::TYPE_GALOIS_KEY;
        glk_arg.size = 1;
        glk_arg.level = glk_level;

        CGaloisKey* c_glk = (CGaloisKey*)malloc(sizeof(CGaloisKey) * glk_arg.size);
        set_galois_key_steps(&c_glk[0], galois_elements.data(), galois_elements.size());

        glk_arg.data = c_glk;

        _export_galois_key(param_id, scheme, ntt_tables, glk, &((CGaloisKey*)glk_arg.data)[0], glk_level, mf_nbits);

        input_args.push_back(glk_arg);
    }
}

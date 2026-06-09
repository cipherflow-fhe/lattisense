#pragma once

extern "C" {
#include "c_types.h"
#include "wrapper.h"
#include "c_argument.h"
#include "c_structs.h"
}
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <seal/seal.h>
#include "nlohmann/json.hpp"

using namespace seal::util;

// ---------------------------------------------------------------------------
// Low-level SEAL → C struct export / import
// ---------------------------------------------------------------------------

inline void _alloc_contiguous_polynomial(CPolynomial* dest, int n_component, int N) {
    dest->n_component = n_component;
    dest->components = (CComponent*)malloc(sizeof(CComponent) * n_component);
    dest->contiguous_data = (uint64_t*)malloc(sizeof(uint64_t) * (size_t)n_component * (size_t)N);
    dest->owns_contiguous_data = 1;

    for (int j = 0; j < n_component; j++) {
        dest->components[j].n = N;
        dest->components[j].data = dest->contiguous_data + (size_t)j * (size_t)N;
    }
}

inline void
_export_ciphertext(uint64_t param_id, const ConstNTTTablesIter& ntt_tables, seal::Ciphertext* src, CCiphertext* dest) {
    dest->level = src->coeff_modulus_size() - 1;
    int N = src->poly_modulus_degree();
    dest->degree = src->size() - 1;
    dest->polys = (CPolynomial*)malloc(sizeof(CPolynomial) * src->size());

    for (int i = 0; i < (int)src->size(); i++) {
        _alloc_contiguous_polynomial(&dest->polys[i], dest->level + 1, N);

        for (int j = 0; j < dest->level + 1; j++) {
            uint64_t* copy = dest->polys[i].components[j].data;
            memcpy(copy, &src->data(i)[j * N], N * sizeof(uint64_t));

            if (src->is_ntt_form()) {
                CoeffIter copy_coeff(copy);
                inverse_ntt_negacyclic_harvey(copy_coeff, ntt_tables[j]);
                ckks_component_ntt(param_id, copy, j);
            }
        }
    }
}

inline void
_import_ciphertext(uint64_t param_id, const ConstNTTTablesIter& ntt_tables, CCiphertext* src, seal::Ciphertext* dest) {
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

inline void _export_plaintext(uint64_t param_id,
                              int N,
                              const ConstNTTTablesIter& ntt_tables,
                              seal::Plaintext* src,
                              CPlaintext* dest) {
    dest->level = src->coeff_count() / N - 1;
    _alloc_contiguous_polynomial(&dest->poly, dest->level + 1, N);

    for (int j = 0; j < dest->level + 1; j++) {
        uint64_t* copy = dest->poly.components[j].data;
        memcpy(copy, &src->data()[j * N], N * sizeof(uint64_t));

        if (src->is_ntt_form()) {
            CoeffIter copy_coeff(copy);
            inverse_ntt_negacyclic_harvey(copy_coeff, ntt_tables[j]);
            ckks_component_ntt(param_id, copy, j);
        }
    }
}

inline void _export_key_switch_key(uint64_t param_id,
                                   seal::scheme_type scheme,
                                   const ConstNTTTablesIter& ntt_tables,
                                   const std::vector<seal::PublicKey>& src,
                                   CKeySwitchKey* dest,
                                   int level,
                                   int mf_nbits) {
    int n_public_key = level + 1;
    int N = src[0].data().poly_modulus_degree();
    int n_component = src[0].data().coeff_modulus_size();

    dest->n_public_key = n_public_key;
    dest->public_keys = (CPublicKey*)malloc(sizeof(CPublicKey) * n_public_key);

    for (int k = 0; k < n_public_key; k++) {
        dest->public_keys[k].level = level;
        dest->public_keys[k].degree = 1;
        dest->public_keys[k].polys = (CPolynomial*)malloc(sizeof(CPolynomial) * 2);

        for (int i = 0; i < 2; i++) {
            _alloc_contiguous_polynomial(&dest->public_keys[k].polys[i], n_component, N);

            for (int j = 0; j < n_component; j++) {
                uint64_t* copy = dest->public_keys[k].polys[i].components[j].data;
                memcpy(copy, &src[k].data().data(i)[j * N], N * sizeof(uint64_t));

                CoeffIter copy_coeff(copy);
                inverse_ntt_negacyclic_harvey(copy_coeff, ntt_tables[j]);

                if (scheme == seal::scheme_type::bfv) {
                    bfv_component_ntt(param_id, copy, j);
                    if (mf_nbits != 0) {
                        bfv_component_mul_by_pow2(param_id, copy, j, mf_nbits);
                    }
                } else {
                    ckks_component_ntt(param_id, copy, j);
                    if (mf_nbits != 0) {
                        ckks_component_mul_by_pow2(param_id, copy, j, mf_nbits);
                    }
                }
            }
        }
    }
}

inline void _export_relin_key(uint64_t param_id,
                              seal::scheme_type scheme,
                              const ConstNTTTablesIter& ntt_tables,
                              const seal::RelinKeys* src,
                              CRelinKey* dest,
                              int level,
                              int mf_nbits) {
    _export_key_switch_key(param_id, scheme, ntt_tables, src->key(2), dest, level, mf_nbits);
}

inline void _export_galois_key(uint64_t param_id,
                               seal::scheme_type scheme,
                               const ConstNTTTablesIter& ntt_tables,
                               const seal::GaloisKeys* src,
                               CGaloisKey* dest,
                               int level,
                               int mf_nbits) {
    int n_key_switch_key = dest->n_key_switch_key;
    dest->key_switch_keys = (CKeySwitchKey*)malloc(sizeof(CKeySwitchKey) * n_key_switch_key);

    for (int i = 0; i < n_key_switch_key; i++) {
        _export_key_switch_key(param_id, scheme, ntt_tables, src->key(dest->galois_elements[i]),
                               &dest->key_switch_keys[i], level, mf_nbits);
    }
}

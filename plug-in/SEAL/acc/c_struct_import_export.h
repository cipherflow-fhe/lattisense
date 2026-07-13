#pragma once

extern "C" {
#include "c_types.h"
#include "wrapper.h"
#include "c_argument.h"
#include "c_structs.h"
}
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <seal/seal.h>

using namespace seal::util;

// ---------------------------------------------------------------------------
// Low-level SEAL → C struct export / import
// ---------------------------------------------------------------------------

inline void
_export_ciphertext(uint64_t param_id, const ConstNTTTablesIter& ntt_tables, seal::Ciphertext* src, CCiphertext* dest) {
    int N = src->poly_modulus_degree();
    int rns_size = src->coeff_modulus_size();

    dest->level = rns_size - 1;
    dest->cipher_size = static_cast<int>(src->size());
    dest->ring_degree = N;
    dest->data = (uint64_t*)malloc((size_t)dest->cipher_size * rns_size * N * sizeof(uint64_t));

    for (int poly_idx = 0; poly_idx < dest->cipher_size; poly_idx++) {
        memcpy(c_ciphertext_rns_limb(dest, poly_idx, 0), src->data(poly_idx), (size_t)rns_size * N * sizeof(uint64_t));
    }

    if (src->is_ntt_form()) {
        PolyIter dest_iter(dest->data, N, rns_size);
        inverse_ntt_negacyclic_harvey(dest_iter, dest->cipher_size, ntt_tables);
        for (int poly_idx = 0; poly_idx < dest->cipher_size; poly_idx++) {
            ckks_poly_ntt(param_id, c_ciphertext_rns_limb(dest, poly_idx, 0), dest->level, -1);
        }
    }
}

inline void
_import_ciphertext(uint64_t param_id, const ConstNTTTablesIter& ntt_tables, CCiphertext* src, seal::Ciphertext* dest) {
    int rns_size = c_ciphertext_rns_size(src);
    int N = src->ring_degree;

    if (dest->is_ntt_form()) {
        for (int poly_idx = 0; poly_idx < src->cipher_size; poly_idx++) {
            ckks_poly_inv_ntt(param_id, c_ciphertext_rns_limb(src, poly_idx, 0), src->level, -1);
        }
    }

    for (int poly_idx = 0; poly_idx < src->cipher_size; poly_idx++) {
        memcpy(dest->data(poly_idx), c_ciphertext_rns_limb(src, poly_idx, 0), (size_t)rns_size * N * sizeof(uint64_t));
    }

    if (dest->is_ntt_form()) {
        PolyIter dest_iter(dest->data(), N, rns_size);
        ntt_negacyclic_harvey(dest_iter, src->cipher_size, ntt_tables);
    }
}

inline void _export_plaintext(uint64_t param_id,
                              int N,
                              const ConstNTTTablesIter& ntt_tables,
                              seal::Plaintext* src,
                              CPlaintext* dest) {
    int rns_size = src->coeff_count() / N;

    dest->level = rns_size - 1;
    dest->ring_degree = N;
    dest->data = (uint64_t*)malloc((size_t)rns_size * N * sizeof(uint64_t));
    memcpy(dest->data, src->data(), (size_t)rns_size * N * sizeof(uint64_t));

    if (src->is_ntt_form()) {
        RNSIter dest_iter(dest->data, N);
        inverse_ntt_negacyclic_harvey(dest_iter, rns_size, ntt_tables);
        ckks_poly_ntt(param_id, dest->data, dest->level, -1);
    }
}

inline void _export_key_switch_key(uint64_t param_id,
                                   seal::scheme_type scheme,
                                   const ConstNTTTablesIter& ntt_tables,
                                   const std::vector<seal::PublicKey>& src,
                                   CSwitchingKey* dest,
                                   int level,
                                   int mf_nbits) {
    if (src.empty()) {
        throw std::runtime_error("empty SEAL key-switch key");
    }

    int ring_degree = src[0].data().poly_modulus_degree();
    int decomp_rns = static_cast<int>(src.size());
    int rns_size = src[0].data().coeff_modulus_size();
    int p_size = rns_size - (level + 1);

    dest->level_q = level;
    dest->level_p = p_size - 1;
    dest->ring_degree = ring_degree;

    dest->data = (uint64_t*)malloc((size_t)decomp_rns * 2 * rns_size * ring_degree * sizeof(uint64_t));

    for (int decomp_idx = 0; decomp_idx < decomp_rns; decomp_idx++) {
        const seal::Ciphertext& public_key = src[decomp_idx].data();
        for (int poly_idx = 0; poly_idx < 2; poly_idx++) {
            uint64_t* dest_poly = c_switching_key_rns_limb(dest, decomp_idx, poly_idx, 0);
            memcpy(dest_poly, public_key.data(poly_idx), (size_t)rns_size * ring_degree * sizeof(uint64_t));
            RNSIter dest_poly_iter(dest_poly, ring_degree);
            inverse_ntt_negacyclic_harvey(dest_poly_iter, rns_size, ntt_tables);

            if (scheme == seal::scheme_type::bfv) {
                bfv_poly_ntt(param_id, dest_poly, dest->level_q, dest->level_p);
                if (mf_nbits != 0) {
                    bfv_poly_mul_by_pow2(param_id, dest_poly, dest->level_q, dest->level_p, mf_nbits);
                }
            } else {
                ckks_poly_ntt(param_id, dest_poly, dest->level_q, dest->level_p);
                if (mf_nbits != 0) {
                    ckks_poly_mul_by_pow2(param_id, dest_poly, dest->level_q, dest->level_p, mf_nbits);
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
    int n_switching_key = dest->n_switching_key;
    dest->switching_keys = (CSwitchingKey*)malloc(sizeof(CSwitchingKey) * n_switching_key);

    for (int i = 0; i < n_switching_key; i++) {
        _export_key_switch_key(param_id, scheme, ntt_tables, src->key(dest->galois_elements[i]),
                               &dest->switching_keys[i], level, mf_nbits);
    }
}

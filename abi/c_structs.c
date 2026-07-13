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

#include <stdlib.h>
#include "c_structs.h"
#include "liblattigo.h"

void alloc_plaintext(CPlaintext* pt, int level, int ring_degree) {
    pt->level = level;
    pt->ring_degree = ring_degree;
    pt->data = (uint64_t*)malloc((size_t)(level + 1) * ring_degree * sizeof(uint64_t));
}

void alloc_ciphertext(CCiphertext* ct, int cipher_size, int level, int ring_degree) {
    ct->level = level;
    ct->cipher_size = cipher_size;
    ct->ring_degree = ring_degree;
    ct->data = (uint64_t*)malloc((size_t)cipher_size * (level + 1) * ring_degree * sizeof(uint64_t));
}

void alloc_switching_key(CSwitchingKey* swk, int level_q, int level_p, int ring_degree) {
    swk->level_q = level_q;
    swk->level_p = level_p;
    swk->ring_degree = ring_degree;
    swk->data = (uint64_t*)malloc((size_t)c_switching_key_decomp_rns(swk) * 2 * c_switching_key_rns_size(swk) *
                                  ring_degree * sizeof(uint64_t));
}

void alloc_relin_key(CRelinKey* rlk, int level_q, int level_p, int ring_degree) {
    alloc_switching_key(rlk, level_q, level_p, ring_degree);
}

void alloc_galois_key(CGaloisKey* glk, int n_switching_key, int level_q, int level_p, int ring_degree) {
    glk->n_switching_key = n_switching_key;
    glk->galois_elements = (uint64_t*)malloc(sizeof(uint64_t) * n_switching_key);
    glk->switching_keys = (CSwitchingKey*)malloc(sizeof(CSwitchingKey) * n_switching_key);
    for (int i = 0; i < n_switching_key; i++) {
        alloc_switching_key(&glk->switching_keys[i], level_q, level_p, ring_degree);
    }
}

void set_galois_key_steps(CGaloisKey* glk, const uint64_t* galois_elements, int n_switching_key) {
    glk->n_switching_key = n_switching_key;
    glk->galois_elements = (uint64_t*)malloc(sizeof(uint64_t) * n_switching_key);
    glk->switching_keys = NULL;
    for (int i = 0; i < n_switching_key; i++) {
        glk->galois_elements[i] = galois_elements[i];
    }
}

void free_plaintext(CPlaintext* pt) {
    free(pt->data);
    pt->data = NULL;
}

void free_ciphertext(CCiphertext* ct) {
    free(ct->data);
    ct->data = NULL;
}

void free_switching_key(CSwitchingKey* swk) {
    free(swk->data);
    swk->data = NULL;
}

void free_relin_key(CRelinKey* rlk) {
    free_switching_key(rlk);
}

void free_galois_key(CGaloisKey* gk) {
    free(gk->galois_elements);
    if (gk->switching_keys != NULL) {
        for (int i = 0; i < gk->n_switching_key; i++) {
            free_switching_key(&gk->switching_keys[i]);
        }
    }
    free(gk->switching_keys);
    gk->galois_elements = NULL;
    gk->switching_keys = NULL;
}

inline void import_bfv_ciphertext(uint64_t dest_handle, CCiphertext* c_ciphertext) {
    ImportBfvCiphertext(dest_handle, c_ciphertext);
}

inline void import_ckks_ciphertext(uint64_t dest_handle, CCiphertext* c_ciphertext) {
    ImportCkksCiphertext(dest_handle, c_ciphertext);
}

inline void export_bfv_plaintext_ringt(uint64_t plaintext_ringt_handle, CPlaintext* plaintext) {
    ExportBfvPlaintextRingt(plaintext_ringt_handle, plaintext);
}

inline void export_ckks_plaintext_ringt(uint64_t plaintext_ringt_handle, CPlaintext* plaintext) {
    ExportCkksPlaintextRingt(plaintext_ringt_handle, plaintext);
}

inline void export_bfv_plaintext_mul(uint64_t parameter_handle,
                                     uint64_t plaintext_mul_handle,
                                     int mf_nbits,
                                     CPlaintext* plaintext) {
    ExportBfvPlaintextMul(parameter_handle, plaintext_mul_handle, mf_nbits, plaintext);
}

inline void export_ckks_plaintext_mul(uint64_t parameter_handle,
                                      uint64_t plaintext_mul_handle,
                                      int mf_nbits,
                                      CPlaintext* plaintext) {
    ExportCkksPlaintextMul(parameter_handle, plaintext_mul_handle, mf_nbits, plaintext);
}

inline void export_bfv_plaintext(uint64_t plaintext_handle, CPlaintext* plaintext) {
    ExportBfvPlaintext(plaintext_handle, plaintext);
}

inline void export_ckks_plaintext(uint64_t plaintext_handle, CPlaintext* plaintext) {
    ExportCkksPlaintext(plaintext_handle, plaintext);
}

inline void export_bfv_ciphertext(uint64_t ciphertext_handle, CCiphertext* ciphertext) {
    ExportBfvCiphertext(ciphertext_handle, ciphertext);
}

inline void export_ckks_ciphertext(uint64_t ciphertext_handle, CCiphertext* ciphertext) {
    ExportCkksCiphertext(ciphertext_handle, ciphertext);
}

inline void export_bfv_relin_key(uint64_t parameter_handle,
                                 uint64_t relin_key_handle,
                                 int level,
                                 int key_mf_nbits,
                                 CRelinKey* relin_key) {
    ExportBfvRelinKey(parameter_handle, relin_key_handle, level, key_mf_nbits, relin_key);
}

inline void export_ckks_relin_key(uint64_t parameter_handle,
                                  uint64_t relin_key_handle,
                                  int level,
                                  int key_mf_nbits,
                                  CRelinKey* relin_key) {
    ExportCkksRelinKey(parameter_handle, relin_key_handle, level, key_mf_nbits, relin_key);
}

inline void export_bfv_galois_key(uint64_t parameter_handle,
                                  uint64_t galois_key_handle,
                                  int level,
                                  int key_mf_nbits,
                                  CGaloisKey* galois_key) {
    ExportBfvGaloisKey(parameter_handle, galois_key_handle, level, key_mf_nbits, galois_key);
}

inline void export_ckks_galois_key(uint64_t parameter_handle,
                                   uint64_t galois_key_handle,
                                   int level,
                                   int key_mf_nbits,
                                   CGaloisKey* galois_key) {
    ExportCkksGaloisKey(parameter_handle, galois_key_handle, level, key_mf_nbits, galois_key);
}

inline void export_ckks_switching_key(uint64_t parameter_handle,
                                      uint64_t switching_key_handle,
                                      int level_q,
                                      int level_p,
                                      int key_mf_nbits,
                                      CSwitchingKey* switching_key) {
    ExportCkksSwitchingKey(parameter_handle, switching_key_handle, level_q, level_p, key_mf_nbits, switching_key);
}

inline void bfv_poly_ntt(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p) {
    BfvPolyNttInplace(parameter_handle, data, level_q, level_p);
}

inline void bfv_poly_inv_ntt(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p) {
    BfvPolyInvNttInplace(parameter_handle, data, level_q, level_p);
}

inline void bfv_poly_mul_by_pow2(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p, int pow2) {
    BfvPolyMulByPow2Inplace(parameter_handle, data, level_q, level_p, pow2);
}

inline void ckks_poly_ntt(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p) {
    CkksPolyNttInplace(parameter_handle, data, level_q, level_p);
}

inline void ckks_poly_inv_ntt(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p) {
    CkksPolyInvNttInplace(parameter_handle, data, level_q, level_p);
}

inline void ckks_poly_mul_by_pow2(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p, int pow2) {
    CkksPolyMulByPow2Inplace(parameter_handle, data, level_q, level_p, pow2);
}

inline uint64_t
c_set_bfv_parameter(uint64_t N, uint64_t T, const uint64_t* Q, int q_len, const uint64_t* P, int p_len) {
    return SetBfvParameter(N, T, (uint64_t*)Q, q_len, (uint64_t*)P, p_len);
}

inline uint64_t c_set_ckks_parameter(uint64_t N, const unsigned long* Q, int q_len, const unsigned long* P, int p_len) {
    return SetCkksParameter(N, (unsigned long*)Q, q_len, (unsigned long*)P, p_len);
}

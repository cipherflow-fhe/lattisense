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

void alloc_component(CComponent* component, int n) {
    component->n = n;
    component->data = (uint64_t*)malloc(n * sizeof(uint64_t));
}

void alloc_polynomial(CPolynomial* polynomial, int level, int n) {
    int n_component = level + 1;
    polynomial->n_component = n_component;
    polynomial->components = (CComponent*)malloc(n_component * sizeof(CComponent));
    for (int i = 0; i < n_component; i++) {
        alloc_component(&polynomial->components[i], n);
    }
}

void alloc_plaintext(CPlaintext* pt, int level, int n) {
    pt->level = level;
    alloc_polynomial(&pt->poly, level, n);
}

void alloc_ciphertext(CCiphertext* ct, int degree, int level, int n) {
    ct->degree = degree;
    ct->level = level;
    ct->polys = (CPolynomial*)malloc((degree + 1) * sizeof(CPolynomial));
    for (int i = 0; i < degree + 1; i++) {
        alloc_polynomial(&ct->polys[i], level, n);
    }
}

void alloc_relin_key(CRelinKey* rlk, int n_public_key, int level, int n) {
    rlk->n_public_key = n_public_key;
    rlk->public_keys = (CCiphertext*)malloc(n_public_key * sizeof(CCiphertext));
    for (int i = 0; i < n_public_key; i++) {
        alloc_ciphertext(&rlk->public_keys[i], 2, level, n);
    }
}

void set_galois_key_steps(CGaloisKey* glk, uint64_t* galois_elements, int n_galois_elements) {
    glk->n_key_switch_key = n_galois_elements;
    glk->galois_elements = (uint64_t*)malloc(sizeof(uint64_t) * n_galois_elements);
    for (int i = 0; i < n_galois_elements; i++) {
        glk->galois_elements[i] = galois_elements[i];
    }
}

void free_polynomial(CPolynomial* polynomial) {
    for (int i = 0; i < polynomial->n_component; i++) {
        free(polynomial->components[i].data);
    }
    free(polynomial->components);
}

void free_plaintext(CPlaintext* pt) {
    free_polynomial(&pt->poly);
}

void free_ciphertext(CCiphertext* ct) {
    for (int i = 0; i < ct->degree + 1; i++) {
        free_polynomial(&ct->polys[i]);
    }
    free(ct->polys);
}

void free_relin_key(CRelinKey* rlk) {
    for (int i = 0; i < rlk->n_public_key; i++) {
        free_ciphertext(&rlk->public_keys[i]);
    }
    free(rlk->public_keys);
}

void free_galois_key(CGaloisKey* gk) {
    for (int i = 0; i < gk->n_key_switch_key; i++) {
        free_relin_key(&gk->key_switch_keys[i]);
    }
    free(gk->galois_elements);
    free(gk->key_switch_keys);
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
                                      int level,
                                      int sp_level,
                                      int key_mf_nbits,
                                      CKeySwitchKey* switching_key) {
    ExportCkksSwitchingKey(parameter_handle, switching_key_handle, level, sp_level, key_mf_nbits, switching_key);
}

inline void bfv_component_ntt(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx) {
    BfvComponentNttInplace(parameter_handle, coeff, lvl_idx);
}

inline void bfv_component_inv_ntt(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx) {
    BfvComponentInvNttInplace(parameter_handle, coeff, lvl_idx);
}

inline void ckks_component_ntt(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx) {
    CkksComponentNttInplace(parameter_handle, coeff, lvl_idx);
}

inline void ckks_component_inv_ntt(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx) {
    CkksComponentInvNttInplace(parameter_handle, coeff, lvl_idx);
}

inline void bfv_component_mul_by_pow2(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx, int pow2) {
    BfvComponentMulByPow2Inplace(parameter_handle, coeff, lvl_idx, pow2);
}

inline void ckks_component_mul_by_pow2(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx, int pow2) {
    CkksComponentMulByPow2Inplace(parameter_handle, coeff, lvl_idx, pow2);
}

inline uint64_t
c_set_bfv_parameter(uint64_t N, uint64_t T, const uint64_t* Q, int q_len, const uint64_t* P, int p_len) {
    return SetBfvParameter(N, T, (uint64_t*)Q, q_len, (uint64_t*)P, p_len);
}

inline uint64_t c_set_ckks_parameter(uint64_t N, const unsigned long* Q, int q_len, const unsigned long* P, int p_len) {
    return SetCkksParameter(N, (unsigned long*)Q, q_len, (unsigned long*)P, p_len);
}

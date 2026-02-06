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
#include "structs_v2.h"
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

void free_polynomial(CPolynomial* polynomial, bool free_component_data) {
    if (free_component_data) {
        for (int i = 0; i < polynomial->n_component; i++) {
            free(polynomial->components[i].data);
        }
    }
    free(polynomial->components);
}

void free_plaintext(CPlaintext* pt, bool free_component_data) {
    free_polynomial(&pt->poly, free_component_data);
}

void free_ciphertext(CCiphertext* ct, bool free_component_data) {
    for (int i = 0; i < ct->degree + 1; i++) {
        free_polynomial(&ct->polys[i], free_component_data);
    }
}

void free_relin_key(CRelinKey* rlk, bool free_component_data) {
    for (int i = 0; i < rlk->n_public_key; i++) {
        free_ciphertext(&rlk->public_keys[i], free_component_data);
    }
    free(rlk->public_keys);
}

void free_galois_key(CGaloisKey* gk, bool free_component_data) {
    for (int i = 0; i < gk->n_key_switch_key; i++) {
        free_relin_key(&gk->key_switch_keys[i], free_component_data);
    }
    free(gk->galois_elements);
    free(gk->key_switch_keys);
}

inline uint64_t import_bfv_ciphertext(uint64_t parameter_handle, CCiphertext* c_ciphertext) {
    return ImportBfvCiphertext(parameter_handle, c_ciphertext);
}

inline uint64_t import_ckks_ciphertext(uint64_t parameter_handle, CCiphertext* c_ciphertext) {
    return ImportCkksCiphertext(parameter_handle, c_ciphertext);
}

inline void export_bfv_plaintext_ringt(uint64_t plaintext_ringt_handle, CPlaintext* plaintext) {
    ExportBfvPlaintextRingt(plaintext_ringt_handle, plaintext);
}

inline void export_ckks_plaintext_ringt(uint64_t plaintext_ringt_handle, CPlaintext* plaintext) {
    ExportCkksPlaintextRingt(plaintext_ringt_handle, plaintext);
}

inline void export_bfv_plaintext_mul(uint64_t plaintext_mul_handle, CPlaintext* plaintext) {
    ExportBfvPlaintextMul(plaintext_mul_handle, plaintext);
}

inline void export_ckks_plaintext_mul(uint64_t plaintext_mul_handle, CPlaintext* plaintext) {
    ExportCkksPlaintextMul(plaintext_mul_handle, plaintext);
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

inline void export_relin_key(uint64_t relin_key_handle, int level, CRelinKey* relin_key) {
    ExportRelinKey(relin_key_handle, level, relin_key);
}

inline void export_galois_key(uint64_t galois_key_handle, int level, CGaloisKey* galois_key) {
    ExportGaloisKey(galois_key_handle, level, galois_key);
}

inline void export_switching_key(uint64_t switching_key_handle, int level, int sp_level, CKeySwitchKey* switching_key) {
    ExportSwitchingKey(switching_key_handle, level, sp_level, switching_key);
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

inline void
bfv_plaintext_mul_inv_mform_and_mul_by_pow2(uint64_t parameter_handle, uint64_t plaintext_mul_handle, int pow2) {
    BfvPlaintextMulInvMFormAndMulByPow2(parameter_handle, plaintext_mul_handle, pow2);
}

inline void
ckks_plaintext_mul_inv_mform_and_mul_by_pow2(uint64_t parameter_handle, uint64_t plaintext_mul_handle, int pow2) {
    CkksPlaintextMulInvMFormAndMulByPow2(parameter_handle, plaintext_mul_handle, pow2);
}

inline void bfv_rlk_inv_mform(uint64_t parameter_handle, uint64_t relin_key_handle) {
    BfvRlkInvMForm(parameter_handle, relin_key_handle);
}

inline void bfv_rlk_inv_mform_and_mul_by_pow2(uint64_t parameter_handle, uint64_t relin_key_handle, int pow2) {
    BfvRlkInvMFormAndMulByPow2(parameter_handle, relin_key_handle, pow2);
}

inline void bfv_glk_inv_mform(uint64_t parameter_handle, uint64_t galois_key_handle) {
    BfvGlkInvMForm(parameter_handle, galois_key_handle);
}

inline void bfv_glk_inv_mform_and_mul_by_pow2(uint64_t parameter_handle, uint64_t galois_key_handle, int pow2) {
    BfvGlkInvMFormAndMulByPow2(parameter_handle, galois_key_handle, pow2);
}

inline void ckks_rlk_inv_mform(uint64_t parameter_handle, uint64_t relin_key_handle) {
    CkksRlkInvMForm(parameter_handle, relin_key_handle);
}

inline void ckks_rlk_inv_mform_and_mul_by_pow2(uint64_t parameter_handle, uint64_t relin_key_handle, int pow2) {
    CkksRlkInvMFormAndMulByPow2(parameter_handle, relin_key_handle, pow2);
}

inline void ckks_glk_inv_mform(uint64_t parameter_handle, uint64_t galois_key_handle) {
    CkksGlkInvMForm(parameter_handle, galois_key_handle);
}

inline void ckks_glk_inv_mform_and_mul_by_pow2(uint64_t parameter_handle, uint64_t galois_key_handle, int pow2) {
    CkksGlkInvMFormAndMulByPow2(parameter_handle, galois_key_handle, pow2);
}

void set_bfv_rlk_n_mform_bits(uint64_t parameter_handle, uint64_t relin_key_handle, int n_mform_bits) {
    SetBfvRlkNMFormBits(parameter_handle, relin_key_handle, n_mform_bits);
}

void set_ckks_rlk_n_mform_bits(uint64_t parameter_handle, uint64_t relin_key_handle, int n_mform_bits) {
    SetCkksRlkNMFormBits(parameter_handle, relin_key_handle, n_mform_bits);
}

void set_bfv_glk_n_mform_bits(uint64_t parameter_handle, uint64_t galois_key_handle, int n_mform_bits) {
    SetBfvGlkNMFormBits(parameter_handle, galois_key_handle, n_mform_bits);
}

void set_ckks_glk_n_mform_bits(uint64_t parameter_handle, uint64_t galois_key_handle, int n_mform_bits) {
    SetCkksGlkNMFormBits(parameter_handle, galois_key_handle, n_mform_bits);
}

void set_ckks_swk_n_mform_bits(uint64_t parameter_handle, uint64_t switching_key_handle, int n_mform_bits) {
    SetCkksSwkNMFormBits(parameter_handle, switching_key_handle, n_mform_bits);
}

inline uint64_t
c_set_bfv_parameter(uint64_t N, uint64_t T, const uint64_t* Q, int q_len, const uint64_t* P, int p_len) {
    return SetBfvParameter(N, T, (uint64_t*)Q, q_len, (uint64_t*)P, p_len);
}

inline uint64_t c_set_ckks_parameter(uint64_t N, const unsigned long* Q, int q_len, const unsigned long* P, int p_len) {
    return SetCkksParameter(N, (unsigned long*)Q, q_len, (unsigned long*)P, p_len);
}

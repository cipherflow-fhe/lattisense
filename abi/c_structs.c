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

void alloc_evaluation_key(CEvaluationKey* evk, int level_q, int level_p, int ring_degree) {
    evk->level_q = level_q;
    evk->level_p = level_p;
    evk->ring_degree = ring_degree;
    evk->data = (uint64_t*)malloc((size_t)c_evaluation_key_decomp_rns(evk) * 2 * c_evaluation_key_rns_size(evk) *
                                  ring_degree * sizeof(uint64_t));
}

void free_plaintext(CPlaintext* pt) {
    free(pt->data);
    pt->data = NULL;
}

void free_ciphertext(CCiphertext* ct) {
    free(ct->data);
    ct->data = NULL;
}

void free_evaluation_key(CEvaluationKey* evk) {
    free(evk->data);
    evk->data = NULL;
}

inline ErrorStatus import_ciphertext(uint64_t parameter_handle,
                                     uint64_t dest_handle,
                                     Metadata* source_metadata,
                                     Metadata* target_metadata,
                                     CCiphertext* c_ciphertext) {
    return ImportCiphertext(parameter_handle, dest_handle, source_metadata, target_metadata, c_ciphertext);
}

inline void
export_plaintext(uint64_t parameter_handle, uint64_t plaintext_handle, Metadata* metadata, CPlaintext* plaintext) {
    ExportPlaintext(parameter_handle, plaintext_handle, metadata, plaintext);
}

inline void
export_ciphertext(uint64_t parameter_handle, uint64_t ciphertext_handle, Metadata* metadata, CCiphertext* ciphertext) {
    ExportCiphertext(parameter_handle, ciphertext_handle, metadata, ciphertext);
}

inline void export_evaluation_key(uint64_t parameter_handle,
                                  uint64_t evaluation_key_handle,
                                  int level_p,
                                  Metadata* metadata,
                                  CEvaluationKey* evaluation_key) {
    ExportEvaluationKey(parameter_handle, evaluation_key_handle, level_p, metadata, evaluation_key);
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

static int log2_uint64(uint64_t n) {
    int log_n = 0;
    while (n > 1) {
        n >>= 1;
        log_n++;
    }
    return log_n;
}

inline uint64_t
c_set_bfv_parameter(uint64_t N, uint64_t T, const uint64_t* Q, int q_len, const uint64_t* P, int p_len) {
    uint64_t handle = 0;
    CreateBfvCustomParameter(log2_uint64(N), T, (uint64_t*)Q, q_len, (uint64_t*)P, p_len, &handle);
    return handle;
}

inline uint64_t c_set_ckks_parameter(uint64_t N, const unsigned long* Q, int q_len, const unsigned long* P, int p_len) {
    uint64_t handle = 0;
    CreateCkksCustomParameter(log2_uint64(N), 40, (uint64_t*)Q, q_len, (uint64_t*)P, p_len, &handle);
    return handle;
}

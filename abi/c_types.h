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

#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int level;
    int ring_degree;
    uint64_t* data;  // [level + 1][ring_degree]
} CPlaintext;

typedef struct {
    int level;
    int cipher_size;
    int ring_degree;
    uint64_t* data;  // [cipher_size][level + 1][ring_degree]
} CCiphertext;

typedef struct {
    int level_q;
    int level_p;
    int ring_degree;
    uint64_t* data;  // [DecompRNS(level_q, level_p)][2][Q+P RNS limbs][ring_degree]
} CSwitchingKey;

typedef CSwitchingKey CRelinKey;

typedef struct {
    int n_switching_key;
    uint64_t* galois_elements;      // [n_switching_key]
    CSwitchingKey* switching_keys;  // [n_switching_key], one switching key per galois element
} CGaloisKey;

static inline int c_plaintext_rns_size(const CPlaintext* pt) {
    return pt->level + 1;
}

static inline int c_ciphertext_rns_size(const CCiphertext* ct) {
    return ct->level + 1;
}

static inline int c_switching_key_decomp_rns(const CSwitchingKey* swk) {
    return (swk->level_q + swk->level_p + 1) / (swk->level_p + 1);
}

static inline int c_switching_key_rns_size(const CSwitchingKey* swk) {
    return swk->level_q + swk->level_p + 2;
}

static inline int c_galois_key_decomp_rns(const CGaloisKey* glk) {
    return c_switching_key_decomp_rns(&glk->switching_keys[0]);
}

static inline int c_galois_key_rns_size(const CGaloisKey* glk) {
    return c_switching_key_rns_size(&glk->switching_keys[0]);
}

static inline int c_relin_key_decomp_rns(const CRelinKey* rlk) {
    return c_switching_key_decomp_rns(rlk);
}

static inline int c_relin_key_rns_size(const CRelinKey* rlk) {
    return c_switching_key_rns_size(rlk);
}

static inline uint64_t* c_plaintext_rns_limb(CPlaintext* pt, int rns_idx) {
    return pt->data + (size_t)rns_idx * pt->ring_degree;
}

static inline const uint64_t* c_plaintext_const_rns_limb(const CPlaintext* pt, int rns_idx) {
    return pt->data + (size_t)rns_idx * pt->ring_degree;
}

static inline uint64_t* c_ciphertext_rns_limb(CCiphertext* ct, int poly_idx, int rns_idx) {
    return ct->data + ((size_t)poly_idx * c_ciphertext_rns_size(ct) + rns_idx) * ct->ring_degree;
}

static inline const uint64_t* c_ciphertext_const_rns_limb(const CCiphertext* ct, int poly_idx, int rns_idx) {
    return ct->data + ((size_t)poly_idx * c_ciphertext_rns_size(ct) + rns_idx) * ct->ring_degree;
}

static inline uint64_t* c_switching_key_rns_limb(CSwitchingKey* swk, int decomp_idx, int poly_idx, int rns_idx) {
    return swk->data +
           (((size_t)decomp_idx * 2 + poly_idx) * c_switching_key_rns_size(swk) + rns_idx) * swk->ring_degree;
}

static inline const uint64_t*
c_switching_key_const_rns_limb(const CSwitchingKey* swk, int decomp_idx, int poly_idx, int rns_idx) {
    return swk->data +
           (((size_t)decomp_idx * 2 + poly_idx) * c_switching_key_rns_size(swk) + rns_idx) * swk->ring_degree;
}

static inline uint64_t* c_relin_key_rns_limb(CRelinKey* rlk, int decomp_idx, int poly_idx, int rns_idx) {
    return c_switching_key_rns_limb(rlk, decomp_idx, poly_idx, rns_idx);
}

static inline const uint64_t*
c_relin_key_const_rns_limb(const CRelinKey* rlk, int decomp_idx, int poly_idx, int rns_idx) {
    return c_switching_key_const_rns_limb(rlk, decomp_idx, poly_idx, rns_idx);
}

static inline uint64_t*
c_galois_key_rns_limb(CGaloisKey* glk, int switching_key_idx, int decomp_idx, int poly_idx, int rns_idx) {
    return c_switching_key_rns_limb(&glk->switching_keys[switching_key_idx], decomp_idx, poly_idx, rns_idx);
}

static inline const uint64_t*
c_galois_key_const_rns_limb(const CGaloisKey* glk, int switching_key_idx, int decomp_idx, int poly_idx, int rns_idx) {
    return c_switching_key_const_rns_limb(&glk->switching_keys[switching_key_idx], decomp_idx, poly_idx, rns_idx);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

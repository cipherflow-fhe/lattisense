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

#ifndef GO_SDK_ERROR_STATUS_DEFINED
#    define GO_SDK_ERROR_STATUS_DEFINED
typedef struct ErrorStatus {
    int code;
    char* message;
} ErrorStatus;
#endif

#ifndef GO_SDK_METADATA_DEFINED
#    define GO_SDK_METADATA_DEFINED
typedef struct Metadata {
    uint8_t is_ringt;
    uint8_t is_batched;
    int degree;
    int level;
    int log_slots;
    double scale;
    uint8_t is_ntt;
    int mform_bits;

#    ifdef __cplusplus
    bool operator==(const Metadata& other) const {
        return is_ringt == other.is_ringt && is_batched == other.is_batched && degree == other.degree &&
               level == other.level && log_slots == other.log_slots && scale == other.scale && is_ntt == other.is_ntt &&
               mform_bits == other.mform_bits;
    }

    bool operator!=(const Metadata& other) const {
        return !(*this == other);
    }
#    endif
} Metadata;
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
} CEvaluationKey;

static inline int c_plaintext_rns_size(const CPlaintext* pt) {
    return pt->level + 1;
}

static inline int c_ciphertext_rns_size(const CCiphertext* ct) {
    return ct->level + 1;
}

static inline int c_evaluation_key_decomp_rns(const CEvaluationKey* evk) {
    return (evk->level_q + evk->level_p + 1) / (evk->level_p + 1);
}

static inline int c_evaluation_key_rns_size(const CEvaluationKey* evk) {
    return evk->level_q + evk->level_p + 2;
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

static inline uint64_t* c_evaluation_key_rns_limb(CEvaluationKey* evk, int decomp_idx, int poly_idx, int rns_idx) {
    return evk->data +
           (((size_t)decomp_idx * 2 + poly_idx) * c_evaluation_key_rns_size(evk) + rns_idx) * evk->ring_degree;
}

static inline const uint64_t*
c_evaluation_key_const_rns_limb(const CEvaluationKey* evk, int decomp_idx, int poly_idx, int rns_idx) {
    return evk->data +
           (((size_t)decomp_idx * 2 + poly_idx) * c_evaluation_key_rns_size(evk) + rns_idx) * evk->ring_degree;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

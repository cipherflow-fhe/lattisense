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
#include "c_types.h"

void alloc_plaintext(CPlaintext* pt, int level, int ring_degree);

void alloc_ciphertext(CCiphertext* ct, int cipher_size, int level, int ring_degree);

void alloc_evaluation_key(CEvaluationKey* evk, int level_q, int level_p, int ring_degree);

void free_plaintext(CPlaintext* pt);

void free_ciphertext(CCiphertext* ct);

void free_evaluation_key(CEvaluationKey* evk);

ErrorStatus import_ciphertext(uint64_t parameter_handle,
                              uint64_t dest_handle,
                              Metadata* source_metadata,
                              Metadata* target_metadata,
                              CCiphertext* c_ciphertext);

void export_plaintext(uint64_t parameter_handle, uint64_t plaintext_handle, Metadata* metadata, CPlaintext* plaintext);

void export_ciphertext(uint64_t parameter_handle,
                       uint64_t ciphertext_handle,
                       Metadata* metadata,
                       CCiphertext* ciphertext);

void export_evaluation_key(uint64_t parameter_handle,
                           uint64_t evaluation_key_handle,
                           int level_p,
                           Metadata* metadata,
                           CEvaluationKey* evaluation_key);

void bfv_poly_ntt(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p);

void bfv_poly_inv_ntt(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p);

void bfv_poly_mul_by_pow2(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p, int pow2);

void ckks_poly_ntt(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p);

void ckks_poly_inv_ntt(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p);

void ckks_poly_mul_by_pow2(uint64_t parameter_handle, uint64_t* data, int level_q, int level_p, int pow2);

uint64_t c_set_bfv_parameter(uint64_t N, uint64_t T, const uint64_t* Q, int q_len, const uint64_t* P, int p_len);

uint64_t c_set_ckks_parameter(uint64_t N, const unsigned long* Q, int q_len, const unsigned long* P, int p_len);

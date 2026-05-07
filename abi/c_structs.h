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

void alloc_component(CComponent* component, int n);

void alloc_plaintext(CPlaintext* pt, int level, int n);

void alloc_ciphertext(CCiphertext* ct, int degree, int level, int n);

void free_plaintext(CPlaintext* pt);

void free_ciphertext(CCiphertext* ct);

void alloc_relin_key(CRelinKey* rlk, int n_public_key, int level, int n);

void set_galois_key_steps(CGaloisKey* glk, uint64_t* galois_elements, int n_galois_elements);

void free_relin_key(CRelinKey* rlk);

void free_galois_key(CGaloisKey* gk);

void import_bfv_ciphertext(uint64_t dest_handle, CCiphertext* c_ciphertext);

void import_ckks_ciphertext(uint64_t dest_handle, CCiphertext* c_ciphertext);

void export_bfv_plaintext_ringt(uint64_t plaintext_ringt_handle, CPlaintext* plaintext);

void export_bfv_plaintext_mul(uint64_t parameter_handle,
                              uint64_t plaintext_mul_handle,
                              int mf_nbits,
                              CPlaintext* plaintext);

void export_ckks_plaintext_mul(uint64_t parameter_handle,
                               uint64_t plaintext_mul_handle,
                               int mf_nbits,
                               CPlaintext* plaintext);

void export_ckks_plaintext_ringt(uint64_t plaintext_ringt_handle, CPlaintext* plaintext);

void export_bfv_plaintext(uint64_t plaintext_handle, CPlaintext* plaintext);

void export_ckks_plaintext(uint64_t plaintext_handle, CPlaintext* plaintext);

void export_bfv_ciphertext(uint64_t ciphertext_handle, CCiphertext* ciphertext);

void export_ckks_ciphertext(uint64_t ciphertext_handle, CCiphertext* ciphertext);

void export_bfv_relin_key(uint64_t parameter_handle,
                          uint64_t relin_key_handle,
                          int level,
                          int key_mf_nbits,
                          CRelinKey* relin_key);

void export_ckks_relin_key(uint64_t parameter_handle,
                           uint64_t relin_key_handle,
                           int level,
                           int key_mf_nbits,
                           CRelinKey* relin_key);

void export_bfv_galois_key(uint64_t parameter_handle,
                           uint64_t galois_key_handle,
                           int level,
                           int key_mf_nbits,
                           CGaloisKey* galois_key);

void export_ckks_galois_key(uint64_t parameter_handle,
                            uint64_t galois_key_handle,
                            int level,
                            int key_mf_nbits,
                            CGaloisKey* galois_key);

void export_ckks_switching_key(uint64_t parameter_handle,
                               uint64_t switching_key_handle,
                               int level,
                               int sp_level,
                               int key_mf_nbits,
                               CKeySwitchKey* switching_key);

void bfv_component_ntt(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx);

void bfv_component_inv_ntt(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx);

void ckks_component_ntt(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx);

void ckks_component_inv_ntt(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx);

void bfv_component_mul_by_pow2(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx, int pow2);

void ckks_component_mul_by_pow2(uint64_t parameter_handle, uint64_t* coeff, int lvl_idx, int pow2);

uint64_t c_set_bfv_parameter(uint64_t N, uint64_t T, const uint64_t* Q, int q_len, const uint64_t* P, int p_len);

uint64_t c_set_ckks_parameter(uint64_t N, const unsigned long* Q, int q_len, const unsigned long* P, int p_len);

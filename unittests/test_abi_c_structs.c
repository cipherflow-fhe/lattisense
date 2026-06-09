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

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "c_structs.h"
#include "liblattigo.h"

#define CHECK_TRUE(expr)                                                                                               \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr);                                 \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

void ImportBfvCiphertext(GoUint64 dest_handle, CCiphertext* c_ciphertext) {}
void ImportCkksCiphertext(GoUint64 dest_handle, CCiphertext* c_ciphertext) {}
void ExportBfvPlaintextRingt(GoUint64 plaintext_ringt_handle, CPlaintext* c_plaintext) {}
void ExportCkksPlaintextRingt(GoUint64 plaintext_ringt_handle, CPlaintext* c_plaintext) {}
void ExportBfvPlaintextMul(GoUint64 parameter_handle,
                           GoUint64 plaintext_mul_handle,
                           GoInt mf_nbits,
                           CPlaintext* c_plaintext) {}
void ExportCkksPlaintextMul(GoUint64 parameter_handle,
                            GoUint64 plaintext_mul_handle,
                            GoInt mf_nbits,
                            CPlaintext* c_plaintext) {}
void ExportBfvPlaintext(GoUint64 plaintext_handle, CPlaintext* c_plaintext) {}
void ExportCkksPlaintext(GoUint64 plaintext_handle, CPlaintext* c_plaintext) {}
void ExportBfvCiphertext(GoUint64 ciphertext_handle, CCiphertext* c_ciphertext) {}
void ExportCkksCiphertext(GoUint64 ciphertext_handle, CCiphertext* c_ciphertext) {}
void ExportBfvRelinKey(GoUint64 parameter_handle,
                       GoUint64 relin_key_handle,
                       GoInt level,
                       GoInt key_mf_nbits,
                       CRelinKey* c_relin_key) {}
void ExportCkksRelinKey(GoUint64 parameter_handle,
                        GoUint64 relin_key_handle,
                        GoInt level,
                        GoInt key_mf_nbits,
                        CRelinKey* c_relin_key) {}
void ExportBfvGaloisKey(GoUint64 parameter_handle,
                        GoUint64 galois_key_handle,
                        GoInt level,
                        GoInt key_mf_nbits,
                        CGaloisKey* c_galois_key) {}
void ExportCkksGaloisKey(GoUint64 parameter_handle,
                         GoUint64 galois_key_handle,
                         GoInt level,
                         GoInt key_mf_nbits,
                         CGaloisKey* c_galois_key) {}
void ExportCkksSwitchingKey(GoUint64 parameter_handle,
                            GoUint64 switching_key_handle,
                            GoInt level,
                            GoInt sp_level,
                            GoInt key_mf_nbits,
                            CKeySwitchKey* c_switching_key) {}
void BfvComponentNttInplace(GoUint64 parameter_handle, uint64_t* coeff, GoInt lvl_idx) {}
void BfvComponentInvNttInplace(GoUint64 parameter_handle, uint64_t* coeff, GoInt lvl_idx) {}
void CkksComponentNttInplace(GoUint64 parameter_handle, uint64_t* coeff, GoInt lvl_idx) {}
void CkksComponentInvNttInplace(GoUint64 parameter_handle, uint64_t* coeff, GoInt lvl_idx) {}
void BfvComponentMulByPow2Inplace(GoUint64 parameter_handle, uint64_t* coeff, GoInt lvl_idx, GoInt pow2) {}
void CkksComponentMulByPow2Inplace(GoUint64 parameter_handle, uint64_t* coeff, GoInt lvl_idx, GoInt pow2) {}
GoUint64 SetBfvParameter(GoUint64 N, GoUint64 T, uint64_t* Q, GoInt q_len, uint64_t* P, GoInt p_len) {
    return 0;
}
GoUint64 SetCkksParameter(GoUint64 N, unsigned long* Q, GoInt q_len, unsigned long* P, GoInt p_len) {
    return 0;
}

int main(void) {
    CPlaintext plaintext;
    alloc_plaintext(&plaintext, 2, 8);

    CHECK_TRUE(plaintext.poly.n_component == 3);
    CHECK_TRUE(plaintext.poly.contiguous_data != NULL);
    CHECK_TRUE(plaintext.poly.owns_contiguous_data == 1);

    for (int i = 0; i < plaintext.poly.n_component; i++) {
        CHECK_TRUE(plaintext.poly.components[i].n == 8);
        CHECK_TRUE(plaintext.poly.components[i].data == plaintext.poly.contiguous_data + (size_t)i * 8);
    }

    plaintext.poly.components[2].data[7] = 42;
    CHECK_TRUE(plaintext.poly.contiguous_data[23] == 42);

    free_plaintext(&plaintext);
    return 0;
}

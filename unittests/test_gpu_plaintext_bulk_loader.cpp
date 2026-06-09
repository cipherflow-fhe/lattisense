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

#include <cstdio>

#include "mega_ag_runners/gpu/gpu_plaintext_bulk_loader.h"

extern "C" {
#include "c_structs.h"
#include "liblattigo.h"
}

#define CHECK_TRUE(expr)                                                                                               \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            std::fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr);                           \
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

static ComputeNode make_load_node(bool is_ringt) {
    static DatumNode input;
    static DatumNode output;

    input = DatumNode{};
    input.index = 1;
    input.datum_type = TYPE_PLAINTEXT;
    DatumNode::FheProperty input_prop;
    input_prop.level = 0;
    DatumNode::FheProperty::ExtraProperty extra;
    extra.is_ringt = is_ringt;
    input_prop.p = extra;
    input.fhe_prop = input_prop;

    output = input;
    output.index = 2;

    ComputeNode node;
    node.index = 3;
    ComputeNode::FheProperty compute_prop;
    compute_prop.op_type = OperationType::LOAD_TO_BACKEND;
    node.fhe_prop = compute_prop;
    node.input_nodes.push_back(&input);
    node.output_nodes.push_back(&output);
    return node;
}

int main(void) {
    ComputeNode ringt_load = make_load_node(true);
    CHECK_TRUE(gpu_wrapper::is_bulk_plaintext_ringt_load_node(ringt_load));

    ComputeNode plain_load = make_load_node(false);
    CHECK_TRUE(!gpu_wrapper::is_bulk_plaintext_ringt_load_node(plain_load));

    CPlaintext plaintext;
    alloc_plaintext(&plaintext, 0, 65536);
    CHECK_TRUE(gpu_wrapper::is_bulk_plaintext_ringt_payload(plaintext));
    CHECK_TRUE(gpu_wrapper::plaintext_payload_bytes(plaintext) == 512 * 1024);
    CHECK_TRUE(!gpu_wrapper::should_use_bulk_plaintext_ringt_batch(2, gpu_wrapper::plaintext_payload_bytes(plaintext),
                                                                   8 * 1024 * 1024));
    CHECK_TRUE(gpu_wrapper::should_use_bulk_plaintext_ringt_batch(16, gpu_wrapper::plaintext_payload_bytes(plaintext),
                                                                  8 * 1024 * 1024));

    plaintext.poly.components[0].data = plaintext.poly.contiguous_data + 1;
    CHECK_TRUE(!gpu_wrapper::is_bulk_plaintext_ringt_payload(plaintext));
    plaintext.poly.components[0].data = plaintext.poly.contiguous_data;

    free_plaintext(&plaintext);
    return 0;
}

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

#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "fhe_lib_v2.h"

using namespace fhe_ops_lib;

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

double sigmoid(double x);
double step_function(double x);

// ---------------------------------------------------------------------------
// BFV test std::vector helpers
// ---------------------------------------------------------------------------

// Each struct holds n_data test std::vectors; values[i] is a full length-n plaintext message.

struct BfvTestCt {
    std::vector<std::vector<uint64_t>> values;
    std::vector<BfvCiphertext> ciphertexts;
};

struct BfvTestPt {
    std::vector<std::vector<uint64_t>> values;
    std::vector<BfvPlaintext> plaintexts;
};

struct BfvTestPtRingt {
    std::vector<std::vector<uint64_t>> values;
    std::vector<BfvPlaintextRingt> plaintexts;
};

struct BfvTestPtMul {
    std::vector<std::vector<uint64_t>> values;
    std::vector<BfvPlaintextMul> plaintexts;
};

BfvTestCt new_bfv_test_ct(int n_data, BfvContext& ctx, int level, uint64_t t);
BfvTestPt new_bfv_test_pt(int n_data, BfvContext& ctx, int level, uint64_t t);
BfvTestPtRingt new_bfv_test_pt_ringt(int n_data, BfvContext& ctx, uint64_t t);
BfvTestPtMul new_bfv_test_pt_mul(int n_data, BfvContext& ctx, int level, uint64_t t);

// Coeffs-domain variants (in_coeffs_domain = true).
BfvTestCt new_bfv_test_ct_coeffs(int n_data, BfvContext& ctx, int level, uint64_t t);
BfvTestPt new_bfv_test_pt_coeffs(int n_data, BfvContext& ctx, int level, uint64_t t);
BfvTestPtRingt new_bfv_test_pt_ringt_coeffs(int n_data, BfvContext& ctx, uint64_t t);
BfvTestPtMul new_bfv_test_pt_mul_coeffs(int n_data, BfvContext& ctx, int level, uint64_t t);

std::vector<std::vector<uint64_t>> decrypt_and_decode(BfvContext& ctx, const std::vector<BfvCiphertext>& cts);
std::vector<std::vector<uint64_t>> decrypt_and_decode(BfvContext& ctx, const std::vector<BfvCiphertext3>& cts);
std::vector<uint64_t> decrypt_and_decode(BfvContext& ctx, const BfvCiphertext& ct);

std::vector<std::vector<uint64_t>> decrypt_and_decode_coeffs(BfvContext& ctx, const std::vector<BfvCiphertext>& cts);
std::vector<uint64_t> decrypt_and_decode_coeffs(BfvContext& ctx, const BfvCiphertext& ct);

// ---------------------------------------------------------------------------
// CKKS test std::vector helpers
// ---------------------------------------------------------------------------

// Each struct holds n_data test std::vectors; values[i] is a full length-n_slot message.

struct CkksTestCt {
    std::vector<std::vector<double>> values;
    std::vector<CkksCiphertext> ciphertexts;
};

struct CkksTestPt {
    std::vector<std::vector<double>> values;
    std::vector<CkksPlaintext> plaintexts;
};

struct CkksTestPtRingt {
    std::vector<std::vector<double>> values;
    std::vector<CkksPlaintextRingt> plaintexts;
};

struct CkksTestPtMul {
    std::vector<std::vector<double>> values;
    std::vector<CkksPlaintextMul> plaintexts;
};

CkksTestCt new_ckks_test_ct(int n_data, CkksContext& ctx, int level, double scale);
CkksTestPt new_ckks_test_pt(int n_data, CkksContext& ctx, int level, double scale);
CkksTestPtRingt new_ckks_test_pt_ringt(int n_data, CkksContext& ctx, double scale);
CkksTestPtMul new_ckks_test_pt_mul(int n_data, CkksContext& ctx, int level, double scale);

CkksTestCt new_ckks_test_ct_coeffs(int n_data, CkksContext& ctx, int level, double scale);
CkksTestPt new_ckks_test_pt_coeffs(int n_data, CkksContext& ctx, int level, double scale);
CkksTestPtRingt new_ckks_test_pt_ringt_coeffs(int n_data, CkksContext& ctx, double scale);
CkksTestPtMul new_ckks_test_pt_mul_coeffs(int n_data, CkksContext& ctx, int level, double scale);

std::vector<std::vector<double>> decrypt_and_decode_ckks(CkksContext& ctx, const std::vector<CkksCiphertext>& cts);
std::vector<std::vector<double>> decrypt_and_decode_ckks(CkksContext& ctx, const std::vector<CkksCiphertext3>& cts);
std::vector<double> decrypt_and_decode_ckks(CkksContext& ctx, const CkksCiphertext& ct);

std::vector<std::vector<double>> decrypt_and_decode_ckks_coeffs(CkksContext& ctx,
                                                                const std::vector<CkksCiphertext>& cts);
std::vector<double> decrypt_and_decode_ckks_coeffs(CkksContext& ctx, const CkksCiphertext& ct);

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

#include <cassert>
#include <cmath>
#include <cstdint>
#include <random>

#include "utils.h"

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

double sigmoid(double x) {
    return 1 / (exp(-x) + 1);
}

double step_function(double x) {
    if (x > 0)
        return 1;
    if (x < 0)
        return 0;
    return 0;
}

// ---------------------------------------------------------------------------
// BFV test std::vector helpers
// ---------------------------------------------------------------------------

BfvTestCt new_bfv_test_ct(int n_data, BfvContext& ctx, int level, uint64_t t) {
    BfvTestCt tv;
    int n = ctx.get_parameter().get_n();
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_values(n, t));
        auto pt = ctx.encode(tv.values[i], level);
        tv.ciphertexts.push_back(ctx.encrypt_asymmetric(pt));
    }
    return tv;
}

BfvTestPt new_bfv_test_pt(int n_data, BfvContext& ctx, int level, uint64_t t) {
    BfvTestPt tv;
    int n = ctx.get_parameter().get_n();
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_values(n, t));
        tv.plaintexts.push_back(ctx.encode(tv.values[i], level));
    }
    return tv;
}

BfvTestPtRingt new_bfv_test_pt_ringt(int n_data, BfvContext& ctx, uint64_t t) {
    BfvTestPtRingt tv;
    int n = ctx.get_parameter().get_n();
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_values(n, t));
        tv.plaintexts.push_back(ctx.encode_ringt(tv.values[i]));
    }
    return tv;
}

BfvTestPtMul new_bfv_test_pt_mul(int n_data, BfvContext& ctx, int level, uint64_t t) {
    BfvTestPtMul tv;
    int n = ctx.get_parameter().get_n();
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_values(n, t));
        tv.plaintexts.push_back(ctx.encode_mul(tv.values[i], level));
    }
    return tv;
}

BfvTestCt new_bfv_test_ct_coeffs(int n_data, BfvContext& ctx, int level, uint64_t t) {
    BfvTestCt tv;
    int n = ctx.get_parameter().get_n();
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_values(n, t));
        auto pt = ctx.encode_coeffs(tv.values[i], level);
        tv.ciphertexts.push_back(ctx.encrypt_asymmetric(pt));
    }
    return tv;
}

BfvTestPt new_bfv_test_pt_coeffs(int n_data, BfvContext& ctx, int level, uint64_t t) {
    BfvTestPt tv;
    int n = ctx.get_parameter().get_n();
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_values(n, t));
        tv.plaintexts.push_back(ctx.encode_coeffs(tv.values[i], level));
    }
    return tv;
}

BfvTestPtRingt new_bfv_test_pt_ringt_coeffs(int n_data, BfvContext& ctx, uint64_t t) {
    BfvTestPtRingt tv;
    int n = ctx.get_parameter().get_n();
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_values(n, t));
        tv.plaintexts.push_back(ctx.encode_coeffs_ringt(tv.values[i]));
    }
    return tv;
}

BfvTestPtMul new_bfv_test_pt_mul_coeffs(int n_data, BfvContext& ctx, int level, uint64_t t) {
    BfvTestPtMul tv;
    int n = ctx.get_parameter().get_n();
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_values(n, t));
        tv.plaintexts.push_back(ctx.encode_coeffs_mul(tv.values[i], level));
    }
    return tv;
}

std::vector<std::vector<uint64_t>> decrypt_and_decode_coeffs(BfvContext& ctx, const std::vector<BfvCiphertext>& cts) {
    std::vector<std::vector<uint64_t>> result(cts.size());
    for (size_t i = 0; i < cts.size(); i++)
        result[i] = ctx.decode_coeffs(ctx.decrypt(cts[i]));
    return result;
}

std::vector<uint64_t> decrypt_and_decode_coeffs(BfvContext& ctx, const BfvCiphertext& ct) {
    return ctx.decode_coeffs(ctx.decrypt(ct));
}

std::vector<std::vector<uint64_t>> decrypt_and_decode(BfvContext& ctx, const std::vector<BfvCiphertext>& cts) {
    std::vector<std::vector<uint64_t>> result(cts.size());
    for (size_t i = 0; i < cts.size(); i++)
        result[i] = ctx.decode(ctx.decrypt(cts[i]));
    return result;
}

std::vector<std::vector<uint64_t>> decrypt_and_decode(BfvContext& ctx, const std::vector<BfvCiphertext3>& cts) {
    std::vector<std::vector<uint64_t>> result(cts.size());
    for (size_t i = 0; i < cts.size(); i++)
        result[i] = ctx.decode(ctx.decrypt(cts[i]));
    return result;
}

std::vector<uint64_t> decrypt_and_decode(BfvContext& ctx, const BfvCiphertext& ct) {
    return ctx.decode(ctx.decrypt(ct));
}

// ---------------------------------------------------------------------------
// CKKS test std::vector helpers
// ---------------------------------------------------------------------------

CkksTestCt new_ckks_test_ct(int n_data, CkksContext& ctx, int level, double scale) {
    CkksTestCt tv;
    int n_slot = ctx.get_parameter().get_n() / 2;
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_double_values(n_slot));
        auto pt = ctx.encode(tv.values[i], level, scale);
        tv.ciphertexts.push_back(ctx.encrypt_asymmetric(pt));
    }
    return tv;
}

CkksTestPt new_ckks_test_pt(int n_data, CkksContext& ctx, int level, double scale) {
    CkksTestPt tv;
    int n_slot = ctx.get_parameter().get_n() / 2;
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_double_values(n_slot));
        tv.plaintexts.push_back(ctx.encode(tv.values[i], level, scale));
    }
    return tv;
}

CkksTestPtRingt new_ckks_test_pt_ringt(int n_data, CkksContext& ctx, double scale) {
    CkksTestPtRingt tv;
    int n_slot = ctx.get_parameter().get_n() / 2;
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_double_values(n_slot));
        tv.plaintexts.push_back(ctx.encode_ringt(tv.values[i], scale));
    }
    return tv;
}

CkksTestPtMul new_ckks_test_pt_mul(int n_data, CkksContext& ctx, int level, double scale) {
    CkksTestPtMul tv;
    int n_slot = ctx.get_parameter().get_n() / 2;
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_double_values(n_slot));
        tv.plaintexts.push_back(ctx.encode_mul(tv.values[i], level, scale));
    }
    return tv;
}

CkksTestCt new_ckks_test_ct_coeffs(int n_data, CkksContext& ctx, int level, double scale) {
    CkksTestCt tv;
    int n_slot = ctx.get_parameter().get_n() / 2;
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_double_values(n_slot));
        auto pt = ctx.encode_coeffs(tv.values[i], level, scale);
        tv.ciphertexts.push_back(ctx.encrypt_asymmetric(pt));
    }
    return tv;
}

CkksTestPt new_ckks_test_pt_coeffs(int n_data, CkksContext& ctx, int level, double scale) {
    CkksTestPt tv;
    int n_slot = ctx.get_parameter().get_n() / 2;
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_double_values(n_slot));
        tv.plaintexts.push_back(ctx.encode_coeffs(tv.values[i], level, scale));
    }
    return tv;
}

CkksTestPtRingt new_ckks_test_pt_ringt_coeffs(int n_data, CkksContext& ctx, double scale) {
    CkksTestPtRingt tv;
    int n_slot = ctx.get_parameter().get_n() / 2;
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_double_values(n_slot));
        tv.plaintexts.push_back(ctx.encode_coeffs_ringt(tv.values[i], scale));
    }
    return tv;
}

CkksTestPtMul new_ckks_test_pt_mul_coeffs(int n_data, CkksContext& ctx, int level, double scale) {
    CkksTestPtMul tv;
    int n_slot = ctx.get_parameter().get_n() / 2;
    for (int i = 0; i < n_data; i++) {
        tv.values.push_back(rand_double_values(n_slot));
        tv.plaintexts.push_back(ctx.encode_coeffs_mul(tv.values[i], level, scale));
    }
    return tv;
}

std::vector<std::vector<double>> decrypt_and_decode_ckks(CkksContext& ctx, const std::vector<CkksCiphertext>& cts) {
    std::vector<std::vector<double>> result(cts.size());
    for (size_t i = 0; i < cts.size(); i++)
        result[i] = ctx.decode(ctx.decrypt(cts[i]));
    return result;
}

std::vector<std::vector<double>> decrypt_and_decode_ckks(CkksContext& ctx, const std::vector<CkksCiphertext3>& cts) {
    std::vector<std::vector<double>> result(cts.size());
    for (size_t i = 0; i < cts.size(); i++)
        result[i] = ctx.decode(ctx.decrypt(cts[i]));
    return result;
}

std::vector<double> decrypt_and_decode_ckks(CkksContext& ctx, const CkksCiphertext& ct) {
    return ctx.decode(ctx.decrypt(ct));
}

std::vector<std::vector<double>> decrypt_and_decode_ckks_coeffs(CkksContext& ctx,
                                                                const std::vector<CkksCiphertext>& cts) {
    std::vector<std::vector<double>> result(cts.size());
    for (size_t i = 0; i < cts.size(); i++)
        result[i] = ctx.decode_coeffs(ctx.decrypt(cts[i]));
    return result;
}

std::vector<double> decrypt_and_decode_ckks_coeffs(CkksContext& ctx, const CkksCiphertext& ct) {
    return ctx.decode_coeffs(ctx.decrypt(ct));
}

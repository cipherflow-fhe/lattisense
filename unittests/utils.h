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

#include <complex>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "../fhe_ops_lib/unittests/test_utils.h"

using namespace fhe_ops_lib;

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

double sigmoid(double x);
double step_function(double x);

// ---------------------------------------------------------------------------
// Batched wrappers over fhe_ops_lib/unittests/test_utils.h samples
// ---------------------------------------------------------------------------

struct BfvTestCtBatch {
    std::vector<BfvTestCt> samples;

    const std::vector<std::vector<uint64_t>>& messages();
    std::vector<BfvCiphertext>& ciphertexts();

private:
    std::vector<std::vector<uint64_t>> _messages;
    std::vector<BfvCiphertext> _ciphertexts;
};

struct BfvTestPtBatch {
    std::vector<BfvTestPt> samples;

    const std::vector<std::vector<uint64_t>>& messages();
    std::vector<BfvPlaintext>& plaintexts();

private:
    std::vector<std::vector<uint64_t>> _messages;
    std::vector<BfvPlaintext> _plaintexts;
};

struct CkksRealTestCtBatch {
    std::vector<CkksRealTestCt> samples;

    const std::vector<std::vector<double>>& messages();
    std::vector<CkksCiphertext>& ciphertexts();

private:
    std::vector<std::vector<double>> _messages;
    std::vector<CkksCiphertext> _ciphertexts;
};

struct CkksComplexTestCtBatch {
    std::vector<CkksComplexTestCt> samples;

    const std::vector<std::vector<std::complex<double>>>& messages();
    std::vector<CkksCiphertext>& ciphertexts();

private:
    std::vector<std::vector<std::complex<double>>> _messages;
    std::vector<CkksCiphertext> _ciphertexts;
};

struct CkksRealTestPtBatch {
    std::vector<CkksRealTestPt> samples;

    const std::vector<std::vector<double>>& messages();
    std::vector<CkksPlaintext>& plaintexts();

private:
    std::vector<std::vector<double>> _messages;
    std::vector<CkksPlaintext> _plaintexts;
};

struct CkksComplexTestPtBatch {
    std::vector<CkksComplexTestPt> samples;

    const std::vector<std::vector<std::complex<double>>>& messages();
    std::vector<CkksPlaintext>& plaintexts();

private:
    std::vector<std::vector<std::complex<double>>> _messages;
    std::vector<CkksPlaintext> _plaintexts;
};

BfvTestPtBatch new_test_pts(int n_samples, BfvContext& ctx, int level, bool is_ringt, bool is_batched);

BfvTestCtBatch new_test_cts(int n_samples, BfvContext& ctx, int level, bool is_batched = true);

CkksRealTestPtBatch
new_test_real_pts(int n_samples, CkksContext& ctx, int level, bool is_ringt, bool is_batched, int log_slots = -1);

CkksComplexTestPtBatch
new_test_complex_pts(int n_samples, CkksContext& ctx, int level, bool is_ringt, int log_slots = -1);

CkksRealTestCtBatch
new_test_real_cts(int n_samples, CkksContext& ctx, int level, bool is_batched = true, int log_slots = -1);

CkksComplexTestCtBatch new_test_complex_cts(int n_samples, CkksContext& ctx, int level, int log_slots = -1);

std::vector<uint64_t> decrypt_and_decode(BfvContext& ctx, const BfvCiphertext& ciphertext);
std::vector<std::vector<uint64_t>> decrypt_and_decode(BfvContext& ctx, const std::vector<BfvCiphertext>& ciphertexts);

std::vector<double> decrypt_and_decode_real(CkksContext& ctx, const CkksCiphertext& ciphertext);
std::vector<std::vector<double>> decrypt_and_decode_real(CkksContext& ctx,
                                                         const std::vector<CkksCiphertext>& ciphertexts);
std::vector<std::complex<double>> decrypt_and_decode_complex(CkksContext& ctx, const CkksCiphertext& ciphertext);
std::vector<std::vector<std::complex<double>>>
decrypt_and_decode_complex(CkksContext& ctx, const std::vector<CkksCiphertext>& ciphertexts);

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

#include <cmath>
#include <cstdint>
#include <utility>

#include "utils.h"

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

double sigmoid(double x) {
    return 1 / (exp(-x) + 1);
}

double step_function(double x) {
    if (x > 0) {
        return 1;
    }
    if (x < 0) {
        return 0;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Batch accessors
// ---------------------------------------------------------------------------

const std::vector<std::vector<uint64_t>>& BfvTestCtBatch::messages() {
    _messages.clear();
    _messages.reserve(samples.size());
    for (const BfvTestCt& sample : samples) {
        _messages.push_back(sample.message);
    }
    return _messages;
}

std::vector<BfvCiphertext>& BfvTestCtBatch::ciphertexts() {
    _ciphertexts.clear();
    _ciphertexts.reserve(samples.size());
    for (BfvTestCt& sample : samples) {
        _ciphertexts.push_back(std::move(sample.ciphertext));
    }
    return _ciphertexts;
}

const std::vector<std::vector<uint64_t>>& BfvTestPtBatch::messages() {
    _messages.clear();
    _messages.reserve(samples.size());
    for (const BfvTestPt& sample : samples) {
        _messages.push_back(sample.message);
    }
    return _messages;
}

std::vector<BfvPlaintext>& BfvTestPtBatch::plaintexts() {
    _plaintexts.clear();
    _plaintexts.reserve(samples.size());
    for (BfvTestPt& sample : samples) {
        _plaintexts.push_back(std::move(sample.plaintext));
    }
    return _plaintexts;
}

const std::vector<std::vector<double>>& CkksRealTestCtBatch::messages() {
    _messages.clear();
    _messages.reserve(samples.size());
    for (const CkksRealTestCt& sample : samples) {
        _messages.push_back(sample.message);
    }
    return _messages;
}

std::vector<CkksCiphertext>& CkksRealTestCtBatch::ciphertexts() {
    _ciphertexts.clear();
    _ciphertexts.reserve(samples.size());
    for (CkksRealTestCt& sample : samples) {
        _ciphertexts.push_back(std::move(sample.ciphertext));
    }
    return _ciphertexts;
}

const std::vector<std::vector<std::complex<double>>>& CkksComplexTestCtBatch::messages() {
    _messages.clear();
    _messages.reserve(samples.size());
    for (const CkksComplexTestCt& sample : samples) {
        _messages.push_back(sample.message);
    }
    return _messages;
}

std::vector<CkksCiphertext>& CkksComplexTestCtBatch::ciphertexts() {
    _ciphertexts.clear();
    _ciphertexts.reserve(samples.size());
    for (CkksComplexTestCt& sample : samples) {
        _ciphertexts.push_back(std::move(sample.ciphertext));
    }
    return _ciphertexts;
}

const std::vector<std::vector<double>>& CkksRealTestPtBatch::messages() {
    _messages.clear();
    _messages.reserve(samples.size());
    for (const CkksRealTestPt& sample : samples) {
        _messages.push_back(sample.message);
    }
    return _messages;
}

std::vector<CkksPlaintext>& CkksRealTestPtBatch::plaintexts() {
    _plaintexts.clear();
    _plaintexts.reserve(samples.size());
    for (CkksRealTestPt& sample : samples) {
        _plaintexts.push_back(std::move(sample.plaintext));
    }
    return _plaintexts;
}

const std::vector<std::vector<std::complex<double>>>& CkksComplexTestPtBatch::messages() {
    _messages.clear();
    _messages.reserve(samples.size());
    for (const CkksComplexTestPt& sample : samples) {
        _messages.push_back(sample.message);
    }
    return _messages;
}

std::vector<CkksPlaintext>& CkksComplexTestPtBatch::plaintexts() {
    _plaintexts.clear();
    _plaintexts.reserve(samples.size());
    for (CkksComplexTestPt& sample : samples) {
        _plaintexts.push_back(std::move(sample.plaintext));
    }
    return _plaintexts;
}

// ---------------------------------------------------------------------------
// Batched wrappers over fhe_ops_lib/unittests/test_utils.h samples
// ---------------------------------------------------------------------------

BfvTestPtBatch new_test_pts(int n_samples, BfvContext& ctx, int level, bool is_ringt, bool is_batched) {
    BfvTestPtBatch batch;
    batch.samples.reserve(n_samples);

    for (int i = 0; i < n_samples; i++) {
        batch.samples.push_back(new_pt(ctx, level, is_ringt, is_batched));
    }
    return batch;
}

BfvTestCtBatch new_test_cts(int n_samples, BfvContext& ctx, int level, bool is_batched) {
    BfvTestCtBatch batch;
    batch.samples.reserve(n_samples);

    for (int i = 0; i < n_samples; i++) {
        batch.samples.push_back(new_ct(ctx, level, is_batched));
    }
    return batch;
}

CkksRealTestPtBatch
new_test_real_pts(int n_samples, CkksContext& ctx, int level, bool is_ringt, bool is_batched, int log_slots) {
    CkksRealTestPtBatch batch;
    batch.samples.reserve(n_samples);

    for (int i = 0; i < n_samples; i++) {
        batch.samples.push_back(new_real_pt(ctx, level, is_ringt, is_batched, log_slots));
    }
    return batch;
}

CkksComplexTestPtBatch new_test_complex_pts(int n_samples, CkksContext& ctx, int level, bool is_ringt, int log_slots) {
    CkksComplexTestPtBatch batch;
    batch.samples.reserve(n_samples);

    for (int i = 0; i < n_samples; i++) {
        batch.samples.push_back(new_complex_pt(ctx, level, is_ringt, log_slots));
    }
    return batch;
}

CkksRealTestCtBatch new_test_real_cts(int n_samples, CkksContext& ctx, int level, bool is_batched, int log_slots) {
    CkksRealTestCtBatch batch;
    batch.samples.reserve(n_samples);

    for (int i = 0; i < n_samples; i++) {
        batch.samples.push_back(new_real_ct(ctx, level, is_batched, log_slots));
    }
    return batch;
}

CkksComplexTestCtBatch new_test_complex_cts(int n_samples, CkksContext& ctx, int level, int log_slots) {
    CkksComplexTestCtBatch batch;
    batch.samples.reserve(n_samples);

    for (int i = 0; i < n_samples; i++) {
        batch.samples.push_back(new_complex_ct(ctx, level, log_slots));
    }
    return batch;
}

std::vector<uint64_t> decrypt_and_decode(BfvContext& ctx, const BfvCiphertext& ciphertext) {
    BfvPlaintext plaintext = ctx.decrypt(ciphertext);
    std::vector<uint64_t> message;
    ctx.decode(plaintext, message);
    return message;
}

std::vector<std::vector<uint64_t>> decrypt_and_decode(BfvContext& ctx, const std::vector<BfvCiphertext>& ciphertexts) {
    std::vector<std::vector<uint64_t>> result;
    result.reserve(ciphertexts.size());
    for (const BfvCiphertext& ciphertext : ciphertexts) {
        result.push_back(decrypt_and_decode(ctx, ciphertext));
    }
    return result;
}

std::vector<double> decrypt_and_decode_real(CkksContext& ctx, const CkksCiphertext& ciphertext) {
    CkksPlaintext plaintext = ctx.decrypt(ciphertext);
    std::vector<double> message;
    ctx.decode(plaintext, message);
    return message;
}

std::vector<std::vector<double>> decrypt_and_decode_real(CkksContext& ctx,
                                                         const std::vector<CkksCiphertext>& ciphertexts) {
    std::vector<std::vector<double>> result;
    result.reserve(ciphertexts.size());
    for (const CkksCiphertext& ciphertext : ciphertexts) {
        result.push_back(decrypt_and_decode_real(ctx, ciphertext));
    }
    return result;
}

std::vector<std::complex<double>> decrypt_and_decode_complex(CkksContext& ctx, const CkksCiphertext& ciphertext) {
    CkksPlaintext plaintext = ctx.decrypt(ciphertext);
    std::vector<std::complex<double>> message;
    ctx.decode(plaintext, message);
    return message;
}

std::vector<std::vector<std::complex<double>>>
decrypt_and_decode_complex(CkksContext& ctx, const std::vector<CkksCiphertext>& ciphertexts) {
    std::vector<std::vector<std::complex<double>>> result;
    result.reserve(ciphertexts.size());
    for (const CkksCiphertext& ciphertext : ciphertexts) {
        result.push_back(decrypt_and_decode_complex(ctx, ciphertext));
    }
    return result;
}

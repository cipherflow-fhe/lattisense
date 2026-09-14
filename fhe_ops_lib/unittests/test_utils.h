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

#include <algorithm>
#include <complex>
#include <cstdint>
#include <vector>

#include "catch.hpp"
#include "schemes/bfv/bfv.h"
#include "schemes/ckks/ckks.h"
#include "schemes/ckks/precision.h"
#include "../utils.h"

struct EncodingCase {
    const char* tag;
    bool is_ringt;
    bool is_batched;
    int log_slots = -1;
    int extra_log_slots = -1;
};

struct EncryptorCase {
    const char* tag;
    fhe_ops_lib::EncryptorType encryptor_type;
};

struct BfvTestPt {
    std::vector<uint64_t> message;
    fhe_ops_lib::BfvPlaintext plaintext;
};

struct BfvTestCt {
    std::vector<uint64_t> message;
    fhe_ops_lib::BfvCiphertext ciphertext;
};

struct CkksRealTestPt {
    std::vector<double> message;
    fhe_ops_lib::CkksPlaintext plaintext;
};

struct CkksComplexTestPt {
    std::vector<std::complex<double>> message;
    fhe_ops_lib::CkksPlaintext plaintext;
};

struct CkksRealTestCt {
    std::vector<double> message;
    fhe_ops_lib::CkksCiphertext ciphertext;
};

struct CkksComplexTestCt {
    std::vector<std::complex<double>> message;
    fhe_ops_lib::CkksCiphertext ciphertext;
};

std::vector<EncodingCase> encoding_cases();
std::vector<EncryptorCase> encryptor_cases();

BfvTestPt new_pt(fhe_ops_lib::BfvContext& ctx, int level, bool is_ringt, bool is_batched);

BfvTestCt new_ct(fhe_ops_lib::BfvContext& ctx, int level, bool is_batched = true);

int ckks_message_size(const fhe_ops_lib::CkksParameter& param, bool is_batched, int log_slots = -1);

CkksRealTestPt
new_real_pt(fhe_ops_lib::CkksContext& ctx, int level, bool is_ringt, bool is_batched, int log_slots = -1);

CkksComplexTestPt new_complex_pt(fhe_ops_lib::CkksContext& ctx, int level, bool is_ringt, int log_slots = -1);

CkksRealTestCt new_real_ct(fhe_ops_lib::CkksContext& ctx, int level, bool is_batched = true, int log_slots = -1);

CkksComplexTestCt new_complex_ct(fhe_ops_lib::CkksContext& ctx, int level, int log_slots = -1);

template <typename ValuesWant, typename ValuesHave>
void verify_ckks_precision(fhe_ops_lib::CkksContext& ctx,
                           const ValuesWant& values_want,
                           const ValuesHave& values_have,
                           int log2_min_prec = -1,
                           bool print_precision_stats = false) {
    if (log2_min_prec < 0) {
        log2_min_prec = ctx.parameter().log_default_scale() - ctx.parameter().log_n() - 2;
        log2_min_prec = std::max(log2_min_prec, 0);
    }

    fhe_ops_lib::PrecisionStats stats =
        fhe_ops_lib::PrecisionAnalyzer::GetPrecisionStats(ctx, values_want, values_have);
    if (print_precision_stats) {
        INFO(stats.toString());
    }

    REQUIRE(stats.AVGLog2Prec.Real >= static_cast<double>(log2_min_prec));
    REQUIRE(stats.AVGLog2Prec.Imag >= static_cast<double>(log2_min_prec));
}

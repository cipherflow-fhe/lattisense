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
#include <complex>
#include <map>
#include <string>
#include <vector>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "fhe_ops_lib_fixture.hpp"
#include "test_utils.h"
#include "schemes/ckks/ckks.h"

namespace {

constexpr double kScaleTolerance = 1e-12;
constexpr int kSparseLogSlots = 9;
constexpr int kSparseBinaryRhsLogSlots = 11;

vector<EncodingCase> sparse_encoding_cases() {
    return {{"sparse batched encoding", false, true, kSparseLogSlots},
            {"sparse ring-t batched encoding", true, true, kSparseLogSlots}};
}

vector<EncodingCase> sparse_binary_encoding_cases() {
    return {{"sparse batched encoding", false, true, kSparseLogSlots, kSparseBinaryRhsLogSlots},
            {"sparse ring-t batched encoding", true, true, kSparseLogSlots, kSparseBinaryRhsLogSlots}};
}

vector<EncodingCase> all_encoding_cases(bool use_binary_case = false) {
    vector<EncodingCase> cases = encoding_cases();
    vector<EncodingCase> sparse_cases = use_binary_case ? sparse_binary_encoding_cases() : sparse_encoding_cases();
    cases.insert(cases.end(), sparse_cases.begin(), sparse_cases.end());
    return cases;
}

template <typename T> vector<T> expand_sparse_slots(const vector<T>& values, int log_slots) {
    vector<T> result(1 << log_slots);
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = values[i % values.size()];
    }
    return result;
}

}  // namespace

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS encode-decode", "", CkksTestParams) {
    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            SECTION(encoding_case.tag) {
                CkksRealTestPt test_data = new_real_pt(this->ctx, this->level, encoding_case.is_ringt,
                                                       encoding_case.is_batched, encoding_case.log_slots);
                if (encoding_case.log_slots >= 0) {
                    REQUIRE(test_data.plaintext.log_slots() == encoding_case.log_slots);
                }
                verify_ckks_precision(this->ctx, test_data.message, test_data.plaintext);
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (!encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestPt test_data =
                    new_complex_pt(this->ctx, this->level, encoding_case.is_ringt, encoding_case.log_slots);
                if (encoding_case.log_slots >= 0) {
                    REQUIRE(test_data.plaintext.log_slots() == encoding_case.log_slots);
                }
                verify_ckks_precision(this->ctx, test_data.message, test_data.plaintext);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS encrypt-decrypt", "", CkksTestParams) {
    for (const EncryptorCase& encryptor_case : encryptor_cases()) {
        SECTION(encryptor_case.tag) {
            CkksContext ctx = CkksContext::create_random_context(this->param, encryptor_case.encryptor_type);

            SECTION("real message") {
                for (const EncodingCase& encoding_case : all_encoding_cases()) {
                    if (encoding_case.is_ringt) {
                        continue;
                    }
                    SECTION(encoding_case.tag) {
                        CkksRealTestCt test_data =
                            new_real_ct(ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                        verify_ckks_precision(ctx, test_data.message, test_data.ciphertext);
                    }
                }
            }

            SECTION("complex message") {
                for (const EncodingCase& encoding_case : all_encoding_cases()) {
                    if (encoding_case.is_ringt) {
                        continue;
                    }
                    if (!encoding_case.is_batched) {
                        continue;
                    }
                    SECTION(encoding_case.tag) {
                        CkksComplexTestCt test_data = new_complex_ct(ctx, this->level, encoding_case.log_slots);
                        verify_ckks_precision(ctx, test_data.message, test_data.ciphertext);
                    }
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS add ciphertext", "", CkksTestParams) {
    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksRealTestCt lhs_ciphertext =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                CkksRealTestCt rhs_ciphertext =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.extra_log_slots);
                vector<double> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<double> expected = vec_add(lhs_message, rhs_ciphertext.message);

                CkksCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, rhs_ciphertext.ciphertext);
                verify_ckks_precision(this->ctx, expected, result);
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt lhs_ciphertext = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                CkksComplexTestCt rhs_ciphertext =
                    new_complex_ct(this->ctx, this->level, encoding_case.extra_log_slots);
                vector<complex<double>> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<complex<double>> expected = vec_add(lhs_message, rhs_ciphertext.message);

                CkksCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, rhs_ciphertext.ciphertext);
                verify_ckks_precision(this->ctx, expected, result);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS add plaintext", "", CkksTestParams) {
    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (!encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksRealTestCt lhs_ciphertext =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                CkksRealTestPt rhs_plaintext = new_real_pt(this->ctx, this->level, encoding_case.is_ringt,
                                                           encoding_case.is_batched, encoding_case.extra_log_slots);
                vector<double> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<double> expected = vec_add(lhs_message, rhs_plaintext.message);

                CkksCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, rhs_plaintext.plaintext);
                verify_ckks_precision(this->ctx, expected, result);
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (!encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt lhs_ciphertext = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                CkksComplexTestPt rhs_plaintext =
                    new_complex_pt(this->ctx, this->level, encoding_case.is_ringt, encoding_case.extra_log_slots);
                vector<complex<double>> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<complex<double>> expected = vec_add(lhs_message, rhs_plaintext.message);

                CkksCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, rhs_plaintext.plaintext);
                verify_ckks_precision(this->ctx, expected, result);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS add scalar", "", CkksTestParams) {
    const vector<pair<const char*, complex<double>>> scalar_cases = {
        {"0.75", {0.75, 0.0}}, {"-1", {-1.0, 0.0}}, {"i", {0.0, 1.0}}, {"-i", {0.0, -1.0}}};

    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                for (const auto& scalar_case : scalar_cases) {
                    if (scalar_case.second.imag() != 0) {
                        continue;
                    }
                    SECTION(scalar_case.first) {
                        const double scalar = scalar_case.second.real();
                        CkksRealTestCt lhs_ciphertext =
                            new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                        vector<double> expected = vec_add(lhs_ciphertext.message, scalar);

                        CkksCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, scalar);
                        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
                        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());
                        REQUIRE(result.scale() == Approx(lhs_ciphertext.ciphertext.scale()).epsilon(kScaleTolerance));
                        verify_ckks_precision(this->ctx, expected, result);
                    }
                }
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                for (const auto& scalar_case : scalar_cases) {
                    SECTION(scalar_case.first) {
                        const complex<double> scalar = scalar_case.second;
                        CkksComplexTestCt lhs_ciphertext =
                            new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                        vector<complex<double>> expected = vec_add(lhs_ciphertext.message, scalar);

                        CkksCiphertext result = scalar.imag() == 0 ?
                                                    this->ctx.add(lhs_ciphertext.ciphertext, scalar.real()) :
                                                    this->ctx.add(lhs_ciphertext.ciphertext, scalar);
                        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
                        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());
                        REQUIRE(result.scale() == Approx(lhs_ciphertext.ciphertext.scale()).epsilon(kScaleTolerance));
                        verify_ckks_precision(this->ctx, expected, result);
                    }
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS sub ciphertext", "", CkksTestParams) {
    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksRealTestCt lhs_ciphertext =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                CkksRealTestCt rhs_ciphertext =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.extra_log_slots);
                vector<double> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<double> expected = vec_sub(lhs_message, rhs_ciphertext.message);

                CkksCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, rhs_ciphertext.ciphertext);
                verify_ckks_precision(this->ctx, expected, result);
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt lhs_ciphertext = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                CkksComplexTestCt rhs_ciphertext =
                    new_complex_ct(this->ctx, this->level, encoding_case.extra_log_slots);
                vector<complex<double>> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<complex<double>> expected = vec_sub(lhs_message, rhs_ciphertext.message);

                CkksCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, rhs_ciphertext.ciphertext);
                verify_ckks_precision(this->ctx, expected, result);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS sub plaintext", "", CkksTestParams) {
    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (!encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksRealTestCt lhs_ciphertext =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                CkksRealTestPt rhs_plaintext = new_real_pt(this->ctx, this->level, encoding_case.is_ringt,
                                                           encoding_case.is_batched, encoding_case.extra_log_slots);
                vector<double> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<double> expected = vec_sub(lhs_message, rhs_plaintext.message);

                CkksCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, rhs_plaintext.plaintext);
                verify_ckks_precision(this->ctx, expected, result);
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (!encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt lhs_ciphertext = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                CkksComplexTestPt rhs_plaintext =
                    new_complex_pt(this->ctx, this->level, encoding_case.is_ringt, encoding_case.extra_log_slots);
                vector<complex<double>> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<complex<double>> expected = vec_sub(lhs_message, rhs_plaintext.message);

                CkksCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, rhs_plaintext.plaintext);
                verify_ckks_precision(this->ctx, expected, result);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS sub scalar", "", CkksTestParams) {
    const vector<pair<const char*, complex<double>>> scalar_cases = {
        {"0.75", {0.75, 0.0}}, {"-1", {-1.0, 0.0}}, {"i", {0.0, 1.0}}, {"-i", {0.0, -1.0}}};

    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                for (const auto& scalar_case : scalar_cases) {
                    if (scalar_case.second.imag() != 0) {
                        continue;
                    }
                    SECTION(scalar_case.first) {
                        const double scalar = scalar_case.second.real();
                        CkksRealTestCt lhs_ciphertext =
                            new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                        vector<double> expected = vec_sub(lhs_ciphertext.message, scalar);

                        CkksCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, scalar);
                        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
                        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());
                        REQUIRE(result.scale() == Approx(lhs_ciphertext.ciphertext.scale()).epsilon(kScaleTolerance));
                        verify_ckks_precision(this->ctx, expected, result);
                    }
                }
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                for (const auto& scalar_case : scalar_cases) {
                    SECTION(scalar_case.first) {
                        const complex<double> scalar = scalar_case.second;
                        CkksComplexTestCt lhs_ciphertext =
                            new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                        vector<complex<double>> expected = vec_sub(lhs_ciphertext.message, scalar);

                        CkksCiphertext result = scalar.imag() == 0 ?
                                                    this->ctx.sub(lhs_ciphertext.ciphertext, scalar.real()) :
                                                    this->ctx.sub(lhs_ciphertext.ciphertext, scalar);
                        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
                        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());
                        REQUIRE(result.scale() == Approx(lhs_ciphertext.ciphertext.scale()).epsilon(kScaleTolerance));
                        verify_ckks_precision(this->ctx, expected, result);
                    }
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS mult ciphertext-relinearize-rescale", "", CkksTestParams) {
    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (encoding_case.is_ringt) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksRealTestCt lhs_ciphertext =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                CkksRealTestCt rhs_ciphertext =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.extra_log_slots);
                vector<double> expected;
                if (encoding_case.is_batched) {
                    vector<double> lhs_message =
                        encoding_case.log_slots == encoding_case.extra_log_slots ?
                            lhs_ciphertext.message :
                            expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                    expected = vec_mul(lhs_message, rhs_ciphertext.message);
                } else {
                    expected =
                        polynomial_multiplication(this->param.n(), lhs_ciphertext.message, rhs_ciphertext.message);
                }

                CkksCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, rhs_ciphertext.ciphertext);
                REQUIRE(result.degree() == 2);
                const double expected_scale = lhs_ciphertext.ciphertext.scale() * rhs_ciphertext.ciphertext.scale();
                REQUIRE(result.scale() == Approx(expected_scale).epsilon(kScaleTolerance));
                verify_ckks_precision(this->ctx, expected, result);

                SECTION("relinearize") {
                    CkksCiphertext relinearized = this->ctx.relinearize(result);
                    REQUIRE(relinearized.degree() == 1);
                    REQUIRE(relinearized.scale() == Approx(expected_scale).epsilon(kScaleTolerance));
                    verify_ckks_precision(this->ctx, expected, relinearized);
                }

                SECTION("rescale") {
                    CkksCiphertext relinearized = this->ctx.relinearize(result);
                    CkksCiphertext rescaled = this->ctx.rescale(relinearized);
                    REQUIRE(rescaled.degree() == relinearized.degree());
                    REQUIRE(rescaled.level() == relinearized.level() - 1);
                    const double expected_rescaled_scale =
                        relinearized.scale() / static_cast<double>(this->param.q()[relinearized.level()]);
                    REQUIRE(rescaled.scale() == Approx(expected_rescaled_scale).epsilon(kScaleTolerance));
                    verify_ckks_precision(this->ctx, expected, rescaled);
                }
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt lhs_ciphertext = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                CkksComplexTestCt rhs_ciphertext =
                    new_complex_ct(this->ctx, this->level, encoding_case.extra_log_slots);
                vector<complex<double>> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<complex<double>> expected = vec_mul(lhs_message, rhs_ciphertext.message);

                CkksCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, rhs_ciphertext.ciphertext);
                REQUIRE(result.degree() == 2);
                const double expected_scale = lhs_ciphertext.ciphertext.scale() * rhs_ciphertext.ciphertext.scale();
                REQUIRE(result.scale() == Approx(expected_scale).epsilon(kScaleTolerance));
                verify_ckks_precision(this->ctx, expected, result);

                SECTION("relinearize") {
                    CkksCiphertext relinearized = this->ctx.relinearize(result);
                    REQUIRE(relinearized.degree() == 1);
                    REQUIRE(relinearized.scale() == Approx(expected_scale).epsilon(kScaleTolerance));
                    verify_ckks_precision(this->ctx, expected, relinearized);
                }

                SECTION("rescale") {
                    CkksCiphertext relinearized = this->ctx.relinearize(result);
                    CkksCiphertext rescaled = this->ctx.rescale(relinearized);
                    REQUIRE(rescaled.degree() == relinearized.degree());
                    REQUIRE(rescaled.level() == relinearized.level() - 1);
                    const double expected_rescaled_scale =
                        relinearized.scale() / static_cast<double>(this->param.q()[relinearized.level()]);
                    REQUIRE(rescaled.scale() == Approx(expected_rescaled_scale).epsilon(kScaleTolerance));
                    verify_ckks_precision(this->ctx, expected, rescaled);
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS mult plaintext", "", CkksTestParams) {
    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            SECTION(encoding_case.tag) {
                CkksRealTestCt lhs_ciphertext =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                CkksRealTestPt rhs_plaintext = new_real_pt(this->ctx, this->level, encoding_case.is_ringt,
                                                           encoding_case.is_batched, encoding_case.extra_log_slots);
                vector<double> expected;
                if (encoding_case.is_batched) {
                    vector<double> lhs_message =
                        encoding_case.log_slots == encoding_case.extra_log_slots ?
                            lhs_ciphertext.message :
                            expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                    expected = vec_mul(lhs_message, rhs_plaintext.message);
                } else {
                    expected =
                        polynomial_multiplication(this->param.n(), lhs_ciphertext.message, rhs_plaintext.message);
                }

                CkksCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, rhs_plaintext.plaintext);
                const double expected_scale = lhs_ciphertext.ciphertext.scale() * rhs_plaintext.plaintext.scale();
                REQUIRE(result.scale() == Approx(expected_scale).epsilon(kScaleTolerance));
                verify_ckks_precision(this->ctx, expected, result);

                SECTION("rescale") {
                    CkksCiphertext rescaled = this->ctx.rescale(result);
                    REQUIRE(rescaled.degree() == result.degree());
                    REQUIRE(rescaled.level() == result.level() - 1);
                    const double expected_rescaled_scale =
                        result.scale() / static_cast<double>(this->param.q()[result.level()]);
                    REQUIRE(rescaled.scale() == Approx(expected_rescaled_scale).epsilon(kScaleTolerance));
                    verify_ckks_precision(this->ctx, expected, rescaled);
                }
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (!encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt lhs_ciphertext = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                CkksComplexTestPt rhs_plaintext =
                    new_complex_pt(this->ctx, this->level, encoding_case.is_ringt, encoding_case.extra_log_slots);
                vector<complex<double>> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs_ciphertext.message :
                        expand_sparse_slots(lhs_ciphertext.message, encoding_case.extra_log_slots);
                vector<complex<double>> expected = vec_mul(lhs_message, rhs_plaintext.message);

                CkksCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, rhs_plaintext.plaintext);
                const double expected_scale = lhs_ciphertext.ciphertext.scale() * rhs_plaintext.plaintext.scale();
                REQUIRE(result.scale() == Approx(expected_scale).epsilon(kScaleTolerance));
                verify_ckks_precision(this->ctx, expected, result);

                SECTION("rescale") {
                    CkksCiphertext rescaled = this->ctx.rescale(result);
                    REQUIRE(rescaled.degree() == result.degree());
                    REQUIRE(rescaled.level() == result.level() - 1);
                    const double expected_rescaled_scale =
                        result.scale() / static_cast<double>(this->param.q()[result.level()]);
                    REQUIRE(rescaled.scale() == Approx(expected_rescaled_scale).epsilon(kScaleTolerance));
                    verify_ckks_precision(this->ctx, expected, rescaled);
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS mult scalar", "", CkksTestParams) {
    const vector<pair<const char*, complex<double>>> scalar_cases = {
        {"0.75", {0.75, 0.0}}, {"-1", {-1.0, 0.0}}, {"i", {0.0, 1.0}}, {"-i", {0.0, -1.0}}};

    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                for (const auto& scalar_case : scalar_cases) {
                    if (scalar_case.second.imag() != 0) {
                        continue;
                    }
                    SECTION(scalar_case.first) {
                        const double scalar = scalar_case.second.real();
                        CkksRealTestCt lhs_ciphertext =
                            new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                        vector<double> expected = vec_mul(lhs_ciphertext.message, scalar);

                        CkksCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, scalar);
                        const bool is_integer = scalar == std::trunc(scalar);
                        const double expected_scale =
                            lhs_ciphertext.ciphertext.scale() *
                            (is_integer ? 1.0 :
                                          static_cast<double>(this->param.q()[lhs_ciphertext.ciphertext.level()]));
                        REQUIRE(result.scale() == Approx(expected_scale).epsilon(kScaleTolerance));
                        verify_ckks_precision(this->ctx, expected, result);
                    }
                }
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                for (const auto& scalar_case : scalar_cases) {
                    SECTION(scalar_case.first) {
                        const complex<double> scalar = scalar_case.second;
                        CkksComplexTestCt lhs_ciphertext =
                            new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                        vector<complex<double>> expected = vec_mul(lhs_ciphertext.message, scalar);

                        CkksCiphertext result = scalar.imag() == 0 ?
                                                    this->ctx.mult(lhs_ciphertext.ciphertext, scalar.real()) :
                                                    this->ctx.mult(lhs_ciphertext.ciphertext, scalar);
                        const bool is_gaussian_integer =
                            scalar.real() == std::trunc(scalar.real()) && scalar.imag() == std::trunc(scalar.imag());
                        const double expected_scale =
                            lhs_ciphertext.ciphertext.scale() *
                            (is_gaussian_integer ?
                                 1.0 :
                                 static_cast<double>(this->param.q()[lhs_ciphertext.ciphertext.level()]));
                        REQUIRE(result.scale() == Approx(expected_scale).epsilon(kScaleTolerance));
                        verify_ckks_precision(this->ctx, expected, result);
                    }
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS drop level", "", CkksTestParams) {
    const vector<int> drop_levels = {1, 2};

    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksRealTestCt test_data =
                    new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                for (int levels : drop_levels) {
                    SECTION("drop " + std::to_string(levels) + " levels") {
                        CkksCiphertext result = this->ctx.drop_level(test_data.ciphertext, levels);
                        REQUIRE(result.degree() == test_data.ciphertext.degree());
                        REQUIRE(result.level() == test_data.ciphertext.level() - levels);
                        REQUIRE(result.scale() == Approx(test_data.ciphertext.scale()).epsilon(kScaleTolerance));
                        verify_ckks_precision(this->ctx, test_data.message, result);
                    }
                }
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt test_data = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                for (int levels : drop_levels) {
                    SECTION("drop " + std::to_string(levels) + " levels") {
                        CkksCiphertext result = this->ctx.drop_level(test_data.ciphertext, levels);
                        REQUIRE(result.degree() == test_data.ciphertext.degree());
                        REQUIRE(result.level() == test_data.ciphertext.level() - levels);
                        REQUIRE(result.scale() == Approx(test_data.ciphertext.scale()).epsilon(kScaleTolerance));
                        verify_ckks_precision(this->ctx, test_data.message, result);
                    }
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS rotate", "", CkksTestParams) {
    const vector<int32_t> steps = {1, -2, 5, -10, 1000};

    SECTION("default rotation") {
        this->ctx.gen_rotation_keys();

        SECTION("real message") {
            for (const EncodingCase& encoding_case : all_encoding_cases()) {
                if (encoding_case.is_ringt || !encoding_case.is_batched) {
                    continue;
                }
                SECTION(encoding_case.tag) {
                    CkksRealTestCt test_data =
                        new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                    std::map<int32_t, CkksCiphertext> rotated = this->ctx.rotate(test_data.ciphertext, steps);
                    for (int32_t step : steps) {
                        SECTION("step " + std::to_string(step)) {
                            verify_ckks_precision(this->ctx, vec_rotate(test_data.message, step), rotated[step]);
                        }
                    }
                }
            }
        }

        SECTION("complex message") {
            for (const EncodingCase& encoding_case : all_encoding_cases()) {
                if (encoding_case.is_ringt || !encoding_case.is_batched) {
                    continue;
                }
                SECTION(encoding_case.tag) {
                    CkksComplexTestCt test_data = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                    std::map<int32_t, CkksCiphertext> rotated = this->ctx.rotate(test_data.ciphertext, steps);
                    for (int32_t step : steps) {
                        SECTION("step " + std::to_string(step)) {
                            verify_ckks_precision(this->ctx, vec_rotate(test_data.message, step), rotated[step]);
                        }
                    }
                }
            }
        }
    }

    SECTION("non-default rotation") {
        this->ctx.gen_rotation_keys(steps);

        SECTION("real message") {
            for (const EncodingCase& encoding_case : all_encoding_cases()) {
                if (encoding_case.is_ringt || !encoding_case.is_batched) {
                    continue;
                }
                SECTION(encoding_case.tag) {
                    CkksRealTestCt test_data =
                        new_real_ct(this->ctx, this->level, encoding_case.is_batched, encoding_case.log_slots);
                    std::map<int32_t, CkksCiphertext> rotated = this->ctx.rotate(test_data.ciphertext, steps);
                    for (int32_t step : steps) {
                        SECTION("step " + std::to_string(step)) {
                            verify_ckks_precision(this->ctx, vec_rotate(test_data.message, step), rotated[step]);
                        }
                    }
                }
            }
        }

        SECTION("complex message") {
            for (const EncodingCase& encoding_case : all_encoding_cases()) {
                if (encoding_case.is_ringt || !encoding_case.is_batched) {
                    continue;
                }
                SECTION(encoding_case.tag) {
                    CkksComplexTestCt test_data = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
                    std::map<int32_t, CkksCiphertext> rotated = this->ctx.rotate(test_data.ciphertext, steps);
                    for (int32_t step : steps) {
                        SECTION("step " + std::to_string(step)) {
                            verify_ckks_precision(this->ctx, vec_rotate(test_data.message, step), rotated[step]);
                        }
                    }
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS conjugate", "", CkksTestParams) {
    this->ctx.gen_rotation_keys();
    for (const EncodingCase& encoding_case : all_encoding_cases()) {
        if (encoding_case.is_ringt || !encoding_case.is_batched) {
            continue;
        }
        SECTION(encoding_case.tag) {
            CkksComplexTestCt test_data = new_complex_ct(this->ctx, this->level, encoding_case.log_slots);
            vector<complex<double>> expected = vec_conj(test_data.message);

            CkksCiphertext result = this->ctx.conjugate(test_data.ciphertext);
            REQUIRE(result.degree() == test_data.ciphertext.degree());
            REQUIRE(result.level() == test_data.ciphertext.level());
            REQUIRE(result.scale() == Approx(test_data.ciphertext.scale()).epsilon(kScaleTolerance));
            verify_ckks_precision(this->ctx, expected, result);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS bootstrap", "", CkksTestParams) {
    this->ctx.create_bootstrapper();
    const int bootstrap_log2_min_prec = std::max(this->param.log_default_scale() - this->param.log_n() - 12, 0);

    SECTION("real message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksRealTestCt test_data = new_real_ct(this->ctx, 0, encoding_case.is_batched, encoding_case.log_slots);

                CkksCiphertext result = this->ctx.bootstrap(test_data.ciphertext);
                REQUIRE(result.degree() == test_data.ciphertext.degree());
                verify_ckks_precision(this->ctx, test_data.message, result, bootstrap_log2_min_prec);
            }
        }
    }

    SECTION("complex message") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt test_data = new_complex_ct(this->ctx, 0, encoding_case.log_slots);
                CkksCiphertext result = this->ctx.bootstrap(test_data.ciphertext);
                REQUIRE(result.degree() == test_data.ciphertext.degree());
                verify_ckks_precision(this->ctx, test_data.message, result, bootstrap_log2_min_prec);
            }
        }
    }

    SECTION("multiple complex messages") {
        for (const EncodingCase& encoding_case : all_encoding_cases()) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt lhs = new_complex_ct(this->ctx, 0, encoding_case.log_slots);
                CkksComplexTestCt rhs = new_complex_ct(this->ctx, 0, encoding_case.log_slots);
                std::vector<CkksCiphertext> ciphertexts;
                ciphertexts.emplace_back(std::move(lhs.ciphertext));
                ciphertexts.emplace_back(std::move(rhs.ciphertext));

                std::vector<CkksCiphertext> results = this->ctx.bootstrap(ciphertexts);
                REQUIRE(results.size() == 2);
                REQUIRE(results[0].degree() == ciphertexts[0].degree());
                REQUIRE(results[1].degree() == ciphertexts[1].degree());
                verify_ckks_precision(this->ctx, lhs.message, results[0], bootstrap_log2_min_prec);
                verify_ckks_precision(this->ctx, rhs.message, results[1], bootstrap_log2_min_prec);
            }
        }
    }

    SECTION("real multiply-relinearize-rescale") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksRealTestCt lhs = new_real_ct(this->ctx, 1, encoding_case.is_batched, encoding_case.log_slots);
                CkksRealTestCt rhs = new_real_ct(this->ctx, 1, encoding_case.is_batched, encoding_case.extra_log_slots);
                vector<double> lhs_message = encoding_case.log_slots == encoding_case.extra_log_slots ?
                                                 lhs.message :
                                                 expand_sparse_slots(lhs.message, encoding_case.extra_log_slots);
                vector<double> expected = vec_mul(lhs_message, rhs.message);

                CkksCiphertext multiplied = this->ctx.mult(lhs.ciphertext, rhs.ciphertext);
                CkksCiphertext relinearized = this->ctx.relinearize(multiplied);
                CkksCiphertext rescaled = this->ctx.rescale(relinearized);
                CkksCiphertext result = this->ctx.bootstrap(rescaled);

                REQUIRE(result.degree() == 1);
                verify_ckks_precision(this->ctx, expected, result, bootstrap_log2_min_prec);
            }
        }
    }

    SECTION("complex multiply-relinearize-rescale") {
        for (const EncodingCase& encoding_case : all_encoding_cases(true)) {
            if (encoding_case.is_ringt || !encoding_case.is_batched) {
                continue;
            }
            SECTION(encoding_case.tag) {
                CkksComplexTestCt lhs = new_complex_ct(this->ctx, 1, encoding_case.log_slots);
                CkksComplexTestCt rhs = new_complex_ct(this->ctx, 1, encoding_case.extra_log_slots);
                vector<complex<double>> lhs_message =
                    encoding_case.log_slots == encoding_case.extra_log_slots ?
                        lhs.message :
                        expand_sparse_slots(lhs.message, encoding_case.extra_log_slots);
                vector<complex<double>> expected = vec_mul(lhs_message, rhs.message);

                CkksCiphertext multiplied = this->ctx.mult(lhs.ciphertext, rhs.ciphertext);
                CkksCiphertext relinearized = this->ctx.relinearize(multiplied);
                CkksCiphertext rescaled = this->ctx.rescale(relinearized);
                CkksCiphertext result = this->ctx.bootstrap(rescaled);

                REQUIRE(result.degree() == 1);
                verify_ckks_precision(this->ctx, expected, result, bootstrap_log2_min_prec);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS ciphertext serialization", "", CkksTestParams) {
    CkksRealTestCt test_data = new_real_ct(this->ctx, this->level);

    Bytes serialized = test_data.ciphertext.serialize();
    CkksCiphertext restored = CkksCiphertext::deserialize(serialized);

    REQUIRE(restored.degree() == test_data.ciphertext.degree());
    REQUIRE(restored.level() == test_data.ciphertext.level());
    REQUIRE(restored.scale() == Approx(test_data.ciphertext.scale()).epsilon(kScaleTolerance));
    verify_ckks_precision(this->ctx, test_data.message, restored);
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS context serialization", "", CkksTestParams) {
    const int32_t step = 13;
    this->ctx.gen_rotation_keys(vector<int32_t>{step});
    this->ctx.create_bootstrapper();
    const int bootstrap_log2_min_prec = std::max(this->param.log_default_scale() - this->param.log_n() - 12, 0);

    Bytes serialized = this->ctx.serialize();
    CkksContext restored = CkksContext::deserialize(serialized);

    REQUIRE(restored.parameter().log_n() == this->param.log_n());
    REQUIRE(restored.parameter().n() == this->param.n());
    REQUIRE(restored.parameter().max_level() == this->param.max_level());
    REQUIRE(restored.parameter().log_max_slots() == this->param.log_max_slots());
    REQUIRE(restored.parameter().log_default_scale() == this->param.log_default_scale());
    REQUIRE(restored.parameter().q() == this->param.q());
    REQUIRE(restored.parameter().p() == this->param.p());

    CkksRealTestCt lhs = new_real_ct(this->ctx, this->level);
    CkksRealTestCt rhs = new_real_ct(this->ctx, this->level);
    vector<double> expected_mult = vec_mul(lhs.message, rhs.message);

    CkksCiphertext product = restored.mult(lhs.ciphertext, rhs.ciphertext);
    CkksCiphertext relinearized = restored.relinearize(product);
    CkksCiphertext rescaled = restored.rescale(relinearized);
    REQUIRE(rescaled.degree() == 1);
    REQUIRE(rescaled.level() == relinearized.level() - 1);
    const double expected_rescaled_scale =
        relinearized.scale() / static_cast<double>(this->param.q()[relinearized.level()]);
    REQUIRE(rescaled.scale() == Approx(expected_rescaled_scale).epsilon(kScaleTolerance));
    verify_ckks_precision(this->ctx, expected_mult, rescaled);

    CkksCiphertext rotated = restored.rotate(lhs.ciphertext, step);
    REQUIRE(rotated.degree() == lhs.ciphertext.degree());
    REQUIRE(rotated.level() == lhs.ciphertext.level());
    REQUIRE(rotated.scale() == Approx(lhs.ciphertext.scale()).epsilon(kScaleTolerance));
    verify_ckks_precision(this->ctx, vec_rotate(lhs.message, step), rotated);

    CkksRealTestCt bootstrap_input = new_real_ct(this->ctx, 0);
    CkksCiphertext bootstrapped = restored.bootstrap(bootstrap_input.ciphertext);
    REQUIRE(bootstrapped.degree() == bootstrap_input.ciphertext.degree());
    verify_ckks_precision(this->ctx, bootstrap_input.message, bootstrapped, bootstrap_log2_min_prec);
}

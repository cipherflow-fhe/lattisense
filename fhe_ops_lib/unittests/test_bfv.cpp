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

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "fhe_ops_lib_fixture.hpp"
#include "test_utils.h"

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV encode-decode", "", BfvTestParams) {
    for (const EncodingCase& encoding_case : encoding_cases()) {
        SECTION(encoding_case.tag) {
            BfvTestPt test_data = new_pt(this->ctx, this->level, encoding_case.is_ringt, encoding_case.is_batched);
            vector<uint64_t> decoded;
            this->ctx.decode(test_data.plaintext, decoded);

            REQUIRE(decoded == test_data.message);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV encrypt-decrypt", "", BfvTestParams) {
    for (const EncryptorCase& encryptor_case : encryptor_cases()) {
        SECTION(encryptor_case.tag) {
            BfvContext ctx = BfvContext::create_random_context(this->param, encryptor_case.encryptor_type);
            for (const EncodingCase& encoding_case : encoding_cases()) {
                if (encoding_case.is_ringt) {
                    continue;
                }
                SECTION(encoding_case.tag) {
                    BfvTestCt test_data = new_ct(ctx, this->level, encoding_case.is_batched);
                    BfvPlaintext decrypted = ctx.decrypt(test_data.ciphertext);
                    vector<uint64_t> decoded;
                    ctx.decode(decrypted, decoded);

                    REQUIRE(decoded == test_data.message);
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV add ciphertext", "", BfvTestParams) {
    BfvTestCt lhs_ciphertext = new_ct(this->ctx, this->level);
    BfvTestCt rhs_ciphertext = new_ct(this->ctx, this->level);
    vector<uint64_t> expected = vec_mod_add(lhs_ciphertext.message, rhs_ciphertext.message, this->param.t());

    BfvCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, rhs_ciphertext.ciphertext);
    REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
    REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

    BfvPlaintext decrypted = this->ctx.decrypt(result);
    vector<uint64_t> decoded;
    this->ctx.decode(decrypted, decoded);
    REQUIRE(decoded == expected);
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV add plaintext", "", BfvTestParams) {
    for (const EncodingCase& plaintext_encoding_case : encoding_cases()) {
        if (!plaintext_encoding_case.is_batched) {
            continue;
        }
        SECTION(plaintext_encoding_case.tag) {
            BfvTestCt lhs_ciphertext = new_ct(this->ctx, this->level, plaintext_encoding_case.is_batched);
            BfvTestPt rhs_plaintext =
                new_pt(this->ctx, this->level, plaintext_encoding_case.is_ringt, plaintext_encoding_case.is_batched);
            vector<uint64_t> expected = vec_mod_add(lhs_ciphertext.message, rhs_plaintext.message, this->param.t());

            BfvCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, rhs_plaintext.plaintext);
            REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
            REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

            BfvPlaintext decrypted = this->ctx.decrypt(result);
            vector<uint64_t> decoded;
            this->ctx.decode(decrypted, decoded);
            REQUIRE(decoded == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV add scalar", "", BfvTestParams) {
    BfvTestCt lhs_ciphertext = new_ct(this->ctx, this->level);

    SECTION("int") {
        const int scalar = 3;
        vector<uint64_t> expected = vec_mod_add(
            lhs_ciphertext.message, vector<uint64_t>(lhs_ciphertext.message.size(), scalar), this->param.t());

        BfvCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, scalar);
        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

        BfvPlaintext decrypted = this->ctx.decrypt(result);
        vector<uint64_t> decoded;
        this->ctx.decode(decrypted, decoded);
        REQUIRE(decoded == expected);
    }

    SECTION("int64_t") {
        const int64_t scalar = -105;
        const uint64_t scalar_mod_t = this->param.t() - 105;
        vector<uint64_t> expected = vec_mod_add(
            lhs_ciphertext.message, vector<uint64_t>(lhs_ciphertext.message.size(), scalar_mod_t), this->param.t());

        BfvCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, scalar);
        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

        BfvPlaintext decrypted = this->ctx.decrypt(result);
        vector<uint64_t> decoded;
        this->ctx.decode(decrypted, decoded);
        REQUIRE(decoded == expected);
    }

    SECTION("uint64_t") {
        const uint64_t scalar = 11;
        vector<uint64_t> expected = vec_mod_add(
            lhs_ciphertext.message, vector<uint64_t>(lhs_ciphertext.message.size(), scalar), this->param.t());

        BfvCiphertext result = this->ctx.add(lhs_ciphertext.ciphertext, scalar);
        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

        BfvPlaintext decrypted = this->ctx.decrypt(result);
        vector<uint64_t> decoded;
        this->ctx.decode(decrypted, decoded);
        REQUIRE(decoded == expected);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV sub ciphertext", "", BfvTestParams) {
    BfvTestCt lhs_ciphertext = new_ct(this->ctx, this->level);
    BfvTestCt rhs_ciphertext = new_ct(this->ctx, this->level);
    vector<uint64_t> expected = vec_mod_sub(lhs_ciphertext.message, rhs_ciphertext.message, this->param.t());

    BfvCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, rhs_ciphertext.ciphertext);
    REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
    REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

    BfvPlaintext decrypted = this->ctx.decrypt(result);
    vector<uint64_t> decoded;
    this->ctx.decode(decrypted, decoded);
    REQUIRE(decoded == expected);
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV sub plaintext", "", BfvTestParams) {
    for (const EncodingCase& plaintext_encoding_case : encoding_cases()) {
        if (!plaintext_encoding_case.is_batched) {
            continue;
        }
        SECTION(plaintext_encoding_case.tag) {
            BfvTestCt lhs_ciphertext = new_ct(this->ctx, this->level, plaintext_encoding_case.is_batched);
            BfvTestPt rhs_plaintext =
                new_pt(this->ctx, this->level, plaintext_encoding_case.is_ringt, plaintext_encoding_case.is_batched);
            vector<uint64_t> expected = vec_mod_sub(lhs_ciphertext.message, rhs_plaintext.message, this->param.t());

            BfvCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, rhs_plaintext.plaintext);
            REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
            REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

            BfvPlaintext decrypted = this->ctx.decrypt(result);
            vector<uint64_t> decoded;
            this->ctx.decode(decrypted, decoded);
            REQUIRE(decoded == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV sub scalar", "", BfvTestParams) {
    BfvTestCt lhs_ciphertext = new_ct(this->ctx, this->level);

    SECTION("int") {
        const int scalar = 3;
        vector<uint64_t> expected = vec_mod_sub(
            lhs_ciphertext.message, vector<uint64_t>(lhs_ciphertext.message.size(), scalar), this->param.t());

        BfvCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, scalar);
        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

        BfvPlaintext decrypted = this->ctx.decrypt(result);
        vector<uint64_t> decoded;
        this->ctx.decode(decrypted, decoded);
        REQUIRE(decoded == expected);
    }

    SECTION("int64_t") {
        const int64_t scalar = 5;
        vector<uint64_t> expected = vec_mod_sub(
            lhs_ciphertext.message, vector<uint64_t>(lhs_ciphertext.message.size(), scalar), this->param.t());

        BfvCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, scalar);
        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

        BfvPlaintext decrypted = this->ctx.decrypt(result);
        vector<uint64_t> decoded;
        this->ctx.decode(decrypted, decoded);
        REQUIRE(decoded == expected);
    }

    SECTION("uint64_t") {
        const uint64_t scalar = 11;
        vector<uint64_t> expected = vec_mod_sub(
            lhs_ciphertext.message, vector<uint64_t>(lhs_ciphertext.message.size(), scalar), this->param.t());

        BfvCiphertext result = this->ctx.sub(lhs_ciphertext.ciphertext, scalar);
        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

        BfvPlaintext decrypted = this->ctx.decrypt(result);
        vector<uint64_t> decoded;
        this->ctx.decode(decrypted, decoded);
        REQUIRE(decoded == expected);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV mult ciphertext-relinearize", "", BfvTestParams) {
    for (bool is_batched : {true, false}) {
        SECTION(is_batched ? "batched" : "coefficient") {
            BfvTestCt lhs_ciphertext = new_ct(this->ctx, this->level, is_batched);
            BfvTestCt rhs_ciphertext = new_ct(this->ctx, this->level, is_batched);
            vector<uint64_t> expected =
                is_batched ? vec_mod_mul(lhs_ciphertext.message, rhs_ciphertext.message, this->param.t()) :
                             polynomial_multiplication(this->param.n(), this->param.t(), lhs_ciphertext.message,
                                                       rhs_ciphertext.message);

            BfvCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, rhs_ciphertext.ciphertext);
            REQUIRE(result.degree() == 2);
            REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

            BfvPlaintext decrypted = this->ctx.decrypt(result);
            vector<uint64_t> decoded;
            this->ctx.decode(decrypted, decoded);
            REQUIRE(decoded == expected);

            SECTION("relinearize") {
                BfvCiphertext relinearized = this->ctx.relinearize(result);
                REQUIRE(relinearized.degree() == 1);
                REQUIRE(relinearized.level() == result.level());

                BfvPlaintext decrypted_relinearized = this->ctx.decrypt(relinearized);
                vector<uint64_t> decoded_relinearized;
                this->ctx.decode(decrypted_relinearized, decoded_relinearized);
                REQUIRE(decoded_relinearized == expected);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV drop level", "", BfvTestParams) {
    const vector<int> drop_levels = {1, 2};
    BfvTestCt test_data = new_ct(this->ctx, this->level);

    for (int levels : drop_levels) {
        if (levels > test_data.ciphertext.level()) {
            continue;
        }

        SECTION("drop " + std::to_string(levels) + " levels") {
            BfvCiphertext result = this->ctx.drop_level(test_data.ciphertext, levels);
            REQUIRE(result.degree() == test_data.ciphertext.degree());
            REQUIRE(result.level() == test_data.ciphertext.level() - levels);

            BfvPlaintext decrypted = this->ctx.decrypt(result);
            vector<uint64_t> decoded;
            this->ctx.decode(decrypted, decoded);
            REQUIRE(decoded == test_data.message);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV rescale", "", BfvTestParams) {
    BfvTestCt test_data = new_ct(this->ctx, this->level);

    BfvCiphertext result = this->ctx.rescale(test_data.ciphertext);
    REQUIRE(result.degree() == test_data.ciphertext.degree());
    REQUIRE(result.level() == test_data.ciphertext.level() - 1);

    BfvPlaintext decrypted = this->ctx.decrypt(result);
    vector<uint64_t> decoded;
    this->ctx.decode(decrypted, decoded);
    REQUIRE(decoded == test_data.message);
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV mult plaintext", "", BfvTestParams) {
    for (const EncodingCase& plaintext_encoding_case : encoding_cases()) {
        SECTION(plaintext_encoding_case.tag) {
            BfvTestCt lhs_ciphertext = new_ct(this->ctx, this->level, plaintext_encoding_case.is_batched);
            BfvTestPt rhs_plaintext =
                new_pt(this->ctx, this->level, plaintext_encoding_case.is_ringt, plaintext_encoding_case.is_batched);
            vector<uint64_t> expected =
                plaintext_encoding_case.is_batched ?
                    vec_mod_mul(lhs_ciphertext.message, rhs_plaintext.message, this->param.t()) :
                    polynomial_multiplication(this->param.n(), this->param.t(), lhs_ciphertext.message,
                                              rhs_plaintext.message);

            BfvCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, rhs_plaintext.plaintext);
            REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
            REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

            BfvPlaintext decrypted = this->ctx.decrypt(result);
            vector<uint64_t> decoded;
            this->ctx.decode(decrypted, decoded);
            REQUIRE(decoded == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV mult scalar", "", BfvTestParams) {
    BfvTestCt lhs_ciphertext = new_ct(this->ctx, this->level);

    SECTION("int") {
        const int scalar = 3;
        vector<uint64_t> expected = vec_mod_mul(
            lhs_ciphertext.message, vector<uint64_t>(lhs_ciphertext.message.size(), scalar), this->param.t());

        BfvCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, scalar);
        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

        BfvPlaintext decrypted = this->ctx.decrypt(result);
        vector<uint64_t> decoded;
        this->ctx.decode(decrypted, decoded);
        REQUIRE(decoded == expected);
    }

    SECTION("int64_t") {
        const int64_t scalar = -5;
        const uint64_t scalar_mod_t = this->param.t() - 5;
        vector<uint64_t> expected = vec_mod_mul(
            lhs_ciphertext.message, vector<uint64_t>(lhs_ciphertext.message.size(), scalar_mod_t), this->param.t());

        BfvCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, scalar);
        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

        BfvPlaintext decrypted = this->ctx.decrypt(result);
        vector<uint64_t> decoded;
        this->ctx.decode(decrypted, decoded);
        REQUIRE(decoded == expected);
    }

    SECTION("uint64_t") {
        const uint64_t scalar = 11;
        vector<uint64_t> expected = vec_mod_mul(
            lhs_ciphertext.message, vector<uint64_t>(lhs_ciphertext.message.size(), scalar), this->param.t());

        BfvCiphertext result = this->ctx.mult(lhs_ciphertext.ciphertext, scalar);
        REQUIRE(result.degree() == lhs_ciphertext.ciphertext.degree());
        REQUIRE(result.level() == lhs_ciphertext.ciphertext.level());

        BfvPlaintext decrypted = this->ctx.decrypt(result);
        vector<uint64_t> decoded;
        this->ctx.decode(decrypted, decoded);
        REQUIRE(decoded == expected);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV rotate columns", "", BfvTestParams) {
    const vector<int32_t> steps = {1, -2, 5, -10, 1000};

    SECTION("default rotation") {
        this->ctx.gen_rotation_keys();
        BfvTestCt test_data = new_ct(this->ctx, this->level);
        std::map<int32_t, BfvCiphertext> rotated = this->ctx.rotate_cols(test_data.ciphertext, steps);
        for (int32_t step : steps) {
            SECTION("step " + std::to_string(step)) {
                REQUIRE(rotated[step].degree() == test_data.ciphertext.degree());
                REQUIRE(rotated[step].level() == test_data.ciphertext.level());

                BfvPlaintext decrypted = this->ctx.decrypt(rotated[step]);
                vector<uint64_t> decoded;
                this->ctx.decode(decrypted, decoded);
                REQUIRE(decoded == vec_rotate_col(test_data.message, step));
            }
        }
    }

    SECTION("non-default rotation") {
        this->ctx.gen_rotation_keys(steps);
        BfvTestCt test_data = new_ct(this->ctx, this->level);
        std::map<int32_t, BfvCiphertext> rotated = this->ctx.rotate_cols(test_data.ciphertext, steps);
        for (int32_t step : steps) {
            SECTION("step " + std::to_string(step)) {
                REQUIRE(rotated[step].degree() == test_data.ciphertext.degree());
                REQUIRE(rotated[step].level() == test_data.ciphertext.level());

                BfvPlaintext decrypted = this->ctx.decrypt(rotated[step]);
                vector<uint64_t> decoded;
                this->ctx.decode(decrypted, decoded);
                REQUIRE(decoded == vec_rotate_col(test_data.message, step));
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV rotate rows", "", BfvTestParams) {
    this->ctx.gen_rotation_keys();
    BfvTestCt test_data = new_ct(this->ctx, this->level);

    BfvCiphertext result = this->ctx.rotate_rows(test_data.ciphertext);
    REQUIRE(result.degree() == test_data.ciphertext.degree());
    REQUIRE(result.level() == test_data.ciphertext.level());

    BfvPlaintext decrypted = this->ctx.decrypt(result);
    vector<uint64_t> decoded;
    this->ctx.decode(decrypted, decoded);
    REQUIRE(decoded == vec_rotate_row(test_data.message));
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV ciphertext serialization", "", BfvTestParams) {
    BfvTestCt test_data = new_ct(this->ctx, this->level);

    Bytes serialized = test_data.ciphertext.serialize();
    BfvCiphertext restored = BfvCiphertext::deserialize(serialized);

    REQUIRE(restored.degree() == test_data.ciphertext.degree());
    REQUIRE(restored.level() == test_data.ciphertext.level());

    BfvPlaintext decrypted = this->ctx.decrypt(restored);
    vector<uint64_t> decoded;
    this->ctx.decode(decrypted, decoded);
    REQUIRE(decoded == test_data.message);
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV context serialization", "", BfvTestParams) {
    const int32_t step = 3;
    this->ctx.gen_rotation_keys(vector<int32_t>{step});

    Bytes serialized = this->ctx.serialize();
    BfvContext restored = BfvContext::deserialize(serialized);

    REQUIRE(restored.parameter().log_n() == this->param.log_n());
    REQUIRE(restored.parameter().n() == this->param.n());
    REQUIRE(restored.parameter().max_level() == this->param.max_level());
    REQUIRE(restored.parameter().t() == this->param.t());
    REQUIRE(restored.parameter().q() == this->param.q());
    REQUIRE(restored.parameter().p() == this->param.p());

    BfvTestCt lhs = new_ct(this->ctx, this->level);
    BfvTestCt rhs = new_ct(this->ctx, this->level);
    vector<uint64_t> expected_mult = vec_mod_mul(lhs.message, rhs.message, this->param.t());

    BfvCiphertext product = restored.mult(lhs.ciphertext, rhs.ciphertext);
    BfvCiphertext relinearized = restored.relinearize(product);
    REQUIRE(relinearized.degree() == 1);
    REQUIRE(relinearized.level() == product.level());

    BfvPlaintext decrypted_product = this->ctx.decrypt(relinearized);
    vector<uint64_t> decoded_product;
    this->ctx.decode(decrypted_product, decoded_product);
    REQUIRE(decoded_product == expected_mult);

    BfvCiphertext rotated = restored.rotate_cols(lhs.ciphertext, step);
    REQUIRE(rotated.degree() == lhs.ciphertext.degree());
    REQUIRE(rotated.level() == lhs.ciphertext.level());

    BfvPlaintext decrypted_rotation = this->ctx.decrypt(rotated);
    vector<uint64_t> decoded_rotation;
    this->ctx.decode(decrypted_rotation, decoded_rotation);
    REQUIRE(decoded_rotation == vec_rotate_col(lhs.message, step));
}

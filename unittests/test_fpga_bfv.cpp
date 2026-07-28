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

#include <algorithm>
#include <random>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "fixture.hpp"
#include "utils.h"

#ifdef LATTISENSE_ENABLE_FPGA

// ---------------------------------------------------------------------------
// Multi-param parallel tests
// Each test type iterates over all valid levels.
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cac level error", "", BfvFpgaTestParams) {
    int level = 3;
    if (this->max_level < level)
        return;

    SECTION("lv=" + to_string(level)) {
        auto xv = new_bfv_test_ct(this->n_op, this->ctx, level - 1, this->param.get_t());
        auto yv = new_bfv_test_ct(this->n_op, this->ctx, level - 1, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(this->n_op);
        for (int _i = 0; _i < this->n_op; _i++)
            z_list.push_back(this->ctx.new_ciphertext(level - 1));

        string path =
            fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cac/level_" + to_string(level);
        FheTaskFpga proj(path);
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"in_y_list", &yv.ciphertexts},
            {"out_z_list", &z_list},
        };
        REQUIRE_THROWS_WITH(proj.run(&this->ctx, args),
                            "For argument in_x_list, expected level is 3, but input level is 2.");
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cap", "", BfvFpgaTestParams) {
    for (int level = 0; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cap/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_add(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cac", "", BfvFpgaTestParams) {
    for (int level = 0; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cac/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_add(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV casc", "", BfvFpgaTestParams) {
    for (int level = 0; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_casc/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_add(xv.values[i], xv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV csp", "", BfvFpgaTestParams) {
    for (int level = 0; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_csp/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_sub(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV csc", "", BfvFpgaTestParams) {
    for (int level = 0; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_csc/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_sub(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cneg", "", BfvFpgaTestParams) {
    for (int level = 0; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cneg/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_neg(xv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cmp_ringt", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_ringt(this->n_op, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmp_ringt/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cmp", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmp/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cmp_mul", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_mul(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmp_mul/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cmp_coeffs_ringt", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct_coeffs(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_ringt_coeffs(this->n_op, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++) {
                auto z_ct = this->ctx.new_ciphertext(level);
                z_list.push_back(std::move(z_ct));
            }
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmp_ringt/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            int n = this->param.get_n();
            for (int i = 0; i < this->n_op; i++) {
                auto z_true = polynomial_multiplication(n, this->param.get_t(), xv.values[i], yv.values[i]);
                REQUIRE(decrypt_and_decode_coeffs(this->ctx, z_list[i]) == z_true);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV power-of-2-t cmp_coeffs_ringt", "[.]", BfvFpgaPow2TTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct_coeffs(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_ringt_coeffs(this->n_op, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++) {
                auto z_ct = this->ctx.new_ciphertext(level);
                z_list.push_back(std::move(z_ct));
            }
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmp_ringt/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            int n = this->param.get_n();
            for (int i = 0; i < this->n_op; i++) {
                auto z_true = polynomial_multiplication(n, this->param.get_t(), xv.values[i], yv.values[i]);
                REQUIRE(decrypt_and_decode_coeffs(this->ctx, z_list[i]) == z_true);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cmp_coeffs_mul", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct_coeffs(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_mul_coeffs(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++) {
                auto z_ct = this->ctx.new_ciphertext(level);
                z_list.push_back(std::move(z_ct));
            }
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmp_mul/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            int n = this->param.get_n();
            for (int i = 0; i < this->n_op; i++) {
                auto z_true = polynomial_multiplication(n, this->param.get_t(), xv.values[i], yv.values[i]);
                REQUIRE(decrypt_and_decode_coeffs(this->ctx, z_list[i]) == z_true);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV ct_mul_mult_pt_ringt", "[.]", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_ringt(this->n_op, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_cmp_ct-mul_pt-ringt/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV ct_ntt_mult_pt_ringt", "[.]", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_ringt(this->n_op, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_cmp_ct-ntt_pt-ringt/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cmc", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext3> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext3(level));
            string path =
                fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmc/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cmc_relin", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmc_relin/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cmc_relin_rescale", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_cmc_relin_rescale/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV csqr", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext3> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext3(level));
            string path =
                fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_csqr/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], xv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV csqr_relin", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_csqr_relin/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], xv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV csqr_relin_rescale", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_csqr_relin_rescale/level_" + to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                expected[i] = vec_mod_mul(xv.values[i], xv.values[i], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV rotate_col", "", BfvFpgaTestParams) {
    vector<int32_t> steps;
    for (int i = 1; i <= 128; i++)
        steps.push_back(i);
    string steps_str = "steps_1_to_128";

    this->ctx.gen_rotation_keys();

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<vector<BfvCiphertext>> y_list(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    y_list[i].push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_rotate_col/level_" +
                          to_string(level) + "/" + steps_str;
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++) {
                for (int j = 0; j < (int)steps.size(); j++) {
                    auto y_mg = decrypt_and_decode(this->ctx, y_list[i][j]);
                    REQUIRE(y_mg == vec_rotate_col(xv.values[i], steps[j]));
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV advanced_rotate_col", "", BfvFpgaTestParams) {
    vector<int32_t> steps = {-900, 20, 400, 2000, 3009};
    string steps_str;
    for (int i = 0; i < (int)steps.size(); i++) {
        if (i > 0)
            steps_str += "_";
        steps_str += to_string(steps[i]);
    }

    this->ctx.gen_rotation_keys_for_rotations(steps);

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<vector<BfvCiphertext>> y_list(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    y_list[i].push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_advanced_rotate_col/level_" + to_string(level) + "/steps_" + steps_str;
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++) {
                for (int j = 0; j < (int)steps.size(); j++) {
                    auto y_mg = decrypt_and_decode(this->ctx, y_list[i][j]);
                    REQUIRE(y_mg == vec_rotate_col(xv.values[i], steps[j]));
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV advanced_rotate_col_imul", "[.]", BfvFpgaTestParams) {
    vector<int32_t> steps = {-900, 20, 400, 2000, 3009};
    string steps_str;
    for (int i = 0; i < (int)steps.size(); i++) {
        if (i > 0)
            steps_str += "_";
        steps_str += to_string(steps[i]);
    }

    this->ctx.gen_rotation_keys_for_rotations(steps);

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<vector<BfvCiphertext>> y_list(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    y_list[i].push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_advanced_rotate_col_imul/level_" + to_string(level) + "/steps_" + steps_str;
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++) {
                for (int j = 0; j < (int)steps.size(); j++) {
                    auto y_mg = decrypt_and_decode(this->ctx, y_list[i][j]);
                    REQUIRE(y_mg == vec_rotate_col(xv.values[i], steps[j]));
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV advanced_rotate_col_imul_ontt", "[.]", BfvFpgaTestParams) {
    vector<int32_t> steps = {-900, 20, 400, 2000, 3009};
    string steps_str;
    for (int i = 0; i < (int)steps.size(); i++) {
        if (i > 0)
            steps_str += "_";
        steps_str += to_string(steps[i]);
    }

    this->ctx.gen_rotation_keys_for_rotations(steps);

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<vector<BfvCiphertext>> y_list(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    y_list[i].push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_advanced_rotate_col_imul_ontt/level_" + to_string(level) + "/steps_" + steps_str;
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++) {
                for (int j = 0; j < (int)steps.size(); j++) {
                    auto y_mg = decrypt_and_decode(this->ctx, y_list[i][j]);
                    REQUIRE(y_mg == vec_rotate_col(xv.values[i], steps[j]));
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV advanced_rotate_col_intt_ontt", "[.]", BfvFpgaTestParams) {
    vector<int32_t> steps = {-900, 20, 400, 2000, 3009};
    string steps_str;
    for (int i = 0; i < (int)steps.size(); i++) {
        if (i > 0)
            steps_str += "_";
        steps_str += to_string(steps[i]);
    }

    this->ctx.gen_rotation_keys_for_rotations(steps);

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<vector<BfvCiphertext>> y_list(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    y_list[i].push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_advanced_rotate_col_intt_ontt/level_" + to_string(level) + "/steps_" + steps_str;
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++) {
                for (int j = 0; j < (int)steps.size(); j++) {
                    auto y_mg = decrypt_and_decode(this->ctx, y_list[i][j]);
                    REQUIRE(y_mg == vec_rotate_col(xv.values[i], steps[j]));
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV rotate_row", "", BfvFpgaTestParams) {
    this->ctx.gen_rotation_keys_for_rotations(vector<int32_t>{}, true);

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> y_list;
            y_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                y_list.push_back(this->ctx.new_ciphertext(level));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_rotate_row/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++) {
                auto y_mg = decrypt_and_decode(this->ctx, y_list[i]);
                REQUIRE(y_mg == vec_rotate_row(xv.values[i]));
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV rescale", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> y_list;
            y_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                y_list.push_back(this->ctx.new_ciphertext(level - 1));
            string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_rescale/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_y_list", &y_list},
            };
            proj.run(&this->ctx, args);
            REQUIRE(decrypt_and_decode(this->ctx, y_list) == xv.values);
        }
    }
}

// ---------------------------------------------------------------------------
// Special tests: complex DAGs, fixed level, default param only
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV ctc_ctc_0", "", BfvFpgaTestParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(this->n_op, this->ctx, 3, this->param.get_t());
        auto yv = new_bfv_test_ct(this->n_op, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(5);
        for (int _i = 0; _i < 5; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskFpga proj(fpga_base_path + "/" + this->tag + "/BFV_ctc_ctc_0/level_3");
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"in_y_list", &yv.ciphertexts},
            {"out_z_list", &z_list},
        };
        proj.run(&this->ctx, args);

        // z[0] = x[0]*y[0], z[1] = z[0]*x[1], z[2..4] = x[i]*y[i] for i=1..3
        vector<vector<uint64_t>> expected(5);
        expected[0] = vec_mod_mul(xv.values[0], yv.values[0], this->param.get_t());
        expected[1] = vec_mod_mul(expected[0], xv.values[1], this->param.get_t());
        for (int i = 1; i < 4; i++)
            expected[i + 1] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
        REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV ctc_ctc_1", "", BfvFpgaTestParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(this->n_op, this->ctx, 3, this->param.get_t());
        auto yv = new_bfv_test_ct(this->n_op, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(4);
        for (int _i = 0; _i < 4; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskFpga proj(fpga_base_path + "/" + this->tag + "/BFV_ctc_ctc_1/level_3");
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"in_y_list", &yv.ciphertexts},
            {"out_z_list", &z_list},
        };
        proj.run(&this->ctx, args);

        // t[i] = x[i]*y[i], z[0]=t[0]*t[1], z[1]=t[1]*x[2], z[2]=t[2]*x[3], z[3]=t[2]*t[3]
        vector<vector<uint64_t>> t(4);
        for (int i = 0; i < 4; i++)
            t[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
        vector<vector<uint64_t>> expected(4);
        expected[0] = vec_mod_mul(t[0], t[1], this->param.get_t());
        expected[1] = vec_mod_mul(t[1], xv.values[2], this->param.get_t());
        expected[2] = vec_mod_mul(t[2], xv.values[3], this->param.get_t());
        expected[3] = vec_mod_mul(t[2], t[3], this->param.get_t());
        REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV 1_square_square", "", BfvFpgaTestParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(1, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(1);
        for (int _i = 0; _i < 1; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskFpga proj(fpga_base_path + "/" + this->tag + "/BFV_1_square_square/level_3");
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"out_z_list", &z_list},
        };
        proj.run(&this->ctx, args);

        vector<vector<uint64_t>> expected(1);
        auto x2 = vec_mod_mul(xv.values[0], xv.values[0], this->param.get_t());
        expected[0] = vec_mod_mul(x2, x2, this->param.get_t());
        REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV 1_ctc_rotate_cac", "", BfvFpgaTestParams) {
    if (this->max_level < 3)
        return;
    this->ctx.gen_rotation_keys();
    int step = 1;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(1, this->ctx, 3, this->param.get_t());
        auto yv = new_bfv_test_ct(1, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(1);
        for (int _i = 0; _i < 1; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskFpga proj(fpga_base_path + "/" + this->tag + "/BFV_1_ctc_rotate_cac/level_3");
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"in_y_list", &yv.ciphertexts},
            {"out_z_list", &z_list},
        };
        proj.run(&this->ctx, args);

        auto t_mg = vec_mod_mul(xv.values[0], yv.values[0], this->param.get_t());
        auto z_true = vec_mod_add(t_mg, vec_rotate_col(t_mg, step), this->param.get_t());
        REQUIRE(decrypt_and_decode(this->ctx, z_list[0]) == z_true);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV double", "", BfvFpgaTestParams) {
    SECTION("lv=1") {
        auto xv = new_bfv_test_ct(3, this->ctx, 1, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(2);
        for (int _i = 0; _i < 2; _i++)
            z_list.push_back(this->ctx.new_ciphertext(1));

        FheTaskFpga proj(fpga_base_path + "/" + this->tag + "/BFV_1_double");
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"out_z_list", &z_list},
        };
        proj.run(&this->ctx, args);

        vector<vector<uint64_t>> expected(2);
        expected[0] = vec_mod_mul(xv.values[0], xv.values[1], this->param.get_t());
        expected[1] = vec_mod_mul(xv.values[0], xv.values[2], this->param.get_t());
        REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV braid", "", BfvFpgaTestParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(4, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(4);
        for (int _i = 0; _i < 4; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskFpga proj(fpga_base_path + "/" + this->tag + "/BFV_braid");
        vector<CxxVectorArgument> args = {
            {"in_list", &xv.ciphertexts},
            {"out_list", &z_list},
        };
        proj.run(&this->ctx, args);

        // braid: z[j] = x[j]*x[(j+1)%4] * x[(j+1)%4]*x[(j+2)%4]
        vector<vector<uint64_t>> expected(4);
        for (int j = 0; j < 4; j++) {
            auto a = vec_mod_mul(xv.values[j], xv.values[(j + 1) % 4], this->param.get_t());
            auto b = vec_mod_mul(xv.values[(j + 1) % 4], xv.values[(j + 2) % 4], this->param.get_t());
            expected[j] = vec_mod_mul(a, b, this->param.get_t());
        }
        REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV poly", "", BfvFpgaTestParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(4, this->ctx, 3, this->param.get_t());
        auto av = new_bfv_test_ct(3, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(4);
        for (int _i = 0; _i < 4; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskFpga proj(fpga_base_path + "/" + this->tag + "/BFV_n_poly/level_3");
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"in_a_list", &av.ciphertexts},
            {"out_z_list", &z_list},
        };
        proj.run(&this->ctx, args);

        // z[i] = a[0]*x[i]^2 + a[1]*x[i] + a[2]
        vector<vector<uint64_t>> expected(4);
        for (int i = 0; i < 4; i++) {
            auto x2 = vec_mod_mul(xv.values[i], xv.values[i], this->param.get_t());
            auto ax2 = vec_mod_mul(av.values[0], x2, this->param.get_t());
            auto bx = vec_mod_mul(av.values[1], xv.values[i], this->param.get_t());
            expected[i] = vec_mod_add(vec_mod_add(ax2, bx, this->param.get_t()), av.values[2], this->param.get_t());
        }
        REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV poly_2", "", BfvFpgaTestParams) {
    if (this->max_level < 5)
        return;
    int n = this->param.get_n();

    SECTION("lv=5") {
        vector<uint64_t> x_vals = {2};
        vector<uint64_t> coeffs_vals = {3, 4};

        // z = coeffs[0]*x + coeffs[1]*x^2
        vector<uint64_t> z_true(n, 0);
        z_true[0] = (coeffs_vals[0] * x_vals[0] % this->param.get_t() +
                     coeffs_vals[1] * x_vals[0] * x_vals[0] % this->param.get_t()) %
                    this->param.get_t();

        vector<BfvCiphertext> x_list;
        vector<BfvPlaintextMul> coeffs_list;
        vector<BfvCiphertext> z_list;

        auto x_pt = this->ctx.encode(x_vals, 5);
        x_list.push_back(this->ctx.encrypt_asymmetric(x_pt));
        for (auto c : coeffs_vals) {
            vector<uint64_t> c_mg{c};
            coeffs_list.push_back(this->ctx.encode_mul(c_mg, 5));
        }
        z_list.push_back(this->ctx.new_ciphertext(5));

        FheTaskFpga proj(fpga_base_path + "/" + this->tag + "/BFV_poly_2/level_5");
        vector<CxxVectorArgument> args = {
            {"in_x", &x_list},
            {"in_coeffs", &coeffs_list},
            {"out_y", &z_list},
        };
        proj.run(&this->ctx, args);

        REQUIRE(decrypt_and_decode(this->ctx, z_list[0]) == z_true);
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV ct_pt_ringt_mac", "", BfvFpgaTestParams) {
    for (int m = 2; m <= 20; m++) {
        SECTION("m=" + to_string(m) + "/lv=1") {
            auto cv = new_bfv_test_ct(m, this->ctx, 1, this->param.get_t());
            auto pv = new_bfv_test_pt_ringt(m, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(1));

            string path = fpga_base_path + "/" + this->tag + "/BFV_cmpac/level_1_m_" + to_string(m);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_c_list", &cv.ciphertexts},
                {"in_p_list", &pv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);

            int n = this->param.get_n();
            vector<vector<uint64_t>> expected(1, vector<uint64_t>(n, 0));
            for (int i = 0; i < m; i++)
                expected[0] = vec_mod_add(expected[0], vec_mod_mul(cv.values[i], pv.values[i], this->param.get_t()),
                                          this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV ct_pt_ringt_mac 1", "", BfvFpgaTestParams) {
    for (int m = 2; m <= 20; m++) {
        SECTION("m=" + to_string(m) + "/lv=1") {
            auto cv = new_bfv_test_ct(m, this->ctx, 1, this->param.get_t());
            auto pv = new_bfv_test_pt_ringt(m, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(1));

            string path = fpga_base_path + "/" + this->tag + "/BFV_cmpac_1/level_1_m_" + to_string(m);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_c_list", &cv.ciphertexts},
                {"in_p_list", &pv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);

            int n = this->param.get_n();
            vector<vector<uint64_t>> expected(1, vector<uint64_t>(n, 0));
            for (int i = 0; i < m; i++)
                expected[0] = vec_mod_add(expected[0], vec_mod_mul(cv.values[i], pv.values[i], this->param.get_t()),
                                          this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV ct_mul_pt_mac", "[.]", BfvFpgaTestParams) {
    for (int m = 2; m <= 20; m++) {
        SECTION("m=" + to_string(m) + "/lv=1") {
            auto cv = new_bfv_test_ct(m, this->ctx, 1, this->param.get_t());
            auto pv = new_bfv_test_pt_ringt(m, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(1));

            string path = fpga_base_path + "/" + this->tag + "/BFV_cmpac_mul/level_1_m_" + to_string(m);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_c_list", &cv.ciphertexts},
                {"in_p_list", &pv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);

            int n = this->param.get_n();
            vector<vector<uint64_t>> expected(1, vector<uint64_t>(n, 0));
            for (int i = 0; i < m; i++)
                expected[0] = vec_mod_add(expected[0], vec_mod_mul(cv.values[i], pv.values[i], this->param.get_t()),
                                          this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV ct_ntt_pt_mac", "[.]", BfvFpgaTestParams) {
    for (int m = 2; m <= 20; m++) {
        SECTION("m=" + to_string(m) + "/lv=1") {
            auto cv = new_bfv_test_ct(m, this->ctx, 1, this->param.get_t());
            auto pv = new_bfv_test_pt_ringt(m, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(1));

            string path = fpga_base_path + "/" + this->tag + "/BFV_cmpac_ntt/level_1_m_" + to_string(m);
            FheTaskFpga proj(path);
            vector<CxxVectorArgument> args = {
                {"in_c_list", &cv.ciphertexts},
                {"in_p_list", &pv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);

            int n = this->param.get_n();
            vector<vector<uint64_t>> expected(1, vector<uint64_t>(n, 0));
            for (int i = 0; i < m; i++)
                expected[0] = vec_mod_add(expected[0], vec_mod_mul(cv.values[i], pv.values[i], this->param.get_t()),
                                          this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV power_dag", "", BfvFpgaTestParams) {
    vector<int> source_power{1, 7, 18, 62, 104, 244, 259};
    int max_power = 1137;

    string source_power_str;
    for (int j = 0; j < (int)source_power.size(); j++) {
        source_power_str += to_string(source_power[j]);
        if (j != (int)source_power.size() - 1)
            source_power_str += "-";
    }
    string task_power_str = "PD-" + to_string(max_power) + "#" + source_power_str;

    SECTION("power_dag " + task_power_str) {
        int n = this->param.get_n();
        auto x_mg = rand_values(n, this->param.get_t());

        vector<vector<uint64_t>> x_source_power(source_power.size());
        for (int j = 0; j < (int)source_power.size(); j++)
            x_source_power[j] = vec_mod_exp(x_mg, source_power[j], this->param.get_t());

        vector<vector<uint64_t>> x_max_power(max_power);
        for (int j = 1; j <= max_power; j++)
            x_max_power[j - 1] = vec_mod_exp(x_mg, j, this->param.get_t());

        for (int level = 5; level <= 5; level++) {
            SECTION("level " + to_string(level)) {
                vector<BfvCiphertext> x_source_power_list;
                for (int j = 0; j < (int)source_power.size(); j++) {
                    auto x_pt = this->ctx.encode(x_source_power[j], level);
                    x_source_power_list.push_back(this->ctx.encrypt_asymmetric(x_pt));
                }
                vector<BfvCiphertext> x_max_power_list;
                for (int j = 0; j < max_power; j++)
                    x_max_power_list.push_back(this->ctx.new_ciphertext(1));

                string path = fpga_base_path + "/" + this->tag + "/BFV_power_dag/" + task_power_str;
                FheTaskFpga proj(path);
                vector<CxxVectorArgument> args = {
                    CxxVectorArgument{"in_x_list", &x_source_power_list},
                    CxxVectorArgument{"out_z_list", &x_max_power_list},
                };
                proj.run(&this->ctx, args);

                for (int j = 0; j < max_power; j++)
                    REQUIRE(decrypt_and_decode(this->ctx, x_max_power_list[j]) == x_max_power[j]);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV power_mul_coeff", "", BfvFpgaTestParams) {
    vector<int> source_power{1, 7, 18, 62, 104, 244, 259};
    int max_power = 1137;
    vector<int> lane_cipher_size{2, 1, 5};

    string source_power_str;
    for (int j = 0; j < (int)source_power.size(); j++) {
        source_power_str += to_string(source_power[j]);
        if (j != (int)source_power.size() - 1)
            source_power_str += "-";
    }
    string task_power_str = "PD-" + to_string(max_power) + "#" + source_power_str;

    SECTION("power_mul_coeff " + task_power_str) {
        int n = this->param.get_n();

        vector<vector<uint64_t>> x_mg(lane_cipher_size[1]);
        vector<vector<vector<uint64_t>>> x_max_power(lane_cipher_size[1]);
        for (int i = 0; i < lane_cipher_size[1]; i++) {
            x_mg[i] = rand_values(n, this->param.get_t());
            x_max_power[i].resize(max_power);
            for (int j = 1; j <= max_power; j++)
                x_max_power[i][j - 1] = vec_mod_exp(x_mg[i], j, this->param.get_t());
        }

        // Polynomial coefficients: p[i][j][k][l] is a length-n vector
        // l=0: constant term (BfvPlaintext), l>0: coefficient for x^l (BfvPlaintextRingt)
        vector<vector<vector<vector<vector<uint64_t>>>>> p(lane_cipher_size[0]);
        for (int i = 0; i < lane_cipher_size[0]; i++) {
            p[i].resize(lane_cipher_size[1]);
            for (int j = 0; j < lane_cipher_size[1]; j++) {
                p[i][j].resize(lane_cipher_size[2]);
                for (int k = 0; k < lane_cipher_size[2]; k++) {
                    p[i][j][k].resize(max_power + 1);
                    for (int l = 0; l <= max_power; l++)
                        p[i][j][k][l] = rand_values(n, this->param.get_t());
                }
            }
        }

        // z[i][j][k][l] = p[i][j][k][0][l] + sum_{m=1}^{max_power}(p[i][j][k][m][l] * x^m[l]) % t
        vector<vector<vector<vector<uint64_t>>>> z_expected(lane_cipher_size[0]);
        for (int i = 0; i < lane_cipher_size[0]; i++) {
            z_expected[i].resize(lane_cipher_size[1]);
            for (int j = 0; j < lane_cipher_size[1]; j++) {
                z_expected[i][j].resize(lane_cipher_size[2]);
                for (int k = 0; k < lane_cipher_size[2]; k++) {
                    z_expected[i][j][k].resize(n, 0);
                    for (int l = 0; l < n; l++) {
                        z_expected[i][j][k][l] = p[i][j][k][0][l];
                        for (int m = 1; m <= max_power; m++)
                            z_expected[i][j][k][l] =
                                (z_expected[i][j][k][l] + p[i][j][k][m][l] * x_max_power[j][m - 1][l]) %
                                this->param.get_t();
                    }
                }
            }
        }

        for (int level = 1; level <= 1; level++) {
            SECTION("level " + to_string(level)) {
                vector<vector<BfvCiphertext>> c_max_power_list(lane_cipher_size[1]);
                for (int i = 0; i < lane_cipher_size[1]; i++) {
                    c_max_power_list[i].resize(max_power);
                    for (int j = 0; j < max_power; j++) {
                        auto x_pt = this->ctx.encode(x_max_power[i][j], level);
                        c_max_power_list[i][j] = this->ctx.encrypt_asymmetric(x_pt);
                    }
                }

                vector<vector<vector<BfvPlaintext>>> p0_list(lane_cipher_size[0]);
                vector<vector<vector<vector<BfvPlaintextRingt>>>> p_list(lane_cipher_size[0]);
                for (int i = 0; i < lane_cipher_size[0]; i++) {
                    p0_list[i].resize(lane_cipher_size[1]);
                    p_list[i].resize(lane_cipher_size[1]);
                    for (int j = 0; j < lane_cipher_size[1]; j++) {
                        p0_list[i][j].resize(lane_cipher_size[2]);
                        p_list[i][j].resize(lane_cipher_size[2]);
                        for (int k = 0; k < lane_cipher_size[2]; k++) {
                            p_list[i][j][k].resize(max_power);
                            p0_list[i][j][k] = this->ctx.encode(p[i][j][k][0], level);
                            for (int l = 1; l <= max_power; l++)
                                p_list[i][j][k][l - 1] = this->ctx.encode_ringt(p[i][j][k][l]);
                        }
                    }
                }

                vector<vector<vector<BfvCiphertext>>> lane_list(lane_cipher_size[0]);
                for (int i = 0; i < lane_cipher_size[0]; i++) {
                    lane_list[i].resize(lane_cipher_size[1]);
                    for (int j = 0; j < lane_cipher_size[1]; j++) {
                        lane_list[i][j].resize(lane_cipher_size[2]);
                        for (int k = 0; k < lane_cipher_size[2]; k++)
                            lane_list[i][j][k] = this->ctx.new_ciphertext(0);
                    }
                }

                string path = fpga_base_path + "/" + this->tag + "/BFV_power_mul_coeff/" + task_power_str + "/" +
                              to_string(lane_cipher_size[0]) + "_" + to_string(lane_cipher_size[1]) + "_" +
                              to_string(lane_cipher_size[2]);
                FheTaskFpga proj(path);
                vector<CxxVectorArgument> args = {
                    CxxVectorArgument{"in_c_list", &c_max_power_list},
                    CxxVectorArgument{"in_p0_list", &p0_list},
                    CxxVectorArgument{"in_p_list", &p_list},
                    CxxVectorArgument{"out_z_list", &lane_list},
                };
                proj.run(&this->ctx, args);

                for (int i = 0; i < lane_cipher_size[0]; i++)
                    for (int j = 0; j < lane_cipher_size[1]; j++)
                        for (int k = 0; k < lane_cipher_size[2]; k++)
                            REQUIRE(decrypt_and_decode(this->ctx, lane_list[i][j][k]) == z_expected[i][j][k]);
            }
        }
    }
}

// TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV cmc_relin offline", "[.][offline]", BfvFpgaTestParams) {
//     for (int level = 1; level <= this->max_level; level++) {
//         SECTION("lv=" + to_string(level)) {
//             auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
//             auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
//             vector<BfvCiphertext> z_list;
//             z_list.reserve(this->n_op);
//             for (int _i = 0; _i < this->n_op; _i++)
//                 z_list.push_back(this->ctx.new_ciphertext(level));

//             string path = fpga_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
//                           "_cmc_relin_offline/level_" + to_string(level);

//             FheTaskFpga offline_proj(path, false);
//             vector<CxxVectorArgument> offline_args = {
//                 {"in_y_list", &yv.ciphertexts},
//             };
//             offline_proj.run(&this->ctx, offline_args);

//             FheTaskFpga online_proj(path, true);
//             vector<CxxVectorArgument> online_args = {
//                 {"in_x_list", &xv.ciphertexts},
//                 {"out_z_list", &z_list},
//             };
//             online_proj.run(&this->ctx, online_args);

//             vector<vector<uint64_t>> expected(this->n_op);
//             for (int i = 0; i < this->n_op; i++)
//                 expected[i] = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
//             REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
//         }
//     }
// }

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV custom_cmpac", "", BfvFpgaTestParams) {
    int n = this->param.get_n();

    // y_vals[0..6]: multiplied with x ciphertexts; y_vals[7]: added as constant term
    vector<vector<uint64_t>> y_vals(8);
    for (int i = 0; i < 8; i++)
        y_vals[i] = rand_values(n, this->param.get_t());

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(7, this->ctx, level, this->param.get_t());

            vector<CustomData> y_list;
            for (int i = 0; i < 8; i++)
                y_list.push_back(CustomData(y_vals[i]));
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));

            string path = fpga_base_path + "/" + this->tag + "/BFV_custom_cmpac/level_" + to_string(level);
            FheTaskFpga fpga_project(path);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["encode_ringt"] = [this](ExecutionContext& exec_ctx,
                                                      const std::unordered_map<NodeIndex, std::any>& inputs,
                                                      std::any& output, const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_idx = self.input_nodes[0]->index;
                auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(inputs.at(input_node_idx));
                auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<uint64_t>>();
                output = std::make_shared<BfvPlaintextRingt>(bfv_ctx->encode_ringt(*msg_vec));
            };
            custom_executors["encode"] = [this](ExecutionContext& exec_ctx,
                                                const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                                                const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                if (!self.custom_prop.has_value())
                    throw std::runtime_error("Custom property not found for encode operation");
                int encode_level = self.custom_prop->attributes["level"].get<int>();
                auto input_node_idx = self.input_nodes[0]->index;
                auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(inputs.at(input_node_idx));
                auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<uint64_t>>();
                output = std::make_shared<BfvPlaintext>(bfv_ctx->encode(*msg_vec, encode_level));
            };

            fpga_project.bind_custom_executors(custom_executors);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &xv.ciphertexts},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            fpga_project.run(&this->ctx, cxx_args);

            // z[k] = (sum_i(x[i][k] * y[i][k]) + y[7][k]) % t
            vector<uint64_t> expected(n, 0);
            for (int i = 0; i < 7; i++)
                expected = vec_mod_add(expected, vec_mod_mul(xv.values[i], y_vals[i], this->param.get_t()),
                                       this->param.get_t());
            expected = vec_mod_add(expected, y_vals[7], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list[0]) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV custom_compute_at_start", "", BfvFpgaTestParams) {
    int n = this->param.get_n();

    vector<vector<uint64_t>> y_vals(8);
    for (int i = 0; i < 8; i++)
        y_vals[i] = rand_values(n, this->param.get_t());

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(7, this->ctx, level, this->param.get_t());

            vector<CustomData> y_list;
            for (int i = 0; i < 8; i++)
                y_list.push_back(CustomData(y_vals[i]));
            vector<BfvCiphertext> z_list;
            z_list.push_back(this->ctx.new_ciphertext(level));

            string path = fpga_base_path + "/" + this->tag + "/BFV_custom_compute_at_start/level_" + to_string(level);
            FheTaskFpga fpga_project(path);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["encode_ringt"] = [this](ExecutionContext& exec_ctx,
                                                      const std::unordered_map<NodeIndex, std::any>& inputs,
                                                      std::any& output, const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_idx = self.input_nodes[0]->index;
                auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(inputs.at(input_node_idx));
                auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<uint64_t>>();
                output = std::make_shared<BfvPlaintextRingt>(bfv_ctx->encode_ringt(*msg_vec));
            };
            custom_executors["encode"] = [this](ExecutionContext& exec_ctx,
                                                const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                                                const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                if (!self.custom_prop.has_value())
                    throw std::runtime_error("Custom property not found for encode operation");
                int encode_level = self.custom_prop->attributes["level"].get<int>();
                auto input_node_idx = self.input_nodes[0]->index;
                auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(inputs.at(input_node_idx));
                auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<uint64_t>>();
                output = std::make_shared<BfvPlaintext>(bfv_ctx->encode(*msg_vec, encode_level));
            };

            fpga_project.bind_custom_executors(custom_executors);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &xv.ciphertexts},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            fpga_project.run(&this->ctx, cxx_args);

            // z[k] = (sum_i(x[i][k] * y[i][k]) + y[7][k]) % t
            vector<uint64_t> expected(n, 0);
            for (int i = 0; i < 7; i++)
                expected = vec_mod_add(expected, vec_mod_mul(xv.values[i], y_vals[i], this->param.get_t()),
                                       this->param.get_t());
            expected = vec_mod_add(expected, y_vals[7], this->param.get_t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list[0]) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV custom_compute_at_end", "", BfvFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));

            string path = fpga_base_path + "/" + this->tag + "/BFV_custom_compute_at_end/level_" + to_string(level);
            FheTaskFpga fpga_project(path);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["custom_add"] = [this](ExecutionContext& exec_ctx,
                                                    const std::unordered_map<NodeIndex, std::any>& inputs,
                                                    std::any& output, const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_idx = self.input_nodes[0]->index;
                auto input_ptr = std::any_cast<std::shared_ptr<BfvCiphertext>>(inputs.at(input_node_idx));
                output = std::make_shared<BfvCiphertext>(bfv_ctx->add(*input_ptr, *input_ptr));
            };
            fpga_project.bind_custom_executors(custom_executors);

            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &xv.ciphertexts},
                CxxVectorArgument{"in_y_list", &yv.ciphertexts},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            fpga_project.run(&this->ctx, cxx_args);

            // custom_add doubles the cmc result: z[i] = 2 * x[i] * y[i]
            vector<vector<uint64_t>> expected(this->n_op);
            for (int i = 0; i < this->n_op; i++) {
                auto prod = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
                expected[i] = vec_mod_add(prod, prod, this->param.get_t());
            }
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFpgaFixture, "BFV custom_compute_in_middle", "", BfvFpgaTestParams) {
    this->ctx.gen_rotation_keys();
    int step = -990;

    for (int level = 2; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));

            string path = fpga_base_path + "/" + this->tag + "/BFV_custom_compute_in_middle/level_" + to_string(level);
            FheTaskFpga fpga_project(path);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["custom_add"] = [this](ExecutionContext& exec_ctx,
                                                    const std::unordered_map<NodeIndex, std::any>& inputs,
                                                    std::any& output, const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_idx = self.input_nodes[0]->index;
                auto input_ptr = std::any_cast<std::shared_ptr<BfvCiphertext>>(inputs.at(input_node_idx));
                output = std::make_shared<BfvCiphertext>(bfv_ctx->add(*input_ptr, *input_ptr));
            };
            fpga_project.bind_custom_executors(custom_executors);

            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &xv.ciphertexts},
                CxxVectorArgument{"in_y_list", &yv.ciphertexts},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            fpga_project.run(&this->ctx, cxx_args);

            // For each i: doubled = 2*x[i]*y[i], then rotate_col by step, then sum
            int n = this->param.get_n();
            vector<uint64_t> expected(n, 0);
            for (int i = 0; i < this->n_op; i++) {
                auto prod = vec_mod_mul(xv.values[i], yv.values[i], this->param.get_t());
                auto doubled = vec_mod_add(prod, prod, this->param.get_t());
                expected = vec_mod_add(expected, vec_rotate_col(doubled, step), this->param.get_t());
            }
            REQUIRE(decrypt_and_decode(this->ctx, z_list[0]) == expected);
        }
    }
}

#endif  // LATTISENSE_ENABLE_FPGA

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
#include <dirent.h>
#include <math.h>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "fixture.hpp"
#include "cxx_fhe_task.h"
#include "utils.h"

#ifdef LATTISENSE_ENABLE_GPU

// ---------------------------------------------------------------------------
// Multi-param n_op parallel tests
// Each test type iterates over all valid levels.
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cap", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cap/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cap_ringt", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_ringt(this->n_op, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cap_ringt/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cac", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cac/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV casc", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_casc/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV csp", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_csp/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV csp_ringt", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_ringt(this->n_op, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_csp_ringt/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV csc", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_csc/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cssc", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cssc/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            vector<vector<uint64_t>> expected(this->n_op, vector<uint64_t>(xv.values[0].size(), 0));
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cneg", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path =
                gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cneg/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cmp_ringt", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_pt_ringt(this->n_op, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmp_ringt/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cmc", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext3> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext3(level));
            string path =
                gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmc/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cmc_relin", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_cmc_relin/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cmc_relin_rescale", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_cmc_relin_rescale/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV csqr", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext3> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext3(level));
            string path =
                gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_csqr/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV csqr_relin", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_csqr_relin/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV csqr_relin_rescale", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_csqr_relin_rescale/level_" + to_string(level);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV rescale", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> y_list;
            y_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                y_list.push_back(this->ctx.new_ciphertext(level - 1));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_rescale/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_y_list", &y_list},
            };
            proj.run(&this->ctx, args);
            REQUIRE(decrypt_and_decode(this->ctx, y_list) == xv.values);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV rotate_col", "", BfvTestDefaultParams, BfvTestCustomParams) {
    vector<int32_t> steps;
    for (int i = 1; i <= 8; i++)
        steps.push_back(i);
    string steps_str = "steps_" + to_string(steps.front()) + "_to_" + to_string(steps.back());

    this->ctx.gen_rotation_keys();

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<vector<BfvCiphertext>> y_list(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    y_list[i].push_back(this->ctx.new_ciphertext(level));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_rotate_col/level_" +
                          to_string(level) + "/" + steps_str;
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV advanced_rotate_col", "", BfvTestDefaultParams, BfvTestCustomParams) {
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
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) +
                          "_advanced_rotate_col/level_" + to_string(level) + "/steps_" + steps_str;
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV rotate_row", "", BfvTestDefaultParams, BfvTestCustomParams) {
    this->ctx.gen_rotation_keys();

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> y_list;
            y_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                y_list.push_back(this->ctx.new_ciphertext(level));
            string path = gpu_base_path + "/" + this->tag + "/BFV_" + to_string(this->n_op) + "_rotate_row/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
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

// ---------------------------------------------------------------------------
// Special tests: complex DAGs, fixed level, default param only
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV ctc_ctc_0", "", BfvTestDefaultParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(this->n_op, this->ctx, 3, this->param.get_t());
        auto yv = new_bfv_test_ct(this->n_op, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(5);
        for (int _i = 0; _i < 5; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskGpu proj(gpu_base_path + "/" + this->tag + "/BFV_ctc_ctc_0/level_3");
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV ctc_ctc_1", "", BfvTestDefaultParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(this->n_op, this->ctx, 3, this->param.get_t());
        auto yv = new_bfv_test_ct(this->n_op, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(4);
        for (int _i = 0; _i < 4; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskGpu proj(gpu_base_path + "/" + this->tag + "/BFV_ctc_ctc_1/level_3");
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV 1_square_square", "", BfvTestDefaultParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(1, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(1);
        for (int _i = 0; _i < 1; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskGpu proj(gpu_base_path + "/" + this->tag + "/BFV_1_square_square/level_3");
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV 1_ctc_rotate_cac", "", BfvTestDefaultParams) {
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

        FheTaskGpu proj(gpu_base_path + "/" + this->tag + "/BFV_1_ctc_rotate_cac/level_3");
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV double", "", BfvTestDefaultParams) {
    SECTION("lv=1") {
        auto xv = new_bfv_test_ct(3, this->ctx, 1, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(2);
        for (int _i = 0; _i < 2; _i++)
            z_list.push_back(this->ctx.new_ciphertext(1));

        FheTaskGpu proj(gpu_base_path + "/" + this->tag + "/BFV_1_double");
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV braid", "", BfvTestDefaultParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(4, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(4);
        for (int _i = 0; _i < 4; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskGpu proj(gpu_base_path + "/" + this->tag + "/BFV_braid");
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV poly", "", BfvTestDefaultParams) {
    if (this->max_level < 3)
        return;

    SECTION("lv=3") {
        auto xv = new_bfv_test_ct(4, this->ctx, 3, this->param.get_t());
        auto av = new_bfv_test_ct(3, this->ctx, 3, this->param.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(4);
        for (int _i = 0; _i < 4; _i++)
            z_list.push_back(this->ctx.new_ciphertext(3));

        FheTaskGpu proj(gpu_base_path + "/" + this->tag + "/BFV_n_poly/level_3");
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV ct_pt_ringt_mac", "", BfvTestDefaultParams) {
    for (int m = 44; m <= 50; m++) {
        SECTION("m=" + to_string(m) + "/lv=1") {
            auto cv = new_bfv_test_ct(m, this->ctx, 1, this->param.get_t());
            auto pv = new_bfv_test_pt_ringt(m, this->ctx, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(1));

            string path = gpu_base_path + "/" + this->tag + "/BFV_cmpac/level_1_m_" + to_string(m);
            FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV power_dag", "[.]", BfvTestDefaultParams) {
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

        // x^p for each source power — input ciphertexts
        vector<vector<uint64_t>> x_source_power(source_power.size());
        for (int j = 0; j < (int)source_power.size(); j++)
            x_source_power[j] = vec_mod_exp(x_mg, source_power[j], this->param.get_t());

        // x^1 .. x^max_power — expected outputs
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

                string path = gpu_base_path + "/" + this->tag + "/BFV_power_dag/" + task_power_str;
                FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV power_mul_coeff", "[.]", BfvTestDefaultParams) {
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

                string path = gpu_base_path + "/" + this->tag + "/BFV_power_mul_coeff/" + task_power_str + "/" +
                              to_string(lane_cipher_size[0]) + "_" + to_string(lane_cipher_size[1]) + "_" +
                              to_string(lane_cipher_size[2]);
                FheTaskGpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV power_dag_and_power_mul_coeff", "[.]", BfvTestDefaultParams) {
    for (int power_dag_idx = 0; power_dag_idx < 1; power_dag_idx++) {
        vector<int> source_power{1, 7, 18, 62, 104, 244, 259};
        int max_power = 1137;

        vector<int> lane_cipher_size{2, 1, 5};

        string source_power_str = "";
        for (int j = 0; j < (int)source_power.size(); j++) {
            source_power_str += to_string(source_power[j]);
            if (j != (int)source_power.size() - 1) {
                source_power_str += "-";
            }
        }
        string task_power_str = "PD-" + to_string(max_power) + "#" + source_power_str;

        SECTION("power_dag_and_power_mul_coeff " + task_power_str) {
            int n = this->param.get_n();

            vector<vector<BfvCiphertext>> c_source_power_list(lane_cipher_size[1]);
            vector<vector<vector<BfvPlaintext>>> p0_list(lane_cipher_size[0]);
            vector<vector<vector<vector<BfvPlaintextRingt>>>> p_list(lane_cipher_size[0]);

            vector<vector<vector<BfvCiphertext>>> lane_list(lane_cipher_size[0]);

            vector<vector<vector<uint64_t>>> x_source_power(lane_cipher_size[1]);
            vector<vector<vector<uint64_t>>> x_max_power(lane_cipher_size[1]);
            vector<vector<vector<vector<vector<uint64_t>>>>> p(lane_cipher_size[0]);

            vector<vector<uint64_t>> x_mg(lane_cipher_size[1]);
            for (int i = 0; i < lane_cipher_size[1]; i++) {
                x_mg[i] = rand_values(n, this->param.get_t());

                x_source_power[i].resize(source_power.size());
                for (int j = 0; j < (int)source_power.size(); j++)
                    x_source_power[i][j] = vec_mod_exp(x_mg[i], source_power[j], this->param.get_t());

                x_max_power[i].resize(max_power);
                for (int j = 1; j <= max_power; j++)
                    x_max_power[i][j - 1] = vec_mod_exp(x_mg[i], j, this->param.get_t());
            }

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

            for (int level = 5; level <= 5; level++) {
                SECTION("level " + to_string(level)) {
                    for (int i = 0; i < lane_cipher_size[1]; i++) {
                        c_source_power_list[i].resize(source_power.size());
                        for (int j = 0; j < (int)source_power.size(); j++) {
                            auto x_pt = this->ctx.encode(x_source_power[i][j], level);
                            c_source_power_list[i][j] = this->ctx.encrypt_asymmetric(x_pt);
                        }
                    }

                    for (int i = 0; i < lane_cipher_size[0]; i++) {
                        p0_list[i].resize(lane_cipher_size[1]);
                        p_list[i].resize(lane_cipher_size[1]);
                        for (int j = 0; j < lane_cipher_size[1]; j++) {
                            p0_list[i][j].resize(lane_cipher_size[2]);
                            p_list[i][j].resize(lane_cipher_size[2]);
                            for (int k = 0; k < lane_cipher_size[2]; k++) {
                                p_list[i][j][k].resize(max_power);
                                p0_list[i][j][k] = this->ctx.encode(p[i][j][k][0], 1);
                                for (int l = 1; l <= max_power; l++)
                                    p_list[i][j][k][l - 1] = this->ctx.encode_ringt(p[i][j][k][l]);
                            }
                        }
                    }

                    for (int i = 0; i < lane_cipher_size[0]; i++) {
                        lane_list[i].resize(lane_cipher_size[1]);
                        for (int j = 0; j < lane_cipher_size[1]; j++) {
                            lane_list[i][j].resize(lane_cipher_size[2]);
                            for (int k = 0; k < lane_cipher_size[2]; k++)
                                lane_list[i][j][k] = this->ctx.new_ciphertext(0);
                        }
                    }

                    string path = gpu_base_path + "/" + this->tag + "/BFV_power_dag_and_power_mul_coeff/" +
                                  task_power_str + "/" + to_string(lane_cipher_size[0]) + "_" +
                                  to_string(lane_cipher_size[1]) + "_" + to_string(lane_cipher_size[2]);
                    FheTaskGpu proj(path);
                    vector<CxxVectorArgument> args = {
                        CxxVectorArgument{"in_x_list", &c_source_power_list},
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
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV custom_cmpac", "", BfvTestDefaultParams) {
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

            string path = gpu_base_path + "/" + this->tag + "/BFV_custom_cmpac/level_" + to_string(level);
            FheTaskGpu gpu_project(path);

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

            gpu_project.bind_custom_executors(custom_executors);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &xv.ciphertexts},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&this->ctx, cxx_args);

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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV custom_compute_at_start", "", BfvTestDefaultParams) {
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

            string path = gpu_base_path + "/" + this->tag + "/BFV_custom_compute_at_start/level_" + to_string(level);
            FheTaskGpu gpu_project(path);

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

            gpu_project.bind_custom_executors(custom_executors);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &xv.ciphertexts},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&this->ctx, cxx_args);

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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV custom_compute_at_end", "", BfvTestDefaultParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));

            string path = gpu_base_path + "/" + this->tag + "/BFV_custom_compute_at_end/level_" + to_string(level);
            FheTaskGpu project(path);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["custom_add"] = [this](ExecutionContext& exec_ctx,
                                                    const std::unordered_map<NodeIndex, std::any>& inputs,
                                                    std::any& output, const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_idx = self.input_nodes[0]->index;
                auto input_ptr = std::any_cast<std::shared_ptr<BfvCiphertext>>(inputs.at(input_node_idx));
                output = std::make_shared<BfvCiphertext>(bfv_ctx->add(*input_ptr, *input_ptr));
            };
            project.bind_custom_executors(custom_executors);

            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &xv.ciphertexts},
                CxxVectorArgument{"in_y_list", &yv.ciphertexts},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            project.run(&this->ctx, cxx_args);

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

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV custom_compute_in_middle", "", BfvTestDefaultParams) {
    this->ctx.gen_rotation_keys();
    int step = -990;

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            auto yv = new_bfv_test_ct(this->n_op, this->ctx, level, this->param.get_t());
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level));

            string path = gpu_base_path + "/" + this->tag + "/BFV_custom_compute_in_middle/level_" + to_string(level);
            FheTaskGpu project(path);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["custom_add"] = [this](ExecutionContext& exec_ctx,
                                                    const std::unordered_map<NodeIndex, std::any>& inputs,
                                                    std::any& output, const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_idx = self.input_nodes[0]->index;
                auto input_ptr = std::any_cast<std::shared_ptr<BfvCiphertext>>(inputs.at(input_node_idx));
                output = std::make_shared<BfvCiphertext>(bfv_ctx->add(*input_ptr, *input_ptr));
            };
            project.bind_custom_executors(custom_executors);

            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &xv.ciphertexts},
                CxxVectorArgument{"in_y_list", &yv.ciphertexts},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            project.run(&this->ctx, cxx_args);

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

#endif  // LATTISENSE_ENABLE_GPU

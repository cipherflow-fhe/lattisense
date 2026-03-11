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
#include <cmath>
#include <random>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "fixture.hpp"
#include "cxx_fhe_task.h"
#include "precision.h"
#include "utils.h"

using namespace fhe_ops_lib;

#ifdef LATTISENSE_ENABLE_GPU

// ---------------------------------------------------------------------------
// Precision helper — same as test_cpu_ckks.cpp
// ---------------------------------------------------------------------------

static void verify_ckks_precision(CkksContext& ctx,
                                  const vector<double>& expected,
                                  const CkksCiphertext& ct,
                                  double minPrec = 10.0) {
    auto stats = PrecisionAnalyzer::GetPrecisionStats(ctx, expected, ct);
    REQUIRE(stats.MeanPrecision.Real >= minPrec);
}

// ---------------------------------------------------------------------------
// Multi-param parallel tests
// Each test type iterates over all valid levels.
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cap", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cap/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_add(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cap_ringt", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt_ringt(this->n_op, this->ctx, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cap_ringt/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_add(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cac", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cac/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_add(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS casc", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_casc/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_add(xv.values[i], xv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS csp", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csp/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_sub(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS csp_ringt", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt_ringt(this->n_op, this->ctx, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csp_ringt/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_sub(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS csc", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csc/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_sub(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cneg", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cneg/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_neg(xv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmp_ringt", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt_ringt(this->n_op, this->ctx, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp_ringt/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_mul(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmp", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_mul(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmc", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext3> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext3(level, this->default_scale * this->default_scale));
            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmc/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++) {
                auto expected = vec_mul(xv.values[i], yv.values[i]);
                verify_ckks_precision(this->ctx, expected, this->ctx.relinearize(z_list[i]));
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmc_relin", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmc_relin/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_mul(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmc_relin_rescale", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 2; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            double out_scale = this->default_scale * this->default_scale / this->param.get_q(level);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1, out_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_cmc_relin_rescale/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_mul(xv.values[i], yv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS csqr", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext3> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext3(level, this->default_scale * this->default_scale));
            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csqr/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++) {
                auto expected = vec_mul(xv.values[i], xv.values[i]);
                verify_ckks_precision(this->ctx, expected, this->ctx.relinearize(z_list[i]));
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS csqr_relin", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csqr_relin/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_mul(xv.values[i], xv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS csqr_relin_rescale", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 2; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            double out_scale = this->default_scale * this->default_scale / this->param.get_q(level);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1, out_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_csqr_relin_rescale/level_" + to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_mul(xv.values[i], xv.values[i]), z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS rescale", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale * this->param.get_q(level));
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1, this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_rescale/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_y_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, xv.values[i], z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS drop_level", "", CkksTestDefaultParams, CkksTestCustomParams) {
    int drop_level = 2;
    for (int level = 2; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - drop_level, this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_drop_level/level_" +
                          to_string(level) + "/drop_" + to_string(drop_level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_y_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, xv.values[i], z_list[i]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS rotate_col", "", CkksTestDefaultParams, CkksTestCustomParams) {
    vector<int32_t> steps;
    for (int i = 1; i <= 8; i++)
        steps.push_back(i);
    string steps_str = "steps_1_to_8";

    this->ctx.gen_rotation_keys();

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<vector<CkksCiphertext>> y_list(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    y_list[i].push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_rotate_col/level_" +
                          to_string(level) + "/" + steps_str;
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    verify_ckks_precision(this->ctx, vec_rotate(xv.values[i], steps[j]), y_list[i][j]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS advanced_rotate_col", "", CkksTestDefaultParams, CkksTestCustomParams) {
    vector<int32_t> steps = {-500, 20, 200, 2000, 4000};
    string steps_str;
    for (int i = 0; i < (int)steps.size(); i++) {
        if (i > 0)
            steps_str += "_";
        steps_str += to_string(steps[i]);
    }

    this->ctx.gen_rotation_keys_for_rotations(steps);

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<vector<CkksCiphertext>> y_list(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    y_list[i].push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_advanced_rotate_col/level_" + to_string(level) + "/steps_" + steps_str;
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    verify_ckks_precision(this->ctx, vec_rotate(xv.values[i], steps[j]), y_list[i][j]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS rotate_row", "", CkksTestDefaultParams, CkksTestCustomParams) {
    this->ctx.gen_rotation_keys_for_rotations(vector<int32_t>{}, true);

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> y_list;
            y_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                y_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_rotate_row/level_" +
                          to_string(level);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++)
                // rotate_row: CKKS uses conjugation — for real-valued inputs values stay the same
                verify_ckks_precision(this->ctx, xv.values[i], y_list[i]);
        }
    }
}

// ---------------------------------------------------------------------------
// MAC tests — default param only
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS ct_pt_mac", "", CkksTestDefaultParams) {
    int level = 5;
    if (this->max_level < level)
        return;

    for (int m = 2; m <= 20; m++) {
        SECTION("m=" + to_string(m) + "/lv=" + to_string(level)) {
            auto cv = new_ckks_test_ct(m, this->ctx, level, this->default_scale);
            auto pv = new_ckks_test_pt(m, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));

            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_cmpac/level_" + to_string(level) + "_m_" + to_string(m);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_c_list", &cv.ciphertexts},
                {"in_p_list", &pv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);

            vector<double> expected(this->n_slot, 0.0);
            for (int i = 0; i < m; i++)
                expected = vec_add(expected, vec_mul(cv.values[i], pv.values[i]));
            verify_ckks_precision(this->ctx, expected, z_list[0]);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS ct_pt_ringt_mac", "", CkksTestDefaultParams) {
    int level = 5;
    if (this->max_level < level)
        return;

    for (int m = 2; m <= 20; m++) {
        SECTION("m=" + to_string(m) + "/lv=" + to_string(level)) {
            auto cv = new_ckks_test_ct(m, this->ctx, level, this->default_scale);
            auto pv = new_ckks_test_pt_ringt(m, this->ctx, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));

            string path =
                gpu_base_path + "/" + this->tag + "/CKKS_cmpac_ringt/level_" + to_string(level) + "_m_" + to_string(m);
            FheTaskGpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_c_list", &cv.ciphertexts},
                {"in_p_list", &pv.plaintexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);

            vector<double> expected(this->n_slot, 0.0);
            for (int i = 0; i < m; i++)
                expected = vec_add(expected, vec_mul(cv.values[i], pv.values[i]));
            verify_ckks_precision(this->ctx, expected, z_list[0]);
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap tests — use CkksBtpFixture
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(CkksBtpFixture, "CKKS toy_bootstrap", "", CkksToyBtpParams) {
    SECTION("lv=0") {
        auto xv = new_ckks_test_ct(this->n_op, this->btp_ctx, 0, this->btp_scale);
        vector<CkksCiphertext> y_list;
        y_list.reserve(this->n_op);
        for (int _i = 0; _i < this->n_op; _i++)
            y_list.push_back(this->btp_ctx.new_ciphertext(9, this->btp_scale));
        string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_toy_bootstrap/level_0";
        FheTaskGpu proj(path);
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"out_y_list", &y_list},
        };
        proj.run(&this->btp_ctx, args);

        for (int i = 0; i < this->n_op; i++)
            verify_ckks_precision(this->btp_ctx, xv.values[i], y_list[i]);
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksBtpFixture, "CKKS bootstrap", "", CkksBtpParams) {
    SECTION("lv=0") {
        auto xv = new_ckks_test_ct(this->n_op, this->btp_ctx, 0, this->btp_scale);
        vector<CkksCiphertext> y_list;
        y_list.reserve(this->n_op);
        for (int _i = 0; _i < this->n_op; _i++)
            y_list.push_back(this->btp_ctx.new_ciphertext(9, this->btp_scale));
        string path = gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_bootstrap/level_0";
        FheTaskGpu proj(path);
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"out_y_list", &y_list},
        };
        proj.run(&this->btp_ctx, args);

        for (int i = 0; i < this->n_op; i++)
            verify_ckks_precision(this->btp_ctx, xv.values[i], y_list[i]);
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksBtpFixture, "CKKS cmc_relin_rescale_bootstrap", "", CkksBtpParams) {
    auto& ckks_param = this->btp_param.get_ckks_parameter();

    SECTION("lv=3") {
        int level = 3;
        auto xv = new_ckks_test_ct(this->n_op, this->btp_ctx, level, this->btp_scale);
        auto yv = new_ckks_test_ct(this->n_op, this->btp_ctx, level, this->btp_scale);
        double out_scale = this->btp_scale * this->btp_scale / ckks_param.get_q(level);
        vector<CkksCiphertext> z_list;
        z_list.reserve(this->n_op);
        for (int _i = 0; _i < this->n_op; _i++)
            z_list.push_back(this->btp_ctx.new_ciphertext(9, out_scale));
        string path =
            gpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmc_relin_rescale_bootstrap/level_3";
        FheTaskGpu proj(path);
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"in_y_list", &yv.ciphertexts},
            {"out_z_list", &z_list},
        };
        proj.run(&this->btp_ctx, args);

        for (int i = 0; i < this->n_op; i++)
            verify_ckks_precision(this->btp_ctx, vec_mul(xv.values[i], yv.values[i]), z_list[i]);
    }
}

#endif  // LATTISENSE_ENABLE_GPU

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

// ---------------------------------------------------------------------------
// Precision helper — mirrors Go's verifyTestCkksVectors:
//   require.GreaterOrEqual(precStats.MeanPrecision.Real, tc.minPrec)
// minPrec = 10.0 bits
// ---------------------------------------------------------------------------

static void verify_ckks_precision(CkksContext& ctx,
                                  const vector<double>& expected,
                                  const CkksCiphertext& ct,
                                  double minPrec = 10.0) {
    auto stats = PrecisionAnalyzer::GetPrecisionStats(ctx, expected, ct);
    REQUIRE(stats.MeanPrecision.Real >= minPrec);
}

// ---------------------------------------------------------------------------
// Multi-param tests (default n=16384 and custom n=8192)
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
                cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cap/level_" + to_string(level);
            FheTaskCpu proj(path);
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cap_ringt/level_" +
                          to_string(level);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cac/level_" + to_string(level);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_casc/level_" + to_string(level);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csp/level_" + to_string(level);
            FheTaskCpu proj(path);
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csp_ringt/level_" +
                          to_string(level);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csc/level_" + to_string(level);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cneg/level_" + to_string(level);
            FheTaskCpu proj(path);
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp_ringt/level_" +
                          to_string(level);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp/level_" + to_string(level);
            FheTaskCpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmp_mul", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt_mul(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp_mul/level_" +
                          to_string(level);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmc/level_" + to_string(level);
            FheTaskCpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &yv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_mul(xv.values[i], yv.values[i]), this->ctx.relinearize(z_list[i]));
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmc_relin/level_" +
                          to_string(level);
            FheTaskCpu proj(path);
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
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            double out_scale = this->default_scale * this->default_scale / this->param.get_q(level);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1, out_scale));
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_cmc_relin_rescale/level_" + to_string(level);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csqr/level_" + to_string(level);
            FheTaskCpu proj(path);
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);
            for (int i = 0; i < this->n_op; i++)
                verify_ckks_precision(this->ctx, vec_mul(xv.values[i], xv.values[i]), this->ctx.relinearize(z_list[i]));
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csqr_relin/level_" +
                          to_string(level);
            FheTaskCpu proj(path);
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
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            double out_scale = this->default_scale * this->default_scale / this->param.get_q(level);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1, out_scale));
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_csqr_relin_rescale/level_" + to_string(level);
            FheTaskCpu proj(path);
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_rescale/level_" +
                          to_string(level);
            FheTaskCpu proj(path);
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_drop_level/level_" +
                          to_string(level) + "/drop_" + to_string(drop_level);
            FheTaskCpu proj(path);
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_rotate_col/level_" +
                          to_string(level) + "/" + steps_str;
            FheTaskCpu proj(path);
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_advanced_rotate_col/level_" + to_string(level) + "/steps_" + steps_str;
            FheTaskCpu proj(path);
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
            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_rotate_row/level_" +
                          to_string(level);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_cmpac/level_" + to_string(level) + "_m_" + to_string(m);
            FheTaskCpu proj(path);
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
                cpu_base_path + "/" + this->tag + "/CKKS_cmpac_ringt/level_" + to_string(level) + "_m_" + to_string(m);
            FheTaskCpu proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS n_poly", "[.]", CkksTestDefaultParams) {
    if (this->max_level < 4)
        return;

    SECTION("lv=4") {
        auto xv = new_ckks_test_ct(1, this->ctx, 4, this->default_scale);
        auto coeff0v = new_ckks_test_pt(1, this->ctx, 2, this->default_scale);
        auto coeffsv = new_ckks_test_pt_ringt(3, this->ctx, this->default_scale);
        vector<CkksCiphertext> y_list;
        y_list.push_back(this->ctx.new_ciphertext(2, this->default_scale * this->default_scale));

        string path = cpu_base_path + "/" + this->tag + "/CKKS_n_poly/level_4";
        FheTaskCpu proj(path);
        vector<CxxVectorArgument> args = {
            {"x", &xv.ciphertexts},
            {"coeff0", &coeff0v.plaintexts},
            {"coeffs", &coeffsv.plaintexts},
            {"y", &y_list},
        };
        proj.run(&this->ctx, args);

        // y_true[s] = coeff0[s] + x[s]*c0[s] + x[s]^2*c1[s] + x[s]^3*c2[s]
        vector<double> y_true = coeff0v.values[0];
        for (int j = 0; j < 3; j++)
            y_true = vec_add(y_true, vec_mul(vec_exp(xv.values[0], j + 1), coeffsv.values[j]));
        verify_ckks_precision(this->ctx, y_true, y_list[0]);
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS custom encode and cap", "", CkksTestDefaultParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);

            vector<vector<double>> y_vals;
            vector<CustomData> y_list;
            for (int i = 0; i < this->n_op; i++) {
                y_vals.push_back(rand_double_values(this->n_slot));
                y_list.push_back(CustomData(y_vals[i]));
            }
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));

            string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_custom_encode_and_cap/level_" + to_string(level);
            FheTaskCpu proj(path);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["encode"] = [this](ExecutionContext& exec_ctx,
                                                const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                                                const ComputeNode& self) -> void {
                auto* ckks_ctx = exec_ctx.get_arithmetic_context<CkksContext>();
                if (!self.custom_prop.has_value())
                    throw std::runtime_error("Custom property not found for encode operation");
                int encode_level = self.custom_prop->attributes["level"].get<int>();
                double encode_scale = self.custom_prop->attributes["scale"].get<double>();
                auto input_node_idx = self.input_nodes[0]->index;
                auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(inputs.at(input_node_idx));
                auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<double>>();
                output = std::make_shared<CkksPlaintext>(ckks_ctx->encode(*msg_vec, encode_level, encode_scale));
            };
            proj.bind_custom_executors(custom_executors);

            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts},
                {"in_y_list", &y_list},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++) {
                vector<double> z_true = vec_add(xv.values[i], y_vals[i]);
                verify_ckks_precision(this->ctx, z_true, z_list[i]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap tests — default param only; use CkksBtpContext
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(CkksBtpFixture, "CKKS toy_bootstrap", "", CkksToyBtpParams) {
    SECTION("lv=0") {
        auto xv = new_ckks_test_ct(this->n_op, this->btp_ctx, 0, this->btp_scale);
        vector<CkksCiphertext> y_list;
        y_list.reserve(this->n_op);
        for (int _i = 0; _i < this->n_op; _i++)
            y_list.push_back(this->btp_ctx.new_ciphertext(9, this->btp_scale));
        string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_toy_bootstrap/level_0";
        FheTaskCpu proj(path);
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"out_y_list", &y_list},
        };
        proj.run(&this->btp_ctx, args);

        for (int i = 0; i < this->n_op; i++)
            verify_ckks_precision(this->btp_ctx, xv.values[i], y_list[i]);
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksBtpFixture, "CKKS bootstrap", "[.]", CkksBtpParams) {
    SECTION("lv=0") {
        auto xv = new_ckks_test_ct(this->n_op, this->btp_ctx, 0, this->btp_scale);
        vector<CkksCiphertext> y_list;
        y_list.reserve(this->n_op);
        for (int _i = 0; _i < this->n_op; _i++)
            y_list.push_back(this->btp_ctx.new_ciphertext(9, this->btp_scale));
        string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_bootstrap/level_0";
        FheTaskCpu proj(path);
        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"out_y_list", &y_list},
        };
        proj.run(&this->btp_ctx, args);

        for (int i = 0; i < this->n_op; i++)
            verify_ckks_precision(this->btp_ctx, xv.values[i], y_list[i]);
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksBtpFixture, "CKKS cmc_relin_rescale_bootstrap", "[.]", CkksBtpParams) {
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
            cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmc_relin_rescale_bootstrap/level_3";
        FheTaskCpu proj(path);
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

// Sparse bootstrap CPU end-to-end: emitted mega_ag.json carries log_slots,
// cpu_task_utils.h init_empty_context must route to create_toy_sparse_parameter,
// and the decoded first 2^log_slots slots must match the encoded input.
TEMPLATE_TEST_CASE_METHOD(CkksBtpFixture,
                          "CKKS toy_sparse_bootstrap",
                          "",
                          CkksToySparseBtpParamsLs8,
                          CkksToySparseBtpParamsLs4) {
    SECTION("lv=0") {
        const int32_t log_slots = TestType::log_slots;
        const size_t sparse_slots = size_t(1) << log_slots;

        vector<vector<double>> sparse_values(this->n_op);
        vector<CkksCiphertext> x_list;
        x_list.reserve(this->n_op);
        for (int i = 0; i < this->n_op; i++) {
            sparse_values[i] = rand_double_values(sparse_slots);
            auto pt = this->btp_ctx.encode(sparse_values[i], 0, this->btp_scale);
            x_list.push_back(this->btp_ctx.encrypt_asymmetric(pt));
        }
        vector<CkksCiphertext> y_list;
        y_list.reserve(this->n_op);
        for (int _i = 0; _i < this->n_op; _i++)
            y_list.push_back(this->btp_ctx.new_ciphertext(9, this->btp_scale));

        string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_toy_sparse_bootstrap_ls" +
                      to_string(log_slots) + "/level_0";
        FheTaskCpu proj(path);
        vector<CxxVectorArgument> args = {
            {"in_x_list", &x_list},
            {"out_y_list", &y_list},
        };
        proj.run(&this->btp_ctx, args);

        for (int i = 0; i < this->n_op; i++) {
            auto decoded = this->btp_ctx.decode(this->btp_ctx.decrypt(y_list[i]));
            vector<double> decoded_sparse(decoded.begin(), decoded.begin() + sparse_slots);
            auto stats = PrecisionAnalyzer::GetPrecisionStats(sparse_values[i], decoded_sparse);
            REQUIRE(stats.MeanPrecision.Real >= 10.0);
        }
    }
}

// Double sparse bootstrap: bootstrap -> drop_level -> bootstrap. Hidden by
// default (uses `[.]` tag) because the second sparse bootstrap currently
// produces garbage (~-3 bits mean precision). This documents a real
// composability gap: sparse bootstrap's level-9 output is not a valid input
// to another sparse bootstrap after a naive drop_level reduction. Users
// chaining sparse bootstraps must interleave a non-trivial op (mult_relin +
// rescale) between them. Run this test explicitly to check if a future
// change fixes composability.
TEMPLATE_TEST_CASE_METHOD(CkksBtpFixture,
                          "CKKS toy_sparse_double_bootstrap_ls8",
                          "[.sparse][.bootstrap][.composability]",
                          CkksToySparseBtpParamsLs8) {
    SECTION("lv=0") {
        const int32_t log_slots = TestType::log_slots;
        const size_t sparse_slots = size_t(1) << log_slots;

        vector<vector<double>> sparse_values(this->n_op);
        vector<CkksCiphertext> x_list;
        x_list.reserve(this->n_op);
        for (int i = 0; i < this->n_op; i++) {
            sparse_values[i] = rand_double_values(sparse_slots);
            auto pt = this->btp_ctx.encode(sparse_values[i], 0, this->btp_scale);
            x_list.push_back(this->btp_ctx.encrypt_asymmetric(pt));
        }
        vector<CkksCiphertext> y_list;
        y_list.reserve(this->n_op);
        for (int _i = 0; _i < this->n_op; _i++)
            y_list.push_back(this->btp_ctx.new_ciphertext(9, this->btp_scale));

        string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                      "_toy_sparse_double_bootstrap_ls8/level_0";
        FheTaskCpu proj(path);
        vector<CxxVectorArgument> args = {
            {"in_x_list", &x_list},
            {"out_y_list", &y_list},
        };
        proj.run(&this->btp_ctx, args);

        for (int i = 0; i < this->n_op; i++) {
            auto decoded = this->btp_ctx.decode(this->btp_ctx.decrypt(y_list[i]));
            vector<double> decoded_sparse(decoded.begin(), decoded.begin() + sparse_slots);
            auto stats = PrecisionAnalyzer::GetPrecisionStats(sparse_values[i], decoded_sparse);
            // Aspirational bound: passes only if composability is fixed.
            REQUIRE(stats.MeanPrecision.Real >= 8.0);
        }
    }
}

// Non-trivial sparse graph: mult_relin → rescale → drop_level → bootstrap.
// Catches regressions where upstream operators (rescale, drop_level) don't
// preserve the sparse packing invariant before bootstrap reads it.
TEMPLATE_TEST_CASE_METHOD(CkksBtpFixture,
                          "CKKS toy_sparse_cmc_relin_rescale_bootstrap_ls8",
                          "",
                          CkksToySparseBtpParamsLs8) {
    auto& ckks_param = this->btp_param.get_ckks_parameter();

    SECTION("lv=3") {
        const int level = 3;
        const int32_t log_slots = TestType::log_slots;
        const size_t sparse_slots = size_t(1) << log_slots;

        vector<vector<double>> x_values(this->n_op);
        vector<vector<double>> y_values(this->n_op);
        vector<CkksCiphertext> x_list;
        vector<CkksCiphertext> y_list;
        x_list.reserve(this->n_op);
        y_list.reserve(this->n_op);
        for (int i = 0; i < this->n_op; i++) {
            x_values[i] = rand_double_values(sparse_slots);
            y_values[i] = rand_double_values(sparse_slots);
            x_list.push_back(
                this->btp_ctx.encrypt_asymmetric(this->btp_ctx.encode(x_values[i], level, this->btp_scale)));
            y_list.push_back(
                this->btp_ctx.encrypt_asymmetric(this->btp_ctx.encode(y_values[i], level, this->btp_scale)));
        }
        double out_scale = this->btp_scale * this->btp_scale / ckks_param.get_q(level);
        vector<CkksCiphertext> z_list;
        z_list.reserve(this->n_op);
        for (int _i = 0; _i < this->n_op; _i++)
            z_list.push_back(this->btp_ctx.new_ciphertext(9, out_scale));

        string path = cpu_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                      "_toy_sparse_cmc_relin_rescale_bootstrap_ls8/level_3";
        FheTaskCpu proj(path);
        vector<CxxVectorArgument> args = {
            {"in_x_list", &x_list},
            {"in_y_list", &y_list},
            {"out_z_list", &z_list},
        };
        proj.run(&this->btp_ctx, args);

        for (int i = 0; i < this->n_op; i++) {
            auto decoded = this->btp_ctx.decode(this->btp_ctx.decrypt(z_list[i]));
            vector<double> decoded_sparse(decoded.begin(), decoded.begin() + sparse_slots);
            vector<double> expected = vec_mul(x_values[i], y_values[i]);
            auto stats = PrecisionAnalyzer::GetPrecisionStats(expected, decoded_sparse);
            REQUIRE(stats.MeanPrecision.Real >= 10.0);
        }
    }
}

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

#ifdef LATTISENSE_ENABLE_FPGA

// ---------------------------------------------------------------------------
// Precision helper — same as test_cpu_ckks.cpp
// ---------------------------------------------------------------------------

static void verify_ckks_precision(CkksContext& ctx,
                                  const vector<double>& expected,
                                  const CkksCiphertext& ct,
                                  double minPrec = 10.0,
                                  bool in_coeffs_domain = false) {
    auto stats = PrecisionAnalyzer::GetPrecisionStats(ctx, expected, ct, in_coeffs_domain);
    REQUIRE(stats.MeanPrecision.Real >= minPrec);
}

// ---------------------------------------------------------------------------
// Multi-param parallel tests
// Each test type iterates over all valid levels.
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cap", "", CkksFpgaTestParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cap/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cac", "", CkksFpgaTestParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cac/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS casc", "", CkksFpgaTestParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_casc/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS csp", "", CkksFpgaTestParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csp/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS csc", "", CkksFpgaTestParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csc/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cneg", "", CkksFpgaTestParams) {
    for (int level = this->min_level; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path =
                fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cneg/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cmp_ringt", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt_ringt(this->n_op, this->ctx, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp_ringt/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cmp", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path =
                fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cmp_mul", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt_mul(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp_mul/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cmp_coeffs_ringt", "", CkksFpgaTestParams) {
    for (int level = 2; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct_coeffs(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt_ringt_coeffs(this->n_op, this->ctx, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++) {
                auto ct = this->ctx.new_ciphertext(level, this->default_scale * this->default_scale);
                z_list.push_back(std::move(ct));
            }

            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp_ringt/level_" +
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
                auto z_true = polynomial_multiplication(n, xv.values[i], yv.values[i]);
                verify_ckks_precision(this->ctx, z_true, z_list[i], 10.0, true);
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cmp_coeffs_mul", "", CkksFpgaTestParams) {
    for (int level = 2; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct_coeffs(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_pt_mul_coeffs(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++) {
                auto ct = this->ctx.new_ciphertext(level, this->default_scale * this->default_scale);
                z_list.push_back(std::move(ct));
            }

            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmp_mul/level_" +
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
                auto z_true = polynomial_multiplication(n, xv.values[i], yv.values[i]);
                verify_ckks_precision(this->ctx, z_true, z_list[i], 10.0, true);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MAC test — level=3 only
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS ct_pt_ringt_mac", "", CkksFpgaTestParams) {
    int level = 3;
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
                fpga_base_path + "/" + this->tag + "/CKKS_cmpac_ringt/level_" + to_string(level) + "_m_" + to_string(m);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cmc", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext3> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext3(level, this->default_scale * this->default_scale));
            string path =
                fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmc/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cmc_relin", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_cmc_relin/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS cmc_relin_rescale", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            auto yv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            double out_scale = this->default_scale * this->default_scale / this->param.get_q(level);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1, out_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_cmc_relin_rescale/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS csqr", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext3> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext3(level, this->default_scale * this->default_scale));
            string path =
                fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csqr/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS csqr_relin", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level, this->default_scale * this->default_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_csqr_relin/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS csqr_relin_rescale", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            double out_scale = this->default_scale * this->default_scale / this->param.get_q(level);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1, out_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_csqr_relin_rescale/level_" + to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS rescale", "", CkksFpgaTestParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale * this->param.get_q(level));
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - 1, this->default_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_rescale/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS drop_level", "", CkksFpgaTestParams) {
    int drop_level = 2;
    for (int level = 2; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(this->ctx.new_ciphertext(level - drop_level, this->default_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_drop_level/level_" +
                          to_string(level) + "/drop_" + to_string(drop_level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS rotate_col", "", CkksFpgaTestParams) {
    vector<int32_t> steps;
    for (int i = 1; i <= 128; i++)
        steps.push_back(i);
    string steps_str = "steps_1_to_128";

    this->ctx.gen_rotation_keys();

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<vector<CkksCiphertext>> y_list(this->n_op);
            for (int i = 0; i < this->n_op; i++)
                for (int j = 0; j < (int)steps.size(); j++)
                    y_list[i].push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_rotate_col/level_" +
                          to_string(level) + "/" + steps_str;
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS advanced_rotate_col", "", CkksFpgaTestParams) {
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
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) +
                          "_advanced_rotate_col/level_" + to_string(level) + "/steps_" + steps_str;
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS rotate_row", "", CkksFpgaTestParams) {
    this->ctx.gen_rotation_keys_for_rotations(vector<int32_t>{}, true);

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_ckks_test_ct(this->n_op, this->ctx, level, this->default_scale);
            vector<CkksCiphertext> y_list;
            y_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                y_list.push_back(this->ctx.new_ciphertext(level, this->default_scale));
            string path = fpga_base_path + "/" + this->tag + "/CKKS_" + to_string(this->n_op) + "_rotate_row/level_" +
                          to_string(level);
            FheTaskFpga proj(path);
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

TEMPLATE_TEST_CASE_METHOD(CkksFpgaFixture, "CKKS n_poly", "", CkksFpgaTestParams) {
    if (this->max_level < 4)
        return;

    SECTION("lv=4") {
        auto xv = new_ckks_test_ct(1, this->ctx, 4, this->default_scale);
        auto coeff0v = new_ckks_test_pt(1, this->ctx, 2, this->default_scale);
        auto coeffsv = new_ckks_test_pt_ringt(3, this->ctx, this->default_scale);
        vector<CkksCiphertext> y_list;
        y_list.push_back(this->ctx.new_ciphertext(2, this->default_scale * this->default_scale));

        string path = fpga_base_path + "/" + this->tag + "/CKKS_n_poly/level_4";
        FheTaskFpga proj(path);
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
        verify_ckks_precision(this->ctx, y_true, y_list[0], 0.9);
    }
}

#endif  // LATTISENSE_ENABLE_FPGA

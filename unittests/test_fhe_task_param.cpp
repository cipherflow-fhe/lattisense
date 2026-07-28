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

#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "test_config.hpp"
#include "cxx_fhe_task.h"
#include "fhe_task_param.h"
#include "utils.h"

using namespace fhe_ops_lib;
using namespace lattisense;
using namespace std;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// BFV custom params matching BfvTestCustomParams in fixture.hpp
static const int BFV_N = 8192;
static const uint64_t BFV_T = 0x10001;
static const vector<uint64_t> BFV_Q = {0x3FFFFFFFEF8001, 0x4000000011C001, 0x40000000120001};
static const vector<uint64_t> BFV_P = {0x7FFFFFFFFB4001};

static const string BFV_TAG = []() {
    ostringstream ss;
    ss << "bfv_param_custom_n" << BFV_N << "_t" << hex << BFV_T;
    return ss.str();
}();

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("create_fhe_parameter returns BfvParameter for BFV cmc_relin task") {
    const int n_op = 4;
    const int level = 1;

    string path =
        test_config::cpu_base_path + "/" + BFV_TAG + "/BFV_" + to_string(n_op) + "_cmc_relin/level_" + to_string(level);
    FheTaskCpu task(path);

    SECTION("variant holds BfvParameter") {
        auto param_var = create_fhe_parameter(task);
        REQUIRE(holds_alternative<BfvParameter>(param_var));
    }

    SECTION("BfvParameter fields match task param_json") {
        auto param_var = create_fhe_parameter(task);
        BfvParameter& p = get<BfvParameter>(param_var);

        REQUIRE(p.get_n() == BFV_N);
        REQUIRE(p.get_t() == BFV_T);
        REQUIRE(p.get_q_count() == (int)BFV_Q.size());
        for (int i = 0; i < p.get_q_count(); i++)
            REQUIRE(p.get_q(i) == BFV_Q[i]);
        REQUIRE(p.get_p_count() == (int)BFV_P.size());
        for (int i = 0; i < p.get_p_count(); i++)
            REQUIRE(p.get_p(i) == BFV_P[i]);
    }

    SECTION("create_bfv_parameter gives identical result") {
        auto param_var = create_fhe_parameter(task);
        BfvParameter& p_via_variant = get<BfvParameter>(param_var);
        BfvParameter p_direct = create_bfv_parameter(task.param_json());

        REQUIRE(p_via_variant.get_n() == p_direct.get_n());
        REQUIRE(p_via_variant.get_t() == p_direct.get_t());
        REQUIRE(p_via_variant.get_q_count() == p_direct.get_q_count());
        for (int i = 0; i < p_via_variant.get_q_count(); i++)
            REQUIRE(p_via_variant.get_q(i) == p_direct.get_q(i));
    }

    SECTION("context created from task parameter runs cmc_relin correctly") {
        auto param_var = create_fhe_parameter(task);
        BfvParameter& p = get<BfvParameter>(param_var);
        BfvContext ctx = BfvContext::create_random_context(p);

        const int n_op_run = 4;
        auto xv = new_bfv_test_ct(n_op_run, ctx, level, p.get_t());
        auto yv = new_bfv_test_ct(n_op_run, ctx, level, p.get_t());
        vector<BfvCiphertext> z_list;
        z_list.reserve(n_op_run);
        for (int i = 0; i < n_op_run; i++)
            z_list.push_back(ctx.new_ciphertext(level));

        vector<CxxVectorArgument> args = {
            {"in_x_list", &xv.ciphertexts},
            {"in_y_list", &yv.ciphertexts},
            {"out_z_list", &z_list},
        };
        task.run(&ctx, args);

        vector<vector<uint64_t>> expected(n_op_run);
        for (int i = 0; i < n_op_run; i++)
            expected[i] = vec_mod_mul(xv.values[i], yv.values[i], p.get_t());
        REQUIRE(decrypt_and_decode(ctx, z_list) == expected);
    }
}

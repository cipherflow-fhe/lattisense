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

namespace {

template <typename RunFunc>
void run_bfv_backends(const string& section_suffix, const string& relative_path, RunFunc run, bool run_gpu = true) {
    const auto section_name = [](const string& backend, const string& suffix) {
        return suffix.empty() ? backend : backend + " " + suffix;
    };

    SECTION(section_name("cpu", section_suffix)) {
        FheTaskCpu project(cpu_base_path + "/" + relative_path);
        run(project);
    }
#ifdef LATTISENSE_ENABLE_GPU
    if (run_gpu) {
        SECTION(section_name("gpu", section_suffix)) {
            FheTaskGpu project(gpu_base_path + "/" + relative_path);
            run(project);
        }
    }
#endif
}

}  // namespace

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cap", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (bool is_ringt : {false, true}) {
        string task_name = is_ringt ? "cap_ringt" : "cap";
        string section_prefix = is_ringt ? "pt-ringt" : "pt";
        for (int level = this->min_level; level <= this->max_level; level++) {
            string relative_path =
                this->tag + "/BFV_" + to_string(this->n_op) + "_" + task_name + "/level_" + to_string(level);
            run_bfv_backends(section_prefix + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                auto yv = new_test_pts(this->n_op, this->ctx, is_ringt ? 0 : level, is_ringt, true);
                vector<BfvCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(BfvCiphertext(this->param, level));
                vector<CxxVectorArgument> args = {
                    {"in_x_list", &xv.ciphertexts()},
                    {"in_y_list", &yv.plaintexts()},
                    {"out_z_list", &z_list},
                };
                proj.run(&this->ctx, args);
                vector<vector<uint64_t>> expected(this->n_op);
                for (int i = 0; i < this->n_op; i++)
                    expected[i] = vec_mod_add(xv.messages()[i], yv.messages()[i], this->param.t());
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cac", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (bool same_input : {false, true}) {
        string task_name = same_input ? "casc" : "cac";
        string section_prefix = same_input ? "same-ct" : "ct";
        for (int level = this->min_level; level <= this->max_level; level++) {
            string relative_path =
                this->tag + "/BFV_" + to_string(this->n_op) + "_" + task_name + "/level_" + to_string(level);
            run_bfv_backends(section_prefix + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                vector<BfvCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(BfvCiphertext(this->param, level));
                vector<vector<uint64_t>> expected(this->n_op);
                if (same_input) {
                    vector<CxxVectorArgument> args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"out_z_list", &z_list},
                    };
                    proj.run(&this->ctx, args);
                    for (int i = 0; i < this->n_op; i++)
                        expected[i] = vec_mod_add(xv.messages()[i], xv.messages()[i], this->param.t());
                } else {
                    auto yv = new_test_cts(this->n_op, this->ctx, level);
                    vector<CxxVectorArgument> args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"in_y_list", &yv.ciphertexts()},
                        {"out_z_list", &z_list},
                    };
                    proj.run(&this->ctx, args);
                    for (int i = 0; i < this->n_op; i++)
                        expected[i] = vec_mod_add(xv.messages()[i], yv.messages()[i], this->param.t());
                }
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV add scalar", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (const string& scalar_tag : vector<string>{"int", "int64_t", "uint64_t"}) {
        const uint64_t scalar_mod_t =
            scalar_tag == "int64_t" ? this->param.t() - 105 : (scalar_tag == "uint64_t" ? 11 : 3);
        for (int level = this->min_level; level <= this->max_level; level++) {
            string relative_path = this->tag + "/BFV_" + to_string(this->n_op) + "_add_scalar/" + scalar_tag +
                                   "/level_" + to_string(level);
            run_bfv_backends(scalar_tag + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                vector<BfvCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(BfvCiphertext(this->param, level));
                vector<CxxVectorArgument> args = {
                    {"in_x_list", &xv.ciphertexts()},
                    {"out_z_list", &z_list},
                };
                proj.run(&this->ctx, args);
                vector<vector<uint64_t>> expected(this->n_op);
                for (int i = 0; i < this->n_op; i++)
                    expected[i] = vec_mod_add(xv.messages()[i], vector<uint64_t>(xv.messages()[i].size(), scalar_mod_t),
                                              this->param.t());
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV csp", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (bool is_ringt : {false, true}) {
        string task_name = is_ringt ? "csp_ringt" : "csp";
        string section_prefix = is_ringt ? "pt-ringt" : "pt";
        for (int level = this->min_level; level <= this->max_level; level++) {
            string relative_path =
                this->tag + "/BFV_" + to_string(this->n_op) + "_" + task_name + "/level_" + to_string(level);
            run_bfv_backends(section_prefix + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                auto yv = new_test_pts(this->n_op, this->ctx, is_ringt ? 0 : level, is_ringt, true);
                vector<BfvCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(BfvCiphertext(this->param, level));
                vector<CxxVectorArgument> args = {
                    {"in_x_list", &xv.ciphertexts()},
                    {"in_y_list", &yv.plaintexts()},
                    {"out_z_list", &z_list},
                };
                proj.run(&this->ctx, args);
                vector<vector<uint64_t>> expected(this->n_op);
                for (int i = 0; i < this->n_op; i++)
                    expected[i] = vec_mod_sub(xv.messages()[i], yv.messages()[i], this->param.t());
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV csc", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (bool same_input : {false, true}) {
        string task_name = same_input ? "cssc" : "csc";
        string section_prefix = same_input ? "same-ct" : "ct";
        for (int level = this->min_level; level <= this->max_level; level++) {
            string relative_path =
                this->tag + "/BFV_" + to_string(this->n_op) + "_" + task_name + "/level_" + to_string(level);
            run_bfv_backends(section_prefix + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                vector<BfvCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(BfvCiphertext(this->param, level));
                vector<vector<uint64_t>> expected(this->n_op);
                if (same_input) {
                    vector<CxxVectorArgument> args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"out_z_list", &z_list},
                    };
                    proj.run(&this->ctx, args);
                    for (int i = 0; i < this->n_op; i++)
                        expected[i] = vec_mod_sub(xv.messages()[i], xv.messages()[i], this->param.t());
                } else {
                    auto yv = new_test_cts(this->n_op, this->ctx, level);
                    vector<CxxVectorArgument> args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"in_y_list", &yv.ciphertexts()},
                        {"out_z_list", &z_list},
                    };
                    proj.run(&this->ctx, args);
                    for (int i = 0; i < this->n_op; i++)
                        expected[i] = vec_mod_sub(xv.messages()[i], yv.messages()[i], this->param.t());
                }
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV sub scalar", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (const string& scalar_tag : vector<string>{"int", "int64_t", "uint64_t"}) {
        const uint64_t scalar_mod_t = scalar_tag == "uint64_t" ? 11 : (scalar_tag == "int64_t" ? 5 : 3);
        for (int level = this->min_level; level <= this->max_level; level++) {
            string relative_path = this->tag + "/BFV_" + to_string(this->n_op) + "_sub_scalar/" + scalar_tag +
                                   "/level_" + to_string(level);
            run_bfv_backends(scalar_tag + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                vector<BfvCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(BfvCiphertext(this->param, level));
                vector<CxxVectorArgument> args = {
                    {"in_x_list", &xv.ciphertexts()},
                    {"out_z_list", &z_list},
                };
                proj.run(&this->ctx, args);
                vector<vector<uint64_t>> expected(this->n_op);
                for (int i = 0; i < this->n_op; i++)
                    expected[i] = vec_mod_sub(xv.messages()[i], vector<uint64_t>(xv.messages()[i].size(), scalar_mod_t),
                                              this->param.t());
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cmp", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (bool is_ringt : {false, true}) {
        string task_name = is_ringt ? "cmp_ringt" : "cmp";
        string section_prefix = is_ringt ? "pt-ringt" : "pt";
        for (int level = 1; level <= this->max_level; level++) {
            string relative_path =
                this->tag + "/BFV_" + to_string(this->n_op) + "_" + task_name + "/level_" + to_string(level);
            run_bfv_backends(
                section_prefix + " lv=" + to_string(level), relative_path,
                [&](auto& proj) {
                    auto xv = new_test_cts(this->n_op, this->ctx, level);
                    auto yv = new_test_pts(this->n_op, this->ctx, is_ringt ? 0 : level, is_ringt, true);
                    vector<BfvCiphertext> z_list;
                    z_list.reserve(this->n_op);
                    for (int _i = 0; _i < this->n_op; _i++)
                        z_list.push_back(BfvCiphertext(this->param, level));
                    vector<CxxVectorArgument> args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"in_y_list", &yv.plaintexts()},
                        {"out_z_list", &z_list},
                    };
                    proj.run(&this->ctx, args);
                    vector<vector<uint64_t>> expected(this->n_op);
                    for (int i = 0; i < this->n_op; i++)
                        expected[i] = vec_mod_mul(xv.messages()[i], yv.messages()[i], this->param.t());
                    REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
                },
                is_ringt);
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV mult scalar", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (const string& scalar_tag : vector<string>{"int", "int64_t", "uint64_t"}) {
        const uint64_t scalar_mod_t =
            scalar_tag == "int64_t" ? this->param.t() - 5 : (scalar_tag == "uint64_t" ? 11 : 3);
        for (int level = 1; level <= this->max_level; level++) {
            string relative_path = this->tag + "/BFV_" + to_string(this->n_op) + "_mult_scalar/" + scalar_tag +
                                   "/level_" + to_string(level);
            run_bfv_backends(scalar_tag + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                vector<BfvCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(BfvCiphertext(this->param, level));
                vector<CxxVectorArgument> args = {
                    {"in_x_list", &xv.ciphertexts()},
                    {"out_z_list", &z_list},
                };
                proj.run(&this->ctx, args);
                vector<vector<uint64_t>> expected(this->n_op);
                for (int i = 0; i < this->n_op; i++)
                    expected[i] = vec_mod_mul(xv.messages()[i], vector<uint64_t>(xv.messages()[i].size(), scalar_mod_t),
                                              this->param.t());
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cmc", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        for (bool same_input : {false, true}) {
            string task_name = same_input ? "csqr" : "cmc";
            string section_prefix = same_input ? "same-ct" : "ct";
            string relative_path =
                this->tag + "/BFV_" + to_string(this->n_op) + "_" + task_name + "/level_" + to_string(level);
            run_bfv_backends(section_prefix + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                auto yv = new_test_cts(this->n_op, this->ctx, level);
                vector<BfvCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(BfvCiphertext(this->param, level, 2));
                vector<CxxVectorArgument> args;
                if (same_input) {
                    args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"out_z_list", &z_list},
                    };
                } else {
                    args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"in_y_list", &yv.ciphertexts()},
                        {"out_z_list", &z_list},
                    };
                }
                proj.run(&this->ctx, args);
                vector<vector<uint64_t>> expected(this->n_op);
                for (int i = 0; i < this->n_op; i++) {
                    const auto& rhs = same_input ? xv.messages()[i] : yv.messages()[i];
                    expected[i] = vec_mod_mul(xv.messages()[i], rhs, this->param.t());
                }
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV cmc_relin", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        for (bool same_input : {false, true}) {
            string task_name = same_input ? "csqr_relin" : "cmc_relin";
            string section_prefix = same_input ? "same-ct" : "ct";
            string relative_path =
                this->tag + "/BFV_" + to_string(this->n_op) + "_" + task_name + "/level_" + to_string(level);
            run_bfv_backends(section_prefix + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                auto yv = new_test_cts(this->n_op, this->ctx, level);
                vector<BfvCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(BfvCiphertext(this->param, level));
                vector<CxxVectorArgument> args;
                if (same_input) {
                    args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"out_z_list", &z_list},
                    };
                } else {
                    args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"in_y_list", &yv.ciphertexts()},
                        {"out_z_list", &z_list},
                    };
                }
                proj.run(&this->ctx, args);
                vector<vector<uint64_t>> expected(this->n_op);
                for (int i = 0; i < this->n_op; i++) {
                    const auto& rhs = same_input ? xv.messages()[i] : yv.messages()[i];
                    expected[i] = vec_mod_mul(xv.messages()[i], rhs, this->param.t());
                }
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV drop_level", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 2; level <= this->max_level; level++) {
        string relative_path = this->tag + "/BFV_" + to_string(this->n_op) + "_drop_level/level_" + to_string(level);
        run_bfv_backends("lv=" + to_string(level), relative_path, [&](auto& proj) {
            auto xv = new_test_cts(this->n_op, this->ctx, level);
            vector<BfvCiphertext> y_list;
            y_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                y_list.push_back(BfvCiphertext(this->param, level - 2));
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts()},
                {"out_y_list", &y_list},
            };
            proj.run(&this->ctx, args);
            REQUIRE(decrypt_and_decode(this->ctx, y_list) == xv.messages());
        });
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV rescale", "", BfvTestDefaultParams, BfvTestCustomParams) {
    for (int level = 1; level <= this->max_level; level++) {
        string relative_path = this->tag + "/BFV_" + to_string(this->n_op) + "_rescale/level_" + to_string(level);
        run_bfv_backends("lv=" + to_string(level), relative_path, [&](auto& proj) {
            auto xv = new_test_cts(this->n_op, this->ctx, level);
            vector<BfvCiphertext> y_list;
            y_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                y_list.push_back(BfvCiphertext(this->param, level - 1));
            vector<CxxVectorArgument> args = {
                {"in_x_list", &xv.ciphertexts()},
                {"out_y_list", &y_list},
            };
            proj.run(&this->ctx, args);
            REQUIRE(decrypt_and_decode(this->ctx, y_list) == xv.messages());
        });
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV rotate_col", "", BfvTestDefaultParams, BfvTestCustomParams) {
    vector<int32_t> steps;
    for (int i = 1; i <= 8; i++)
        steps.push_back(i);
    string steps_str = "steps_" + to_string(steps.front()) + "_to_" + to_string(steps.back());

    for (bool use_default_rotation_keys : {true, false}) {
        if (use_default_rotation_keys) {
            this->ctx.gen_rotation_keys();
        } else {
            this->ctx.gen_rotation_keys(steps);
        }

        string key_mode_tag = use_default_rotation_keys ? "default" : "non-default";
        for (int level = 1; level <= this->max_level; level++) {
            string relative_path = this->tag + "/BFV_" + to_string(this->n_op) + "_rotate_col/level_" +
                                   to_string(level) + "/" + steps_str + "/" + key_mode_tag;
            run_bfv_backends(key_mode_tag + " lv=" + to_string(level), relative_path, [&](auto& proj) {
                auto xv = new_test_cts(this->n_op, this->ctx, level);
                vector<vector<BfvCiphertext>> y_list(this->n_op);
                for (int i = 0; i < this->n_op; i++)
                    for (int j = 0; j < (int)steps.size(); j++)
                        y_list[i].push_back(BfvCiphertext(this->param, level));
                vector<CxxVectorArgument> args = {
                    {"arg_x", &xv.ciphertexts()},
                    {"arg_y", &y_list},
                };
                proj.run(&this->ctx, args);

                for (int i = 0; i < this->n_op; i++) {
                    for (int j = 0; j < (int)steps.size(); j++) {
                        auto y_mg = decrypt_and_decode(this->ctx, y_list[i][j]);
                        REQUIRE(y_mg == vec_rotate_col(xv.messages()[i], steps[j]));
                    }
                }
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV rotate_row", "", BfvTestDefaultParams, BfvTestCustomParams) {
    this->ctx.gen_rotation_keys({}, true);

    for (int level = 1; level <= this->max_level; level++) {
        string relative_path = this->tag + "/BFV_" + to_string(this->n_op) + "_rotate_row/level_" + to_string(level);
        run_bfv_backends("lv=" + to_string(level), relative_path, [&](auto& proj) {
            auto xv = new_test_cts(this->n_op, this->ctx, level);
            vector<BfvCiphertext> y_list;
            y_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                y_list.push_back(BfvCiphertext(this->param, level));
            vector<CxxVectorArgument> args = {
                {"arg_x", &xv.ciphertexts()},
                {"arg_y", &y_list},
            };
            proj.run(&this->ctx, args);

            for (int i = 0; i < this->n_op; i++) {
                auto y_mg = decrypt_and_decode(this->ctx, y_list[i]);
                REQUIRE(y_mg == vec_rotate_row(xv.messages()[i]));
            }
        });
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV ct_pt_ringt_mac", "", BfvTestDefaultParams) {
    for (int m = 44; m <= 50; m++) {
        string relative_path = this->tag + "/BFV_cmpac/level_1_m_" + to_string(m);
        run_bfv_backends("m=" + to_string(m) + "/lv=1", relative_path, [&](auto& proj) {
            auto cv = new_test_cts(m, this->ctx, 1);
            auto pv = new_test_pts(m, this->ctx, 0, true, true);
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(BfvCiphertext(this->param, 1));

            vector<CxxVectorArgument> args = {
                {"in_c_list", &cv.ciphertexts()},
                {"in_p_list", &pv.plaintexts()},
                {"out_z_list", &z_list},
            };
            proj.run(&this->ctx, args);

            int n = this->param.n();
            vector<vector<uint64_t>> expected(1, vector<uint64_t>(n, 0));
            for (int i = 0; i < m; i++)
                expected[0] = vec_mod_add(expected[0], vec_mod_mul(cv.messages()[i], pv.messages()[i], this->param.t()),
                                          this->param.t());
            REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
        });
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV power_dag", "[.]", BfvTestDefaultParams) {
    vector<int> source_power{1, 7, 18, 62, 104, 244, 259};
    int max_power = 1137;

    // vector<int> source_power{1, 3, 7, 9, 19, 24};
    // int max_power = 52;

    string source_power_str;
    for (int j = 0; j < (int)source_power.size(); j++) {
        source_power_str += to_string(source_power[j]);
        if (j != (int)source_power.size() - 1)
            source_power_str += "-";
    }
    string task_power_str = "PD-" + to_string(max_power) + "#" + source_power_str;

    SECTION("power_dag " + task_power_str) {
        int n = this->param.n();
        auto x_mg = rand_values(n, this->param.t());

        // x^p for each source power — input ciphertexts
        vector<vector<uint64_t>> x_source_power(source_power.size());
        for (int j = 0; j < (int)source_power.size(); j++)
            x_source_power[j] = vec_mod_exp(x_mg, source_power[j], this->param.t());

        // x^1 .. x^max_power — expected outputs
        vector<vector<uint64_t>> x_max_power(max_power);
        for (int j = 1; j <= max_power; j++)
            x_max_power[j - 1] = vec_mod_exp(x_mg, j, this->param.t());

        for (int level = 5; level <= 5; level++) {
            SECTION("level " + to_string(level)) {
                vector<BfvCiphertext> x_source_power_list;
                for (int j = 0; j < (int)source_power.size(); j++) {
                    BfvPlaintext x_pt(this->param, plaintext_metadata(false, true, level));
                    this->ctx.encode(x_source_power[j], x_pt);
                    x_source_power_list.push_back(this->ctx.encrypt(x_pt));
                }
                vector<BfvCiphertext> x_max_power_list;
                for (int j = 0; j < max_power; j++)
                    x_max_power_list.push_back(BfvCiphertext(this->param, 1));

                string relative_path = this->tag + "/BFV_power_dag/" + task_power_str;
                run_bfv_backends("level " + to_string(level), relative_path, [&](auto& proj) {
                    vector<CxxVectorArgument> args = {
                        {"in_x_list", &x_source_power_list},
                        {"out_z_list", &x_max_power_list},
                    };
                    proj.run(&this->ctx, args);

                    for (int j = 0; j < max_power; j++)
                        REQUIRE(decrypt_and_decode(this->ctx, x_max_power_list[j]) == x_max_power[j]);
                });
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV power_mul_coeff", "[.]", BfvTestDefaultParams) {
    vector<int> source_power{1, 7, 18, 62, 104, 244, 259};
    int max_power = 1137;
    // vector<int> source_power{1, 3, 7, 9, 19, 24};
    // int max_power = 52;
    vector<int> lane_cipher_size{2, 1, 5};

    string source_power_str;
    for (int j = 0; j < (int)source_power.size(); j++) {
        source_power_str += to_string(source_power[j]);
        if (j != (int)source_power.size() - 1)
            source_power_str += "-";
    }
    string task_power_str = "PD-" + to_string(max_power) + "#" + source_power_str;

    SECTION("power_mul_coeff " + task_power_str) {
        int n = this->param.n();

        vector<vector<uint64_t>> x_mg(lane_cipher_size[1]);
        vector<vector<vector<uint64_t>>> x_max_power(lane_cipher_size[1]);
        for (int i = 0; i < lane_cipher_size[1]; i++) {
            x_mg[i] = rand_values(n, this->param.t());
            x_max_power[i].resize(max_power);
            for (int j = 1; j <= max_power; j++)
                x_max_power[i][j - 1] = vec_mod_exp(x_mg[i], j, this->param.t());
        }

        // Polynomial coefficients: p[i][j][k][l] is a length-n vector
        // l=0: constant term, l>0: ring-t coefficient for x^l
        vector<vector<vector<vector<vector<uint64_t>>>>> p(lane_cipher_size[0]);
        for (int i = 0; i < lane_cipher_size[0]; i++) {
            p[i].resize(lane_cipher_size[1]);
            for (int j = 0; j < lane_cipher_size[1]; j++) {
                p[i][j].resize(lane_cipher_size[2]);
                for (int k = 0; k < lane_cipher_size[2]; k++) {
                    p[i][j][k].resize(max_power + 1);
                    for (int l = 0; l <= max_power; l++)
                        p[i][j][k][l] = rand_values(n, this->param.t());
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
                                this->param.t();
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
                        BfvPlaintext x_pt(this->param, plaintext_metadata(false, true, level));
                        this->ctx.encode(x_max_power[i][j], x_pt);
                        c_max_power_list[i][j] = this->ctx.encrypt(x_pt);
                    }
                }

                vector<vector<vector<BfvPlaintext>>> p0_list(lane_cipher_size[0]);
                vector<vector<vector<vector<BfvPlaintext>>>> p_list(lane_cipher_size[0]);
                for (int i = 0; i < lane_cipher_size[0]; i++) {
                    p0_list[i].resize(lane_cipher_size[1]);
                    p_list[i].resize(lane_cipher_size[1]);
                    for (int j = 0; j < lane_cipher_size[1]; j++) {
                        p0_list[i][j].resize(lane_cipher_size[2]);
                        p_list[i][j].resize(lane_cipher_size[2]);
                        for (int k = 0; k < lane_cipher_size[2]; k++) {
                            p_list[i][j][k].resize(max_power);
                            BfvPlaintext p0(this->param, plaintext_metadata(false, true, level));
                            this->ctx.encode(p[i][j][k][0], p0);
                            p0_list[i][j][k] = std::move(p0);
                            for (int l = 1; l <= max_power; l++) {
                                BfvPlaintext p_ringt(this->param, plaintext_metadata());
                                this->ctx.encode(p[i][j][k][l], p_ringt);
                                p_list[i][j][k][l - 1] = std::move(p_ringt);
                            }
                        }
                    }
                }

                vector<vector<vector<BfvCiphertext>>> lane_list(lane_cipher_size[0]);
                for (int i = 0; i < lane_cipher_size[0]; i++) {
                    lane_list[i].resize(lane_cipher_size[1]);
                    for (int j = 0; j < lane_cipher_size[1]; j++) {
                        lane_list[i][j].resize(lane_cipher_size[2]);
                        for (int k = 0; k < lane_cipher_size[2]; k++)
                            lane_list[i][j][k] = BfvCiphertext(this->param, 0);
                    }
                }

                string relative_path = this->tag + "/BFV_power_mul_coeff/" + task_power_str + "/" +
                                       to_string(lane_cipher_size[0]) + "_" + to_string(lane_cipher_size[1]) + "_" +
                                       to_string(lane_cipher_size[2]);
                run_bfv_backends("level " + to_string(level), relative_path, [&](auto& proj) {
                    vector<CxxVectorArgument> args = {
                        {"in_c_list", &c_max_power_list},
                        {"in_p0_list", &p0_list},
                        {"in_p_list", &p_list},
                        {"out_z_list", &lane_list},
                    };
                    proj.run(&this->ctx, args);

                    for (int i = 0; i < lane_cipher_size[0]; i++)
                        for (int j = 0; j < lane_cipher_size[1]; j++)
                            for (int k = 0; k < lane_cipher_size[2]; k++)
                                REQUIRE(decrypt_and_decode(this->ctx, lane_list[i][j][k]) == z_expected[i][j][k]);
                });
            }
        }
    }
}

// TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV power_dag_and_power_mul_coeff", "[.]", BfvTestDefaultParams) {
//     vector<int> source_power{1, 7, 18, 62, 104, 244, 259};
//     int max_power = 1137;
//     vector<int> lane_cipher_size{2, 1, 5};

//     string source_power_str;
//     for (int j = 0; j < (int)source_power.size(); j++) {
//         source_power_str += to_string(source_power[j]);
//         if (j != (int)source_power.size() - 1)
//             source_power_str += "-";
//     }
//     string task_power_str = "PD-" + to_string(max_power) + "#" + source_power_str;

//     SECTION("power_dag_and_power_mul_coeff " + task_power_str) {
//         int n = this->param.n();

//         vector<vector<uint64_t>> x_mg(lane_cipher_size[1]);
//         vector<vector<vector<uint64_t>>> x_source_power(lane_cipher_size[1]);
//         vector<vector<vector<uint64_t>>> x_max_power(lane_cipher_size[1]);
//         for (int i = 0; i < lane_cipher_size[1]; i++) {
//             x_mg[i] = rand_values(n, this->param.t());

//             x_source_power[i].resize(source_power.size());
//             for (int j = 0; j < (int)source_power.size(); j++)
//                 x_source_power[i][j] = vec_mod_exp(x_mg[i], source_power[j], this->param.t());

//             x_max_power[i].resize(max_power);
//             for (int j = 1; j <= max_power; j++)
//                 x_max_power[i][j - 1] = vec_mod_exp(x_mg[i], j, this->param.t());
//         }

//         vector<vector<vector<vector<vector<uint64_t>>>>> p(lane_cipher_size[0]);
//         for (int i = 0; i < lane_cipher_size[0]; i++) {
//             p[i].resize(lane_cipher_size[1]);
//             for (int j = 0; j < lane_cipher_size[1]; j++) {
//                 p[i][j].resize(lane_cipher_size[2]);
//                 for (int k = 0; k < lane_cipher_size[2]; k++) {
//                     p[i][j][k].resize(max_power + 1);
//                     for (int l = 0; l <= max_power; l++)
//                         p[i][j][k][l] = rand_values(n, this->param.t());
//                 }
//             }
//         }

//         vector<vector<vector<vector<uint64_t>>>> z_expected(lane_cipher_size[0]);
//         for (int i = 0; i < lane_cipher_size[0]; i++) {
//             z_expected[i].resize(lane_cipher_size[1]);
//             for (int j = 0; j < lane_cipher_size[1]; j++) {
//                 z_expected[i][j].resize(lane_cipher_size[2]);
//                 for (int k = 0; k < lane_cipher_size[2]; k++) {
//                     z_expected[i][j][k].resize(n, 0);
//                     for (int l = 0; l < n; l++) {
//                         z_expected[i][j][k][l] = p[i][j][k][0][l];
//                         for (int m = 1; m <= max_power; m++)
//                             z_expected[i][j][k][l] =
//                                 (z_expected[i][j][k][l] + p[i][j][k][m][l] * x_max_power[j][m - 1][l]) %
//                                 this->param.t();
//                     }
//                 }
//             }
//         }

//         for (int level = 5; level <= 5; level++) {
//             SECTION("level " + to_string(level)) {
//                 vector<vector<BfvCiphertext>> c_source_power_list(lane_cipher_size[1]);
//                 for (int i = 0; i < lane_cipher_size[1]; i++) {
//                     c_source_power_list[i].resize(source_power.size());
//                     for (int j = 0; j < (int)source_power.size(); j++) {
//                         auto x_pt = this->ctx.encode(x_source_power[i][j], level);
//                         c_source_power_list[i][j] = this->ctx.encrypt_asymmetric(x_pt);
//                     }
//                 }

//                 vector<vector<vector<BfvPlaintext>>> p0_list(lane_cipher_size[0]);
//                 vector<vector<vector<vector<BfvPlaintextRingt>>>> p_list(lane_cipher_size[0]);
//                 for (int i = 0; i < lane_cipher_size[0]; i++) {
//                     p0_list[i].resize(lane_cipher_size[1]);
//                     p_list[i].resize(lane_cipher_size[1]);
//                     for (int j = 0; j < lane_cipher_size[1]; j++) {
//                         p0_list[i][j].resize(lane_cipher_size[2]);
//                         p_list[i][j].resize(lane_cipher_size[2]);
//                         for (int k = 0; k < lane_cipher_size[2]; k++) {
//                             p_list[i][j][k].resize(max_power);
//                             p0_list[i][j][k] = this->ctx.encode(p[i][j][k][0], 1);
//                             for (int l = 1; l <= max_power; l++)
//                                 p_list[i][j][k][l - 1] = this->ctx.encode_ringt(p[i][j][k][l]);
//                         }
//                     }
//                 }

//                 vector<vector<vector<BfvCiphertext>>> lane_list(lane_cipher_size[0]);
//                 for (int i = 0; i < lane_cipher_size[0]; i++) {
//                     lane_list[i].resize(lane_cipher_size[1]);
//                     for (int j = 0; j < lane_cipher_size[1]; j++) {
//                         lane_list[i][j].resize(lane_cipher_size[2]);
//                         for (int k = 0; k < lane_cipher_size[2]; k++)
//                             lane_list[i][j][k] = BfvCiphertext(this->param, 0);
//                     }
//                 }

//                 string path = cpu_base_path + "/" + this->tag + "/BFV_power_dag_and_power_mul_coeff/" +
//                 task_power_str +
//                               "/" + to_string(lane_cipher_size[0]) + "_" + to_string(lane_cipher_size[1]) + "_" +
//                               to_string(lane_cipher_size[2]);
//                 FheTaskCpu proj(path);
//                 vector<CxxVectorArgument> args = {
//                     {"in_x_list", &c_source_power_list},
//                     {"in_p0_list", &p0_list},
//                     {"in_p_list", &p_list},
//                     {"out_z_list", &lane_list},
//                 };
//                 proj.run(&this->ctx, args);

//                 for (int i = 0; i < lane_cipher_size[0]; i++)
//                     for (int j = 0; j < lane_cipher_size[1]; j++)
//                         for (int k = 0; k < lane_cipher_size[2]; k++)
//                             REQUIRE(decrypt_and_decode(this->ctx, lane_list[i][j][k]) == z_expected[i][j][k]);
//             }
//         }
//     }
// }

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV custom cmpac", "", BfvTestDefaultParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            int n = this->param.n();
            auto xv = new_test_cts(7, this->ctx, level);

            vector<vector<uint64_t>> y_vals(7);
            for (int i = 0; i < 7; i++)
                y_vals[i] = rand_values(n, this->param.t());
            vector<uint64_t> y7_vals = rand_values(n, this->param.t());

            vector<CustomData> y_list;
            for (int i = 0; i < 7; i++)
                y_list.push_back(CustomData(y_vals[i]));
            y_list.push_back(CustomData(y7_vals));
            vector<BfvCiphertext> z_list;
            z_list.reserve(1);
            for (int _i = 0; _i < 1; _i++)
                z_list.push_back(BfvCiphertext(this->param, level));

            string relative_path = this->tag + "/BFV_custom_cmpac/level_" + to_string(level);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["encode_ringt"] = [this](ExecutionContext& exec_ctx,
                                                      std::unordered_map<NodeId, std::any>& local_data,
                                                      const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_id = self.input_nodes[0]->id;
                auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(local_data.at(input_node_id));
                auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<uint64_t>>();
                BfvPlaintext pt(bfv_ctx->parameter(), plaintext_metadata());
                bfv_ctx->encode(*msg_vec, pt);
                local_data[self.output_nodes[0]->id] = std::make_shared<BfvPlaintext>(std::move(pt));
            };
            custom_executors["encode"] = [this](ExecutionContext& exec_ctx,
                                                std::unordered_map<NodeId, std::any>& local_data,
                                                const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                if (!self.custom_prop.has_value())
                    throw std::runtime_error("Custom property not found for encode operation");
                int encode_level = self.custom_prop->attributes["level"].get<int>();
                auto input_node_id = self.input_nodes[0]->id;
                auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(local_data.at(input_node_id));
                auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<uint64_t>>();
                BfvPlaintext pt(bfv_ctx->parameter(), plaintext_metadata(false, true, encode_level));
                bfv_ctx->encode(*msg_vec, pt);
                local_data[self.output_nodes[0]->id] = std::make_shared<BfvPlaintext>(std::move(pt));
            };

            run_bfv_backends("lv=" + to_string(level), relative_path, [&](auto& project) {
                project.bind_custom_executors(custom_executors);
                vector<CxxVectorArgument> cxx_args = {
                    CxxVectorArgument{"in_x_list", &xv.ciphertexts()},
                    CxxVectorArgument{"in_y_list", &y_list},
                    CxxVectorArgument{"out_z_list", &z_list},
                };
                project.run(&this->ctx, cxx_args);

                // z[0][k] = (sum_i(x[i][k] * y[i][k]) + y7[k]) % t
                vector<vector<uint64_t>> expected(1, vector<uint64_t>(n, 0));
                for (int i = 0; i < 7; i++)
                    expected[0] = vec_mod_add(expected[0], vec_mod_mul(xv.messages()[i], y_vals[i], this->param.t()),
                                              this->param.t());
                expected[0] = vec_mod_add(expected[0], y7_vals, this->param.t());
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV custom_compute_at_start", "", BfvTestDefaultParams) {
    int n = this->param.n();

    vector<vector<uint64_t>> y_vals(8);
    for (int i = 0; i < 8; i++)
        y_vals[i] = rand_values(n, this->param.t());

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_test_cts(7, this->ctx, level);

            vector<CustomData> y_list;
            for (int i = 0; i < 8; i++)
                y_list.push_back(CustomData(y_vals[i]));
            vector<BfvCiphertext> z_list;
            z_list.push_back(BfvCiphertext(this->param, level));

            string relative_path = this->tag + "/BFV_custom_compute_at_start/level_" + to_string(level);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["encode_ringt"] = [this](ExecutionContext& exec_ctx,
                                                      std::unordered_map<NodeId, std::any>& local_data,
                                                      const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_id = self.input_nodes[0]->id;
                auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(local_data.at(input_node_id));
                auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<uint64_t>>();
                BfvPlaintext pt(bfv_ctx->parameter(), plaintext_metadata());
                bfv_ctx->encode(*msg_vec, pt);
                local_data[self.output_nodes[0]->id] = std::make_shared<BfvPlaintext>(std::move(pt));
            };
            custom_executors["encode"] = [this](ExecutionContext& exec_ctx,
                                                std::unordered_map<NodeId, std::any>& local_data,
                                                const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                if (!self.custom_prop.has_value())
                    throw std::runtime_error("Custom property not found for encode operation");
                int encode_level = self.custom_prop->attributes["level"].get<int>();
                auto input_node_id = self.input_nodes[0]->id;
                auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(local_data.at(input_node_id));
                auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<uint64_t>>();
                BfvPlaintext pt(bfv_ctx->parameter(), plaintext_metadata(false, true, encode_level));
                bfv_ctx->encode(*msg_vec, pt);
                local_data[self.output_nodes[0]->id] = std::make_shared<BfvPlaintext>(std::move(pt));
            };

            run_bfv_backends("lv=" + to_string(level), relative_path, [&](auto& project) {
                project.bind_custom_executors(custom_executors);
                vector<CxxVectorArgument> cxx_args = {
                    CxxVectorArgument{"in_x_list", &xv.ciphertexts()},
                    CxxVectorArgument{"in_y_list", &y_list},
                    CxxVectorArgument{"out_z_list", &z_list},
                };
                project.run(&this->ctx, cxx_args);

                vector<uint64_t> expected(n, 0);
                for (int i = 0; i < 7; i++)
                    expected = vec_mod_add(expected, vec_mod_mul(xv.messages()[i], y_vals[i], this->param.t()),
                                           this->param.t());
                expected = vec_mod_add(expected, y_vals[7], this->param.t());
                REQUIRE(decrypt_and_decode(this->ctx, z_list[0]) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV custom_compute_at_end", "", BfvTestDefaultParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_test_cts(this->n_op, this->ctx, level);
            auto yv = new_test_cts(this->n_op, this->ctx, level);
            vector<BfvCiphertext> z_list;
            z_list.reserve(this->n_op);
            for (int _i = 0; _i < this->n_op; _i++)
                z_list.push_back(BfvCiphertext(this->param, level));

            string relative_path = this->tag + "/BFV_custom_compute_at_end/level_" + to_string(level);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["custom_add"] = [this](ExecutionContext& exec_ctx,
                                                    std::unordered_map<NodeId, std::any>& local_data,
                                                    const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_id = self.input_nodes[0]->id;
                auto input_ptr = std::any_cast<std::shared_ptr<BfvCiphertext>>(local_data.at(input_node_id));
                local_data[self.output_nodes[0]->id] =
                    std::make_shared<BfvCiphertext>(bfv_ctx->add(*input_ptr, *input_ptr));
            };

            run_bfv_backends("lv=" + to_string(level), relative_path, [&](auto& project) {
                project.bind_custom_executors(custom_executors);
                vector<CxxVectorArgument> cxx_args = {
                    CxxVectorArgument{"in_x_list", &xv.ciphertexts()},
                    CxxVectorArgument{"in_y_list", &yv.ciphertexts()},
                    CxxVectorArgument{"out_z_list", &z_list},
                };
                project.run(&this->ctx, cxx_args);

                vector<vector<uint64_t>> expected(this->n_op);
                for (int i = 0; i < this->n_op; i++) {
                    auto prod = vec_mod_mul(xv.messages()[i], yv.messages()[i], this->param.t());
                    expected[i] = vec_mod_add(prod, prod, this->param.t());
                }
                REQUIRE(decrypt_and_decode(this->ctx, z_list) == expected);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(BfvFixture, "BFV custom_compute_in_middle", "", BfvTestDefaultParams) {
    this->ctx.gen_rotation_keys();
    int step = -990;

    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            auto xv = new_test_cts(this->n_op, this->ctx, level);
            auto yv = new_test_cts(this->n_op, this->ctx, level);
            vector<BfvCiphertext> z_list;
            z_list.push_back(BfvCiphertext(this->param, level));

            string relative_path = this->tag + "/BFV_custom_compute_in_middle/level_" + to_string(level);

            std::unordered_map<std::string, ExecutorFunc> custom_executors;
            custom_executors["custom_add"] = [this](ExecutionContext& exec_ctx,
                                                    std::unordered_map<NodeId, std::any>& local_data,
                                                    const ComputeNode& self) -> void {
                auto* bfv_ctx = exec_ctx.get_arithmetic_context<BfvContext>();
                auto input_node_id = self.input_nodes[0]->id;
                auto input_ptr = std::any_cast<std::shared_ptr<BfvCiphertext>>(local_data.at(input_node_id));
                local_data[self.output_nodes[0]->id] =
                    std::make_shared<BfvCiphertext>(bfv_ctx->add(*input_ptr, *input_ptr));
            };

            run_bfv_backends("lv=" + to_string(level), relative_path, [&](auto& project) {
                project.bind_custom_executors(custom_executors);
                vector<CxxVectorArgument> cxx_args = {
                    CxxVectorArgument{"in_x_list", &xv.ciphertexts()},
                    CxxVectorArgument{"in_y_list", &yv.ciphertexts()},
                    CxxVectorArgument{"out_z_list", &z_list},
                };
                project.run(&this->ctx, cxx_args);

                vector<uint64_t> expected(this->param.n(), 0);
                for (int i = 0; i < this->n_op; i++) {
                    auto prod = vec_mod_mul(xv.messages()[i], yv.messages()[i], this->param.t());
                    auto doubled = vec_mod_add(prod, prod, this->param.t());
                    expected = vec_mod_add(expected, vec_rotate_col(doubled, step), this->param.t());
                }
                REQUIRE(decrypt_and_decode(this->ctx, z_list[0]) == expected);
            });
        }
    }
}

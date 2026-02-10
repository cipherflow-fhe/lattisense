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
#include <algorithm>
#include <random>
#include <dirent.h>
#include <math.h>

#include "catch.hpp"
#include "fixture.hpp"
#include "cxx_fhe_task.h"

uint64_t mod_exp(uint64_t x, int power, uint64_t mod) {
    if (power == 0)
        return 1;
    if (power % 2 == 1)
        return x * mod_exp(x * x % mod, power / 2, mod) % mod;
    else
        return mod_exp(x * x % mod, power / 2, mod) % mod;
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV ct_add_pt_ringt", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvPlaintextRingt> y_list;
    vector<BfvCiphertext> z_list;
    vector<uint64_t> x;
    vector<uint64_t> y;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i);
        y.push_back(i);
        z_true[i] = (x[i] + y[i]) % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                vector<uint64_t> y_mg{y[i]};
                print_message(x_mg.data(), "x_mg", 1);
                print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt_ringt = ctx.encode_ringt(y_mg);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt_ringt));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cap_ringt/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV cap", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvPlaintext> y_list;
    vector<BfvCiphertext> z_list;
    vector<uint64_t> x;
    vector<uint64_t> y;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i);
        y.push_back(i);
        z_true[i] = (x[i] + y[i]) % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                vector<uint64_t> y_mg{y[i]};
                print_message(x_mg.data(), "x_mg", 1);
                print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cap/level_" + to_string(level);
            FheTaskGpu project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV cac", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;

    vector<vector<uint64_t>> x(n_op);
    vector<vector<uint64_t>> y(n_op);

    vector<vector<uint64_t>> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        for (int j = 0; j < n; j++) {
            x[i].push_back(i + j + 2);
            y[i].push_back(i + j + 3);
            z_true[i].push_back((x[i].back() + y[i].back()) % t);
        }
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg;
                vector<uint64_t> y_mg;
                for (int j = 0; j < n; j++) {
                    x_mg.push_back(x[i][j]);
                    y_mg.push_back(y[i][j]);
                }
                print_message(x_mg.data(), "x_mg", 10);
                print_message(y_mg.data(), "y_mg", 10);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cac/level_" + to_string(level);
            FheTaskGpu project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            project.run(&ctx, cxx_args);

            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 10);

                REQUIRE(z_mg == z_true[i]);
            }
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV casc", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 2);
        z_true[i] = (x[i] + x[i]) % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_casc/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV ct_sub_pt_ringt", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvPlaintextRingt> y_list;
    vector<BfvCiphertext> z_list;
    vector<uint64_t> x;
    vector<uint64_t> y;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + i);
        y.push_back(i);
        z_true[i] = (x[i] - y[i]) % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                vector<uint64_t> y_mg{y[i]};
                print_message(x_mg.data(), "x_mg", 1);
                print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt_ringt = ctx.encode_ringt(y_mg);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt_ringt));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_csp_ringt/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV csp", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvPlaintext> y_list;
    vector<BfvCiphertext> z_list;
    vector<uint64_t> x;
    vector<uint64_t> y;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + i);
        y.push_back(i);
        z_true[i] = (x[i] - y[i]) % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                vector<uint64_t> y_mg{y[i]};
                print_message(x_mg.data(), "x_mg", 1);
                print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt_ringt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt_ringt));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_csp/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV csc", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x;
    vector<uint64_t> y;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(3 * i);
        y.push_back(i);
        z_true[i] = (x[i] - y[i]) % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                vector<uint64_t> y_mg{y[i]};
                print_message(x_mg.data(), "x_mg", 1);
                print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_csc/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV cssc", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(3 * i);
        z_true[i] = (x[i] - x[i]) % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cssc/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV cneg", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(3 * i);
        z_true[i] = (t - x[i]) % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);

                x_list.push_back(std::move(x_ct));

                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cneg/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV ct_mult_pt_ringt", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvPlaintextRingt> y_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x;
    vector<uint64_t> y;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 1);
        y.push_back(i + 10);
        z_true[i] = x[i] * y[i] % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                vector<uint64_t> y_mg{y[i]};
                print_message(x_mg.data(), "x_mg", 1);
                print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode_ringt(y_mg);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(move(x_ct));
                y_list.push_back(move(y_pt));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cmp_ringt/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV cmc", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext3> z_list;

    vector<vector<uint64_t>> x(n_op);
    vector<vector<uint64_t>> y(n_op);

    vector<vector<uint64_t>> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        for (int j = 0; j < n; j++) {
            x[i].push_back(i + j + 2);
            y[i].push_back(i + j + 3);
            z_true[i].push_back((x[i].back() * y[i].back()) % t);
        }
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg;
                vector<uint64_t> y_mg;
                for (int j = 0; j < n; j++) {
                    x_mg.push_back(x[i][j]);
                    y_mg.push_back(y[i][j]);
                }
                print_message(x_mg.data(), "x_mg", 10);
                print_message(y_mg.data(), "y_mg", 10);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext3(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cmc/level_" + to_string(level);
            FheTaskGpu project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            project.run(&ctx, cxx_args);

            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 10);

                REQUIRE(z_mg == z_true[i]);
            }
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV cmc_relin", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;

    vector<vector<uint64_t>> x(n_op);
    vector<vector<uint64_t>> y(n_op);

    vector<vector<uint64_t>> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        for (int j = 0; j < n; j++) {
            x[i].push_back(i + j + 2);
            y[i].push_back(i + j + 3);
            z_true[i].push_back((x[i].back() * y[i].back()) % t);
        }
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg;
                vector<uint64_t> y_mg;
                for (int j = 0; j < n; j++) {
                    x_mg.push_back(x[i][j]);
                    y_mg.push_back(y[i][j]);
                }
                print_message(x_mg.data(), "x_mg", 10);
                print_message(y_mg.data(), "y_mg", 10);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cmc_relin/level_" + to_string(level);
            FheTaskGpu project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            project.run(&ctx, cxx_args);

            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 10);

                REQUIRE(z_mg == z_true[i]);
            }
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV cmc_relin_rescale", "") {
    std::random_device rd;   // a seed source for the random number engine
    std::mt19937 gen(rd());  // mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<uint64_t> distrib(0, t - 1);

    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x;
    vector<uint64_t> y;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(distrib(gen));
        y.push_back(distrib(gen));
        z_true[i] = x[i] * y[i] % t;
    }

    for (int level = min_level + 1; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                vector<uint64_t> y_mg{y[i]};
                // print_message(x_mg.data(), "x_mg", 1);
                // print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext(level - 1));
            }

            string project_path =
                gpu_base_path + "/BFV_" + to_string(n_op) + "_cmc_relin_rescale/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                // print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV csqr", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext3> z_list;
    vector<uint64_t> x;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 10);
        z_true[i] = x[i] * x[i] % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext3(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_csqr/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
}

TEST_CASE_METHOD(BfvGpuFixture, "BFV csqr_relin", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> z_list;
    vector<uint64_t> x;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 10);
        z_true[i] = x[i] * x[i] % t;
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_csqr_relin/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
}

TEST_CASE_METHOD(BfvGpuFixture, "BFV csqr_relin_rescale", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> z_list;
    vector<uint64_t> x;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 10);
        z_true[i] = x[i] * x[i] % t;
    }

    for (int level = min_level + 1; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level - 1));
            }

            string project_path =
                gpu_base_path + "/BFV_" + to_string(n_op) + "_csqr_relin_rescale/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
}

TEST_CASE_METHOD(BfvGpuFixture, "BFV rotate_col", "") {
    vector<BfvCiphertext> x_list;
    vector<vector<BfvCiphertext>> y_list(n_op);
    vector<vector<uint64_t>> x_mgs;
    vector<int32_t> steps;
    for (int i = 1; i <= 8; i++) {
        steps.push_back(i);
    }
    ctx.gen_rotation_keys();
    int n_col = n / 2;

    for (int i = 0; i < n_op; i++) {
        vector<uint64_t> x;
        for (int j = 0; j < n_col; j++) {
            x.push_back(i * 2 + j);
        }
        x_mgs.push_back(x);
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level) + ", steps_1_to_8") {
            for (int i = 0; i < n_op; i++) {
                print_message(x_mgs[i].data(), "x_mg", 5);
                auto x_pt = ctx.encode(x_mgs[i], level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                for (int j = 0; j < steps.size(); j++) {
                    y_list[i].push_back(ctx.new_ciphertext(level));
                }
            }

            string project_path =
                gpu_base_path + "/BFV_" + to_string(n_op) + "_rotate_col/level_" + to_string(level) + "/steps_1_to_8";
            FheTaskGpu project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"arg_x", &x_list},
                CxxVectorArgument{"arg_y", &y_list},
            };
            project.run(&ctx, cxx_args);

            for (int i = 0; i < n_op; i++) {
                for (int j = 0; j < steps.size(); j++) {
                    auto y_pt = ctx.decrypt(y_list[i][j]);
                    auto y_mg = ctx.decode(y_pt);
                    print_message(y_mg.data(), "y_mg", 5);

                    vector<uint64_t> y;
                    for (int k = 0; k < n_col; k++) {
                        y.push_back(y_mg[(k - steps[j] + n_col) % n_col]);
                    }
                    REQUIRE(y == x_mgs[i]);
                }
            }
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV advanced_rotate_col", "") {
    vector<BfvCiphertext> x_list;
    vector<vector<BfvCiphertext>> y_list(n_op);
    vector<vector<uint64_t>> x_mgs;
    vector<int32_t> steps = {-900, 20, 400, 2000, 3009};
    int n_col = n / 2;
    ctx.gen_rotation_keys_for_rotations(steps);

    for (int i = 0; i < n_op; i++) {
        vector<uint64_t> x;
        for (int j = 0; j < n_col; j++) {
            x.push_back(i * 2 + j);
        }
        x_mgs.push_back(x);
    }

    string steps_str = "";
    for (int i = 0; i < steps.size(); i++) {
        steps_str += to_string(steps[i]);
        if (i < steps.size() - 1) {
            steps_str += "_";
        }
    }
    steps_str += "";

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level) + ", steps=" + steps_str) {
            for (int i = 0; i < n_op; i++) {
                print_message(x_mgs[i].data(), "x_mg", 5);
                auto x_pt = ctx.encode(x_mgs[i], level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                for (int j = 0; j < steps.size(); j++) {
                    y_list[i].push_back(ctx.new_ciphertext(level));
                }
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_advanced_rotate_col/level_" +
                                  to_string(level) + "/steps_" + steps_str;
            FheTaskGpu project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"arg_x", &x_list},
                CxxVectorArgument{"arg_y", &y_list},
            };
            project.run(&ctx, cxx_args);

            for (int i = 0; i < n_op; i++) {
                for (int j = 0; j < steps.size(); j++) {
                    auto y_pt = ctx.decrypt(y_list[i][j]);
                    auto y_mg = ctx.decode(y_pt);
                    print_message(y_mg.data(), "y_mg", 5);
                    vector<uint64_t> y;
                    for (int k = 0; k < n_col; k++) {
                        y.push_back(y_mg[(k - steps[j] + n_col) % n_col]);
                    }
                    print_message(y.data(), "y", 5);
                    print_message(x_mgs[i].data(), "x_mgs[i]", 5);
                    REQUIRE(y == x_mgs[i]);
                }
            }
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV rotate_row", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<vector<uint64_t>> x_mgs;

    int n_col = n / 2;
    ctx.gen_rotation_keys();

    for (int i = 0; i < n_op; i++) {
        vector<uint64_t> x;
        for (int j = 0; j < 2 * n_col; j++) {
            x.push_back(i * 2 + j);
        }
        x_mgs.push_back(x);
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                print_message(x_mgs[i].data(), "x_mg", 5);
                auto x_pt = ctx.encode(x_mgs[i], level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_rotate_row/level_" + to_string(level);
            FheTaskGpu project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"arg_x", &x_list},
                CxxVectorArgument{"arg_y", &y_list},
            };
            project.run(&ctx, cxx_args);

            for (int i = 0; i < n_op; i++) {
                auto y_pt = ctx.decrypt(y_list[i]);
                auto y_mg = ctx.decode(y_pt);
                print_message(y_mg.data(), "y_mg", 5);
                vector<uint64_t> y;
                for (int k = 0; k < n_col * 2; k++) {
                    if (k < n_col) {
                        y.push_back(x_mgs[i][k + n_col]);
                    } else {
                        y.push_back(x_mgs[i][k - n_col]);
                    }
                }

                REQUIRE(y == y_mg);
            }
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV rescale", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;

    vector<vector<uint64_t>> x;
    vector<vector<uint64_t>> z_true;

    for (int i = 0; i < n_op; i++) {
        vector<uint64_t> x_mg(n);
        vector<uint64_t> z_tr(n);

        for (int j = 0; j < n; j++) {
            x_mg[j] = uint64_t(i + j);
            z_tr[j] = x_mg[j];
        }

        x.push_back(x_mg);
        z_true.push_back(z_tr);
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                auto x_pt = ctx.encode(x[i], level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(ctx.new_ciphertext(level - 1));
            }

            string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_rescale/level_" + to_string(level);
            FheTaskGpu project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_y_list", &y_list},
            };
            project.run(&ctx, cxx_args);

            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(y_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 10);
                REQUIRE(z_mg == z_true[i]);
            }
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV ctc_ctc_0", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x = {1, 2, 3, 4};
    vector<uint64_t> y = {1, 2, 3, 4};

    vector<uint64_t> z_true;
    z_true.push_back(x[0] * y[0]);
    z_true.push_back(x[0] * y[0] * x[1] % t);
    for (int i = 1; i < 4; i++) {
        z_true.push_back(x[i] * y[i] % t);
    }

    for (int level = 3; level <= 3; level++) {
        SECTION("lv=" + to_string(level)) {
            for (int i = 0; i < 4; i++) {
                vector<uint64_t> x_mg{x[i]};
                vector<uint64_t> y_mg{y[i]};
                print_message(x_mg.data(), "x_mg", 1);
                print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
            }
            for (int i = 0; i < 5; i++) {
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_ctc_ctc_0/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < 5; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV ctc_ctc_1", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x = {1, 2, 3, 4};
    vector<uint64_t> y = {1, 2, 3, 4};

    vector<uint64_t> z_true;
    z_true.push_back(x[0] * y[0] * x[1] * y[1] % t);
    z_true.push_back(x[1] * y[1] * x[2] % t);
    z_true.push_back(x[2] * y[2] * x[3] % t);
    z_true.push_back(x[2] * y[2] * x[3] * y[3] % t);

    for (int level = 3; level <= 3; level++) {
        SECTION("lv=" + to_string(level)) {
            for (int i = 0; i < 4; i++) {
                vector<uint64_t> x_mg{x[i]};
                vector<uint64_t> y_mg{y[i]};
                print_message(x_mg.data(), "x_mg", 1);
                print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
            }
            for (int i = 0; i < 4; i++) {
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_ctc_ctc_1/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < 4; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV 1_square_square", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x = {1};

    vector<uint64_t> z_true(1);

    z_true[0] = x[0] * x[0] * x[0] * x[0] % t;

    for (int level = 3; level <= 3; level++) {
        SECTION("lv=" + to_string(level)) {
            for (int i = 0; i < 1; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
            }
            for (int i = 0; i < 1; i++) {
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_1_square_square/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < 1; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV 1_ctc_rotate_cac", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;
    ctx.gen_rotation_keys();

    int step = 1;
    int n_slot = n;
    int n_col = n / 2;

    vector<uint64_t> z_true(n_slot);

    vector<uint64_t> x_mg(n_slot, 0);
    vector<uint64_t> y_mg(n_slot, 0);
    for (int i = 0; i < 10; i++) {
        x_mg[i] = 1 + i;
        y_mg[i] = 1 + i;
    }
    vector<uint64_t> t_mg(n_slot, 0);
    vector<uint64_t> rotated_t_mg(n_slot);
    for (int i = 0; i < n_slot; i++) {
        t_mg[i] = (x_mg[i] * y_mg[i]) % t;
    }

    for (int i = 0; i < n_slot; i++) {
        int row = i / n_col;
        int new_col = (i - step + n_col) % n_col;
        rotated_t_mg[row * n_col + new_col] = t_mg[i];
    }
    for (int i = 0; i < n_slot; i++) {
        z_true[i] = rotated_t_mg[i] + t_mg[i];
    }

    for (int level = 3; level <= 3; level++) {
        SECTION("lv=" + to_string(level)) {
            for (int i = 0; i < 1; i++) {
                print_message(x_mg.data(), "x_mg", 1);
                print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto y_pt = ctx.encode(y_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
            }
            for (int i = 0; i < 1; i++) {
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_1_ctc_rotate_cac/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<vector<uint64_t>> z;
            for (int i = 0; i < 1; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 20);
                for (int j = 0; j < 20; j++) {
                    cout << z_true[j] << ", ";
                }
                cout << endl;
                // cout << z_mg.back() << endl;
                z.push_back(z_mg);
            }

            REQUIRE(z[0] == z_true);
        }
    }
}

TEST_CASE_METHOD(BfvGpuFixture, "BFV double", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x = {1, 2, 3};

    vector<uint64_t> z_true(2);

    z_true[0] = x[0] * x[1] % t;
    z_true[1] = x[0] * x[2] % t;

    for (int level = 1; level <= 1; level++) {
        SECTION("lv=" + to_string(level)) {
            for (int i = 0; i < 3; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
            }
            for (int i = 0; i < 2; i++) {
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_1_double";
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < 2; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV braid", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> y_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> x = {1, 2, 3, 4};

    vector<uint64_t> z_true(4);

    for (int i = 0; i < 4; i++) {
        z_true[0] = x[0] * x[1] * x[1] * x[2];
        z_true[1] = x[1] * x[2] * x[2] * x[3];
        z_true[2] = x[2] * x[3] * x[3] * x[0];
        z_true[3] = x[3] * x[0] * x[0] * x[1];
    }

    for (int level = 3; level <= 3; level++) {
        SECTION("lv=" + to_string(level)) {
            for (int i = 0; i < 4; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);

                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
            }
            for (int i = 0; i < 4; i++) {
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_braid";
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_list", &x_list},
                CxxVectorArgument{"out_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < 4; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV poly", "") {
    vector<BfvCiphertext> x_list;
    vector<BfvCiphertext> a_list;
    vector<BfvCiphertext> z_list;

    vector<uint64_t> a = {5, 7, 9};
    vector<uint64_t> x;
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 1);  // 1, 2, 3, 4,...
    }

    vector<uint64_t> z_true;
    for (int i = 0; i < n_op; i++) {
        z_true.push_back(uint64_t(a[0] * pow(x[i], 2) + a[1] * x[i] + a[2]) % t);  // ax^2 + bx + c
    }

    for (int level = 3; level <= 3; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<uint64_t> x_mg{x[i]};
                print_message(x_mg.data(), "x_mg", 1);
                auto x_pt = ctx.encode(x_mg, level);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
            }
            for (int i = 0; i < 3; i++) {
                vector<uint64_t> a_mg{a[i]};
                print_message(a_mg.data(), "a_mg", 1);
                auto a_pt = ctx.encode(a_mg, level);
                auto a_ct = ctx.encrypt_asymmetric(a_pt);
                a_list.push_back(std::move(a_ct));
            }
            for (int i = 0; i < n_op; i++) {
                z_list.push_back(ctx.new_ciphertext(level));
            }

            string project_path = gpu_base_path + "/BFV_n_poly/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_a_list", &a_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            vector<uint64_t> z;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_message(z_mg.data(), "z_mg", 1);
                z.push_back(z_mg[0]);
            }

            REQUIRE(z == z_true);
        }
    }
};

TEST_CASE_METHOD(BfvGpuFixture, "BFV ct_pt_ringt_mac", "") {
    for (int level = 1; level <= 1; level++) {
        for (int m = 44; m <= 50; m++) {
            SECTION("m=" + to_string(m) + ", lv=" + to_string(level)) {
                vector<BfvCiphertext> c_list;
                vector<BfvPlaintextRingt> p_list;
                vector<BfvCiphertext> z_list;

                vector<uint64_t> c;
                vector<uint64_t> p;
                uint64_t tmp = 0;
                vector<uint64_t> z_true;
                for (int i = 0; i < m; i++) {
                    c.push_back(11);
                    p.push_back(10);
                    tmp += c[i] * p[i];
                }
                z_true.push_back(tmp);

                for (int i = 0; i < m; i++) {
                    vector<uint64_t> c_mg{c[i]};
                    vector<uint64_t> p_mg{p[i]};
                    auto c_pt = ctx.encode(c_mg, level);
                    auto p_pt = ctx.encode_ringt(p_mg);
                    auto c_ct = ctx.encrypt_asymmetric(c_pt);
                    c_list.push_back(std::move(c_ct));
                    p_list.push_back(std::move(p_pt));
                }
                z_list.push_back(ctx.new_ciphertext(level));

                string project_path = gpu_base_path + "/BFV_cmpac/level_" + to_string(level) + "_m_" + to_string(m);
                FheTaskGpu gpu_project(project_path);
                vector<CxxVectorArgument> cxx_args = {
                    CxxVectorArgument{"in_c_list", &c_list},
                    CxxVectorArgument{"in_p_list", &p_list},
                    CxxVectorArgument{"out_z_list", &z_list},
                };
                gpu_project.run(&ctx, cxx_args);

                double epsilon = 1;
                auto z_pt = ctx.decrypt(z_list[0]);
                auto z_mg = ctx.decode(z_pt);
                cout << "z_mg = " << z_mg[0] << endl;
                cout << "z_true = " << z_true[0] << endl;
                REQUIRE(vector<uint64_t>{z_mg[0]} == z_true);
            }
        }
    }
};

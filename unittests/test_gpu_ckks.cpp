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

TEST_CASE_METHOD(CkksGpuFixture, "CKKS cap", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksPlaintext> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> y;

    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(12);
        y.push_back(13);
        z_true[i] = x[i] + y[i];
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode(y_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt));
                z_list.push_back(ctx.new_ciphertext(level, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cap/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double epsilon = 1;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, epsilon) == false);

                for (int j = 0; j < 10; j++) {
                    cout << z_mg[j] << ", ";
                }
                cout << endl;
                cout << z_mg.back() << endl;
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS ct_add_pt_ringt", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksPlaintextRingt> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> y;

    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(12);
        y.push_back(13);
        z_true[i] = x[i] + y[i];
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode_ringt(y_mg, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt));
                z_list.push_back(ctx.new_ciphertext(level, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cap_ringt/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double epsilon = 1;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, epsilon) == false);

                for (int j = 0; j < 10; j++) {
                    cout << z_mg[j] << ", ";
                }
                cout << endl;
                cout << z_mg.back() << endl;
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS cac", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> y;
    vector<double> z_true;
    for (int i = 0; i < n_op; i++) {
        x.push_back(i * 2.0);
        y.push_back(i * 2.0 + 1.0);
        z_true.push_back(x[i] + y[i]);
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                print_double_message(x_mg.data(), "x_mg", 1);
                print_double_message(y_mg.data(), "y_mg", 1);
                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode(y_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext(level, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cac/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-5;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_double_message(z_mg.data(), "z_mg", 1);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS casc", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> z_true;
    for (int i = 0; i < n_op; i++) {
        x.push_back(i * 2.0);
        z_true.push_back(x[i] + x[i]);
    }

    for (int level = 0; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                print_double_message(x_mg.data(), "x_mg", 4);

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);

                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_casc/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-5;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_double_message(z_mg.data(), "z_mg", 4);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS csp", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksPlaintext> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> y;

    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i * 10);
        y.push_back(i * 13);
        z_true[i] = x[i] - y[i];
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode(y_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt));
                z_list.push_back(ctx.new_ciphertext(level, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_csp/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double epsilon = 1;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, epsilon) == false);

                for (int j = 0; j < 10; j++) {
                    cout << z_mg[j] << ", ";
                }
                cout << endl;
                cout << z_mg.back() << endl;
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS ct_sub_pt_ringt", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksPlaintextRingt> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> y;

    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i * 10);
        y.push_back(i * 13);
        z_true[i] = x[i] - y[i];
    }

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode_ringt(y_mg, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt));
                z_list.push_back(ctx.new_ciphertext(level, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_csp_ringt/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double epsilon = 1;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, epsilon) == false);

                for (int j = 0; j < 10; j++) {
                    cout << z_mg[j] << ", ";
                }
                cout << endl;
                cout << z_mg.back() << endl;
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS csc", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> y;
    vector<double> z_true;
    for (int i = 0; i < n_op; i++) {
        x.push_back(i * 2.0);
        y.push_back(i * 2.0 + 1.0);
        z_true.push_back(x[i] - y[i]);
    }

    for (int level = 0; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                print_double_message(x_mg.data(), "x_mg", 4);
                print_double_message(y_mg.data(), "y_mg", 4);
                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode(y_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext(level, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_csc/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-5;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_double_message(z_mg.data(), "z_mg", 4);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS cneg", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> z_true;
    for (int i = 0; i < n_op; i++) {
        x.push_back(i * 2.0);
        z_true.push_back(0.0 - x[i]);
    }

    for (int level = 0; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                print_double_message(x_mg.data(), "x_mg", 4);

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);

                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cneg/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-5;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                print_double_message(z_mg.data(), "z_mg", 4);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS ct_mult_pt_ringt", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksPlaintextRingt> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> y;

    srand(time(0));

    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back((double)i + 2.1);
        y.push_back((double)i + 1.3);
        z_true[i] = x[i] * y[i];
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};
                // print_message(x_mg.data(), "x_mg", 1);
                // print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode_ringt(y_mg, default_scale);

                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt));
                z_list.push_back(ctx.new_ciphertext(level, default_scale * default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cmp_ringt/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double epsilon = 1;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                cout << "z_mg[i] = " << z_mg[i] << endl;
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, epsilon) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS ct_mult_pt", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksPlaintext> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x;
    vector<double> y;

    srand(time(0));

    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back((double)i + 2.1);
        y.push_back((double)i + 1.3);
        z_true[i] = x[i] * y[i];
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};
                // print_message(x_mg.data(), "x_mg", 1);
                // print_message(y_mg.data(), "y_mg", 1);

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode(y_mg, level, default_scale);

                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_pt));
                z_list.push_back(ctx.new_ciphertext(level, default_scale * default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cmp/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double epsilon = 1;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                cout << "z_mg[i] = " << z_mg[i] << endl;
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, epsilon) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS ct_pt_mac", "") {
    min_level = 1;

    for (int level = 5; level <= 5; level++) {
        for (int m = 2; m <= 20; m++) {
            SECTION("m=" + to_string(m) + ", lv=" + to_string(level)) {
                vector<CkksCiphertext> c_list;
                vector<CkksPlaintext> p_list;
                vector<CkksCiphertext> z_list;

                vector<double> c;
                vector<double> p;
                double tmp = 0;
                vector<double> z_true;
                for (int i = 0; i < m; i++) {
                    c.push_back(11);
                    p.push_back(10);
                    tmp += c[i] * p[i];
                }
                z_true.push_back(tmp);

                for (int i = 0; i < m; i++) {
                    vector<double> c_mg{c[i]};
                    vector<double> p_mg{p[i]};
                    auto c_pt = ctx.encode(c_mg, level, default_scale);
                    auto c_ct = ctx.encrypt_asymmetric(c_pt);
                    c_list.push_back(std::move(c_ct));
                    auto p_pt = ctx.encode(p_mg, level, default_scale);
                    p_list.push_back(std::move(p_pt));
                }
                z_list.push_back(ctx.new_ciphertext(level, default_scale * default_scale));

                string project_path = gpu_base_path + "/CKKS_cmpac/level_" + to_string(level) + "_m_" + to_string(m);
                FheTaskGpu gpu_project(project_path);
                vector<CxxVectorArgument> cxx_args = {
                    CxxVectorArgument{"in_c_list", &c_list},
                    CxxVectorArgument{"in_p_list", &p_list},
                    CxxVectorArgument{"out_z_list", &z_list},
                };
                gpu_project.run(&ctx, cxx_args);

                double epsilon = 1.0;
                auto z_pt = ctx.decrypt(z_list[0]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true}, 1, epsilon) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS ct_pt_ringt_mac", "") {
    min_level = 1;

    for (int level = 5; level <= 5; level++) {
        for (int m = 2; m <= 20; m++) {
            SECTION("m=" + to_string(m) + ", lv=" + to_string(level)) {
                vector<CkksCiphertext> c_list;
                vector<CkksPlaintextRingt> p_list;
                vector<CkksCiphertext> z_list;

                vector<double> c;
                vector<double> p;
                double tmp = 0;
                vector<double> z_true;
                for (int i = 0; i < m; i++) {
                    c.push_back(1.1);
                    p.push_back(2.0);
                    tmp += c[i] * p[i];
                }
                z_true.push_back(tmp);

                for (int i = 0; i < m; i++) {
                    vector<double> c_mg{c[i]};
                    vector<double> p_mg{p[i]};
                    auto c_pt = ctx.encode(c_mg, level, default_scale);
                    auto c_ct = ctx.encrypt_asymmetric(c_pt);
                    c_list.push_back(std::move(c_ct));
                    auto p_pt = ctx.encode_ringt(p_mg, default_scale);
                    p_list.push_back(std::move(p_pt));
                }
                z_list.push_back(ctx.new_ciphertext(level, default_scale * default_scale));

                string project_path =
                    gpu_base_path + "/CKKS_cmpac_ringt/level_" + to_string(level) + "_m_" + to_string(m);
                FheTaskGpu gpu_project(project_path);
                vector<CxxVectorArgument> cxx_args = {
                    CxxVectorArgument{"in_c_list", &c_list},
                    CxxVectorArgument{"in_p_list", &p_list},
                    CxxVectorArgument{"out_z_list", &z_list},
                };
                gpu_project.run(&ctx, cxx_args);

                double epsilon = 1.0;
                auto z_pt = ctx.decrypt(z_list[0]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true}, 1, epsilon) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS cmc", "") {
    std::random_device rd;   // a seed source for the random number engine
    std::mt19937 gen(rd());  // mersenne_twister_engine seeded with rd()

    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;
    vector<CkksCiphertext3> z_list;

    vector<double> x(n_op);
    vector<double> y(n_op);
    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x[i] = 10;
        y[i] = 11;
        z_true[i] = x[i] * y[i];
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode(y_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext3(level, default_scale * default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cmc/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-4;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS cmc_relin", "") {
    std::random_device rd;   // a seed source for the random number engine
    std::mt19937 gen(rd());  // mersenne_twister_engine seeded with rd()

    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x(n_op);
    vector<double> y(n_op);
    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x[i] = 10;
        y[i] = 11;
        z_true[i] = x[i] * y[i];
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode(y_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext(level, default_scale * default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cmc_relin/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-4;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS cmc_relin_rescale", "") {
    std::random_device rd;   // a seed source for the random number engine
    std::mt19937 gen(rd());  // mersenne_twister_engine seeded with rd()

    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x(n_op);
    vector<double> y(n_op);
    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x[i] = 10;
        y[i] = 11;
        z_true[i] = x[i] * y[i];
    }

    min_level = 1;

    for (int level = min_level + 1; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto y_pt = ctx.encode(y_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                auto y_ct = ctx.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(ctx.new_ciphertext(level - 1, default_scale * default_scale / param.get_q(level)));
            }

            string project_path =
                gpu_base_path + "/CKKS_" + to_string(n_op) + "_cmc_relin_rescale/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-4;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS csqr", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext3> z_list;
    vector<double> x;

    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 10);
        z_true[i] = x[i] * x[i];
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext3(level, default_scale * default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_csqr/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-4;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS csqr_relin", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> z_list;
    vector<double> x;

    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 10);
        z_true[i] = x[i] * x[i];
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level, default_scale * default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_csqr_relin/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-4;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS csqr_relin_rescale", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> z_list;
    vector<double> x;

    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 10);
        z_true[i] = x[i] * x[i];
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level - 1, default_scale * default_scale / param.get_q(level)));
            }

            string project_path =
                gpu_base_path + "/CKKS_" + to_string(n_op) + "_csqr_relin_rescale/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-4;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = ctx.decrypt(z_list[i]);
                auto z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS rescale", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> z_list;
    vector<vector<double>> x;

    for (int i = 0; i < n_op; i++) {
        vector<double> tmp;
        for (int j = 0; j < 10; j++) {
            tmp.push_back(j + 10);
        }
        x.push_back(tmp);
    }

    min_level = 1;

    for (int level = 2; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = ctx.encode(x_mg, level, default_scale * param.get_q(level));
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level - 1, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_rescale/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_y_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            // REQUIRE(CkksContext::get_ciphertext_level(z_list[0]) == CkksContext::get_ciphertext_level(x_list[0]) -
            // 1); REQUIRE(fabs(CkksContext::get_ciphertext_scale(z_list[0]) / default_scale - 1.0) < 0.01);

            double tolerance = 1.0e-5;
            for (int i = 0; i < n_op; i++) {
                CkksPlaintext z_pt = ctx.decrypt(z_list[i]);
                vector<double> z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, x[i], 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS drop level", "") {
    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> z_list;
    vector<vector<double>> x;
    for (int i = 0; i < n_op; i++) {
        vector<double> tmp;
        for (int j = 0; j < 10; j++) {
            tmp.push_back(j + 10);
        }
        x.push_back(tmp);
    }

    int drop_level = 2;

    min_level = 3;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                z_list.push_back(ctx.new_ciphertext(level - drop_level, default_scale));
            }

            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_drop_level/level_" + to_string(level) +
                                  "/drop_" + to_string(drop_level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_y_list", &z_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-5;
            for (int i = 0; i < n_op; i++) {
                CkksPlaintext z_pt = ctx.decrypt(z_list[i]);
                vector<double> z_mg = ctx.decode(z_pt);
                REQUIRE(compare_double_vectors(z_mg, x[i], 1, tolerance) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS rotate_col", "") {
    std::random_device rd;   // a seed source for the random number engine
    std::mt19937 gen(rd());  // mersenne_twister_engine seeded with rd()

    vector<CkksCiphertext> x_list;
    vector<vector<CkksCiphertext>> y_list(n_op);

    vector<int32_t> steps;
    for (int i = 1; i <= 8; i++) {
        steps.push_back(i);
    }
    ctx.gen_rotation_keys();
    int n_value = n / 2;
    vector<vector<double>> x;
    for (int i = 0; i < n_op; i++) {
        vector<double> tmp;
        for (int j = 0; j < n_value; j++) {
            tmp.push_back(n_value - 1 - j + 1.0);
        }
        x.push_back(tmp);
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level) + ", steps_1_to_8") {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                for (int j = 0; j < steps.size(); j++) {
                    y_list[i].push_back(ctx.new_ciphertext(level, default_scale));
                }
            }
            string project_path =
                gpu_base_path + "/CKKS_" + to_string(n_op) + "_rotate_col/level_" + to_string(level) + "/steps_1_to_8";
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"arg_x", &x_list},
                CxxVectorArgument{"arg_y", &y_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-2;
            for (int i = 0; i < n_op; i++) {
                for (int j = 0; j < steps.size(); j++) {
                    CkksPlaintext y_pt = ctx.decrypt(y_list[i][j]);
                    vector<double> y_mg = ctx.decode(y_pt);
                    vector<double> y_true(n_slot, 0.0);
                    for (int k = 0; k < n_value; k++) {
                        y_true[(k - steps[j] + n_slot) % n_slot] = n_value - 1 - k + 1.0;
                    }
                    REQUIRE(compare_double_vectors_w_offset(y_mg, y_true, n_value, tolerance, -steps[j], n_slot) ==
                            false);
                }
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS advanced_rotate_col", "") {
    std::random_device rd;   // a seed source for the random number engine
    std::mt19937 gen(rd());  // mersenne_twister_engine seeded with rd()

    vector<CkksCiphertext> x_list;
    vector<vector<CkksCiphertext>> y_list(n_op);

    ctx.gen_rotation_keys_for_rotations(vector<int32_t>{-500, 20, 200, 2000, 4000});
    vector<int> steps = {-500, 20, 200, 2000, 4000};
    int n_value = n_slot;
    vector<vector<double>> x;
    for (int i = 0; i < n_op; i++) {
        vector<double> tmp;
        for (int j = 0; j < n_value; j++) {
            tmp.push_back(n_value - 1 - j + 1.0);
        }
        x.push_back(tmp);
    }

    string steps_str = "";
    for (int i = 0; i < steps.size(); i++) {
        steps_str += to_string(steps[i]);
        if (i < steps.size() - 1) {
            steps_str += "_";
        }
    }
    steps_str += "";

    for (int level = 1; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level) + ", steps=" + steps_str) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                for (int j = 0; j < steps.size(); j++) {
                    y_list[i].push_back(ctx.new_ciphertext(level, default_scale));
                }
            }
            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_advanced_rotate_col/level_" +
                                  to_string(level) + "/steps_" + steps_str;
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"arg_x", &x_list},
                CxxVectorArgument{"arg_y", &y_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-2;
            for (int i = 0; i < n_op; i++) {
                for (int j = 0; j < steps.size(); j++) {
                    CkksPlaintext y_pt = ctx.decrypt(y_list[i][j]);
                    vector<double> y_mg = ctx.decode(y_pt);
                    vector<double> y_true(n_slot, 0.0);
                    for (int k = 0; k < n_value; k++) {
                        y_true[(k - steps[j] + n_slot) % n_slot] = n_value - 1 - k + 1.0;
                    }
                    REQUIRE(compare_double_vectors_w_offset(y_mg, y_true, n_value, tolerance, -steps[j], n_slot) ==
                            false);
                }
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS rotate_row", "") {
    std::random_device rd;   // a seed source for the random number engine
    std::mt19937 gen(rd());  // mersenne_twister_engine seeded with rd()

    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;

    ctx.gen_rotation_keys();
    int n_value = n_slot;
    vector<vector<double>> x;
    for (int i = 0; i < n_op; i++) {
        vector<double> tmp;
        for (int j = 0; j < n_value; j++) {
            tmp.push_back(n_value - 1 - j + 1.0);
        }
        x.push_back(tmp);
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = ctx.encode(x_mg, level, default_scale);
                auto x_ct = ctx.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(ctx.new_ciphertext(level, default_scale));
            }
            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_rotate_row/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"arg_x", &x_list},
                CxxVectorArgument{"arg_y", &y_list},
            };
            gpu_project.run(&ctx, cxx_args);

            double tolerance = 1.0e-2;
            for (int i = 0; i < n_op; i++) {
                CkksPlaintext y_pt = ctx.decrypt(y_list[i]);
                vector<double> y_mg = ctx.decode(y_pt);

                REQUIRE(compare_double_vectors_w_offset(y_mg, x[i], n_value, tolerance, 0, n_slot) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS toy bootstrap", "") {
    CkksBtpParameter btp_param = CkksBtpParameter::create_toy_parameter();
    CkksBtpContext btp_context = CkksBtpContext::create_random_context(btp_param);
    default_scale = pow(2, 40);

    n_slot = btp_param.get_ckks_parameter().get_n() / 2;

    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;

    int n_value = n_slot;
    vector<vector<double>> x;
    for (int i = 0; i < n_op; i++) {
        vector<double> tmp;
        for (int j = 0; j < n_value; j++) {
            tmp.push_back(0.2);
        }
        x.push_back(tmp);
    }

    for (int level = 0; level <= 0; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = btp_context.encode(x_mg, level, default_scale);
                auto x_ct = btp_context.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(btp_context.new_ciphertext(9, default_scale));
            }
            string project_path =
                gpu_base_path + "/CKKS_" + to_string(n_op) + "_toy_bootstrap/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_y_list", &y_list},
            };
            gpu_project.run(&btp_context, cxx_args);

            double tolerance = 1.0e-2;
            for (int i = 0; i < n_op; i++) {
                CkksPlaintext y_pt = btp_context.decrypt(y_list[i]);
                vector<double> y_mg = btp_context.decode(y_pt);
                print_double_message(y_mg.data(), "z_mg", 4);
                REQUIRE(compare_double_vectors_w_offset(y_mg, x[i], n_value, tolerance, 0, n_slot) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS bootstrap", "") {
    CkksBtpParameter btp_param = CkksBtpParameter::create_parameter();
    CkksBtpContext btp_context = CkksBtpContext::create_random_context(btp_param);
    default_scale = pow(2, 40);

    n_slot = btp_param.get_ckks_parameter().get_n() / 2;

    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;

    int n_value = n_slot;
    vector<vector<double>> x;
    for (int i = 0; i < n_op; i++) {
        vector<double> tmp;
        for (int j = 0; j < n_value; j++) {
            tmp.push_back(0.27);
        }
        x.push_back(tmp);
    }

    for (int level = 0; level <= 0; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                auto x_pt = btp_context.encode(x_mg, level, default_scale);
                auto x_ct = btp_context.encrypt_asymmetric(x_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(btp_context.new_ciphertext(9, default_scale));
            }
            string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_bootstrap/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"out_y_list", &y_list},
            };
            gpu_project.run(&btp_context, cxx_args);

            double tolerance = 1.0e-2;
            for (int i = 0; i < n_op; i++) {
                CkksPlaintext y_pt = btp_context.decrypt(y_list[i]);
                vector<double> y_mg = btp_context.decode(y_pt);
                print_double_message(y_mg.data(), "z_mg", 4);
                REQUIRE(compare_double_vectors_w_offset(y_mg, x[i], n_value, tolerance, 0, n_slot) == false);
            }
        }
    }
};

TEST_CASE_METHOD(CkksGpuFixture, "CKKS cmc_relin rescale and bootstrap", "") {
    CkksBtpParameter btp_param = CkksBtpParameter::create_parameter();
    CkksBtpContext btp_context = CkksBtpContext::create_random_context(btp_param);
    default_scale = pow(2, 40);

    std::random_device rd;
    std::mt19937 gen(rd());

    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;
    vector<CkksCiphertext> z_list;

    vector<double> x(n_op);
    vector<double> y(n_op);
    vector<double> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x[i] = 0.2;
        y[i] = 0.3;
        z_true[i] = x[i] * y[i];
    }

    for (int level = 3; level <= 3; level++) {
        SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
            for (int i = 0; i < n_op; i++) {
                vector<double> x_mg{x[i]};
                vector<double> y_mg{y[i]};

                auto x_pt = btp_context.encode(x_mg, level, default_scale);
                auto y_pt = btp_context.encode(y_mg, level, default_scale);
                auto x_ct = btp_context.encrypt_asymmetric(x_pt);
                auto y_ct = btp_context.encrypt_asymmetric(y_pt);
                x_list.push_back(std::move(x_ct));
                y_list.push_back(std::move(y_ct));
                z_list.push_back(btp_context.new_ciphertext(9, default_scale * default_scale /
                                                                   btp_param.get_ckks_parameter().get_q(level)));
            }

            string project_path =
                gpu_base_path + "/CKKS_" + to_string(n_op) + "_cmc_relin_rescale_bootstrap/level_" + to_string(level);
            FheTaskGpu gpu_project(project_path);
            vector<CxxVectorArgument> cxx_args = {
                CxxVectorArgument{"in_x_list", &x_list},
                CxxVectorArgument{"in_y_list", &y_list},
                CxxVectorArgument{"out_z_list", &z_list},
            };
            gpu_project.run(&btp_context, cxx_args);

            double tolerance = 1.0e-3;
            for (int i = 0; i < n_op; i++) {
                auto z_pt = btp_context.decrypt(z_list[i]);
                auto z_mg = btp_context.decode(z_pt);
                print_double_message(z_mg.data(), "z_mg", 1);
                REQUIRE(compare_double_vectors(z_mg, vector<double>{z_true[i]}, 1, tolerance) == false);
            }
        }
    }
}

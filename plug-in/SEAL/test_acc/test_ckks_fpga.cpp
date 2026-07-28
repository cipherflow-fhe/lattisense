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
#include <dirent.h>
#include <math.h>
#include "utils.h"

using namespace seal;
using namespace seal::util;
using namespace std;

static const string ckks_fpga_base_path = fpga_base_path + "/ckks_param_fpga_n8192";

TEST_CASE_METHOD(TestCkksFpgaFixture, "CKKS cap", "") {
    seal::CKKSEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    vector<seal::Ciphertext> x_list, z_list;
    vector<seal::Plaintext> y_list;
    vector<double> x, y;
    vector<double> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 0.2);
        y.push_back(i + 3.1);
        z_true[i] = x[i] + y[i];
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<double> x_mg{x[i]};
            vector<double> y_mg{y[i]};
            print_double_message(x_mg.data(), "x_mg", 1);
            print_double_message(y_mg.data(), "y_mg", 1);

            seal::Plaintext x_pt, y_pt;
            encoder.encode(x_mg, default_scale, x_pt);
            encoder.encode(y_mg, default_scale, y_pt);

            seal::Ciphertext x_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);

            z_ct.resize(ctx, 2);
            z_ct.is_ntt_form() = true;
            z_ct.scale() = default_scale;

            x_list.push_back(x_ct);
            y_list.push_back(y_pt);
            z_list.push_back(z_ct);
        }

        string project_path = ckks_fpga_base_path + "/CKKS_" + to_string(n_op) + "_cap/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "in_y_list", &y_list},
            SealVectorArgument{param, "out_z_list", &z_list},
        };

        project.run(&ctx, nullptr, nullptr, seal_args);

        vector<double> z;
        double tolerance = 1.0e-5;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<double> z_mg;
            encoder.decode(z_pt, z_mg);
            print_double_message(z_mg.data(), "z_mg", 1);
            z.push_back(z_mg[0]);
        }
        REQUIRE(compare_double_vectors(z, z_true, n_op, tolerance) == false);
    }
}

TEST_CASE_METHOD(TestCkksFpgaFixture, "CKKS cac", "") {
    seal::CKKSEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    vector<seal::Ciphertext> x_list, y_list, z_list;
    vector<double> x, y;
    vector<double> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 0.2);
        y.push_back(i + 3.1);
        z_true[i] = x[i] + y[i];
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<double> x_mg{x[i]};
            vector<double> y_mg{y[i]};
            print_double_message(x_mg.data(), "x_mg", 1);
            print_double_message(y_mg.data(), "y_mg", 1);

            seal::Plaintext x_pt, y_pt;
            encoder.encode(x_mg, default_scale, x_pt);
            encoder.encode(y_mg, default_scale, y_pt);

            seal::Ciphertext x_ct, y_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);
            encryptor.encrypt(y_pt, y_ct);

            z_ct.resize(ctx, 2);
            z_ct.is_ntt_form() = true;
            z_ct.scale() = default_scale;

            x_list.push_back(x_ct);
            y_list.push_back(y_ct);
            z_list.push_back(z_ct);
        }

        string project_path = ckks_fpga_base_path + "/CKKS_" + to_string(n_op) + "_cac/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "in_y_list", &y_list},
            SealVectorArgument{param, "out_z_list", &z_list},
        };

        project.run(&ctx, nullptr, nullptr, seal_args);

        vector<double> z;
        double tolerance = 1.0e-5;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<double> z_mg;
            encoder.decode(z_pt, z_mg);
            print_double_message(z_mg.data(), "z_mg", 1);
            z.push_back(z_mg[0]);
        }
        REQUIRE(compare_double_vectors(z, z_true, n_op, tolerance) == false);
    }
}

TEST_CASE_METHOD(TestCkksFpgaFixture, "CKKS cmp", "") {
    seal::CKKSEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    vector<seal::Ciphertext> x_list, z_list;
    vector<seal::Plaintext> y_list;
    vector<double> x, y;
    vector<double> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 0.2);
        y.push_back(i + 3.1);
        z_true[i] = x[i] * y[i];
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<double> x_mg{x[i]};
            vector<double> y_mg{y[i]};
            print_double_message(x_mg.data(), "x_mg", 1);
            print_double_message(y_mg.data(), "y_mg", 1);

            seal::Plaintext x_pt, y_pt;
            encoder.encode(x_mg, default_scale, x_pt);
            encoder.encode(y_mg, default_scale, y_pt);

            seal::Ciphertext x_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);

            z_ct.resize(ctx, 2);
            z_ct.is_ntt_form() = true;
            z_ct.scale() = default_scale * default_scale;

            x_list.push_back(x_ct);
            y_list.push_back(y_pt);
            z_list.push_back(z_ct);
        }

        string project_path = ckks_fpga_base_path + "/CKKS_" + to_string(n_op) + "_cmp/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "in_y_list", &y_list},
            SealVectorArgument{param, "out_z_list", &z_list},
        };

        project.run(&ctx, nullptr, nullptr, seal_args);

        vector<double> z;
        double tolerance = 1.0e-5;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<double> z_mg;
            encoder.decode(z_pt, z_mg);
            print_double_message(z_mg.data(), "z_mg", 1);
            z.push_back(z_mg[0]);
        }
        REQUIRE(compare_double_vectors(z, z_true, n_op, tolerance) == false);
    }
}

TEST_CASE_METHOD(TestCkksFpgaFixture, "CKKS cmc_relin", "") {
    seal::CKKSEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Evaluator evaluator(ctx);

    vector<seal::Ciphertext> x_list, y_list, z_list;
    vector<double> x, y;
    vector<double> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 0.2);
        y.push_back(i + 3.1);
        z_true[i] = x[i] * y[i];
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<double> x_mg{x[i]};
            vector<double> y_mg{y[i]};
            print_double_message(x_mg.data(), "x_mg", 1);
            print_double_message(y_mg.data(), "y_mg", 1);

            seal::Plaintext x_pt, y_pt;
            encoder.encode(x_mg, default_scale, x_pt);
            encoder.encode(y_mg, default_scale, y_pt);

            seal::Ciphertext x_ct, y_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);
            encryptor.encrypt(y_pt, y_ct);

            z_ct.resize(ctx, 2);
            z_ct.is_ntt_form() = true;
            z_ct.scale() = default_scale * default_scale;

            x_list.push_back(x_ct);
            y_list.push_back(y_ct);
            z_list.push_back(z_ct);
        }

        string project_path = ckks_fpga_base_path + "/CKKS_" + to_string(n_op) + "_cmc_relin/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "in_y_list", &y_list},
            SealVectorArgument{param, "out_z_list", &z_list},
        };

        project.run(&ctx, &relin_keys, nullptr, seal_args);

        vector<double> z;
        double tolerance = 1.0e-5;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<double> z_mg;
            encoder.decode(z_pt, z_mg);
            print_double_message(z_mg.data(), "z_mg", 1);
            z.push_back(z_mg[0]);
        }
        REQUIRE(compare_double_vectors(z, z_true, n_op, tolerance) == false);
    }
}

TEST_CASE_METHOD(TestCkksFpgaFixture, "CKKS rescale", "") {
    seal::CKKSEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    Evaluator evaluator(ctx);

    vector<seal::Ciphertext> x_list, z_list;
    vector<double> x;
    vector<double> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 0.2);
        z_true[i] = x[i];
    }

    auto& context_data = *ctx.first_context_data();
    auto& next_context_data = *context_data.next_context_data();

    double scale = default_scale * (double)(context_data.parms().coeff_modulus().back().value());

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<double> x_mg{x[i]};
            print_double_message(x_mg.data(), "x_mg", 1);

            seal::Plaintext x_pt;
            encoder.encode(x_mg, scale, x_pt);

            seal::Ciphertext x_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);

            z_ct.resize(ctx, next_context_data.parms_id(), 2);

            z_ct.is_ntt_form() = true;
            z_ct.scale() = default_scale;

            x_list.push_back(x_ct);
            z_list.push_back(z_ct);
        }

        string project_path = ckks_fpga_base_path + "/CKKS_" + to_string(n_op) + "_rescale/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "out_y_list", &z_list},
        };

        project.run(&ctx, nullptr, nullptr, seal_args);

        vector<double> z;
        double tolerance = 1.0e-5;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<double> z_mg;
            encoder.decode(z_pt, z_mg);
            print_double_message(z_mg.data(), "z_mg", 1);
            z.push_back(z_mg[0]);
        }
        REQUIRE(compare_double_vectors(z, z_true, n_op, tolerance) == false);
    }
}

TEST_CASE_METHOD(TestCkksFpgaFixture, "CKKS drop level // mod_switch", "") {
    seal::CKKSEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    Evaluator evaluator(ctx);

    vector<seal::Ciphertext> x_list, z_list;
    vector<double> x;
    vector<double> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 0.2);
        z_true[i] = x[i];
    }

    int drop_level = 2;

    auto& context_data = *ctx.first_context_data();
    auto& next_next_context_data = *context_data.next_context_data()->next_context_data();

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<double> x_mg{x[i]};
            print_double_message(x_mg.data(), "x_mg", 1);

            seal::Plaintext x_pt;
            encoder.encode(x_mg, default_scale, x_pt);

            seal::Ciphertext x_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);

            z_ct.resize(ctx, next_next_context_data.parms_id(), 2);

            z_ct.is_ntt_form() = true;
            z_ct.scale() = default_scale;

            x_list.push_back(x_ct);
            z_list.push_back(z_ct);
        }

        string project_path = ckks_fpga_base_path + "/CKKS_" + to_string(n_op) + "_drop_level/level_" +
                              to_string(level) + "/drop_" + to_string(drop_level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "out_y_list", &z_list},
        };

        project.run(&ctx, nullptr, nullptr, seal_args);

        vector<double> z;
        double tolerance = 1.0e-5;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<double> z_mg;
            encoder.decode(z_pt, z_mg);
            print_double_message(z_mg.data(), "z_mg", 1);
            z.push_back(z_mg[0]);
        }
        REQUIRE(compare_double_vectors(z, z_true, n_op, tolerance) == false);
    }
}

TEST_CASE_METHOD(TestCkksFpgaFixture, "CKKS conjugate", "") {
    seal::CKKSEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Evaluator evaluator(ctx);

    vector<seal::Ciphertext> x_list;
    vector<seal::Ciphertext> y_list;

    int n_value = 4096;
    vector<vector<double>> x;
    for (int i = 0; i < n_op; i++) {
        vector<double> tmp;
        for (int j = 0; j < n_value; j++) {
            tmp.push_back(n_value - 1 - j + 1.0);
        }
        x.push_back(tmp);
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<double> x_mg{x[i]};
            seal::Plaintext x_pt;
            encoder.encode(x_mg, default_scale, x_pt);

            seal::Ciphertext x_ct, y_ct;
            encryptor.encrypt(x_pt, x_ct);

            y_ct.resize(ctx, 2);

            y_ct.is_ntt_form() = true;
            y_ct.scale() = default_scale;

            x_list.push_back(x_ct);
            y_list.push_back(y_ct);
        }

        string project_path =
            ckks_fpga_base_path + "/CKKS_" + to_string(n_op) + "_seal_rotate_row/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "arg_x", &x_list},
            SealVectorArgument{param, "arg_y", &y_list},
        };

        project.run(&ctx, nullptr, &gal_keys, seal_args);

        vector<double> z;
        double tolerance = 1.0e-3;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext y_pt;
            decryptor.decrypt(y_list[i], y_pt);
            vector<double> y_mg;
            encoder.decode(y_pt, y_mg);

            vector<uint64_t> y;
            for (int k = 0; k < n_value * 2; k++) {
                if (k < n_value) {
                    y.push_back(x[i][k + n_value]);
                } else {
                    y.push_back(x[i][k - n_value]);
                }
            }

            REQUIRE(compare_double_vectors_w_offset(y_mg, x[i], n_value, tolerance, 0, n_slot) == false);
        }
    }
}

TEST_CASE_METHOD(TestCkksFpgaFixture, "CKKS rotate", "") {
    seal::CKKSEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    vector<int32_t> steps = {-500, 20, 200, 2000, 4000};

    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Evaluator evaluator(ctx);

    vector<seal::Ciphertext> x_list;
    vector<vector<seal::Ciphertext>> y_list(n_op);

    int n_value = 4096;
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

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level) + ", steps=" + steps_str) {
        for (int i = 0; i < n_op; i++) {
            vector<double> x_mg{x[i]};
            seal::Plaintext x_pt;
            encoder.encode(x_mg, default_scale, x_pt);

            seal::Ciphertext x_ct;
            encryptor.encrypt(x_pt, x_ct);
            x_list.push_back(x_ct);

            for (int j = 0; j < steps.size(); j++) {
                seal::Ciphertext y_ct;
                y_ct.resize(ctx, 2);
                y_ct.is_ntt_form() = true;
                y_ct.scale() = default_scale;

                y_list[i].push_back(y_ct);
            }
        }

        string project_path = ckks_fpga_base_path + "/CKKS_" + to_string(n_op) + "_seal_rotate_col/level_" +
                              to_string(level) + "/steps_" + steps_str;
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "arg_x", &x_list},
            SealVectorArgument{param, "arg_y", &y_list},
        };

        project.run(&ctx, nullptr, &gal_keys, seal_args);

        vector<double> z;
        double tolerance = 1.0e-3;
        for (int i = 0; i < n_op; i++) {
            for (int j = 0; j < steps.size(); j++) {
                seal::Plaintext y_pt;
                decryptor.decrypt(y_list[i][j], y_pt);
                vector<double> y_mg;
                encoder.decode(y_pt, y_mg);
                vector<double> y_true(n_value, 0.0);
                for (int k = 0; k < n_value; k++) {
                    y_true[(k - steps[j] + n_value) % n_value] = n_value - 1 - k + 1.0;
                }
                REQUIRE(compare_double_vectors_w_offset(y_mg, y_true, n_value, tolerance, -steps[j], n_slot) == false);
            }
        }
    }
}

TEST_CASE_METHOD(TestCkksFpgaFixture, "CKKS advanced rotate", "") {
    seal::CKKSEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    vector<int32_t> steps = {-500, 20, 200, 2000, 4000};
    vector<int> steps_ = {-500, 20, 200, 2000, 4000};

    GaloisKeys gal_keys;
    keygen.create_galois_keys(steps_, gal_keys);

    Evaluator evaluator(ctx);

    vector<seal::Ciphertext> x_list;
    vector<vector<seal::Ciphertext>> y_list(n_op);

    int n_value = 4096;
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

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level) + ", steps=" + steps_str) {
        for (int i = 0; i < n_op; i++) {
            vector<double> x_mg{x[i]};
            seal::Plaintext x_pt;
            encoder.encode(x_mg, default_scale, x_pt);

            seal::Ciphertext x_ct;
            encryptor.encrypt(x_pt, x_ct);
            x_list.push_back(x_ct);

            for (int j = 0; j < steps.size(); j++) {
                seal::Ciphertext y_ct;
                y_ct.resize(ctx, 2);
                y_ct.is_ntt_form() = true;
                y_ct.scale() = default_scale;

                y_list[i].push_back(y_ct);
            }
        }

        string project_path = ckks_fpga_base_path + "/CKKS_" + to_string(n_op) + "_seal_advanced_rotate_col/level_" +
                              to_string(level) + "/steps_" + steps_str;
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "arg_x", &x_list},
            SealVectorArgument{param, "arg_y", &y_list},
        };

        project.run(&ctx, nullptr, &gal_keys, seal_args);

        vector<double> z;
        double tolerance = 1.0e-3;
        for (int i = 0; i < n_op; i++) {
            for (int j = 0; j < steps.size(); j++) {
                seal::Plaintext y_pt;
                decryptor.decrypt(y_list[i][j], y_pt);
                vector<double> y_mg;
                encoder.decode(y_pt, y_mg);
                vector<double> y_true(n_value, 0.0);
                for (int k = 0; k < n_value; k++) {
                    y_true[(k - steps[j] + n_value) % n_value] = n_value - 1 - k + 1.0;
                }
                REQUIRE(compare_double_vectors_w_offset(y_mg, y_true, n_value, tolerance, -steps[j], n_slot) == false);
            }
        }
    }
}

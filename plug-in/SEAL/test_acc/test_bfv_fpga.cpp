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

static const string bfv_fpga_base_path = fpga_base_path + "/bfv_param_fpga_n8192_t1b4001";

// TEST_CASE_METHOD(TestBfvFixture, "BFV cap", "") {
//     seal::BatchEncoder encoder(ctx);
//     seal::KeyGenerator keygen(ctx);
//     seal::SecretKey secret_key = keygen.secret_key();
//     seal::PublicKey public_key;
//     keygen.create_public_key(public_key);
//     seal::Encryptor encryptor(ctx, public_key);
//     seal::Decryptor decryptor(ctx, secret_key);

//     vector<seal::Ciphertext> x_list, z_list;
//     vector<seal::Plaintext> y_list;
//     vector<uint64_t> x, y;
//     vector<uint64_t> z_true(n_op);

//     for(int i = 0; i < n_op; i++) {
//         x.push_back(i);
//         y.push_back(i+3);
//         z_true[i] = (x[i]+y[i]) % t;
//     }

//     SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
//         for (int i = 0; i < n_op; i++) {
//             vector<uint64_t> x_mg{x[i]};
//             vector<uint64_t> y_mg{y[i]};
//             print_message(x_mg.data(), "x_mg", 1);
//             print_message(y_mg.data(), "y_mg", 1);

//             seal::Plaintext x_pt, y_pt;
//             encoder.encode(x_mg, x_pt);
//             encoder.encode(y_mg, y_pt);

//             seal::Ciphertext x_ct, z_ct;
//             encryptor.encrypt(x_pt, x_ct);
//             z_ct.resize(ctx, 2);

//             x_list.push_back(x_ct);
//             y_list.push_back(y_pt);
//             z_list.push_back(z_ct);
//         }

//         string project_path = base_path + "/BFV_" + to_string(n_op) + "_cap/level_" + to_string(level);
//         FheTaskFpga project(project_path);
//         vector<SealVectorArgument> seal_args = {
//             SealVectorArgument{param, "in_x_list", &x_list},
//             SealVectorArgument{param, "in_y_list", &y_list},
//             SealVectorArgument{param, "out_z_list", &z_list},
//         };

//         project.run(&ctx, nullptr, nullptr, seal_args);

//         vector<uint64_t> z;
//         for (int i = 0; i < n_op; i++) {
//             seal::Plaintext z_pt;
//             decryptor.decrypt(z_list[i], z_pt);
//             vector<uint64_t> z_mg;
//             encoder.decode(z_pt, z_mg);
//             print_message(z_mg.data(), "z_mg", 1);
//             z.push_back(z_mg[0]);
//         }

//         REQUIRE(z == z_true);
//     }

// }

TEST_CASE_METHOD(TestBfvFpgaFixture, "BFV cac", "") {
    seal::BatchEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    vector<seal::Ciphertext> x_list, y_list, z_list;
    vector<uint64_t> x, y;
    vector<uint64_t> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        x.push_back(i);
        y.push_back(i + 3);
        z_true[i] = (x[i] + y[i]) % t;
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<uint64_t> x_mg{x[i]};
            vector<uint64_t> y_mg{y[i]};
            print_message(x_mg.data(), "x_mg", 1);
            print_message(y_mg.data(), "y_mg", 1);

            seal::Plaintext x_pt, y_pt;
            encoder.encode(x_mg, x_pt);
            encoder.encode(y_mg, y_pt);

            seal::Ciphertext x_ct, y_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);
            encryptor.encrypt(y_pt, y_ct);
            z_ct.resize(ctx, 2);

            x_list.push_back(x_ct);
            y_list.push_back(y_ct);
            z_list.push_back(z_ct);
        }

        string project_path = bfv_fpga_base_path + "/BFV_" + to_string(n_op) + "_cac/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "in_y_list", &y_list},
            SealVectorArgument{param, "out_z_list", &z_list},
        };

        project.run(&ctx, nullptr, nullptr, seal_args);

        vector<uint64_t> z;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<uint64_t> z_mg;
            encoder.decode(z_pt, z_mg);
            print_message(z_mg.data(), "z_mg", 1);
            z.push_back(z_mg[0]);
        }

        REQUIRE(z == z_true);
    }
}

TEST_CASE_METHOD(TestBfvFpgaFixture, "BFV ct_mult_pt_ringt", "") {
    seal::BatchEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    vector<seal::Ciphertext> x_list;
    vector<seal::Plaintext> y_list;
    vector<seal::Ciphertext> z_list;

    vector<uint64_t> x;
    vector<uint64_t> y;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        x.push_back(i + 1);
        y.push_back(i + 10);
        z_true[i] = x[i] * y[i] % t;
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<uint64_t> x_mg{x[i]};
            vector<uint64_t> y_mg{y[i]};
            print_message(x_mg.data(), "x_mg", 1);
            print_message(y_mg.data(), "y_mg", 1);

            seal::Plaintext x_pt, y_pt;
            encoder.encode(x_mg, x_pt);
            encoder.encode(y_mg, y_pt);

            seal::Ciphertext x_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);
            z_ct.resize(ctx, 2);

            x_list.push_back(x_ct);
            y_list.push_back(y_pt);
            z_list.push_back(z_ct);
        }

        string project_path = bfv_fpga_base_path + "/BFV_" + to_string(n_op) + "_cmp_ringt/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "in_y_list", &y_list},
            SealVectorArgument{param, "out_z_list", &z_list},
        };

        project.run(&ctx, nullptr, nullptr, seal_args);

        vector<uint64_t> z;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<uint64_t> z_mg;
            encoder.decode(z_pt, z_mg);
            print_message(z_mg.data(), "z_mg", 1);
            z.push_back(z_mg[0]);
        }

        REQUIRE(z == z_true);
    }
}

TEST_CASE_METHOD(TestBfvFpgaFixture, "BFV cmc_relin", "") {
    seal::BatchEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    std::random_device rd;   // a seed source for the random number engine
    std::mt19937 gen(rd());  // mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<uint64_t> distrib(0, t - 1);

    vector<seal::Ciphertext> x_list, y_list, z_list;
    vector<uint64_t> x, y;

    vector<uint64_t> z_true(n_op);
    for (int i = 0; i < n_op; i++) {
        // x.push_back(distrib(gen));
        // y.push_back(distrib(gen));
        x.push_back(i);
        y.push_back(i + 1);
        z_true[i] = (x[i] * y[i]) % t;
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<uint64_t> x_mg{x[i]};
            vector<uint64_t> y_mg{y[i]};
            print_message(x_mg.data(), "x_mg", 1);
            print_message(y_mg.data(), "y_mg", 1);

            seal::Plaintext x_pt, y_pt;
            encoder.encode(x_mg, x_pt);
            encoder.encode(y_mg, y_pt);

            seal::Ciphertext x_ct, y_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);
            encryptor.encrypt(y_pt, y_ct);
            z_ct.resize(ctx, 2);

            x_list.push_back(x_ct);
            y_list.push_back(y_ct);
            z_list.push_back(z_ct);
        }

        string project_path = bfv_fpga_base_path + "/BFV_" + to_string(n_op) + "_cmc_relin/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "in_y_list", &y_list},
            SealVectorArgument{param, "out_z_list", &z_list},
        };

        project.run(&ctx, &relin_keys, nullptr, seal_args);

        vector<uint64_t> z;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<uint64_t> z_mg;
            encoder.decode(z_pt, z_mg);
            z.push_back(z_mg[0]);
        }

        REQUIRE(z == z_true);
    }
};

TEST_CASE_METHOD(TestBfvFpgaFixture, "BFV rescale // mod_switch", "") {
    seal::BatchEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    auto& ctx_data = *ctx.first_context_data();
    auto& next_ctx_data = *ctx_data.next_context_data();

    vector<seal::Ciphertext> x_list, z_list;

    vector<uint64_t> x;
    vector<uint64_t> z_true(n_op);

    for (int i = 0; i < n_op; i++) {
        x.push_back(i);
        z_true[i] = x[i] % t;
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            vector<uint64_t> x_mg{x[i]};
            print_message(x_mg.data(), "x_mg", 1);

            seal::Plaintext x_pt;
            encoder.encode(x_mg, x_pt);

            seal::Ciphertext x_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);
            z_ct.resize(ctx, next_ctx_data.parms_id(), 2);

            x_list.push_back(x_ct);
            z_list.push_back(z_ct);
        }

        string project_path = bfv_fpga_base_path + "/BFV_" + to_string(n_op) + "_rescale/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "out_y_list", &z_list},
        };

        project.run(&ctx, nullptr, nullptr, seal_args);

        vector<uint64_t> z;
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext z_pt;
            decryptor.decrypt(z_list[i], z_pt);
            vector<uint64_t> z_mg;
            encoder.decode(z_pt, z_mg);
            print_message(z_mg.data(), "z_mg", 1);
            z.push_back(z_mg[0]);
        }

        REQUIRE(z == z_true);
    }
}

TEST_CASE_METHOD(TestBfvFpgaFixture, "BFV rotate row", "") {
    seal::BatchEncoder encoder(ctx);
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

    vector<vector<uint64_t>> x_mgs;
    int n_col = n / 2;
    for (int i = 0; i < n_op; i++) {
        vector<uint64_t> x;
        for (int j = 0; j < 2 * n_col; j++) {
            x.push_back(i * 2 + j);
        }
        x_mgs.push_back(x);
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level)) {
        for (int i = 0; i < n_op; i++) {
            seal::Plaintext x_pt;
            encoder.encode(x_mgs[i], x_pt);

            seal::Ciphertext x_ct, y_ct;
            encryptor.encrypt(x_pt, x_ct);
            y_ct.resize(ctx, 2);

            x_list.push_back(x_ct);
            y_list.push_back(y_ct);
        }

        string project_path =
            bfv_fpga_base_path + "/BFV_" + to_string(n_op) + "_seal_rotate_row/level_" + to_string(level);
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "arg_x", &x_list},
            SealVectorArgument{param, "arg_y", &y_list},
        };

        project.run(&ctx, nullptr, &gal_keys, seal_args);

        for (int i = 0; i < n_op; i++) {
            seal::Plaintext y_pt;
            decryptor.decrypt(y_list[i], y_pt);
            vector<uint64_t> y_mg;
            encoder.decode(y_pt, y_mg);
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

TEST_CASE_METHOD(TestBfvFpgaFixture, "BFV rotate col", "") {
    seal::BatchEncoder encoder(ctx);
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
    vector<vector<seal::Ciphertext>> y_list(n_op);
    int n_col = n / 2;
    vector<vector<uint64_t>> x_mgs;
    for (int i = 0; i < n_op; i++) {
        vector<uint64_t> x;
        for (int j = 0; j < n_col; j++) {
            x.push_back(i * 2 + j);
        }
        x_mgs.push_back(x);
    }

    vector<int32_t> steps = {-900, 20, 400, 2000, 3009};
    string steps_str = "";
    for (int i = 0; i < steps.size(); i++) {
        steps_str += to_string(steps[i]);
        if (i < steps.size() - 1) {
            steps_str += "_";
        }
    }

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level) + ", steps=" + steps_str) {
        for (int i = 0; i < n_op; i++) {
            print_message(x_mgs[i].data(), "x_mg", 5);
            seal::Plaintext x_pt;
            encoder.encode(x_mgs[i], x_pt);

            seal::Ciphertext x_ct;
            encryptor.encrypt(x_pt, x_ct);
            x_list.push_back(x_ct);

            for (int j = 0; j < steps.size(); j++) {
                seal::Ciphertext y_ct;
                y_ct.resize(ctx, 2);
                y_list[i].push_back(y_ct);
            }
        }

        string project_path = bfv_fpga_base_path + "/BFV_" + to_string(n_op) + "_seal_rotate_col/level_" +
                              to_string(level) + "/steps_" + steps_str;
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "arg_x", &x_list},
            SealVectorArgument{param, "arg_y", &y_list},
        };

        project.run(&ctx, nullptr, &gal_keys, seal_args);

        for (int i = 0; i < n_op; i++) {
            for (int j = 0; j < steps.size(); j++) {
                seal::Plaintext y_pt;
                decryptor.decrypt(y_list[i][j], y_pt);
                vector<uint64_t> y_mg;
                encoder.decode(y_pt, y_mg);

                vector<uint64_t> y;
                for (int k = 0; k < n_col; k++) {
                    y.push_back(y_mg[(k - steps[j] + n_col) % n_col]);
                }

                REQUIRE(y == x_mgs[i]);
            }
        }
    }
}

TEST_CASE_METHOD(TestBfvFpgaFixture, "BFV advanced rotate col", "") {
    seal::BatchEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    vector<int32_t> steps = {-900, 20, 400, 2000, 3009};
    vector<int> steps_ = {-900, 20, 400, 2000, 3009};

    GaloisKeys gal_keys;
    keygen.create_galois_keys(steps_, gal_keys);

    Evaluator evaluator(ctx);

    vector<seal::Ciphertext> x_list;
    vector<vector<seal::Ciphertext>> y_list(n_op);
    int n_col = n / 2;
    vector<vector<uint64_t>> x_mgs;
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

    SECTION("n=" + to_string(n_op) + ", lv=" + to_string(level) + ", steps=" + steps_str) {
        for (int i = 0; i < n_op; i++) {
            print_message(x_mgs[i].data(), "x_mg", 5);
            seal::Plaintext x_pt;
            encoder.encode(x_mgs[i], x_pt);

            seal::Ciphertext x_ct;
            encryptor.encrypt(x_pt, x_ct);
            x_list.push_back(x_ct);

            for (int j = 0; j < steps.size(); j++) {
                seal::Ciphertext y_ct;
                y_ct.resize(ctx, 2);
                y_list[i].push_back(y_ct);
            }
        }

        string project_path = bfv_fpga_base_path + "/BFV_" + to_string(n_op) + "_seal_advanced_rotate_col/level_" +
                              to_string(level) + "/steps_" + steps_str;
        FheTaskFpga project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "arg_x", &x_list},
            SealVectorArgument{param, "arg_y", &y_list},
        };

        project.run(&ctx, nullptr, &gal_keys, seal_args);

        for (int i = 0; i < n_op; i++) {
            for (int j = 0; j < steps.size(); j++) {
                seal::Plaintext y_pt;
                decryptor.decrypt(y_list[i][j], y_pt);
                vector<uint64_t> y_mg;
                encoder.decode(y_pt, y_mg);

                vector<uint64_t> y;
                for (int k = 0; k < n_col; k++) {
                    y.push_back(y_mg[(k - steps[j] + n_col) % n_col]);
                }

                REQUIRE(y == x_mgs[i]);
            }
        }
    }
}

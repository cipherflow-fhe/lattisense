#include <algorithm>
#include <random>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "fixture.hpp"
#include <dirent.h>
#include <math.h>
#include "utils.h"
#include "runner.h"

using namespace seal;
using namespace seal::util;
using namespace std;

TEST_CASE_METHOD(TestCkksGpuFixture, "CKKS cap", "") {
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

        string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cap/level_" + to_string(level);
        FheTaskGpu project(project_path);
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

TEST_CASE_METHOD(TestCkksGpuFixture, "CKKS cac", "") {
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

        string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cac/level_" + to_string(level);
        FheTaskGpu project(project_path);
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

TEST_CASE_METHOD(TestCkksGpuFixture, "CKKS cmp", "") {
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

        string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cmp/level_" + to_string(level);
        FheTaskGpu project(project_path);
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

TEST_CASE_METHOD(TestCkksGpuFixture, "CKKS cmc_relin", "") {
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

        string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_cmc_relin/level_" + to_string(level);
        FheTaskGpu project(project_path);
        vector<SealVectorArgument> seal_args = {
            SealVectorArgument{param, "in_x_list", &x_list},
            SealVectorArgument{param, "in_y_list", &y_list},
            SealVectorArgument{param, "out_z_list", &z_list},
        };

        project.run(&ctx, &relin_keys, nullptr, seal_args);

        vector<double> z;
        double tolerance = 1.0e-4;
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

TEST_CASE_METHOD(TestCkksGpuFixture, "CKKS rescale", "") {
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

        string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_rescale/level_" + to_string(level);
        FheTaskGpu project(project_path);
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

TEST_CASE_METHOD(TestCkksGpuFixture, "CKKS drop level // mod_switch", "") {
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

        string project_path = gpu_base_path + "/CKKS_" + to_string(n_op) + "_drop_level/level_" + to_string(level) +
                              "/drop_" + to_string(drop_level);
        FheTaskGpu project(project_path);
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

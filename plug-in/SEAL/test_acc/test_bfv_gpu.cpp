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

TEST_CASE_METHOD(TestBfvGpuFixture, "BFV cap_ringt", "") {
    seal::BatchEncoder encoder(ctx);
    seal::KeyGenerator keygen(ctx);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Encryptor encryptor(ctx, public_key);
    seal::Decryptor decryptor(ctx, secret_key);

    vector<seal::Ciphertext> x_list, z_list;
    vector<seal::Plaintext> y_list;
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

            seal::Ciphertext x_ct, z_ct;
            encryptor.encrypt(x_pt, x_ct);
            z_ct.resize(ctx, 2);

            x_list.push_back(x_ct);
            y_list.push_back(y_pt);
            z_list.push_back(z_ct);
        }

        string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cap_ringt/level_" + to_string(level);
        FheTaskGpu project(project_path);
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

TEST_CASE_METHOD(TestBfvGpuFixture, "BFV cac", "") {
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

        string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cac/level_" + to_string(level);
        FheTaskGpu project(project_path);
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

TEST_CASE_METHOD(TestBfvGpuFixture, "BFV ct_mult_pt_ringt", "") {
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

        string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cmp_ringt/level_" + to_string(level);
        FheTaskGpu project(project_path);
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

TEST_CASE_METHOD(TestBfvGpuFixture, "BFV cmc_relin", "") {
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

        string project_path = gpu_base_path + "/BFV_" + to_string(n_op) + "_cmc_relin/level_" + to_string(level);
        FheTaskGpu project(project_path);
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

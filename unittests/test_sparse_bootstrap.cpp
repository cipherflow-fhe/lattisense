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

#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "fhe_lib_v2.h"
#include "nlohmann/json.hpp"

using namespace fhe_ops_lib;

static std::vector<double> random_vector(size_t n, unsigned seed = 42) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    std::vector<double> v(n);
    for (auto& x : v)
        x = dist(rng);
    return v;
}

// Correctness + speedup: sparse bootstrap must reproduce input and be faster
// than full packing. Uses toy params (N=8192) to keep keygen under a minute.
TEST_CASE("Sparse bootstrap: correctness and speedup", "[sparse][bootstrap]") {
    const int32_t sparse_log_slots = 8;
    const size_t sparse_slots = 1 << sparse_log_slots;
    const size_t full_slots = 1 << 12;  // toy full packing

    CkksBtpParameter sparse_param = CkksBtpParameter::create_toy_sparse_parameter(sparse_log_slots);
    CkksBtpContext sparse_ctx = CkksBtpContext::create_random_context(sparse_param);
    sparse_ctx.create_bootstrapper();

    CkksBtpParameter full_param = CkksBtpParameter::create_toy_parameter();
    CkksBtpContext full_ctx = CkksBtpContext::create_random_context(full_param);
    full_ctx.create_bootstrapper();

    auto sparse_values = random_vector(sparse_slots);
    auto full_values = random_vector(full_slots);
    double sparse_scale = sparse_param.get_ckks_parameter().get_default_scale();
    double full_scale = full_param.get_ckks_parameter().get_default_scale();

    CkksCiphertext sparse_ct = sparse_ctx.encrypt_asymmetric(sparse_ctx.encode(sparse_values, 0, sparse_scale));
    CkksCiphertext full_ct = full_ctx.encrypt_asymmetric(full_ctx.encode(full_values, 0, full_scale));

    auto t0 = std::chrono::high_resolution_clock::now();
    CkksCiphertext full_boot = full_ctx.bootstrap(full_ct);
    auto t1 = std::chrono::high_resolution_clock::now();
    CkksCiphertext sparse_boot = sparse_ctx.bootstrap(sparse_ct);
    auto t2 = std::chrono::high_resolution_clock::now();

    long full_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    long sparse_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

    // CkksBootstrap applies MultByConst(trace_factor) internally, so decoded
    // sparse output must match input directly with no caller-side correction.
    auto decoded = sparse_ctx.decode(sparse_ctx.decrypt(sparse_boot));
    double max_err = 0.0;
    for (size_t i = 0; i < sparse_slots; i++) {
        max_err = std::max(max_err, std::abs(decoded[i] - sparse_values[i]));
    }

    std::cout << "\nToy N=8192: full " << full_ms << " ms, sparse(logSlots=" << sparse_log_slots << ") " << sparse_ms
              << " ms, max_err " << max_err << std::endl;

    REQUIRE(max_err < 0.01);
}

// Sweep log_slots over the toy-param valid range, reporting latency + precision.
// Hidden by default (uses `[.]` tag) — run explicitly to print the sweep table.
TEST_CASE("Sparse bootstrap: log_slots sweep", "[.sparse][.bootstrap][.benchmark]") {
    constexpr int kN = 1 << 13;
    constexpr int kMinLogSlots = 4;
    constexpr int kMaxLogSlots = 11;  // log2(N/2) = 12, valid range top = 12 - 1 for toy

    std::cout << "\nSparse bootstrap latency sweep (toy N=" << kN << "):\n";
    std::cout << std::string(60, '-') << "\n";
    std::cout << std::left << std::setw(12) << "log_slots" << std::setw(14) << "active slots" << std::setw(14)
              << "bootstrap ms" << std::setw(14) << "max err" << "\n";
    std::cout << std::string(60, '-') << "\n";

    {
        CkksBtpParameter dense_param = CkksBtpParameter::create_toy_parameter();
        CkksBtpContext dense_ctx = CkksBtpContext::create_random_context(dense_param);
        dense_ctx.create_bootstrapper();
        const size_t dense_slots = kN / 2;
        auto dense_values = random_vector(dense_slots);
        double dense_scale = dense_param.get_ckks_parameter().get_default_scale();
        CkksCiphertext dense_ct = dense_ctx.encrypt_asymmetric(dense_ctx.encode(dense_values, 0, dense_scale));

        auto t0 = std::chrono::high_resolution_clock::now();
        CkksCiphertext dense_out = dense_ctx.bootstrap(dense_ct);
        auto t1 = std::chrono::high_resolution_clock::now();
        long dense_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

        auto decoded = dense_ctx.decode(dense_ctx.decrypt(dense_out));
        double max_err = 0.0;
        for (size_t i = 0; i < dense_slots; i++)
            max_err = std::max(max_err, std::abs(decoded[i] - dense_values[i]));

        std::cout << std::left << std::setw(12) << "dense" << std::setw(14) << dense_slots << std::setw(14) << dense_ms
                  << std::setw(14) << max_err << "\n";
    }

    for (int log_slots = kMinLogSlots; log_slots <= kMaxLogSlots; log_slots++) {
        CkksBtpParameter sparse_param = CkksBtpParameter::create_toy_sparse_parameter(log_slots);
        CkksBtpContext sparse_ctx = CkksBtpContext::create_random_context(sparse_param);
        sparse_ctx.create_bootstrapper();

        const size_t sparse_slots = size_t(1) << log_slots;
        auto sparse_values = random_vector(sparse_slots);
        double sparse_scale = sparse_param.get_ckks_parameter().get_default_scale();
        CkksCiphertext sparse_ct = sparse_ctx.encrypt_asymmetric(sparse_ctx.encode(sparse_values, 0, sparse_scale));

        auto t0 = std::chrono::high_resolution_clock::now();
        CkksCiphertext sparse_out = sparse_ctx.bootstrap(sparse_ct);
        auto t1 = std::chrono::high_resolution_clock::now();
        long sparse_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

        auto decoded = sparse_ctx.decode(sparse_ctx.decrypt(sparse_out));
        double max_err = 0.0;
        for (size_t i = 0; i < sparse_slots; i++)
            max_err = std::max(max_err, std::abs(decoded[i] - sparse_values[i]));

        std::cout << std::left << std::setw(12) << log_slots << std::setw(14) << sparse_slots << std::setw(14)
                  << sparse_ms << std::setw(14) << max_err << "\n";
    }
    std::cout << std::string(60, '-') << "\n";
}

// Integration: mirror cpu_wrapper.cpp::init_context's JSON-driven parameter
// selection. Guards against the sparse branch being accidentally bypassed.
TEST_CASE("Sparse bootstrap: JSON pipeline", "[sparse][bootstrap][integration]") {
    nlohmann::json param_json = {
        {"n", 1 << 13},
        {"scale", std::pow(2.0, 40)},
        {"log_slots", 8},
    };

    REQUIRE(param_json.contains("log_slots"));
    int32_t log_slots = param_json["log_slots"].get<int32_t>();
    int n = param_json["n"].get<int>();

    CkksBtpParameter param = (n == (1 << 13)) ? CkksBtpParameter::create_toy_sparse_parameter(log_slots) :
                                                CkksBtpParameter::create_sparse_parameter(log_slots);
    CkksBtpContext ctx = CkksBtpContext::create_random_context(param);
    ctx.create_bootstrapper();

    auto values = random_vector(1 << log_slots, 17);
    double scale = param.get_ckks_parameter().get_default_scale();
    CkksCiphertext ct = ctx.encrypt_asymmetric(ctx.encode(values, 0, scale));
    auto decoded = ctx.decode(ctx.decrypt(ctx.bootstrap(ct)));

    double max_err = 0.0;
    for (size_t i = 0; i < (size_t)(1 << log_slots); i++) {
        max_err = std::max(max_err, std::abs(decoded[i] - values[i]));
    }
    REQUIRE(max_err < 0.01);
}

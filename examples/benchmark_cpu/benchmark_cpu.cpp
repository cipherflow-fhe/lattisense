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

#include <cxx_sdk_v2/cxx_fhe_task.h>
#include <fhe_ops_lib/fhe_lib_v2.h>
#include <cmath>
#include <cstdio>
#include <cstring>

using namespace cxx_sdk_v2;

void benchmark_bfv_mult_relin() {
    const int n_op = 1024;
    const uint64_t n = 16384;
    const uint64_t t = 65537;
    const int level = 3;

    BfvParameter param = BfvParameter::create_parameter(n, t);
    BfvContext ctx = BfvContext::create_random_context(param);

    std::vector<BfvCiphertext> xs, ys, zs;
    for (int i = 0; i < n_op; i++) {
        std::vector<uint64_t> x_mg = {uint64_t(i + 2)};
        std::vector<uint64_t> y_mg = {uint64_t(i + 3)};
        xs.push_back(ctx.encrypt_asymmetric(ctx.encode(x_mg, level)));
        ys.push_back(ctx.encrypt_asymmetric(ctx.encode(y_mg, level)));
        zs.push_back(ctx.new_ciphertext(level));
    }

    FheTaskCpu task("bfv_mult_relin");
    std::vector<CxxVectorArgument> args = {{"xs", &xs}, {"ys", &ys}, {"zs", &zs}};
    uint64_t time_ns = task.run(&ctx, args);

    printf("BFV mult_relin: %d ops, %.2f ms, %.1f ops/sec\n", n_op, time_ns / 1.0e6, n_op / (time_ns / 1.0e9));
}

void benchmark_ckks_mult_relin() {
    const int n_op = 1024;
    const uint64_t n = 16384;
    const double scale = pow(2, 40);
    const int level = 3;

    CkksParameter param = CkksParameter::create_parameter(n);
    CkksContext ctx = CkksContext::create_random_context(param);

    std::vector<CkksCiphertext> xs, ys, zs;
    for (int i = 0; i < n_op; i++) {
        std::vector<double> x_mg = {double(i + 2)};
        std::vector<double> y_mg = {double(i + 3)};
        xs.push_back(ctx.encrypt_asymmetric(ctx.encode(x_mg, level, scale)));
        ys.push_back(ctx.encrypt_asymmetric(ctx.encode(y_mg, level, scale)));
        zs.push_back(ctx.new_ciphertext(level, scale * scale));
    }

    FheTaskCpu task("ckks_mult_relin");
    std::vector<CxxVectorArgument> args = {{"xs", &xs}, {"ys", &ys}, {"zs", &zs}};
    uint64_t time_ns = task.run(&ctx, args);

    printf("CKKS mult_relin: %d ops, %.2f ms, %.1f ops/sec\n", n_op, time_ns / 1.0e6, n_op / (time_ns / 1.0e9));
}

void benchmark_bfv_rotate_col() {
    const int n_op = 1024;
    const uint64_t n = 16384;
    const uint64_t t = 65537;
    const int level = 3;

    BfvParameter param = BfvParameter::create_parameter(n, t);
    BfvContext ctx = BfvContext::create_random_context(param);
    ctx.gen_rotation_keys();

    std::vector<BfvCiphertext> xs, ys;
    for (int i = 0; i < n_op; i++) {
        std::vector<uint64_t> x_mg(n / 2);
        for (uint64_t j = 0; j < n / 2; j++)
            x_mg[j] = i + j;
        xs.push_back(ctx.encrypt_asymmetric(ctx.encode(x_mg, level)));
        ys.push_back(ctx.new_ciphertext(level));
    }

    FheTaskCpu task("bfv_rotate_col");
    std::vector<CxxVectorArgument> args = {{"xs", &xs}, {"ys", &ys}};
    uint64_t time_ns = task.run(&ctx, args);

    printf("BFV rotate_col: %d ops, %.2f ms, %.1f ops/sec\n", n_op, time_ns / 1.0e6, n_op / (time_ns / 1.0e9));
}

int main(int argc, char* argv[]) {
    const char* help = "Usage: benchmark_cpu <0|1|2|all>\n"
                       "  0: BFV mult_relin\n"
                       "  1: CKKS mult_relin\n"
                       "  2: BFV rotate_col\n"
                       "  all: Run all benchmarks\n";

    if (argc != 2) {
        printf("%s", help);
        return 0;
    }

    if (strcmp(argv[1], "0") == 0) {
        benchmark_bfv_mult_relin();
    } else if (strcmp(argv[1], "1") == 0) {
        benchmark_ckks_mult_relin();
    } else if (strcmp(argv[1], "2") == 0) {
        benchmark_bfv_rotate_col();
    } else if (strcmp(argv[1], "all") == 0) {
        benchmark_bfv_mult_relin();
        benchmark_ckks_mult_relin();
        benchmark_bfv_rotate_col();
    } else {
        printf("%s", help);
    }
    return 0;
}

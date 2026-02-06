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

/**
 * FHE SDK Project Template
 *
 * This example demonstrates BFV ciphertext multiplication using LattiSense.
 * Before running this program, generate the computation graph by running:
 *   python3 bfv_mult.py
 */

#include <fhe_ops_lib/fhe_lib_v2.h>
#include <cxx_sdk_v2/cxx_fhe_task.h>

#include <cstdio>
#include <vector>

using namespace cxx_sdk_v2;
using namespace std;

int main() {
    // Initialize BFV parameters (must match bfv_mult.py)
    uint64_t n = 16384;
    uint64_t t = 65537;
    BfvParameter param = BfvParameter::create_parameter(n, t);
    BfvContext context = BfvContext::create_random_context(param);
    int level = 3;

    // Prepare input data
    vector<uint64_t> x_mg({5, 10});
    vector<uint64_t> y_mg({2, 3});

    // Encode and encrypt
    BfvCiphertext x_ct = context.encrypt_asymmetric(context.encode(x_mg, level));
    BfvCiphertext y_ct = context.encrypt_asymmetric(context.encode(y_mg, level));
    BfvCiphertext z_ct = context.new_ciphertext(level);

    // Load and execute FHE task
    FheTaskCpu task("bfv_mult");
    vector<CxxVectorArgument> args = {
        {"x", &x_ct},
        {"y", &y_ct},
        {"z", &z_ct},
    };
    task.run(&context, args);

    // Decrypt and verify result
    vector<uint64_t> z_mg = context.decode(context.decrypt(z_ct));

    printf("=== BFV Multiplication Example ===\n");
    printf("x = [%lu, %lu]\n", x_mg[0], x_mg[1]);
    printf("y = [%lu, %lu]\n", y_mg[0], y_mg[1]);
    printf("z = x * y = [%lu, %lu]\n", z_mg[0], z_mg[1]);
    printf("Expected:   [10, 30]\n");

    // Verify correctness
    if (z_mg[0] == 10 && z_mg[1] == 30) {
        printf("\nSUCCESS: FHE SDK is working correctly!\n");
        return 0;
    } else {
        printf("\nERROR: Unexpected result!\n");
        return 1;
    }
}

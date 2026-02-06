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

#include <cstdio>

using namespace cxx_sdk_v2;
using namespace std;

void bfv_poly_7_cpu() {
    uint64_t n = 16384;
    uint64_t t = 65537;
    BfvParameter param = BfvParameter::create_parameter(n, t);
    BfvContext context = BfvContext::create_random_context(param);

    vector<uint64_t> x_mg({1, 2, 3, 4});
    vector<uint64_t> a0_mg({1, 1, 1, 1});
    vector<vector<uint64_t>> a_mg;
    for (uint64_t i = 0; i < 7; i++) {
        a_mg.push_back({i + 2, i + 2, i + 2, i + 2});
    }
    BfvPlaintext x_pt = context.encode(x_mg, 4);
    BfvPlaintext a0_pt = context.encode(a0_mg, 1);
    vector<BfvPlaintextMul> a_pt_mul;
    for (int i = 0; i < 7; i++) {
        a_pt_mul.push_back(context.encode_mul(a_mg[i], 1));
    }
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    BfvCiphertext y_ct = context.new_ciphertext(1);

    FheTaskCpu cpu_project("project");
    vector<CxxVectorArgument> cxx_args = {
        {"x", &x_ct},
        {"a0", &a0_pt},
        {"a", &a_pt_mul},
        {"y", &y_ct},
    };
    cpu_project.run(&context, cxx_args);

    BfvPlaintext y_pt = context.decrypt(y_ct);
    vector<uint64_t> y_mg = context.decode(y_pt);

    printf("BFV order-7 polynomial evaluation, computed by CPU\n");
    print_message(x_mg.data(), "x_mg", 4);
    print_message(a0_mg.data(), "a0_mg", 4);
    for (int i = 0; i < 7; i++) {
        print_message(a_mg[i].data(), ("a" + to_string(i + 1) + "_mg").c_str(), 4);
    }
    print_message(y_mg.data(), "y_mg", 4);
}

int main() {
    bfv_poly_7_cpu();
    return 0;
}

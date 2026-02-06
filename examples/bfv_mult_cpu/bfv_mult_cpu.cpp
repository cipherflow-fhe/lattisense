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

void bfv_mult_cpu() {
    uint64_t n = 16384;
    uint64_t t = 65537;
    BfvParameter param = BfvParameter::create_parameter(n, t);
    BfvContext context = BfvContext::create_random_context(param);
    int level = 3;

    vector<uint64_t> x_mg({5, 10});
    vector<uint64_t> y_mg({2, 3});
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintext y_pt = context.encode(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);
    BfvCiphertext z_ct = context.new_ciphertext(level);

    vector<CxxVectorArgument> cxx_args = {
        {"x", &x_ct},
        {"y", &y_ct},
        {"z", &z_ct},
    };

    string project_path = "bfv_mult_cpu";
    FheTaskCpu cpu_project(project_path);
    cpu_project.run(&context, cxx_args);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode(z_pt);

    printf("BFV ct-ct multiplication and relinerization, computed by CPU\n");
    print_message(x_mg.data(), "x_mg", 2);
    print_message(y_mg.data(), "y_mg", 2);
    print_message(z_mg.data(), "z_mg", 2);
}

int main() {
    bfv_mult_cpu();

    return 0;
}

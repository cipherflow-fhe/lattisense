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

void ckks_mult_cpu() {
    int N = 16384;
    CkksParameter param = CkksParameter::create_parameter(N);
    CkksContext context = CkksContext::create_random_context(param);
    int level = 3;
    double default_scale = param.get_default_scale();

    vector<double> x_mg({5.0, 10.0});
    vector<double> y_mg({2.0, 3.0});
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    FheTaskCpu cpu_project("project");
    CkksCiphertext z_ct = context.new_ciphertext(level - 1, default_scale * default_scale / param.get_q(level));
    vector<CxxVectorArgument> cxx_args = {
        {"x", &x_ct},
        {"y", &y_ct},
        {"z", &z_ct},
    };
    cpu_project.run(&context, cxx_args);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    printf("CKKS ct-ct multiplication, relinerization, and rescale, computed by CPU\n");
    print_double_message(x_mg.data(), "x_mg", 2);
    print_double_message(y_mg.data(), "y_mg", 2);
    print_double_message(z_mg.data(), "z_mg", 2);
}

int main() {
    ckks_mult_cpu();
    return 0;
}

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
#include <vector>

using namespace lattisense;
using namespace std;

void ckks_sparse_bootstrap_cpu() {
    constexpr int log_slots = 8;
    constexpr int sparse_slots = 1 << log_slots;

    CkksBtpParameter btp_param = CkksBtpParameter::create_toy_sparse_parameter(log_slots);
    CkksBtpContext btp_ctx = CkksBtpContext::create_random_context(btp_param);
    btp_ctx.create_bootstrapper();

    double scale = btp_param.get_ckks_parameter().get_default_scale();
    vector<double> x_mg(sparse_slots);
    for (int i = 0; i < sparse_slots; i++)
        x_mg[i] = 0.5 * cos(2.0 * M_PI * i / sparse_slots);

    CkksCiphertext x_ct = btp_ctx.encrypt_asymmetric(btp_ctx.encode(x_mg, 0, scale));
    CkksCiphertext y_ct = btp_ctx.new_ciphertext(9, scale);

    FheTaskCpu cpu_project("project");
    vector<CxxVectorArgument> cxx_args = {
        {"x", &x_ct},
        {"y", &y_ct},
    };
    cpu_project.run(&btp_ctx, cxx_args);

    vector<double> y_mg = btp_ctx.decode(btp_ctx.decrypt(y_ct));

    double max_err = 0.0;
    for (int i = 0; i < sparse_slots; i++)
        max_err = std::max(max_err, std::abs(y_mg[i] - x_mg[i]));

    printf("CKKS sparse bootstrap (log_slots=%d, n=%d), CPU\n", log_slots, btp_param.get_ckks_parameter().get_n());
    print_double_message(x_mg.data(), "x_mg (input, first 4 slots)", 4);
    print_double_message(y_mg.data(), "y_mg (bootstrapped, first 4 slots)", 4);
    printf("max abs error over active %d slots: %.3e\n", sparse_slots, max_err);
}

int main() {
    ckks_sparse_bootstrap_cpu();
    return 0;
}

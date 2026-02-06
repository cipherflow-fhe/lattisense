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

#include <algorithm>
#include <cstdio>
#include <iostream>

using namespace std;
using namespace cxx_sdk_v2;

void ckks_euclidean_distance_cpu() {
    int level = 3;
    int n_ct = 1;
    int pack = 4;
    int skip = 256;
    int N = 16384;
    CkksParameter param = CkksParameter::create_parameter(N);
    CkksContext ctx = CkksContext::create_random_context(param);
    double default_scale = param.get_default_scale();

    ctx.gen_rotation_keys();

    vector<CkksCiphertext> x_input;
    vector<CkksCiphertext> w_input_inv;
    vector<double> x_values;  // Store packed x values for printing
    vector<double> w_values;  // Store packed w values for printing
    double t_distance = 0;
    for (int i = 0; i < n_ct; i++) {
        const int size = 4096;
        vector<double> x(size, 0.0);
        vector<double> w(size, 0.0);
        srand(time(0));
        double u = 0;
        for (int j = 0; j < pack; j++) {
            x[j * skip] = (double)rand() / RAND_MAX * 2 - 1;
            w[j * skip] = (double)rand() / RAND_MAX * 2 - 1;
            x_values.push_back(x[j * skip]);
            w_values.push_back(w[j * skip]);
            u += pow((x[j * skip] - w[j * skip]), 2);
        }
        t_distance += u;
        vector<double> w_inv(w.size());  // trans w_mg to its inverse
        std::transform(w.begin(), w.end(), w_inv.begin(), [](double d) { return -d; });

        auto x_pt = ctx.encode(x, level, default_scale);
        auto x_ct = ctx.encrypt_asymmetric(x_pt);
        auto w_inv_pt = ctx.encode(w_inv, level, default_scale);
        auto w_inv_ct = ctx.encrypt_asymmetric(w_inv_pt);
        x_input.push_back(std::move(x_ct));
        w_input_inv.push_back(std::move(w_inv_ct));
    }
    auto d_ct = ctx.new_ciphertext(level - 2, default_scale * default_scale * default_scale / param.get_q(level) /
                                                  param.get_q(level - 1));
    vector<double> mask{1.0};
    auto mask_pt = ctx.encode_ringt(mask, default_scale);

    FheTaskCpu cpu_project("project");
    vector<CxxVectorArgument> cxx_args = {
        {"x_input", &x_input},
        {"w_input_inv", &w_input_inv},
        {"mask", &mask_pt},
        {"d", &d_ct},
    };
    cpu_project.run(&ctx, cxx_args);

    CkksPlaintext d_pt = ctx.decrypt(d_ct);
    vector<double> d_mg = ctx.decode(d_pt);

    cout << "CKKS euclidean distance of two packed vectors, computed by CPU" << endl;
    print_double_message(x_values.data(), "x", x_values.size());
    print_double_message(w_values.data(), "w", w_values.size());
    print_double_message(d_mg.data(), "distance", 8);
    cout << "expected euclidean distance = " << t_distance << endl;
}

int main() {
    ckks_euclidean_distance_cpu();
    return 0;
}

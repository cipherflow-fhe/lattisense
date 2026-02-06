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
#include <iomanip>
#include <iostream>
#include <map>
#include <string>

using namespace std;
using namespace cxx_sdk_v2;

void ckks_logistic_regression_cpu() {
    int level = 3;
    int n_input_feature = 30;
    int N = 16384;
    CkksParameter param = CkksParameter::create_parameter(N);
    CkksContext ctx = CkksContext::create_random_context(param);
    double default_scale = param.get_default_scale();

    ctx.gen_rotation_keys();

    vector<double> x_mg{
        0.04207487339675331,  -0.954683801149814,  0.09197705756340246, -0.27253446447507956, 0.18750564232192835,
        0.5840745966505123,   0.4062792877225865,  0.4622266401590458,  0.3727272727272728,   0.21103622577927572,
        -0.2877059569074779,  -0.7590611739745403, -0.2619328087452292, -0.45237748366635655, -0.6814087092497536,
        -0.29720311232613317, -0.7286363636363636, -0.3987497632127297, -0.3767096302133168,  -0.6339151223691666,
        0.24155104944859485,  -0.716950959488273,  0.336620349619005,   -0.09860401101061744, 0.20227167668229562,
        0.23858311261169463,  0.13722044728434502, 0.8240549828178696,  0.19692489651094025,  -0.16227207136298039};
    vector<double> w_mg{
        -0.38779230675573784, -0.08020498791940865, -0.42494960644275187, -0.3011337927885834, 0.19736016953065058,
        -0.3452779920215878,  -0.678324870145478,   -0.8177783668067259,  0.15226510934692553, 0.5859673866284915,
        0.01255264233893136,  0.4752989745604508,   0.05023635251466458,  0.11310208234475544, 0.5530291648269257,
        0.12287678195417821,  0.3339257590342935,   0.07939103265266986,  0.5650923127926508,  0.44168413736941736,
        -0.5564150081657178,  -0.2552746866713479,  -0.544768402633023,   -0.3273054244777431, -0.05454841442127498,
        -0.3247696994741705,  -0.498143298043605,   -1.092540674562078,   0.08402652360008195, 0.16040344319412192};
    vector<double> b_mg{0.430568328365614};
    vector<double> mask{1.0};

    auto x_pt = ctx.encode(x_mg, level, default_scale);
    auto x_ct = ctx.encrypt_asymmetric(x_pt);
    auto w_pt = ctx.encode_ringt(w_mg, default_scale);
    auto b_pt = ctx.encode(b_mg, level - 1, default_scale * default_scale / param.get_q(level));
    auto mask_pt = ctx.encode_ringt(mask, default_scale);
    auto y_ct = ctx.new_ciphertext(level - 2, default_scale * default_scale * default_scale / param.get_q(level) /
                                                  param.get_q(level - 1));

    FheTaskCpu cpu_project("project");
    vector<CxxVectorArgument> cxx_args = {
        {"x", &x_ct}, {"w", &w_pt}, {"b", &b_pt}, {"mask", &mask_pt}, {"y", &y_ct},
    };
    cpu_project.run(&ctx, cxx_args);

    CkksPlaintext y_pt = ctx.decrypt(y_ct);
    vector<double> y_mg = ctx.decode(y_pt);

    printf("CKKS logistic regression, computed by CPU\n");
    print_double_message(x_mg.data(), "x_mg", 8);
    print_double_message(w_mg.data(), "w_mg", 8);
    print_double_message(b_mg.data(), "b_mg", 1);
    print_double_message(mask.data(), "mask", 1);
    print_double_message(y_mg.data(), "y_mg", 8);
}

int main() {
    ckks_logistic_regression_cpu();
    return 0;
}

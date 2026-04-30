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

void ckks_sparse_bootstrap(bool is_toy = false, const vector<int>& sparse_slots = {2, 8, 6, 10}) {
    CkksBtpParameter param;
    if (is_toy) {
        param = CkksBtpParameter::create_toy_parameter();
    } else {
        param = CkksBtpParameter::create_parameter();
    }
    CkksBtpContext btp_context = CkksBtpContext::create_random_context(param);

    SecretKey sk = btp_context.extract_secret_key();
    for (int slots : sparse_slots) {
        btp_context.generate_sparse_bootstrapper(slots, sk, is_toy);
    }

    int level = 0;
    double default_scale = param.get_ckks_parameter().get_default_scale();

    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;
    vector<vector<double>> x_true_list;

    for (int i = 0; i < sparse_slots.size(); i++) {
        int current_slots = sparse_slots[i];
        int num_slots = 1 << current_slots;
        int verify_data_len = std::min(10, num_slots);

        vector<double> x_mg(num_slots);
        for (int j = 0; j < verify_data_len; j++) {
            x_mg[j] = double(0.5 + j * 0.1);
        }
        x_true_list.push_back(x_mg);

        auto x_pt = btp_context.encode_with_slots(x_mg, level, default_scale, current_slots);
        auto x_ct = btp_context.encrypt_symmetric(x_pt);
        x_list.push_back(std::move(x_ct));
        y_list.push_back(btp_context.new_ciphertext(9, default_scale));
    }

    string sparse_slots_str = "[";
    for (int i = 0; i < sparse_slots.size(); i++) {
        sparse_slots_str += to_string(sparse_slots[i]);
        if (i != sparse_slots.size() - 1) {
            sparse_slots_str += ", ";
        }
    }
    sparse_slots_str += "]";
    string project_path = "project_";
    if (is_toy) {
        project_path += "toy";
    } else {
        project_path += "default";
    }
    project_path += "_sparse_bootstrap/slots_" + sparse_slots_str;
    FheTaskCpu cpu_project(project_path);

    vector<CxxVectorArgument> cxx_args = {
        CxxVectorArgument{"in_x_list", &x_list},
        CxxVectorArgument{"out_y_list", &y_list},
    };
    cpu_project.run(&btp_context, cxx_args);

    for (int i = 0; i < sparse_slots.size(); i++) {
        int current_slots = sparse_slots[i];
        int num_slots = 1 << current_slots;
        int verify_data_len = std::min(10, num_slots);

        auto z_pt = btp_context.decrypt(y_list[i]);
        auto z_mg = btp_context.decode(z_pt);
        print_double_message(z_mg.data(), ("z_mg (slots=" + to_string(current_slots) + ")").c_str(), verify_data_len);
    }
}

int main() {
    ckks_sparse_bootstrap();
    return 0;
}

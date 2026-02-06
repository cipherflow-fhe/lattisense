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

#include <cmath>
#include <cstdio>
#include <tuple>

#include "fhe_ops_lib/fhe_lib_v2.h"

using namespace fhe_ops_lib;
using namespace std;

tuple<CkksContext, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>> client_phase_0() {
    int N = 16384;
    CkksParameter param = CkksParameter::create_parameter(N);
    CkksContext ctx = CkksContext::create_random_context(param);
    int level = 3;
    double default_scale = param.get_default_scale();

    vector<double> x_mg({5.0, 10.0});
    vector<double> y_mg({2.0, 3.0});
    CkksPlaintext x_pt = ctx.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = ctx.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = ctx.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = ctx.encrypt_asymmetric(y_pt);

    CkksContext public_ctx = ctx.make_public_context();
    vector<uint8_t> public_ctx_bin = public_ctx.serialize();
    vector<uint8_t> x_bin = x_ct.serialize(param);
    vector<uint8_t> y_bin = y_ct.serialize(param);

    print_double_message(x_mg.data(), "x_mg", 2);
    print_double_message(y_mg.data(), "y_mg", 2);

    return {std::move(ctx), public_ctx_bin, x_bin, y_bin};
}

vector<uint8_t>
server_phase_1(const vector<uint8_t>& ctx_bin, const vector<uint8_t>& x_bin, const vector<uint8_t>& y_bin) {
    CkksContext public_context = CkksContext::deserialize(ctx_bin);
    CkksCiphertext x_ct = CkksCiphertext::deserialize(x_bin);
    CkksCiphertext y_ct = CkksCiphertext::deserialize(y_bin);

    CkksCiphertext3 z_ct3 = public_context.mult(x_ct, y_ct);
    CkksCiphertext z_ct = public_context.relinearize(z_ct3);

    vector<uint8_t> z_bin = z_ct.serialize(public_context.get_parameter());

    return z_bin;
}

void client_phase_2(CkksContext& ctx, const vector<uint8_t>& z_bin) {
    CkksCiphertext z_ct = CkksCiphertext::deserialize(z_bin);
    CkksPlaintext z_pt = ctx.decrypt(z_ct);
    vector<double> z_mg = ctx.decode(z_pt);

    print_double_message(z_mg.data(), "z_mg", 2);
}

int main() {
    printf("CKKS two-party encrypted computation with serialization\n");
    auto [ctx, public_ctx_bin, x_bin, y_bin] = client_phase_0();
    vector<uint8_t> z_bin = server_phase_1(public_ctx_bin, x_bin, y_bin);
    client_phase_2(ctx, z_bin);
}

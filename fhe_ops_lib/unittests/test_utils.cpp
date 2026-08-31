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

#include "test_utils.h"

#include <cstdint>
#include <utility>

using namespace fhe_ops_lib;
using namespace std;

vector<EncodingCase> encoding_cases() {
    return {{"batched encoding", false, true},
            {"coefficient encoding", false, false},
            {"ring-t batched encoding", true, true},
            {"ring-t coefficient encoding", true, false}};
}

vector<EncryptorCase> encryptor_cases() {
    return {{"public-key encryption", EncryptorType::PUBLIC_KEY}, {"secret-key encryption", EncryptorType::SECRET_KEY}};
}

int ckks_message_size(const CkksParameter& param, bool is_batched, int log_slots) {
    if (!is_batched) {
        return param.n();
    }
    return 1 << (log_slots >= 0 ? log_slots : param.log_max_slots());
}

BfvTestPt new_pt(BfvContext& ctx, int level, bool is_ringt, bool is_batched) {
    const BfvParameter& param = ctx.parameter();
    vector<uint64_t> message = rand_values(param.n(), param.t());
    BfvPlaintext plaintext(param, plaintext_metadata(is_ringt, is_batched, level));
    ctx.encode(message, plaintext);
    return {std::move(message), std::move(plaintext)};
}

BfvTestCt new_ct(BfvContext& ctx, int level, bool is_batched) {
    BfvTestPt plaintext = new_pt(ctx, level, false, is_batched);
    BfvCiphertext ciphertext = ctx.encrypt(plaintext.plaintext);
    return {std::move(plaintext.message), std::move(ciphertext)};
}

CkksRealTestPt new_real_pt(CkksContext& ctx, int level, bool is_ringt, bool is_batched, int log_slots) {
    const CkksParameter& param = ctx.parameter();
    const int plaintext_log_slots = log_slots >= 0 ? log_slots : param.log_max_slots();
    vector<double> message = rand_real_values(ckks_message_size(param, is_batched, log_slots));
    CkksPlaintext plaintext(
        param, plaintext_metadata(is_ringt, is_batched, level, plaintext_log_slots, param.default_scale()));
    ctx.encode(message, plaintext);
    return {std::move(message), std::move(plaintext)};
}

CkksComplexTestPt new_complex_pt(CkksContext& ctx, int level, bool is_ringt, int log_slots) {
    const CkksParameter& param = ctx.parameter();
    const int plaintext_log_slots = log_slots >= 0 ? log_slots : param.log_max_slots();
    vector<complex<double>> message = rand_complex_values(ckks_message_size(param, true, log_slots));
    CkksPlaintext plaintext(param,
                            plaintext_metadata(is_ringt, true, level, plaintext_log_slots, param.default_scale()));
    ctx.encode(message, plaintext);
    return {std::move(message), std::move(plaintext)};
}

CkksRealTestCt new_real_ct(CkksContext& ctx, int level, bool is_batched, int log_slots) {
    const CkksParameter& param = ctx.parameter();
    const int plaintext_log_slots = log_slots >= 0 ? log_slots : param.log_max_slots();
    vector<double> message = rand_real_values(ckks_message_size(param, is_batched, log_slots));
    CkksPlaintext plaintext(param,
                            plaintext_metadata(false, is_batched, level, plaintext_log_slots, param.default_scale()));
    ctx.encode(message, plaintext);
    CkksCiphertext ciphertext = ctx.encrypt(plaintext);
    return {std::move(message), std::move(ciphertext)};
}

CkksComplexTestCt new_complex_ct(CkksContext& ctx, int level, int log_slots) {
    const CkksParameter& param = ctx.parameter();
    const int plaintext_log_slots = log_slots >= 0 ? log_slots : param.log_max_slots();
    vector<complex<double>> message = rand_complex_values(ckks_message_size(param, true, log_slots));
    CkksPlaintext plaintext(param, plaintext_metadata(false, true, level, plaintext_log_slots, param.default_scale()));
    ctx.encode(message, plaintext);
    CkksCiphertext ciphertext = ctx.encrypt(plaintext);
    return {std::move(message), std::move(ciphertext)};
}

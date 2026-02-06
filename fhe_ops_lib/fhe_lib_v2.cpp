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

#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <functional>
#include <stdexcept>
#include "fhe_lib_v2.h"

using namespace std::placeholders;

namespace fhe_ops_lib {

std::string get_error_message() {
    char* data = GetErrorMessage();
    std::string s(data);
    free(data);
    return s;
}

void CHECK(int result) {
    if (result != 0) {
        char* data = GetErrorMessage();
        fprintf(stderr, "%s\n", data);
        std::string errorMessage(data);
        free(data);
        throw std::runtime_error(errorMessage);
    }
}

template <typename T> std::vector<T> export_raw_data(std::function<uint64_t(T**, uint64_t*)> f) {
    T* raw_data;
    uint64_t length;
    uint64_t binary_data_handle = f(&raw_data, &length);
    std::vector<T> data_vector(raw_data, raw_data + length);
    ReleaseHandle(binary_data_handle);
    return data_vector;
}

void FheContext::resize_copies(int n) {
    if (_copies.size() < n) {
        _copies.resize(n);
    }
}

KeySwitchKey RelinKey::extract_key_switch_key() const {
    return KeySwitchKey(ExtractKeySwitchKeyFromRelinKey(this->get()));
}

KeySwitchKey GaloisKey::extract_key_switch_key(uint64_t k) const {
    uint64_t key_switch_key_handle_id;
    CHECK(ExtractKeySwitchKeyFromGaloisKey(this->get(), k, &key_switch_key_handle_id));
    return KeySwitchKey(std::move(key_switch_key_handle_id));
}

int KeySwitchKey::get_level() const {
    return GetKeySwitchKeyLevel(this->get());
}

// BFV

// BfvContext
const BfvParameter& BfvContext::get_parameter() {
    if (_parameter.get() == 0) {
        _parameter = BfvParameter(GetBfvParameter(this->get()));
    }
    return _parameter;
}

BfvContext BfvContext::create_random_context(const BfvParameter& param, int level) {
    return BfvContext(CreateRandomBfvContext(param.get(), level));
}

void BfvContext::gen_rotation_keys(int level) {
    GenBfvContextRotationKeys(this->get(), level);
}

void BfvContext::gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows, int level) {
    GenBfvContextRotationKeysForRotations(this->get(), (int32_t*)rots.data(), rots.size(), include_swap_rows, level);
}

BfvContext BfvContext::create_empty_context(const BfvParameter& param) {
    return BfvContext(CreateEmptyBfvContext(param.get()));
}

BfvContext BfvContext::make_public_context(bool include_pk, bool include_rlk, bool include_gk) const {
    return BfvContext(MakePublicBfvContext(this->get(), include_pk, include_rlk, include_gk));
}

void BfvContext::generate_public_keys(int level) {
    GenerateBfvContextPublicKeys(this->get(), level);
}

BfvContext BfvContext::shallow_copy_context() const {
    return BfvContext(ShallowCopyBfvContext(this->get()));
}

Bytes BfvContext::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeBfvContext, this->get(), _1, _2));
}

BfvContext BfvContext::deserialize(BytesView data) {
    return BfvContext(DeserializeBfvContext((uint8_t*)data.data(), data.size()));
}

Bytes BfvContext::serialize_advanced() const {
    return export_raw_data<uint8_t>(std::bind(SerializeBfvContextAdvanced, this->get(), _1, _2));
}

BfvContext BfvContext::deserialize_advanced(BytesView data) {
    auto context = BfvContext(DeserializeBfvContextAdvanced((uint8_t*)data.data(), data.size()));
    BfvContextDecompress(context.get());
    return context;
}

SecretKey BfvContext::extract_secret_key() const {
    return SecretKey(ExtractBfvSecretKey(this->get()));
}

PublicKey BfvContext::extract_public_key() const {
    return PublicKey(ExtractBfvPublicKey(this->get()));
}

RelinKey BfvContext::extract_relin_key() const {
    return RelinKey(ExtractBfvRelinKey(this->get()));
}

GaloisKey BfvContext::extract_galois_key() const {
    return GaloisKey(ExtractBfvGaloisKey(this->get()));
}

void BfvContext::set_context_secret_key(const SecretKey& sk) {
    SetBfvContextSecretKey(this->get(), sk.get());
}

void BfvContext::set_context_public_key(const PublicKey& pk) {
    SetBfvContextPublicKey(this->get(), pk.get());
}

void BfvContext::set_context_relin_key(const RelinKey& rlk) {
    SetBfvContextRelinKey(this->get(), rlk.get());
}

void BfvContext::set_context_galois_key(const GaloisKey& gk) {
    SetBfvContextGaloisKey(this->get(), gk.get());
}

BfvPlaintext BfvContext::encode(const std::vector<uint64_t>& x_mg, int level) {
    uint64_t plaintext_handle_id;
    CHECK(BfvEncode(this->get(), (uint64_t*)x_mg.data(), x_mg.size(), level, &plaintext_handle_id));
    return BfvPlaintext(std::move(plaintext_handle_id));
}

BfvPlaintextMul BfvContext::encode_mul(const std::vector<uint64_t>& x_mg, int level) {
    return BfvPlaintextMul(BfvEncodeMul(this->get(), (uint64_t*)x_mg.data(), x_mg.size(), level));
}

BfvPlaintextRingt BfvContext::encode_ringt(const std::vector<uint64_t>& x_mg) {
    uint64_t plaintext_handle_id;
    CHECK(BfvEncodeRingt(this->get(), (uint64_t*)x_mg.data(), x_mg.size(), &plaintext_handle_id));
    return BfvPlaintextRingt(std::move(plaintext_handle_id));
}

BfvPlaintext BfvContext::encode_coeffs(const std::vector<uint64_t>& x_mg, int level) {
    return BfvPlaintext(BfvEncodeCoeffs(this->get(), (uint64_t*)x_mg.data(), x_mg.size(), level));
}

BfvPlaintextMul BfvContext::encode_coeffs_mul(const std::vector<uint64_t>& x_mg, int level) {
    return BfvPlaintextMul(BfvEncodeCoeffsMul(this->get(), (uint64_t*)x_mg.data(), x_mg.size(), level));
}

BfvPlaintextRingt BfvContext::encode_coeffs_ringt(const std::vector<uint64_t>& x_mg) {
    return BfvPlaintextRingt(BfvEncodeCoeffsRingt(this->get(), (uint64_t*)x_mg.data(), x_mg.size()));
}

// std::vector<BfvPlaintext> BfvContext::bitwise_encode(const std::vector<uint64_t>& x_mg, int level) {
//     int t_len = int(ceil(log2(this->get_parameter().get_t())));
//     std::vector<BfvPlaintext> x_bit_pts(t_len);
//     for (int i = 0; i < t_len; i++) {
//         std::vector<uint64_t> bit_mg(x_mg.size());
//         for (int j = 0; j < x_mg.size(); j++) {
//             bit_mg[j] = (x_mg[j] >> i) & 1;
//         }
//         x_bit_pts[i] = this->encode(bit_mg, level);
//     }
//     return x_bit_pts;
// }

// std::vector<BfvPlaintextRingt> BfvContext::bitwise_encode_ringt(const std::vector<uint64_t>& x_mg) {
//     int t_len = int(ceil(log2(this->get_parameter().get_t())));
//     std::vector<BfvPlaintextRingt> x_bit_pts(t_len);
//     for (int i = 0; i < t_len; i++) {
//         std::vector<uint64_t> bit_mg(x_mg.size());
//         for (int j = 0; j < x_mg.size(); j++) {
//             bit_mg[j] = (x_mg[j] >> i) & 1;
//         }
//         x_bit_pts[i] = this->encode_ringt(bit_mg);
//     }
//     return x_bit_pts;
// }

BfvCiphertext BfvContext::new_ciphertext(int degree, int level) {
    return BfvCiphertext(NewBfvCiphertext(this->get(), degree, level));
}

BfvCiphertext BfvContext::new_ciphertext(int level) {
    return BfvCiphertext(NewBfvCiphertext(this->get(), 1, level));
}

BfvCiphertext3 BfvContext::new_ciphertext3(int level) {
    return BfvCiphertext3(NewBfvCiphertext(this->get(), 2, level));
}

// BfvParameter
BfvParameter BfvParameter::create_fpga_parameter(uint64_t t) {
    return BfvParameter(CreateBfvParameterV2(t));
}

BfvParameter BfvParameter::create_parameter(uint64_t N, uint64_t t) {
    return BfvParameter(CreateBfvParameter(N, t));
}

BfvParameter BfvParameter::create_custom_parameter(uint64_t N,
                                                   uint64_t t,
                                                   const std::vector<uint64_t>& Q,
                                                   const std::vector<uint64_t>& P) {
    return BfvParameter(SetBfvParameter(N, t, (uint64_t*)Q.data(), Q.size(), (uint64_t*)P.data(), P.size()));
}

BfvParameter
BfvParameter::set_parameter(uint64_t N, uint64_t t, const std::vector<uint64_t>& Q, const std::vector<uint64_t>& P) {
    return BfvParameter(SetBfvParameter(N, t, (uint64_t*)Q.data(), Q.size(), (uint64_t*)P.data(), P.size()));
}

BfvParameter BfvParameter::copy() const {
    return BfvParameter(CopyBfvParameter(this->get()));
}

void BfvParameter::print() const {
    PrintBfvParameter(this->get());
}

int BfvParameter::get_n() const {
    return GetBfvN(this->get());
}

uint64_t BfvParameter::get_t() const {
    return GetBfvT(this->get());
}

uint64_t BfvParameter::get_q(int index) const {
    return GetBfvQ(this->get(), index);
}

uint64_t BfvParameter::get_p(int index) const {
    return GetBfvP(this->get(), index);
}

int BfvParameter::get_q_count() const {
    return GetBfvQCount(this->get());
}

int BfvParameter::get_p_count() const {
    return GetBfvPCount(this->get());
}

int BfvParameter::get_max_level() const {
    return GetBfvMaxLevel(this->get());
}

// BfvPlaintext
std::vector<uint64_t> BfvContext::decode(const BfvPlaintext& x_pt) {
    return export_raw_data<uint64_t>(std::bind(BfvDecode, this->get(), x_pt.get(), _1, _2));
}

std::vector<uint64_t> BfvContext::decode_coeffs(const BfvPlaintext& x_pt) {
    return export_raw_data<uint64_t>(std::bind(BfvDecodeCoeffs, this->get(), x_pt.get(), _1, _2));
}

std::vector<uint64_t> BfvContext::decode_ringt(const BfvPlaintextRingt& x_pt) {
    return export_raw_data<uint64_t>(std::bind(BfvDecodeRingt, this->get(), x_pt.get(), _1, _2));
}

BfvCiphertext BfvContext::encrypt_asymmetric(const BfvPlaintext& x_pt) {
    return BfvCiphertext(BfvEncryptAsymmetric(this->get(), x_pt.get()));
}

BfvCompressedCiphertext BfvContext::encrypt_symmetric_compressed(const BfvPlaintext& x_pt) {
    uint64_t ciphertext_handle_id;
    CHECK(BfvEncryptSymmetricCompressed(this->get(), x_pt.get(), &ciphertext_handle_id));
    return BfvCompressedCiphertext(std::move(ciphertext_handle_id));
}

BfvCiphertext BfvContext::compressed_ciphertext_to_ciphertext(const BfvCompressedCiphertext& x_ct) {
    return BfvCiphertext(BfvCompressedCiphertextToCiphertext(this->get(), x_ct.get()));
}

BfvCiphertext BfvContext::encrypt_symmetric(const BfvPlaintext& x_pt) {
    uint64_t ciphertext_handle_id;
    CHECK(BfvEncryptSymmetric(this->get(), x_pt.get(), &ciphertext_handle_id));
    return BfvCiphertext(std::move(ciphertext_handle_id));
}

BfvPlaintext BfvContext::decrypt(const BfvCiphertext& x_ct) {
    uint64_t plaintext_handle_id;
    CHECK(BfvDecrypt(this->get(), x_ct.get(), &plaintext_handle_id));
    return BfvPlaintext(std::move(plaintext_handle_id));
}

BfvPlaintext BfvContext::decrypt(const BfvCiphertext3& x_ct) {
    uint64_t plaintext_handle_id;
    CHECK(BfvDecrypt(this->get(), x_ct.get(), &plaintext_handle_id));
    return BfvPlaintext(std::move(plaintext_handle_id));
}

BfvPlaintextRingt BfvContext::plaintext_to_plaintext_ringt(const BfvPlaintext& x_pt) {
    return BfvPlaintextRingt(BfvPlaintextToPlaintextRingt(this->get(), x_pt.get()));
}

BfvCiphertext BfvContext::add(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct) {
    uint64_t y_ct_handle_id;
    CHECK(BfvAdd(this->get(), x0_ct.get(), x1_ct.get(), &y_ct_handle_id));
    return BfvCiphertext(std::move(y_ct_handle_id));
}

BfvCiphertext3 BfvContext::add(const BfvCiphertext3& x0_ct, const BfvCiphertext3& x1_ct) {
    uint64_t y_ct_handle_id;
    CHECK(BfvAdd(this->get(), x0_ct.get(), x1_ct.get(), &y_ct_handle_id));
    return BfvCiphertext3(std::move(y_ct_handle_id));
}

BfvCiphertext BfvContext::sub(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct) {
    return BfvCiphertext(BfvSub(this->get(), x0_ct.get(), x1_ct.get()));
}

BfvCiphertext BfvContext::sub_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt) {
    return BfvCiphertext(BfvSubPlain(this->get(), x0_ct.get(), x1_pt.get()));
}

BfvCiphertext BfvContext::sub_plain_ringt(const BfvCiphertext& x0_ct, const BfvPlaintextRingt& x1_pt) {
    return BfvCiphertext(BfvSubPlainRingt(this->get(), x0_ct.get(), x1_pt.get()));
}

BfvCiphertext BfvContext::negate(const BfvCiphertext& x0_ct) {
    return BfvCiphertext(BfvNegate(this->get(), x0_ct.get()));
}

void BfvContext::add_inplace(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct) {
    AddInplace(this->get(), x0_ct.get(), x1_ct.get());
}

BfvCiphertext BfvContext::add_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt) {
    return BfvCiphertext(BfvAddPlain(this->get(), x0_ct.get(), x1_pt.get()));
}

BfvCiphertext BfvContext::add_plain_ringt(const BfvCiphertext& x0_ct, const BfvPlaintextRingt& x1_pt) {
    return BfvCiphertext(BfvAddPlainRingt(this->get(), x0_ct.get(), x1_pt.get()));
}

void BfvContext::add_plain_inplace(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt) {
    AddPlainInplace(this->get(), x0_ct.get(), x1_pt.get());
}

BfvCiphertext3 BfvContext::mult(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct) {
    return BfvCiphertext3(BfvMult(this->get(), x0_ct.get(), x1_ct.get()));
}

BfvCiphertext BfvContext::mult_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt) {
    return BfvCiphertext(BfvMultPlain(this->get(), x0_ct.get(), x1_pt.get()));
}

BfvCiphertext BfvContext::mult_plain_ringt(const BfvCiphertext& x0_ct, const BfvPlaintextRingt& x1_pt) {
    return BfvCiphertext(BfvMultPlainRingt(this->get(), x0_ct.get(), x1_pt.get()));
}

BfvCiphertext BfvContext::mult_scalar(const BfvCiphertext& x0_ct, const int64_t x1_value) {
    return BfvCiphertext(BfvMultScalar(this->get(), x0_ct.get(), x1_value));
}

BfvCiphertext BfvContext::mult_plain_mul(const BfvCiphertext& x0_ct, const BfvPlaintextMul& x1_pt) {
    return BfvCiphertext(BfvMultPlainMul(this->get(), x0_ct.get(), x1_pt.get()));
}

BfvPlaintextMul BfvContext::ringt_to_mul(const BfvPlaintextRingt& x_pt, int level) {
    return BfvPlaintextMul(BfvPlaintextRingtToPlaintextMul(this->get(), x_pt.get(), level));
}

BfvPlaintext BfvContext::ringt_to_pt(const BfvPlaintextRingt& x_pt, int level) {
    return BfvPlaintext(BfvPlaintextRingtToPlaintext(this->get(), x_pt.get(), level));
}

BfvCiphertext BfvContext::relinearize(const BfvCiphertext3& x_ct) {
    return BfvCiphertext(BfvRelinearize(this->get(), x_ct.get()));
}

BfvCiphertext BfvContext::rotate_cols(const BfvCiphertext& x_ct, int32_t step) {
    uint64_t y_ct_handle_id;
    CHECK(BfvRotateColumns(this->get(), x_ct.get(), &step, 1, &y_ct_handle_id));
    return BfvCiphertext(std::move(y_ct_handle_id));
}

BfvCiphertext BfvContext::advanced_rotate_cols(const BfvCiphertext& x_ct, int32_t step) {
    uint64_t y_ct_handle_id;
    CHECK(BfvAdvancedRotateColumns(this->get(), x_ct.get(), &step, 1, &y_ct_handle_id));
    return BfvCiphertext(std::move(y_ct_handle_id));
}

std::map<int32_t, BfvCiphertext> BfvContext::rotate_cols(const BfvCiphertext& x_ct, const std::vector<int32_t>& steps) {
    std::map<int32_t, BfvCiphertext> ct_rotated_map;
    std::vector<uint64_t> x_rotated_cts(steps.size());
    CHECK(BfvRotateColumns(this->get(), x_ct.get(), (int32_t*)steps.data(), steps.size(), x_rotated_cts.data()));
    for (int i = 0; i < steps.size(); i++) {
        ct_rotated_map[steps[i]] = BfvCiphertext(std::move(x_rotated_cts[i]));
    }
    return ct_rotated_map;
}

std::map<int32_t, BfvCiphertext> BfvContext::advanced_rotate_cols(const BfvCiphertext& x_ct,
                                                                  const std::vector<int32_t>& steps) {
    std::map<int32_t, BfvCiphertext> ct_rotated_map;
    std::vector<uint64_t> x_rotated_cts(steps.size());
    CHECK(
        BfvAdvancedRotateColumns(this->get(), x_ct.get(), (int32_t*)steps.data(), steps.size(), x_rotated_cts.data()));
    for (int i = 0; i < steps.size(); i++) {
        ct_rotated_map[steps[i]] = BfvCiphertext(std::move(x_rotated_cts[i]));
    }
    return ct_rotated_map;
}

BfvCiphertext BfvContext::rescale(const BfvCiphertext& x_ct) {
    return BfvCiphertext(BfvRescale(this->get(), x_ct.get()));
}

BfvCiphertext BfvContext::rotate_rows(const BfvCiphertext& x_ct) {
    return BfvCiphertext(BfvRotateRows(this->get(), x_ct.get()));
}

// BfvCiphertext BfvContext::equal_to(const std::vector<BfvCiphertext>& x0_bit_cts,
//                                    const std::vector<BfvCiphertext>& x1_bit_cts) {
//     const BfvParameter& param = this->get_parameter();
//     int n = param.get_n();
//     uint64_t t = param.get_t();
//     int t_len = int(ceil(log2(t)));
//     int log_t_len = int(ceil(log2(t_len)));

//     int level = x0_bit_cts[0].get_level();

//     std::vector<uint64_t> one_mg(n, 1);
//     BfvPlaintext one_pt = this->encode(one_mg, level);

//     std::vector<std::vector<BfvCiphertext>> bit_eqs(log_t_len + 1);
//     for (int i = 0; i < t_len; i++) {
//         BfvCiphertext bit_prod = this->relinearize(this->mult(x0_bit_cts[i], x1_bit_cts[i]));
//         BfvCiphertext bit_sum = this->add(x0_bit_cts[i], x1_bit_cts[i]);
//         BfvCiphertext bit_e = this->sub(this->add_plain(this->mult_scalar(bit_prod, 2), one_pt), bit_sum);
//         bit_eqs[0].push_back(std::move(bit_e));
//     }

//     int width = t_len;
//     for (int i = 0; i < log_t_len; i++) {
//         for (int j = 0; j < width / 2; j++) {
//             bit_eqs[i + 1].push_back(
//                 std::move(this->relinearize(this->mult(bit_eqs[i][j * 2 + 1], bit_eqs[i][j * 2]))));
//         }
//         if (width % 2 == 1) {
//             bit_eqs[i + 1].push_back(std::move(bit_eqs[i][width - 1]));
//         }
//         width = (width + 1) / 2;
//     }

//     return std::move(bit_eqs[log_t_len][0]);
// }

// BfvCiphertext BfvContext::less_than(const std::vector<BfvCiphertext>& x0_bit_cts,
//                                     const std::vector<BfvCiphertext>& x1_bit_cts) {
//     const BfvParameter& param = this->get_parameter();
//     int n = param.get_n();
//     uint64_t t = param.get_t();
//     int t_len = int(ceil(log2(t)));
//     int log_t_len = int(ceil(log2(t_len)));

//     int level = x0_bit_cts[0].get_level();

//     std::vector<uint64_t> one_mg(n, 1);
//     BfvPlaintext one_pt = this->encode(one_mg, level);

//     std::vector<std::vector<BfvCiphertext>> bit_eqs(log_t_len + 1);
//     std::vector<std::vector<BfvCiphertext>> bit_lts(log_t_len + 1);
//     for (int i = 0; i < t_len; i++) {
//         BfvCiphertext bit_prod = this->relinearize(this->mult(x0_bit_cts[i], x1_bit_cts[i]));
//         BfvCiphertext bit_sum = this->add(x0_bit_cts[i], x1_bit_cts[i]);
//         bit_lts[0].push_back(std::move(this->sub(x1_bit_cts[i], bit_prod)));
//         BfvCiphertext bit_e = this->sub(this->add_plain(this->mult_scalar(bit_prod, 2), one_pt), bit_sum);
//         bit_eqs[0].push_back(std::move(bit_e));
//     }

//     int width = t_len;
//     for (int i = 0; i < log_t_len; i++) {
//         for (int j = 0; j < width / 2; j++) {
//             bit_lts[i + 1].push_back(std::move(this->add(
//                 bit_lts[i][j * 2 + 1], this->relinearize(this->mult(bit_eqs[i][j * 2 + 1], bit_lts[i][j * 2])))));
//             if (i != log_t_len - 1) {
//                 bit_eqs[i + 1].push_back(
//                     std::move(this->relinearize(this->mult(bit_eqs[i][j * 2 + 1], bit_eqs[i][j * 2]))));
//             }
//         }
//         if (width % 2 == 1) {
//             bit_lts[i + 1].push_back(std::move(bit_lts[i][width - 1]));
//             if (i != log_t_len - 1) {
//                 bit_eqs[i + 1].push_back(std::move(bit_eqs[i][width - 1]));
//             }
//         }
//         width = (width + 1) / 2;
//     }

//     return std::move(bit_lts[log_t_len][0]);
// }

BfvContext& BfvContext::get_copy(int index) {
    if (index >= _copies.size()) {
        throw std::out_of_range(
            "BfvContext::get_copy() index out of range. Call FheContext::resize_copies() to alloc more copies.");
    }
    if (!_copies[index]->get()) {
        _copies[index] = std::make_unique<BfvContext>(this->shallow_copy_context());
    }
    return dynamic_cast<BfvContext&>(*_copies[index]);
}

Bytes BfvCiphertext::serialize(const BfvParameter& param, int n_drop_bit_0, int n_drop_bit_1) const {
    return export_raw_data<uint8_t>(
        std::bind(SerializeBfvCiphertext, this->get(), param.get(), _1, _2, n_drop_bit_0, n_drop_bit_1));
}

Bytes BfvCompressedCiphertext::serialize(const BfvParameter& param) const {
    return export_raw_data<uint8_t>(std::bind(SerializeBfvCompressedCiphertext, this->get(), param.get(), _1, _2));
}

BfvCiphertext BfvCiphertext::deserialize(BytesView data) {
    return BfvCiphertext(DeserializeBfvCiphertext((uint8_t*)data.data(), data.size()));
}

BfvCompressedCiphertext BfvCompressedCiphertext::deserialize(BytesView data) {
    return BfvCompressedCiphertext(DeserializeBfvCompressedCiphertext((uint8_t*)data.data(), data.size()));
}

BfvCiphertext BfvCiphertext::copy() const {
    return BfvCiphertext(CopyBfvCiphertext(this->get()));
}

void BfvCiphertext::copy_to(const BfvCiphertext& y_ct) const {
    CopyBfvCiphertextTo(this->get(), y_ct.get());
}

void BfvCiphertext3::copy_to(const BfvCiphertext3& y_ct) const {
    CopyBfvCiphertextTo(this->get(), y_ct.get());
}

void BfvCiphertext::print() const {
    PrintBfvCiphertext(this->get());
}

int BfvPlaintext::get_level() const {
    return GetBfvPlaintextLevel(this->get());
}

void BfvPlaintext::print() const {
    PrintBfvPlaintext(this->get());
}

int BfvPlaintextRingt::get_level() const {
    return GetBfvPlaintextRingtLevel(this->get());
}

int BfvPlaintextMul::get_level() const {
    return GetBfvPlaintextMulLevel(this->get());
}

int BfvCiphertext::get_level() const {
    return GetBfvCiphertextLevel(this->get());
}

uint64_t BfvCiphertext::get_coeff(int poly_idx, int rns_idx, int coeff_idx) const {
    return GetBfvCiphertextCoeff(this->get(), poly_idx, rns_idx, coeff_idx);
}

// BfvCiphertext3
int BfvCiphertext3::get_level() const {
    return GetBfvCiphertext3Level(this->get());
}

// CKKS
CkksParameter CkksParameter::create_fpga_parameter() {
    return CkksParameter(CreateCkksParameterV2());
}

CkksBtpParameter CkksBtpParameter::create_parameter() {
    return CkksBtpParameter(CreateCkksBtpParameter());
}

CkksBtpParameter CkksBtpParameter::create_toy_parameter() {
    return CkksBtpParameter(CreateCkksToyBtpParameter());
}

// CkksParameter
CkksParameter CkksParameter::create_parameter(uint64_t N) {
    return CkksParameter(CreateCkksParameter(N));
}

CkksParameter
CkksParameter::create_custom_parameter(uint64_t N, const std::vector<uint64_t>& Q, const std::vector<uint64_t>& P) {
    return CkksParameter(SetCkksParameter(N, (uint64_t*)Q.data(), Q.size(), (uint64_t*)P.data(), P.size()));
}

CkksParameter CkksParameter::copy() const {
    return CkksParameter(CopyCkksParameter(this->get()));
}

void CkksParameter::print() const {
    PrintCkksParameter(this->get());
}

int CkksParameter::get_n() const {
    return GetCkksN(this->get());
}

int CkksParameter::get_max_level() const {
    return GetCkksMaxLevel(this->get());
}

int CkksParameter::get_p_count() const {
    return GetCkksPCount(this->get());
}

uint64_t CkksParameter::get_p(int index) const {
    return GetCkksP(this->get(), index);
}

uint64_t CkksParameter::get_q(int index) const {
    return GetCkksQ(this->get(), index);
}

double CkksParameter::get_default_scale() const {
    return GetDefaultScale(this->get());
}

// CkksContext
CkksContext CkksContext::create_empty_context(const CkksParameter& param, bool support_big_complex) {
    return CkksContext(CreateEmptyCkksContext(param.get(), support_big_complex));
}

CkksContext CkksContext::create_random_context(const CkksParameter& param, int level, bool support_big_complex) {
    return CkksContext(CreateRandomCkksContext(param.get(), level, support_big_complex));
}

CkksContext CkksContext::create_random_context_with_seed(const CkksParameter& param,
                                                         const std::vector<uint8_t>& seed,
                                                         bool support_big_complex) {
    return CkksContext(CreateRandomCkksContextWithSeed(param.get(), (uint8_t*)seed.data(), support_big_complex));
}

void CkksContext::gen_rotation_keys(int level) {
    GenCkksContextRotationKeys(this->get(), level);
}

void CkksContext::gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows, int level) {
    GenCkksContextRotationKeysForRotations(this->get(), (int32_t*)rots.data(), rots.size(), include_swap_rows, level);
}

CkksContext CkksContext::make_public_context(bool include_pk, bool include_rlk, bool include_gk) const {
    return CkksContext(MakePublicCkksContext(this->get(), include_pk, include_rlk, include_gk));
}

CkksContext CkksContext::shallow_copy_context() {
    return CkksContext(ShallowCopyCkksContext(this->get()));
}

CkksContext& CkksContext::get_copy(int index) {
    if (index >= _copies.size()) {
        throw std::out_of_range(
            "CkksContext::get_copy() index out of range. Call FheContext::resize_copies() to alloc more copies.");
    }
    if (!_copies[index]) {
        _copies[index] = std::make_unique<CkksContext>(this->shallow_copy_context());
    }
    return dynamic_cast<CkksContext&>(*_copies[index]);
}

CkksContext& CkksContext::get_extra_level_context() {
    if (!_extra_level_context) {
        _extra_level_context = std::make_unique<CkksContext>(CreateCkksExtraLevelContext(this->get()));
    }
    return *_extra_level_context;
}

const CkksParameter& CkksContext::get_parameter() {
    if (_parameter.get() == 0) {
        _parameter = CkksParameter(GetCkksParameter(this->get()));
    }
    return _parameter;
}

SecretKey CkksContext::extract_secret_key() const {
    return SecretKey(ExtractCkksSecretKey(this->get()));
}

PublicKey CkksContext::extract_public_key() const {
    return PublicKey(ExtractCkksPublicKey(this->get()));
}

RelinKey CkksContext::extract_relin_key() const {
    return RelinKey(ExtractCkksRelinKey(this->get()));
}

GaloisKey CkksContext::extract_galois_key() const {
    return GaloisKey(ExtractCkksGaloisKey(this->get()));
}

void CkksContext::set_context_secret_key(const SecretKey& sk) {
    SetCkksContextSecretKey(this->get(), sk.get());
}

void CkksContext::set_context_public_key(const PublicKey& pk) {
    SetCkksContextPublicKey(this->get(), pk.get());
}

void CkksContext::set_context_relin_key(const RelinKey& rlk) {
    SetCkksContextRelinKey(this->get(), rlk.get());
}

void CkksContext::set_context_galois_key(const GaloisKey& gk) {
    SetCkksContextGaloisKey(this->get(), gk.get());
}

Bytes CkksContext::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeCkksContext, this->get(), _1, _2));
}

Bytes CkksContext::serialize_advanced() const {
    return export_raw_data<uint8_t>(std::bind(SerializeCkksContextAdvanced, this->get(), _1, _2));
}

CkksContext CkksContext::deserialize(BytesView data) {
    return CkksContext(DeserializeCkksContext((uint8_t*)data.data(), data.size()));
}

CkksContext CkksContext::deserialize_advanced(BytesView data) {
    auto context = CkksContext(DeserializeCkksContextAdvanced((uint8_t*)data.data(), data.size()));
    CkksContextDecompress(context.get());
    return context;
}

CkksPlaintext CkksContext::encode(const std::vector<double>& x_mg, int level, double scale) {
    return CkksPlaintext(CkksEncode(this->get(), (double*)x_mg.data(), x_mg.size(), level, scale));
}

CkksPlaintext CkksContext::encode_complex(const std::vector<double>& x_mg, int level, double scale) {
    return CkksPlaintext(CkksEncodeComplex(this->get(), (double*)x_mg.data(), x_mg.size() / 2, level, scale));
}

CkksPlaintextRingt CkksContext::encode_ringt(const std::vector<double>& x_mg, double scale) {
    return CkksPlaintextRingt(CkksEncodeRingt(this->get(), (double*)x_mg.data(), x_mg.size(), scale));
}

CkksPlaintextMul CkksContext::encode_mul(const std::vector<double>& x_mg, int level, double scale) {
    return CkksPlaintextMul(CkksEncodeMul(this->get(), (double*)x_mg.data(), x_mg.size(), level, scale));
}

CkksPlaintext CkksContext::encode_coeffs(const std::vector<double>& x_mg, int level, double scale) {
    return CkksPlaintext(CkksEncodeCoeffs(this->get(), (double*)x_mg.data(), x_mg.size(), level, scale));
}

CkksPlaintextRingt CkksContext::encode_coeffs_ringt(const std::vector<double>& x_mg, double scale) {
    return CkksPlaintextRingt(CkksEncodeCoeffsRingt(this->get(), (double*)x_mg.data(), x_mg.size(), scale));
}

CkksPlaintextMul CkksContext::encode_coeffs_mul(const std::vector<double>& x_mg, int level, double scale) {
    return CkksPlaintextMul(CkksEncodeCoeffsMul(this->get(), (double*)x_mg.data(), x_mg.size(), level, scale));
}

std::vector<double> CkksContext::decode(const CkksPlaintext& x_pt) {
    double* raw_data;
    uint64_t length;
    uint64_t binary_data_handle = CkksDecode(this->get(), x_pt.get(), &raw_data, &length);
    std::vector<double> message(length);
    // Copy only the real part of the complex values.
    for (int i = 0; i < length; i++) {
        message[i] = raw_data[i * 2];
    }
    ReleaseHandle(binary_data_handle);
    return message;
}

std::vector<double> CkksContext::decode_complex(const CkksPlaintext& x_pt) {
    double* raw_data;
    uint64_t length;
    uint64_t binary_data_handle = CkksDecode(this->get(), x_pt.get(), &raw_data, &length);
    std::vector<double> message(length * 2);
    for (int i = 0; i < length * 2; i++) {
        message[i] = raw_data[i];
    }
    ReleaseHandle(binary_data_handle);
    return message;
}

std::vector<double> CkksContext::decode_coeffs(const CkksPlaintext& x_pt) {
    return export_raw_data<double>(std::bind(CkksDecodeCoeffs, this->get(), x_pt.get(), _1, _2));
}

CkksPlaintext CkksContext::recode_big_complex(const CkksPlaintext& x_pt, int level, double scale) {
    return CkksRecodeBigComplex(this->get(), x_pt.get(), level, scale);
}

CkksCiphertext CkksContext::new_ciphertext(int degree, int level, double scale) {
    return CkksCiphertext(NewCkksCiphertext(this->get(), degree, level, scale));
}

CkksCiphertext CkksContext::new_ciphertext(int level, double scale) {
    return CkksCiphertext(NewCkksCiphertext(this->get(), 1, level, scale));
}

CkksCiphertext3 CkksContext::new_ciphertext3(int level, double scale) {
    return CkksCiphertext3(NewCkksCiphertext(this->get(), 2, level, scale));
}

CkksCiphertext CkksContext::encrypt_asymmetric(const CkksPlaintext& x_pt) {
    return CkksCiphertext(CkksEncryptAsymmetric(this->get(), x_pt.get()));
}

CkksCiphertext CkksContext::encrypt_symmetric(const CkksPlaintext& x_pt) {
    return CkksCiphertext(CkksEncryptSymmetric(this->get(), x_pt.get()));
}

CkksCompressedCiphertext CkksContext::encrypt_symmetric_compressed(const CkksPlaintext& x_pt) {
    return CkksCompressedCiphertext(CkksEncryptSymmetricCompressed(this->get(), x_pt.get()));
}

CkksCiphertext CkksContext::compressed_ciphertext_to_ciphertext(const CkksCompressedCiphertext& x_ct) {
    return CkksCiphertext(CkksCompressedCiphertextToCiphertext(this->get(), x_ct.get()));
}

CkksPlaintext CkksContext::decrypt(const CkksCiphertext& x_ct) {
    uint64_t plaintext_handle_id;
    CHECK(CkksDecrypt(this->get(), x_ct.get(), &plaintext_handle_id));
    return CkksPlaintext(std::move(plaintext_handle_id));
}

CkksPlaintext CkksContext::decrypt(const CkksCiphertext3& x_ct) {
    uint64_t plaintext_handle_id;
    CHECK(CkksDecrypt(this->get(), x_ct.get(), &plaintext_handle_id));
    return CkksPlaintext(std::move(plaintext_handle_id));
}

// CkksBtpContext
CkksBtpContext CkksBtpContext::create_random_context(const CkksBtpParameter& param) {
    return CkksBtpContext(CreateRandomCkksBtpContext(param.get()));
}

CkksBtpContext CkksBtpContext::create_empty_context(const CkksBtpParameter& param) {
    return CkksBtpContext(CreateEmptyCkksBtpContext(param.get()));
}

void CkksBtpContext::gen_rotation_keys() {
    GenCkksBtpContextRotationKeys(this->get());
}

void CkksBtpContext::gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows) {
    GenCkksBtpContextRotationKeysForRotations(this->get(), (int32_t*)rots.data(), rots.size(), include_swap_rows);
}

// cppcheck-suppress duplInheritedMember
CkksBtpContext CkksBtpContext::shallow_copy_context() {
    return CkksBtpContext(ShallowCopyCkksBtpContext(this->get()));
}

CkksParameter& CkksBtpContext::get_parameter() {
    if (_parameter.get() == 0) {
        _parameter = CkksParameter(GetCkksSchemeParameter(this->get()));
    }
    return _parameter;
}

CkksParameter& CkksBtpParameter::get_ckks_parameter() {
    if (_parameter.get() == 0) {
        _parameter = CkksParameter(GetCkksParameterFromBtpParameter(this->get()));
    }
    return _parameter;
}

CkksBtpContext CkksBtpContext::make_public_context() {
    return CkksBtpContext(MakePublicCkksBtpContext(this->get()));
}

CkksCiphertext CkksContext::add_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt) {
    return CkksCiphertext(CkksAddPlain(this->get(), x0_ct.get(), x1_pt.get()));
}

CkksCiphertext CkksContext::add(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct) {
    return CkksCiphertext(CkksAdd(this->get(), x0_ct.get(), x1_ct.get()));
}

CkksCiphertext3 CkksContext::add(const CkksCiphertext3& x0_ct, const CkksCiphertext3& x1_ct) {
    uint64_t y_ct_handle_id;
    // CHECK(CkksAdd(this->get(), x0_ct.get(), x1_ct.get(), &y_ct_handle_id));
    return CkksCiphertext3(CkksAdd(this->get(), x0_ct.get(), x1_ct.get()));
    // return BfvCiphertext3(std::move(y_ct_handle_id));
}

CkksCiphertext CkksContext::sub(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct) {
    return CkksCiphertext(CkksSub(this->get(), x0_ct.get(), x1_ct.get()));
}

CkksCiphertext CkksContext::sub_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt) {
    return CkksCiphertext(CkksSubPlain(this->get(), x0_ct.get(), x1_pt.get()));
}

CkksCiphertext CkksContext::add_plain_ringt(const CkksCiphertext& x0_ct, const CkksPlaintextRingt& x1_pt) {
    return CkksCiphertext(CkksAddPlainRingt(this->get(), x0_ct.get(), x1_pt.get()));
}

CkksCiphertext CkksContext::sub_plain_ringt(const CkksCiphertext& x0_ct, const CkksPlaintextRingt& x1_pt) {
    return CkksCiphertext(CkksSubPlainRingt(this->get(), x0_ct.get(), x1_pt.get()));
}

CkksPlaintext CkksContext::ringt_to_pt(const CkksPlaintextRingt& pt_ringt, int level) {
    return CkksPlaintext(CkksPlaintextRingtToPlaintext(this->get(), pt_ringt.get(), level));
}

CkksCiphertext CkksContext::negate(const CkksCiphertext& x0_ct) {
    return CkksCiphertext(CkksNegate(this->get(), x0_ct.get()));
}

CkksCiphertext3 CkksContext::mult(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct) {
    return CkksCiphertext3(CkksMult(this->get(), x0_ct.get(), x1_ct.get()));
}

CkksCiphertext CkksContext::mult_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt) {
    return CkksCiphertext(CkksMultPlain(this->get(), x0_ct.get(), x1_pt.get()));
}

CkksCiphertext CkksContext::mult_plain_mul(const CkksCiphertext& x0_ct, const CkksPlaintextMul& x1_pt) {
    return CkksCiphertext(CkksMultPlainMul(this->get(), x0_ct.get(), x1_pt.get()));
}

CkksPlaintextMul CkksContext::ringt_to_mul(const CkksPlaintextRingt& x_pt, int level) {
    return CkksPlaintextMul(CkksPlaintextRingtToPlaintextMul(this->get(), x_pt.get(), level));
}

CkksCiphertext CkksContext::relinearize(const CkksCiphertext3& x_ct) {
    return CkksCiphertext(CkksRelinearize(this->get(), x_ct.get()));
}

CkksCiphertext CkksContext::drop_level(const CkksCiphertext& x_ct, int levels) {
    return CkksCiphertext(CkksDropLevel(this->get(), x_ct.get(), levels));
}

CkksCiphertext CkksContext::rescale(const CkksCiphertext& x_ct, double min_scale) {
    return CkksCiphertext(CkksRescale(this->get(), x_ct.get(), min_scale));
}

CkksCiphertext CkksContext::rotate(const CkksCiphertext& x_ct, int32_t step) {
    uint64_t y_ct_handle_id;
    CHECK(CkksRotate(this->get(), x_ct.get(), &step, 1, &y_ct_handle_id));
    return CkksCiphertext(std::move(y_ct_handle_id));
}

CkksCiphertext CkksContext::advanced_rotate(const CkksCiphertext& x_ct, int32_t step) {
    uint64_t y_ct_handle_id;
    CHECK(CkksAdvancedRotate(this->get(), x_ct.get(), &step, 1, &y_ct_handle_id));
    return CkksCiphertext(std::move(y_ct_handle_id));
}

std::map<int32_t, CkksCiphertext> CkksContext::rotate(const CkksCiphertext& x_ct, const std::vector<int32_t>& steps) {
    std::map<int32_t, CkksCiphertext> ct_rotated_map;
    std::vector<uint64_t> x_rotated_cts(steps.size());
    CHECK(CkksRotate(this->get(), x_ct.get(), (int32_t*)steps.data(), steps.size(), x_rotated_cts.data()));
    for (int i = 0; i < steps.size(); i++) {
        ct_rotated_map[steps[i]] = CkksCiphertext(std::move(x_rotated_cts[i]));
    }
    return ct_rotated_map;
}

std::map<int32_t, CkksCiphertext> CkksContext::advanced_rotate(const CkksCiphertext& x_ct,
                                                               const std::vector<int32_t>& steps) {
    std::map<int32_t, CkksCiphertext> ct_rotated_map;
    std::vector<uint64_t> x_rotated_cts(steps.size());
    CHECK(CkksAdvancedRotate(this->get(), x_ct.get(), (int32_t*)steps.data(), steps.size(), x_rotated_cts.data()));
    for (int i = 0; i < steps.size(); i++) {
        ct_rotated_map[steps[i]] = CkksCiphertext(std::move(x_rotated_cts[i]));
    }
    return ct_rotated_map;
}

CkksCiphertext
CkksContext::poly_eval_relu_function(const CkksCiphertext& x_ct_h, double left, double right, int degree) {
    return CkksCiphertext(PolyEvalReluFunction(this->get(), x_ct_h.get(), left, right, degree));
}

CkksCiphertext
CkksContext::poly_eval_function(Operation op, const CkksCiphertext& x_ct_h, double left, double right, int degree) {
    if (auto* ptr = op.target<double (*)(double)>()) {
        return CkksCiphertext(
            PolyEvalFunction(reinterpret_cast<void*>(*ptr), this->get(), x_ct_h.get(), left, right, degree));
    }

    throw std::invalid_argument("CkksContext::poly_eval_function() unsupported operation type.");
}

CkksCiphertext CkksContext::conjugate(const CkksCiphertext& x_ct) {
    return CkksCiphertext(CkksConjugate(this->get(), x_ct.get()));
}

CkksCiphertext CkksContext::poly_eval_step_function(const CkksCiphertext& x_ct,
                                                    const double left,
                                                    const double right,
                                                    const uint64_t degree,
                                                    const double threshold) {
    return CkksCiphertext(CkksPolyEvalStepFunction(this->get(), x_ct.get(), left, right, degree, threshold));
}

CkksCiphertext CkksBtpContext::bootstrap(const CkksCiphertext& x_ct) {
    return CkksCiphertext(CkksBootstrap(this->get(), x_ct.get()));
}

CkksBtpContext& CkksBtpContext::get_copy(int index) {
    if (index >= _copies.size()) {
        throw std::out_of_range(
            "CkksContext::get_copy() index out of range. Call FheContext::resize_copies() to alloc more copies.");
    }
    if (!_copies[index]) {
        _copies[index] = std::make_unique<CkksBtpContext>(this->shallow_copy_context());
    }
    return dynamic_cast<CkksBtpContext&>(*_copies[index]);
}

// cppcheck-suppress duplInheritedMember
Bytes CkksBtpContext::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeCkksBtpContextAdvanced, this->get(), _1, _2));
}

// cppcheck-suppress duplInheritedMember
CkksBtpContext CkksBtpContext::deserialize(BytesView data) {
    return CkksBtpContext(DeserializeCkksBtpContextAdvanced((uint8_t*)data.data(), data.size()));
}

KeySwitchKey CkksBtpContext::extract_swk_dts() const {
    return KeySwitchKey(ExtractCkksBtpSwkDtS(this->get()));
}

KeySwitchKey CkksBtpContext::extract_swk_std() const {
    return KeySwitchKey(ExtractCkksBtpSwkStD(this->get()));
}

// cppcheck-suppress duplInheritedMember
void CkksBtpContext::set_context_relin_key(const RelinKey& rlk) {
    SetCkksBtpContextRelinKey(this->get(), rlk.get());
}

// cppcheck-suppress duplInheritedMember
void CkksBtpContext::set_context_galois_key(const GaloisKey& glk) {
    SetCkksBtpContextGaloisKey(this->get(), glk.get());
}

void CkksBtpContext::set_context_switch_key_dts(const KeySwitchKey& swk) {
    SetCkksBtpContextSwitchkeyDts(this->get(), swk.get());
}

void CkksBtpContext::set_context_switch_key_std(const KeySwitchKey& swk) {
    SetCkksBtpContextSwitchkeyStd(this->get(), swk.get());
}

void CkksBtpContext::create_bootstrapper() {
    CreateCkksBtpContextBootstrapper(this->get());
}

// CkksCiphertext
int CkksCiphertext::get_level() const {
    return GetCkksCiphertextLevel(this->get());
}

double CkksCiphertext::get_scale() const {
    return GetCkksCiphertextScale(this->get());
}

double CkksCiphertext::set_scale(double scale_in) const {
    return SetCkksCiphertextScale(this->get(), scale_in);
}

Bytes CkksCiphertext::serialize(const CkksParameter& param) const {
    return export_raw_data<uint8_t>(std::bind(SerializeCkksCiphertext, this->get(), param.get(), _1, _2));
}

Bytes CkksCompressedCiphertext::serialize(const CkksParameter& param) const {
    return export_raw_data<uint8_t>(std::bind(SerializeCkksCompressedCiphertext, this->get(), param.get(), _1, _2));
}

CkksCiphertext CkksCiphertext::deserialize(BytesView data) {
    return CkksCiphertext(DeserializeCkksCiphertext((uint8_t*)data.data(), data.size()));
}

CkksCompressedCiphertext CkksCompressedCiphertext::deserialize(BytesView data) {
    return CkksCompressedCiphertext(DeserializeCkksCompressedCiphertext((uint8_t*)data.data(), data.size()));
}

CkksCiphertext CkksCiphertext::copy() const {
    return CkksCiphertext(CopyCkksCiphertext(this->get()));
}

void CkksCiphertext::copy_to(const CkksCiphertext& y_ct) const {
    CopyCkksCiphertextTo(this->get(), y_ct.get());
}

void CkksCiphertext::print() const {
    PrintCkksCiphertext(this->get());
}

int CkksPlaintext::get_level() const {
    return GetCkksPlaintextLevel(this->get());
}

uint64_t CkksPlaintext::get_coeff(int rns_idx, int coeff_idx) {
    return GetCkksPlaintextCoeff(this->get(), rns_idx, coeff_idx);
}

void CkksPlaintext::set_coeff(int rns_idx, int coeff_idx, uint64_t coeff) {
    SetCkksPlaintextCoeff(this->get(), rns_idx, coeff_idx, coeff);
}

int CkksPlaintextRingt::get_level() const {
    return GetCkksPlaintextRingtLevel(this->get());
}

int CkksPlaintextMul::get_level() const {
    return GetCkksPlaintextMulLevel(this->get());
}

int CkksCiphertext3::get_level() const {
    return GetCkksCiphertext3Level(this->get());
}

double CkksCiphertext3::get_scale() const {
    return GetCkksCiphertextScale(this->get());
}

void CkksCiphertext3::copy_to(const CkksCiphertext3& y_ct) const {
    CopyCkksCiphertext3To(this->get(), y_ct.get());
}

double CkksCiphertext3::set_scale(double scale_in) const {
    return SetCkksCiphertextScale(this->get(), scale_in);
}

DBfvContext
DBfvContext::create_random_context(const BfvParameter& param, const std::vector<uint8_t>& seed, double sigma_smudging) {
    BfvContext context = BfvContext::create_empty_context(param);
    return DBfvContext(CreateRandomDBfvContext(context.get(), (uint8_t*)seed.data(), sigma_smudging));
}

BfvContext DBfvContext::get_bfv_context() {
    return BfvContext(GetDBfvBfvContext(this->get()));
}

CkgContext CkgContext::create_context(const DBfvContext& context) {
    return CkgContext(CreateCKGContext(context.get()));
}

PublicKeyShare CkgContext::gen_public_key_share() {
    return PublicKeyShare(GenDBfvPublicKeyShare(this->get()));
}

PublicKeyShare CkgContext::aggregate_public_key_share(const PublicKeyShare& x0_share, const PublicKeyShare& x1_share) {
    return PublicKeyShare(AggregateDBfvPublicKeyShare(this->get(), x0_share.get(), x1_share.get()));
}

void CkgContext::set_public_key(const PublicKeyShare& share) {
    SetDBfvPublicKey(this->get(), share.get());
}

RkgContext RkgContext::create_context(const DBfvContext& context) {
    return RkgContext(CreateRKGContext(context.get()));
}

std::pair<RelinKeyShare, SecretKey> RkgContext::gen_relin_key_share_round_one() {
    uint64_t eph_sk_handle_id;
    uint64_t share1_handle_id = GenDBfvRelinKeyShareRoundOne(this->get(), &eph_sk_handle_id);
    return std::make_pair(RelinKeyShare(std::move(share1_handle_id)), SecretKey(std::move(eph_sk_handle_id)));
}

RelinKeyShare RkgContext::gen_relin_key_share_round_two(const SecretKey& eph_sk, const RelinKeyShare& share1) {
    return RelinKeyShare(GenDBfvRelinKeyShareRoundTwo(this->get(), eph_sk.get(), share1.get()));
}

RelinKeyShare RkgContext::aggregate_relin_key_share(const RelinKeyShare& x0_share, const RelinKeyShare& x1_share) {
    return RelinKeyShare(AggregateDBfvRelinKeyShare(this->get(), x0_share.get(), x1_share.get()));
}

void RkgContext::set_relin_key(const RelinKeyShare& share1, const RelinKeyShare& share2) {
    SetDBfvRelinKey(this->get(), share1.get(), share2.get());
}

RtgContext RtgContext::create_context(const DBfvContext& context) {
    return RtgContext(CreateRTGContext(context.get()));
}

std::vector<GaloisKeyShare> RtgContext::gen_share(const std::vector<int32_t>& rots, bool include_swap_rows) {
    int len = rots.size();
    if (include_swap_rows) {
        len += 1;
    }
    std::vector<uint64_t> share_ids(len);
    std::vector<GaloisKeyShare> shares(len);
    CHECK(GenDBfvGaloisKeyShare(this->get(), (int32_t*)rots.data(), rots.size(), include_swap_rows, share_ids.data()));
    for (int i = 0; i < len; i++) {
        shares[i] = GaloisKeyShare(std::move(share_ids[i]));
    }
    return shares;
}

std::vector<GaloisKeyShare> RtgContext::aggregate_share(const std::vector<GaloisKeyShare>& x0_share,
                                                        const std::vector<GaloisKeyShare>& x1_share) {
    int len = x0_share.size();
    std::vector<uint64_t> x0_share_ids(len);
    std::vector<uint64_t> x1_share_ids(len);
    for (int i = 0; i < len; i++) {
        x0_share_ids[i] = x0_share[i].get();
        x1_share_ids[i] = x1_share[i].get();
    }

    std::vector<uint64_t> y_share_ids(len);
    CHECK(AggregateDBfvGaloisKeyShare(this->get(), x0_share_ids.data(), x1_share_ids.data(), len, y_share_ids.data()));

    std::vector<GaloisKeyShare> y_shares(len);
    for (int i = 0; i < len; i++) {
        y_shares[i] = GaloisKeyShare(std::move(y_share_ids[i]));
    }
    return y_shares;
}

void RtgContext::set_galois_key(const std::vector<int32_t>& rots,
                                bool include_swap_rows,
                                const std::vector<GaloisKeyShare>& share) {
    int len = rots.size();
    if (include_swap_rows) {
        len += 1;
    }
    std::vector<uint64_t> share_ids(len);
    for (int i = 0; i < len; i++) {
        share_ids[i] = share[i].get();
    }
    SetDBfvRotationKey(this->get(), (int32_t*)rots.data(), rots.size(), include_swap_rows, share_ids.data());
}

E2sContext E2sContext::create_context(const DBfvContext& context) {
    return E2sContext(CreateE2SContext(context.get()));
}

std::pair<E2sPublicShare, AdditiveShare> E2sContext::gen_public_share(const BfvCiphertext& x_ct) {
    uint64_t secret_share_handle_id;
    uint64_t public_share_handle_id = GenDBfvE2SPublicAndSecretShare(this->get(), x_ct.get(), &secret_share_handle_id);
    return std::make_pair(E2sPublicShare(std::move(public_share_handle_id)),
                          AdditiveShare(std::move(secret_share_handle_id)));
}

E2sPublicShare E2sContext::aggregate_public_share(const E2sPublicShare& x0_share, const E2sPublicShare& x1_share) {
    return E2sPublicShare(AggregateDBfvE2SCKSShare(this->get(), x0_share.get(), x1_share.get()));
}

AdditiveShare E2sContext::get_secret_share(const BfvCiphertext& x_ct,
                                           const E2sPublicShare& public_share,
                                           const AdditiveShare& secret_share) {
    return AdditiveShare(GetDBfvE2SSecretShare(this->get(), x_ct.get(), public_share.get(), secret_share.get()));
}

AdditiveShare E2sContext::aggregate_secret_share(const DBfvContext& context,
                                                 const AdditiveShare& x0_share,
                                                 const AdditiveShare& x1_share) {
    return AdditiveShare(AggregateDBfvAdditiveShare(context.get(), x0_share.get(), x1_share.get()));
}

BfvPlaintextRingt E2sContext::set_plaintext_ringt(const DBfvContext& context, const AdditiveShare& secret_share) {
    return BfvPlaintextRingt(SetDBfvE2SPlaintextRingT(context.get(), secret_share.get()));
}

S2eContext S2eContext::create_context(const DBfvContext& context) {
    return S2eContext(CreateS2EContext(context.get()));
}

S2ePublicShare S2eContext::gen_public_share(const AdditiveShare& secret_share) {
    return S2ePublicShare(GenDBfvS2EPublicShare(this->get(), secret_share.get()));
}

S2ePublicShare S2eContext::aggregate_public_share(const S2ePublicShare& x0_share, const S2ePublicShare& x1_share) {
    return S2ePublicShare(AggregateDBfvS2ECKSShare(this->get(), x0_share.get(), x1_share.get()));
}

BfvCiphertext S2eContext::set_ciphertetext(const S2ePublicShare& public_share) {
    return BfvCiphertext(SetDBfvS2ECiphertext(this->get(), public_share.get()));
}

RefreshContext RefreshContext::create_context(const DBfvContext& context) {
    return RefreshContext(CreateRefreshContext(context.get()));
}

RefreshShare RefreshContext::gen_share(const BfvCiphertext& x_ct) {
    return RefreshShare(GenDBfvRefreshShare(this->get(), x_ct.get()));
}

RefreshShare RefreshContext::aggregate_share(const RefreshShare& x0_share, const RefreshShare& x1_share) {
    return RefreshShare(AggregateDBfvRefreshShare(this->get(), x0_share.get(), x1_share.get()));
}

BfvCiphertext RefreshContext::finalize(const BfvCiphertext& x_ct, const RefreshShare& share) {
    return BfvCiphertext(DBfvRefreshFinalize(this->get(), x_ct.get(), share.get()));
}

RefreshAndPermuteContext RefreshAndPermuteContext::create_context(const DBfvContext& context) {
    return RefreshAndPermuteContext(CreateRefreshAndPermuteContext(context.get()));
}

RefreshAndPermuteShare RefreshAndPermuteContext::gen_share(const BfvCiphertext& x_ct, std::vector<uint64_t>& permute) {
    return RefreshAndPermuteShare(GenDBfvRefreshAndPermuteShare(this->get(), x_ct.get(), permute.data()));
}

RefreshAndPermuteShare RefreshAndPermuteContext::aggregate_share(const RefreshAndPermuteShare& x0_share,
                                                                 const RefreshAndPermuteShare& x1_share) {
    return RefreshAndPermuteShare(AggregateDBfvRefreshAndPermuteShare(this->get(), x0_share.get(), x1_share.get()));
}

BfvCiphertext RefreshAndPermuteContext::transform(const BfvCiphertext& x_ct,
                                                  std::vector<uint64_t>& permute,
                                                  const RefreshAndPermuteShare& share) {
    return BfvCiphertext(DBfvRefreshAndPermuteTransform(this->get(), x_ct.get(), permute.data(), share.get()));
}

Bytes PublicKeyShare::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeDBfvPublicKeyShare, this->get(), _1, _2));
}

PublicKeyShare PublicKeyShare::deserialize(const CkgContext& context, BytesView data) {
    return PublicKeyShare(DeserializeDBfvPublicKeyShare(context.get(), const_cast<uint8_t*>(data.data()), data.size()));
}

Bytes E2sPublicShare::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeDBfvCKSShare, this->get(), _1, _2));
}

E2sPublicShare E2sPublicShare::deserialize(const E2sContext& context, BytesView data) {
    return E2sPublicShare(DeserializeDBfvE2SCKSShare(context.get(), const_cast<uint8_t*>(data.data()), data.size()));
}

Bytes S2ePublicShare::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeDBfvCKSShare, this->get(), _1, _2));
}

S2ePublicShare S2ePublicShare::deserialize(const S2eContext& context, BytesView data) {
    return S2ePublicShare(DeserializeDBfvS2ECKSShare(context.get(), const_cast<uint8_t*>(data.data()), data.size()));
}

Bytes AdditiveShare::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeDBfvAdditiveShare, this->get(), _1, _2));
}

AdditiveShare AdditiveShare::deserialize(const DBfvContext& context, BytesView data) {
    return AdditiveShare(DeserializeDBfvAdditiveShare(context.get(), const_cast<uint8_t*>(data.data()), data.size()));
}

Bytes RelinKeyShare::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeDBfvRelinKeyShare, this->get(), _1, _2));
}

RelinKeyShare RelinKeyShare::deserialize(const RkgContext& context, BytesView data) {
    return RelinKeyShare(DeserializeDBfvRelinKeyShare(context.get(), const_cast<uint8_t*>(data.data()), data.size()));
}

Bytes RefreshShare::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeDBfvRefreshShare, this->get(), _1, _2));
}

RefreshShare RefreshShare::deserialize(const RefreshContext& context, BytesView data) {
    return RefreshShare(DeserializeDBfvRefreshShare(context.get(), const_cast<uint8_t*>(data.data()), data.size()));
}

Bytes RefreshAndPermuteShare::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeDBfvRefreshAndPermuteShare, this->get(), _1, _2));
}

RefreshAndPermuteShare RefreshAndPermuteShare::deserialize(const RefreshAndPermuteContext& context, BytesView data) {
    return RefreshAndPermuteShare(
        DeserializeDBfvvRefreshAndPermuteShare(context.get(), const_cast<uint8_t*>(data.data()), data.size()));
}

Bytes GaloisKeyShare::serialize() const {
    return export_raw_data<uint8_t>(std::bind(SerializeDBfvGaloisKeyShare, this->get(), _1, _2));
}

GaloisKeyShare GaloisKeyShare::deserialize(const RtgContext& context, BytesView data) {
    return GaloisKeyShare(DeserializeDBfvGaloisKeyShare(context.get(), const_cast<uint8_t*>(data.data()), data.size()));
}

}  // namespace fhe_ops_lib

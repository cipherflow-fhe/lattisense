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

#include <algorithm>
#include <stdexcept>
#include "ckks.h"
#include "../base/internal.h"

namespace fhe_ops_lib {

// ─── CkksParameter ───────────────────────────────────────────────────────────

CkksParameter CkksParameter::create_parameter(int log_n) {
    uint64_t handle = 0;
    CHECK(CreateCkksDefaultParameter(log_n, &handle));
    return CkksParameter(std::move(handle));
}

CkksParameter CkksParameter::create_custom_parameter(int log_n,
                                                     int log_default_scale,
                                                     const std::vector<uint64_t>& q,
                                                     const std::vector<uint64_t>& p) {
    uint64_t handle = 0;
    CHECK(CreateCkksCustomParameter(log_n, log_default_scale, (uint64_t*)q.data(), q.size(), (uint64_t*)p.data(),
                                    p.size(), &handle));
    return CkksParameter(std::move(handle));
}

CkksParameter CkksParameter::copy() const {
    uint64_t handle = 0;
    CHECK(CopyCkksParameter(this->get(), &handle));
    return CkksParameter(std::move(handle));
}

Bytes CkksParameter::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeCkksParameter(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

CkksParameter CkksParameter::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeCkksParameter((uint8_t*)data.data(), data.size(), &handle));
    return CkksParameter(std::move(handle));
}

void CkksParameter::print() const {
    CHECK(PrintCkksParameter(this->get()));
}

int CkksParameter::n() const {
    int value = 0;
    CHECK(GetCkksN(this->get(), &value));
    return value;
}

int CkksParameter::log_n() const {
    int value = 0;
    CHECK(GetCkksLogN(this->get(), &value));
    return value;
}

int CkksParameter::max_level() const {
    int value = 0;
    CHECK(GetCkksMaxLevel(this->get(), &value));
    return value;
}

std::vector<uint64_t> CkksParameter::q() const {
    std::vector<uint64_t> result(max_level() + 1);
    CHECK(GetCkksQ(this->get(), result.data()));
    return result;
}

std::vector<uint64_t> CkksParameter::p() const {
    uint64_t length = 0;
    CHECK(GetCkksP(this->get(), nullptr, &length));
    std::vector<uint64_t> result(length);
    if (length != 0) {
        CHECK(GetCkksP(this->get(), result.data(), &length));
    }
    return result;
}

int CkksParameter::log_max_slots() const {
    int value = 0;
    CHECK(GetCkksLogMaxSlots(this->get(), &value));
    return value;
}

int CkksParameter::max_slots() const {
    int value = 0;
    CHECK(GetCkksMaxSlots(this->get(), &value));
    return value;
}

double CkksParameter::default_scale() const {
    double value = 0;
    CHECK(GetCkksDefaultScale(this->get(), &value));
    return value;
}

int CkksParameter::log_default_scale() const {
    int value = 0;
    CHECK(GetCkksLogDefaultScale(this->get(), &value));
    return value;
}

// ─── CkksEncoder ─────────────────────────────────────────────────────────────

CkksEncoder::CkksEncoder(const CkksParameter& parameter) {
    if (parameter.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }

    uint64_t encoder_handle = 0;
    CHECK(CreateCkksEncoder(parameter.get(), &encoder_handle));
    _value = encoder_handle;
    _keep = false;
}

// ─── CkksEvaluator ───────────────────────────────────────────────────────────

CkksEvaluator::CkksEvaluator(const CkksParameter& parameter, const EvaluationKeySet& evaluation_key_set) {
    if (parameter.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }
    if (evaluation_key_set.is_empty()) {
        throw std::runtime_error("CKKS evaluation key set is not set");
    }

    uint64_t evaluator_handle = 0;
    CHECK(CreateCkksEvaluator(parameter.get(), evaluation_key_set.get(), &evaluator_handle));
    _value = evaluator_handle;
    _keep = false;
}

void CkksEvaluator::update_evaluation_key_set(const EvaluationKeySet& evaluation_key_set) {
    if (is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }
    if (evaluation_key_set.is_empty()) {
        throw std::runtime_error("CKKS evaluation key set is not set");
    }
    CHECK(SetCkksEvaluatorEvaluationKeySet(get(), evaluation_key_set.get()));
}

// ─── CkksPlaintext ───────────────────────────────────────────────────────────

CkksPlaintext::CkksPlaintext(uint64_t&& h, bool k) : Handle(std::move(h), k) {
    if (is_empty()) {
        throw std::runtime_error("CKKS plaintext handle is empty");
    }
    sync_metadata();
}

CkksPlaintext::CkksPlaintext(const CkksParameter& param, Metadata metadata, bool k) {
    if (param.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }
    uint64_t handle = 0;
    CHECK(NewPlaintext(param.get(), &metadata, &handle));
    _value = handle;
    _keep = k;
    if (is_empty()) {
        throw std::runtime_error("CKKS plaintext handle is empty");
    }
    sync_metadata();
}

bool CkksPlaintext::is_ringt() const {
    return _metadata.is_ringt != 0;
}

bool CkksPlaintext::is_batched() const {
    return _metadata.is_batched != 0;
}

int CkksPlaintext::log_slots() const {
    return _metadata.log_slots;
}

double CkksPlaintext::scale() const {
    return _metadata.scale;
}

void CkksPlaintext::sync_metadata() {
    GetPlaintextMetadata(this->get(), &_metadata);
}

Metadata CkksPlaintext::metadata() const {
    return _metadata;
}

int CkksPlaintext::level() const {
    return _metadata.level;
}

Bytes CkksPlaintext::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializePlaintext(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

CkksPlaintext CkksPlaintext::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializePlaintext((uint8_t*)data.data(), data.size(), &handle));
    return CkksPlaintext(std::move(handle));
}

// ─── CkksCiphertext ──────────────────────────────────────────────────────────

CkksCiphertext::CkksCiphertext(uint64_t&& h, bool k) : Handle(std::move(h), k) {
    if (is_empty()) {
        throw std::runtime_error("CKKS ciphertext handle is empty");
    }
    sync_metadata();
}

CkksCiphertext::CkksCiphertext(const CkksParameter& param, int level, int degree, bool k) {
    if (param.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }
    uint64_t handle = 0;
    CHECK(NewCiphertext(param.get(), degree, level, &handle));
    _value = handle;
    _keep = k;
    if (is_empty()) {
        throw std::runtime_error("CKKS ciphertext handle is empty");
    }
    sync_metadata();
}

int CkksCiphertext::degree() const {
    return _metadata.degree;
}

int CkksCiphertext::level() const {
    return _metadata.level;
}

double CkksCiphertext::scale() const {
    return _metadata.scale;
}

double CkksCiphertext::set_scale(double scale_in) {
    SetCiphertextScale(this->get(), scale_in);
    sync_metadata();
    return _metadata.scale;
}

void CkksCiphertext::sync_metadata() {
    GetCiphertextMetadata(this->get(), &_metadata);
}

Metadata CkksCiphertext::metadata() const {
    return _metadata;
}

Bytes CkksCiphertext::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeCiphertext(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

CkksCiphertext CkksCiphertext::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeCiphertext((uint8_t*)data.data(), data.size(), &handle));
    return CkksCiphertext(std::move(handle));
}

CkksCiphertext CkksCiphertext::copy() const {
    CkksCiphertext opOut(CopyCkksCiphertext(this->get()));
    opOut._metadata = _metadata;
    return opOut;
}

void CkksCiphertext::copy(CkksCiphertext& y_ct) const {
    CopyCkksCiphertextTo(this->get(), y_ct.get());
    y_ct.sync_metadata();
}

// ─── CkksContext ─────────────────────────────────────────────────────────────

const uint8_t CkksContext::CONTEXT_MAGIC[8] = {'C', 'K', 'K', 'S', 'C', 'T', 'X', '1'};

CkksContext CkksContext::create_empty_context(const CkksParameter& param) {
    if (param.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }

    CkksContext context;
    context._parameter = param.copy();
    context._encoder = CkksEncoder(context._parameter);

    context._key_generator = KeyGenerator(context._parameter);
    context._evaluation_key_set = EvaluationKeySet(RelinKey(), {});
    context._evaluator = CkksEvaluator(context._parameter, context._evaluation_key_set);
    return context;
}

CkksContext CkksContext::create_random_context(const CkksParameter& param,
                                               EncryptorType encryptor_type,
                                               bool enable_bootstrapping) {
    if (param.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }

    CkksContext context;
    context._parameter = param.copy();
    int level = context._parameter.max_level();

    context._encoder = CkksEncoder(context._parameter);

    context._key_generator = KeyGenerator(context._parameter);

    context._secret_key = SecretKey(context._key_generator);
    context._public_key = PublicKey(context._key_generator, context._secret_key);

    if (encryptor_type == EncryptorType::PUBLIC_KEY) {
        context._encryptor = Encryptor(context._parameter, context._public_key);
    } else {
        context._encryptor = Encryptor(context._parameter, context._secret_key);
    }

    context._decryptor = Decryptor(context._parameter, context._secret_key);

    context._evaluation_key_set = EvaluationKeySet(RelinKey(context._key_generator, context._secret_key, level), {});
    context._evaluator = CkksEvaluator(context._parameter, context._evaluation_key_set);
    if (enable_bootstrapping) {
        context.create_bootstrapper();
    }
    return context;
}

void CkksContext::gen_rotation_keys(int level) {
    const int log_n = parameter().log_n();
    std::vector<int32_t> rotations;
    rotations.reserve(2 * log_n - 3);
    for (int i = 0; i < log_n - 1; ++i) {
        rotations.push_back(1 << i);
    }
    for (int i = 0; i < log_n - 2; ++i) {
        rotations.push_back(-1 * (1 << i));
    }

    gen_rotation_keys(rotations, true, level);
    _use_default_rotation_keys = true;
}

void CkksContext::set_use_default_rotation_keys(bool use_default_rotation_keys) {
    _use_default_rotation_keys = use_default_rotation_keys;
}

void CkksContext::gen_rotation_keys(const std::vector<int32_t>& rots, bool include_swap_rows, int level) {
    std::vector<int32_t> rotations;
    rotations.reserve(rots.size());
    for (int32_t rotation : rots) {
        if (std::find(rotations.begin(), rotations.end(), rotation) == rotations.end()) {
            rotations.push_back(rotation);
        }
    }

    std::vector<uint64_t> galois_elements(rotations.size() + (include_swap_rows ? 1 : 0));
    std::vector<uint64_t> galois_key_handles(galois_elements.size());
    CHECK(GenGaloisKeysForRotations(key_generator().get(), secret_key().get(),
                                    rotations.empty() ? nullptr : rotations.data(), static_cast<int>(rotations.size()),
                                    include_swap_rows, level,
                                    galois_elements.empty() ? nullptr : galois_elements.data(),
                                    galois_key_handles.empty() ? nullptr : galois_key_handles.data()));

    if (_evaluation_key_set.is_empty()) {
        throw std::runtime_error("CKKS evaluation key set is not set");
    }
    for (size_t i = 0; i < galois_elements.size(); ++i) {
        uint64_t handle = galois_key_handles[i];
        _evaluation_key_set.set_galois_key(GaloisKey(std::move(handle)));
    }
    _evaluator.update_evaluation_key_set(_evaluation_key_set);
    _use_default_rotation_keys = false;
}

const CkksParameter& CkksContext::parameter() {
    if (_parameter.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }
    return _parameter;
}

const SecretKey& CkksContext::secret_key() const {
    if (_secret_key.is_empty()) {
        throw std::runtime_error("CKKS secret key is not set");
    }
    return _secret_key;
}

const PublicKey& CkksContext::public_key() const {
    if (_public_key.is_empty()) {
        throw std::runtime_error("CKKS public key is not set");
    }
    return _public_key;
}

const EvaluationKeySet& CkksContext::evaluation_key_set() const {
    if (_evaluation_key_set.is_empty()) {
        throw std::runtime_error("CKKS evaluation key set is not set");
    }
    return _evaluation_key_set;
}

void CkksContext::set_relin_key(const RelinKey& rlk) {
    if (rlk.is_empty()) {
        throw std::runtime_error("CKKS relinearization key is not set");
    }
    if (_evaluation_key_set.is_empty()) {
        throw std::runtime_error("CKKS evaluation key set is not set");
    }

    _evaluation_key_set.set_relin_key(rlk.copy());
    _evaluator.update_evaluation_key_set(_evaluation_key_set);
}

void CkksContext::set_galois_key(const GaloisKey& gk) {
    if (gk.is_empty()) {
        throw std::runtime_error("CKKS Galois key is not set");
    }
    if (_evaluation_key_set.is_empty()) {
        throw std::runtime_error("CKKS evaluation key set is not set");
    }

    _evaluation_key_set.set_galois_key(gk.copy());
    _evaluator.update_evaluation_key_set(_evaluation_key_set);
}

Bytes CkksContext::serialize() const {
    if (_parameter.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }

    Bytes data;
    data.insert(data.end(), CONTEXT_MAGIC, CONTEXT_MAGIC + sizeof(CONTEXT_MAGIC));
    append_bytes(data, _parameter.serialize());

    append_u8(data, _use_default_rotation_keys ? 1 : 0);
    append_u8(data, _enable_bootstrapping ? 1 : 0);

    const bool has_public_key = !_public_key.is_empty();
    append_u8(data, has_public_key ? 1 : 0);
    if (has_public_key) {
        append_bytes(data, _public_key.serialize());
    }

    const bool has_evaluation_key_set = !_evaluation_key_set.is_empty();
    append_u8(data, has_evaluation_key_set ? 1 : 0);
    if (has_evaluation_key_set) {
        append_bytes(data, _evaluation_key_set.serialize());
    }

    const bool has_bootstrapping_evaluation_keys = !_bootstrapping_evaluation_keys.is_empty();
    append_u8(data, has_bootstrapping_evaluation_keys ? 1 : 0);
    if (has_bootstrapping_evaluation_keys) {
        append_bytes(data, _bootstrapping_evaluation_keys.serialize());
    }
    return data;
}

CkksContext CkksContext::deserialize(BytesView data) {
    size_t offset = 0;
    if (data.size() < sizeof(CONTEXT_MAGIC)) {
        throw std::runtime_error("CKKS context data is truncated");
    }
    for (uint8_t value : CONTEXT_MAGIC) {
        if (data[offset++] != value) {
            throw std::runtime_error("invalid CKKS context data");
        }
    }

    CkksContext context;
    context._parameter = CkksParameter::deserialize(read_bytes(data, offset, "parameter"));

    const bool use_default_rotation_keys = read_u8(data, offset, "rotation key flag") != 0;
    const bool enable_bootstrapping = read_u8(data, offset, "bootstrapping flag") != 0;
    const bool has_public_key = read_u8(data, offset, "public key flag") != 0;
    context._encoder = CkksEncoder(context._parameter);
    context._key_generator = KeyGenerator(context._parameter);

    if (has_public_key) {
        context._public_key = PublicKey::deserialize(read_bytes(data, offset, "public key"));
        context._encryptor = Encryptor(context._parameter, context._public_key);
    }

    const bool has_evaluation_key_set = read_u8(data, offset, "evaluation key set flag") != 0;
    if (has_evaluation_key_set) {
        context._evaluation_key_set = EvaluationKeySet::deserialize(read_bytes(data, offset, "evaluation key set"));
    } else {
        context._evaluation_key_set = EvaluationKeySet(RelinKey(), {});
    }
    context._evaluator = CkksEvaluator(context._parameter, context._evaluation_key_set);
    context._use_default_rotation_keys = use_default_rotation_keys;

    const bool has_bootstrapping_evaluation_keys = read_u8(data, offset, "bootstrapping evaluation keys flag") != 0;
    if (has_bootstrapping_evaluation_keys) {
        uint64_t handle = 0;
        CHECK(CreateCkksBtpParameterFromResidualParameter(context._parameter.get(), &handle));
        context._btp_parameter = Handle(std::move(handle));
        context._bootstrapping_evaluation_keys =
            BootstrappingEvaluationKeys::deserialize(read_bytes(data, offset, "bootstrapping evaluation keys"));
    }
    context._enable_bootstrapping = enable_bootstrapping;

    if (offset != data.size()) {
        throw std::runtime_error("CKKS context data has trailing bytes");
    }
    return context;
}

void CkksContext::encode(const std::vector<double>& message, CkksPlaintext& pt) {
    if (_encoder.is_empty()) {
        throw std::runtime_error("CKKS encoder is not set");
    }
    CHECK(CkksEncodeReal(_encoder.get(), (double*)message.data(), message.size(), pt.get()));
    pt.sync_metadata();
}

void CkksContext::encode(const std::vector<std::complex<double>>& message, CkksPlaintext& pt) {
    if (_encoder.is_empty()) {
        throw std::runtime_error("CKKS encoder is not set");
    }
    if (!pt.is_batched()) {
        throw std::runtime_error("CKKS coefficient encoding only supports real inputs");
    }
    CHECK(CkksEncodeComplex(_encoder.get(), (double*)message.data(), message.size(), pt.get()));
    pt.sync_metadata();
}

void CkksContext::decode(const CkksPlaintext& pt, std::vector<double>& message) {
    if (_encoder.is_empty()) {
        throw std::runtime_error("CKKS encoder is not set");
    }

    double* raw_data = nullptr;
    uint64_t length = 0;
    uint64_t data_handle = 0;
    CHECK(CkksDecode(_encoder.get(), pt.get(), &raw_data, &length, &data_handle));
    message.resize(length);
    for (size_t i = 0; i < length; i++) {
        message[i] = raw_data[i * 2];
    }
    ReleaseHandle(data_handle);
}

void CkksContext::decode(const CkksPlaintext& pt, std::vector<std::complex<double>>& message) {
    if (_encoder.is_empty()) {
        throw std::runtime_error("CKKS encoder is not set");
    }

    double* raw_data = nullptr;
    uint64_t length = 0;
    uint64_t data_handle = 0;
    CHECK(CkksDecode(_encoder.get(), pt.get(), &raw_data, &length, &data_handle));
    message.resize(length);
    for (size_t i = 0; i < length; i++) {
        message[i] = std::complex<double>(raw_data[i * 2], raw_data[i * 2 + 1]);
    }
    ReleaseHandle(data_handle);
}

// CkksPlaintext CkksContext::recode_big_complex(const CkksPlaintext& pt, int level, double scale) {
//     return CkksRecodeBigComplex(require_handle(_encoder, "CKKS encoder is not set"), pt.get(), level, scale);
// }

CkksCiphertext CkksContext::encrypt(const CkksPlaintext& pt) {
    if (_encryptor.is_empty()) {
        throw std::runtime_error("CKKS encryptor is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksEncrypt(_encryptor.get(), pt.get(), &ciphertext_handle));
    CkksCiphertext ct(std::move(ciphertext_handle));
    ct.sync_metadata();
    return ct;
}

// CkksCompressedCiphertext CkksContext::encrypt_symmetric_compressed(const CkksPlaintext& pt) {
//     return CkksCompressedCiphertext(
//         CkksEncryptSymmetricCompressed(require_handle(_encryptor, "CKKS encryptor is not set"), pt.get()));
// }

CkksPlaintext CkksContext::decrypt(const CkksCiphertext& ct) {
    if (_decryptor.is_empty()) {
        throw std::runtime_error("CKKS decryptor is not set");
    }

    uint64_t plaintext_handle = 0;
    CHECK(CkksDecrypt(_decryptor.get(), ct.get(), &plaintext_handle));
    CkksPlaintext pt(std::move(plaintext_handle));
    pt.sync_metadata();
    return pt;
}

CkksCiphertext CkksContext::add(const CkksCiphertext& op0, const CkksCiphertext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksAdd(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::add(const CkksCiphertext& op0, const CkksPlaintext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksAdd(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::add(const CkksCiphertext& op0, double op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksAddScalar(_evaluator.get(), op0.get(), op1, 0, &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::add(const CkksCiphertext& op0, const std::complex<double>& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksAddScalar(_evaluator.get(), op0.get(), op1.real(), op1.imag(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::sub(const CkksCiphertext& op0, const CkksCiphertext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksSub(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::sub(const CkksCiphertext& op0, const CkksPlaintext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksSub(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::sub(const CkksCiphertext& op0, double op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksSubScalar(_evaluator.get(), op0.get(), op1, 0, &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::sub(const CkksCiphertext& op0, const std::complex<double>& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksSubScalar(_evaluator.get(), op0.get(), op1.real(), op1.imag(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::mult(const CkksCiphertext& op0, const CkksCiphertext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksMul(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::mult(const CkksCiphertext& op0, const CkksPlaintext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksMul(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::mult(const CkksCiphertext& op0, double op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksMulScalar(_evaluator.get(), op0.get(), op1, 0, &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::mult(const CkksCiphertext& op0, const std::complex<double>& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksMulScalar(_evaluator.get(), op0.get(), op1.real(), op1.imag(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::relinearize(const CkksCiphertext& op0) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksRelinearize(_evaluator.get(), op0.get(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::drop_level(const CkksCiphertext& op0, int levels) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksDropLevel(_evaluator.get(), op0.get(), levels, &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::rescale(const CkksCiphertext& op0) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksRescale(_evaluator.get(), op0.get(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

CkksCiphertext CkksContext::rotate(const CkksCiphertext& op0, int32_t step) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    const uint8_t use_default_rotation_keys = _use_default_rotation_keys ? 1 : 0;
    CHECK(CkksRotate(_evaluator.get(), op0.get(), &step, 1, use_default_rotation_keys, &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

std::map<int32_t, CkksCiphertext> CkksContext::rotate(const CkksCiphertext& op0, const std::vector<int32_t>& steps) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    std::map<int32_t, CkksCiphertext> opOut;
    std::vector<uint64_t> ciphertext_handles(steps.size());
    const uint8_t use_default_rotation_keys = _use_default_rotation_keys ? 1 : 0;
    CHECK(CkksRotate(_evaluator.get(), op0.get(), (int32_t*)steps.data(), steps.size(), use_default_rotation_keys,
                     ciphertext_handles.data()));
    for (size_t i = 0; i < steps.size(); i++) {
        CkksCiphertext rotated(std::move(ciphertext_handles[i]));
        rotated.sync_metadata();
        opOut[steps[i]] = std::move(rotated);
    }
    return opOut;
}

// CkksCiphertext
// CkksContext::poly_eval_relu_function(const CkksCiphertext& x_ct_h, double left, double right, int degree) {
//     (void)x_ct_h;
//     (void)left;
//     (void)right;
//     (void)degree;
//     unsupported_context_handle_api("CkksContext::poly_eval_relu_function");
// }

// CkksCiphertext
// CkksContext::poly_eval_function(Operation op, const CkksCiphertext& x_ct_h, double left, double right, int degree) {
//     (void)op;
//     (void)x_ct_h;
//     (void)left;
//     (void)right;
//     (void)degree;
//     unsupported_context_handle_api("CkksContext::poly_eval_function");
// }

CkksCiphertext CkksContext::conjugate(const CkksCiphertext& op0) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("CKKS evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(CkksConjugate(_evaluator.get(), op0.get(), &ciphertext_handle));
    CkksCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

// CkksCiphertext CkksContext::poly_eval_step_function(const CkksCiphertext& x_ct,
//                                                     const double left,
//                                                     const double right,
//                                                     const uint64_t degree,
//                                                     const double threshold) {
//     return CkksCiphertext(
//         CkksPolyEvalStepFunction(require_handle(_evaluator, "CKKS evaluator is not set"), x_ct.get(), left, right,
//         degree, threshold));
// }

}  // namespace fhe_ops_lib

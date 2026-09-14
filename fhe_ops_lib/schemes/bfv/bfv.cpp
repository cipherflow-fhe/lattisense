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
#include "bfv.h"
#include "../base/internal.h"

namespace fhe_ops_lib {

// ─── BfvParameter ────────────────────────────────────────────────────────────

BfvParameter BfvParameter::create_parameter(int log_n, uint64_t t) {
    uint64_t handle = 0;
    CHECK(CreateBfvDefaultParameter(log_n, t, &handle));
    return BfvParameter(std::move(handle));
}

BfvParameter BfvParameter::create_custom_parameter(int log_n,
                                                   uint64_t t,
                                                   const std::vector<uint64_t>& q,
                                                   const std::vector<uint64_t>& p) {
    uint64_t handle = 0;
    CHECK(CreateBfvCustomParameter(log_n, t, (uint64_t*)q.data(), q.size(), (uint64_t*)p.data(), p.size(), &handle));
    return BfvParameter(std::move(handle));
}

BfvParameter BfvParameter::copy() const {
    uint64_t handle = 0;
    CHECK(CopyBfvParameter(this->get(), &handle));
    return BfvParameter(std::move(handle));
}

Bytes BfvParameter::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeBfvParameter(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

BfvParameter BfvParameter::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeBfvParameter((uint8_t*)data.data(), data.size(), &handle));
    return BfvParameter(std::move(handle));
}

void BfvParameter::print() const {
    CHECK(PrintBfvParameter(this->get()));
}

int BfvParameter::n() const {
    int value = 0;
    CHECK(GetBfvN(this->get(), &value));
    return value;
}

int BfvParameter::log_n() const {
    int value = 0;
    CHECK(GetBfvLogN(this->get(), &value));
    return value;
}

int BfvParameter::max_level() const {
    int value = 0;
    CHECK(GetBfvMaxLevel(this->get(), &value));
    return value;
}

std::vector<uint64_t> BfvParameter::q() const {
    std::vector<uint64_t> result(max_level() + 1);
    CHECK(GetBfvQ(this->get(), result.data()));
    return result;
}

std::vector<uint64_t> BfvParameter::p() const {
    uint64_t length = 0;
    CHECK(GetBfvP(this->get(), nullptr, &length));
    std::vector<uint64_t> result(length);
    CHECK(GetBfvP(this->get(), result.data(), &length));
    return result;
}

uint64_t BfvParameter::t() const {
    uint64_t value = 0;
    CHECK(GetBfvT(this->get(), &value));
    return value;
}

// ─── BfvEncoder ──────────────────────────────────────────────────────────────

BfvEncoder::BfvEncoder(const BfvParameter& parameter) {
    if (parameter.is_empty()) {
        throw std::runtime_error("BFV parameter is not set");
    }

    uint64_t encoder_handle = 0;
    CHECK(CreateBfvEncoder(parameter.get(), &encoder_handle));
    _value = encoder_handle;
    _keep = false;
}

// ─── BfvEvaluator ────────────────────────────────────────────────────────────

BfvEvaluator::BfvEvaluator(const BfvParameter& parameter, const EvaluationKeySet& evaluation_key_set) {
    if (parameter.is_empty()) {
        throw std::runtime_error("BFV parameter is not set");
    }
    if (evaluation_key_set.is_empty()) {
        throw std::runtime_error("BFV evaluation key set is not set");
    }

    uint64_t evaluator_handle = 0;
    CHECK(CreateBfvEvaluator(parameter.get(), evaluation_key_set.get(), &evaluator_handle));
    _value = evaluator_handle;
    _keep = false;
}

void BfvEvaluator::update_evaluation_key_set(const EvaluationKeySet& evaluation_key_set) {
    if (is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }
    if (evaluation_key_set.is_empty()) {
        throw std::runtime_error("BFV evaluation key set is not set");
    }
    CHECK(SetBfvEvaluatorEvaluationKeySet(get(), evaluation_key_set.get()));
}

// ─── BfvPlaintext ────────────────────────────────────────────────────────────

BfvPlaintext::BfvPlaintext(uint64_t&& h, bool k) : Handle(std::move(h), k) {
    if (is_empty()) {
        throw std::runtime_error("BFV plaintext handle is empty");
    }
    sync_metadata();
}

BfvPlaintext::BfvPlaintext(const BfvParameter& param, Metadata metadata, bool k) {
    if (param.is_empty()) {
        throw std::runtime_error("BFV parameter is not set");
    }
    uint64_t handle = 0;
    CHECK(NewPlaintext(param.get(), &metadata, &handle));
    _value = handle;
    _keep = k;
    if (is_empty()) {
        throw std::runtime_error("BFV plaintext handle is empty");
    }
    sync_metadata();
}

bool BfvPlaintext::is_ringt() const {
    return _metadata.is_ringt != 0;
}

bool BfvPlaintext::is_batched() const {
    return _metadata.is_batched != 0;
}

void BfvPlaintext::sync_metadata() {
    GetPlaintextMetadata(this->get(), &_metadata);
}

Metadata BfvPlaintext::metadata() const {
    return _metadata;
}

int BfvPlaintext::level() const {
    return _metadata.level;
}

Bytes BfvPlaintext::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializePlaintext(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

BfvPlaintext BfvPlaintext::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializePlaintext((uint8_t*)data.data(), data.size(), &handle));
    return BfvPlaintext(std::move(handle));
}

// ─── BfvCiphertext ───────────────────────────────────────────────────────────

BfvCiphertext::BfvCiphertext(uint64_t&& h, bool k) : Handle(std::move(h), k) {
    if (is_empty()) {
        throw std::runtime_error("BFV ciphertext handle is empty");
    }
    sync_metadata();
}

BfvCiphertext::BfvCiphertext(const BfvParameter& param, int level, int degree, bool k) {
    if (param.is_empty()) {
        throw std::runtime_error("BFV parameter is not set");
    }
    uint64_t handle = 0;
    CHECK(NewCiphertext(param.get(), degree, level, &handle));
    _value = handle;
    _keep = k;
    if (is_empty()) {
        throw std::runtime_error("BFV ciphertext handle is empty");
    }
    sync_metadata();
}

int BfvCiphertext::degree() const {
    return _metadata.degree;
}

int BfvCiphertext::level() const {
    return _metadata.level;
}

Metadata BfvCiphertext::metadata() const {
    return _metadata;
}

void BfvCiphertext::sync_metadata() {
    GetCiphertextMetadata(this->get(), &_metadata);
}

Bytes BfvCiphertext::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeCiphertext(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

BfvCiphertext BfvCiphertext::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeCiphertext((uint8_t*)data.data(), data.size(), &handle));
    return BfvCiphertext(std::move(handle));
}

BfvCiphertext BfvCiphertext::copy() const {
    BfvCiphertext opOut(CopyBfvCiphertext(this->get()));
    opOut._metadata = _metadata;
    return opOut;
}

void BfvCiphertext::copy(BfvCiphertext& y_ct) const {
    CopyBfvCiphertextTo(this->get(), y_ct.get());
    y_ct.sync_metadata();
}

// ─── BfvContext ──────────────────────────────────────────────────────────────

const uint8_t BfvContext::CONTEXT_MAGIC[8] = {'B', 'F', 'V', 'C', 'T', 'X', '0', '1'};

BfvContext BfvContext::create_empty_context(const BfvParameter& param) {
    if (param.is_empty()) {
        throw std::runtime_error("BFV parameter is not set");
    }

    BfvContext context;
    context._parameter = param.copy();
    context._encoder = BfvEncoder(context._parameter);

    context._key_generator = KeyGenerator(context._parameter);
    context._evaluation_key_set = EvaluationKeySet(RelinKey(), {});
    context._evaluator = BfvEvaluator(context._parameter, context._evaluation_key_set);
    return context;
}

BfvContext BfvContext::create_random_context(const BfvParameter& param, EncryptorType encryptor_type) {
    if (param.is_empty()) {
        throw std::runtime_error("BFV parameter is not set");
    }

    BfvContext context;
    context._parameter = param.copy();
    int level = context._parameter.max_level();

    context._encoder = BfvEncoder(context._parameter);

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
    context._evaluator = BfvEvaluator(context._parameter, context._evaluation_key_set);
    return context;
}

const BfvParameter& BfvContext::parameter() {
    if (_parameter.is_empty()) {
        throw std::runtime_error("BFV parameter is not set");
    }
    return _parameter;
}

const SecretKey& BfvContext::secret_key() const {
    if (_secret_key.is_empty()) {
        throw std::runtime_error("BFV secret key is not set");
    }
    return _secret_key;
}

const PublicKey& BfvContext::public_key() const {
    if (_public_key.is_empty()) {
        throw std::runtime_error("BFV public key is not set");
    }
    return _public_key;
}

void BfvContext::gen_rotation_keys(int level) {
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

void BfvContext::set_use_default_rotation_keys(bool use_default_rotation_keys) {
    _use_default_rotation_keys = use_default_rotation_keys;
}

void BfvContext::gen_rotation_keys(const std::vector<int32_t>& rots, bool include_swap_rows, int level) {
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
        throw std::runtime_error("BFV evaluation key set is not set");
    }
    for (size_t i = 0; i < galois_elements.size(); ++i) {
        uint64_t handle = galois_key_handles[i];
        _evaluation_key_set.set_galois_key(GaloisKey(std::move(handle)));
    }
    _evaluator.update_evaluation_key_set(_evaluation_key_set);
    _use_default_rotation_keys = false;
}

const EvaluationKeySet& BfvContext::evaluation_key_set() const {
    if (_evaluation_key_set.is_empty()) {
        throw std::runtime_error("BFV evaluation key set is not set");
    }
    return _evaluation_key_set;
}

void BfvContext::set_relin_key(const RelinKey& rlk) {
    if (rlk.is_empty()) {
        throw std::runtime_error("BFV relinearization key is not set");
    }
    if (_evaluation_key_set.is_empty()) {
        throw std::runtime_error("BFV evaluation key set is not set");
    }

    try {
        _evaluation_key_set.set_relin_key(rlk.copy());
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("failed to set BFV evaluation key set relin key: ") + e.what());
    }
    try {
        _evaluator.update_evaluation_key_set(_evaluation_key_set);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("failed to update BFV evaluator with relin key: ") + e.what());
    }
}

void BfvContext::set_galois_key(const GaloisKey& gk) {
    if (gk.is_empty()) {
        throw std::runtime_error("BFV Galois key is not set");
    }
    if (_evaluation_key_set.is_empty()) {
        throw std::runtime_error("BFV evaluation key set is not set");
    }

    _evaluation_key_set.set_galois_key(gk.copy());
    _evaluator.update_evaluation_key_set(_evaluation_key_set);
}

Bytes BfvContext::serialize() const {
    if (_parameter.is_empty()) {
        throw std::runtime_error("BFV parameter is not set");
    }

    Bytes data;
    data.insert(data.end(), CONTEXT_MAGIC, CONTEXT_MAGIC + sizeof(CONTEXT_MAGIC));
    append_bytes(data, _parameter.serialize());

    append_u8(data, _use_default_rotation_keys ? 1 : 0);

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
    return data;
}

BfvContext BfvContext::deserialize(BytesView data) {
    size_t offset = 0;
    if (data.size() < sizeof(CONTEXT_MAGIC)) {
        throw std::runtime_error("BFV context data is truncated");
    }
    for (uint8_t value : CONTEXT_MAGIC) {
        if (data[offset++] != value) {
            throw std::runtime_error("invalid BFV context data");
        }
    }

    BfvContext context;
    context._parameter = BfvParameter::deserialize(read_bytes(data, offset, "parameter"));

    const bool use_default_rotation_keys = read_u8(data, offset, "rotation key flag") != 0;
    const bool has_public_key = read_u8(data, offset, "public key flag") != 0;
    context._encoder = BfvEncoder(context._parameter);
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
    context._evaluator = BfvEvaluator(context._parameter, context._evaluation_key_set);
    context._use_default_rotation_keys = use_default_rotation_keys;

    if (offset != data.size()) {
        throw std::runtime_error("BFV context data has trailing bytes");
    }
    return context;
}

void BfvContext::encode(const std::vector<uint64_t>& message, BfvPlaintext& pt) {
    if (_encoder.is_empty()) {
        throw std::runtime_error("BFV encoder is not set");
    }
    CHECK(BfvEncode(_encoder.get(), (uint64_t*)message.data(), message.size(), pt.get()));
    pt.sync_metadata();
}

void BfvContext::decode(const BfvPlaintext& pt, std::vector<uint64_t>& message) {
    if (_encoder.is_empty()) {
        throw std::runtime_error("BFV encoder is not set");
    }

    uint64_t* raw_data = nullptr;
    uint64_t length = 0;
    uint64_t data_handle = 0;
    CHECK(BfvDecode(_encoder.get(), pt.get(), &raw_data, &length, &data_handle));
    message.resize(length);
    for (size_t i = 0; i < length; i++) {
        message[i] = raw_data[i];
    }
    ReleaseHandle(data_handle);
}

BfvCiphertext BfvContext::encrypt(const BfvPlaintext& pt) {
    if (_encryptor.is_empty()) {
        throw std::runtime_error("BFV encryptor is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvEncrypt(_encryptor.get(), pt.get(), &ciphertext_handle));
    BfvCiphertext ct(std::move(ciphertext_handle));
    ct.sync_metadata();
    return ct;
}

BfvPlaintext BfvContext::decrypt(const BfvCiphertext& ct) {
    if (_decryptor.is_empty()) {
        throw std::runtime_error("BFV decryptor is not set");
    }

    uint64_t plaintext_handle = 0;
    CHECK(BfvDecrypt(_decryptor.get(), ct.get(), &plaintext_handle));
    BfvPlaintext pt(std::move(plaintext_handle));
    pt.sync_metadata();
    return pt;
}

BfvCiphertext BfvContext::add(const BfvCiphertext& op0, const BfvCiphertext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvAdd(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::add(const BfvCiphertext& op0, const BfvPlaintext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvAdd(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::add(const BfvCiphertext& op0, int op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvAddScalarInt(_evaluator.get(), op0.get(), op1, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::add(const BfvCiphertext& op0, int64_t op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvAddScalar(_evaluator.get(), op0.get(), op1, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::add(const BfvCiphertext& op0, uint64_t op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvAddScalarUint(_evaluator.get(), op0.get(), op1, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::sub(const BfvCiphertext& op0, const BfvCiphertext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvSub(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::sub(const BfvCiphertext& op0, const BfvPlaintext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvSub(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::sub(const BfvCiphertext& op0, int op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvSubScalarInt(_evaluator.get(), op0.get(), op1, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::sub(const BfvCiphertext& op0, int64_t op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvSubScalar(_evaluator.get(), op0.get(), op1, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::sub(const BfvCiphertext& op0, uint64_t op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvSubScalarUint(_evaluator.get(), op0.get(), op1, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::mult(const BfvCiphertext& op0, const BfvCiphertext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvMult(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::mult(const BfvCiphertext& op0, const BfvPlaintext& op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvMult(_evaluator.get(), op0.get(), op1.get(), &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::mult(const BfvCiphertext& op0, int op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvMultScalarInt(_evaluator.get(), op0.get(), op1, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::mult(const BfvCiphertext& op0, int64_t op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvMultScalar(_evaluator.get(), op0.get(), op1, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::mult(const BfvCiphertext& op0, uint64_t op1) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvMultScalarUint(_evaluator.get(), op0.get(), op1, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::relinearize(const BfvCiphertext& op0) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    try {
        CHECK(BfvRelinearize(_evaluator.get(), op0.get(), &ciphertext_handle));
    } catch (const std::exception& e) { throw std::runtime_error(std::string("BFV relinearize failed: ") + e.what()); }
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::drop_level(const BfvCiphertext& op0, int levels) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvDropLevel(_evaluator.get(), op0.get(), levels, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::rescale(const BfvCiphertext& op0) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvRescale(_evaluator.get(), op0.get(), &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

BfvCiphertext BfvContext::rotate_cols(const BfvCiphertext& op0, int32_t step) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    const uint8_t use_default_rotation_keys = _use_default_rotation_keys ? 1 : 0;
    CHECK(BfvRotateColumns(_evaluator.get(), op0.get(), &step, 1, use_default_rotation_keys, &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

std::map<int32_t, BfvCiphertext> BfvContext::rotate_cols(const BfvCiphertext& op0, const std::vector<int32_t>& steps) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    std::map<int32_t, BfvCiphertext> opOut;
    std::vector<uint64_t> ciphertext_handles(steps.size());
    const uint8_t use_default_rotation_keys = _use_default_rotation_keys ? 1 : 0;
    CHECK(BfvRotateColumns(_evaluator.get(), op0.get(), (int32_t*)steps.data(), steps.size(), use_default_rotation_keys,
                           ciphertext_handles.data()));
    for (size_t i = 0; i < steps.size(); i++) {
        BfvCiphertext rotated(std::move(ciphertext_handles[i]));
        rotated.sync_metadata();
        opOut[steps[i]] = std::move(rotated);
    }
    return opOut;
}

BfvCiphertext BfvContext::rotate_rows(const BfvCiphertext& op0) {
    if (_evaluator.is_empty()) {
        throw std::runtime_error("BFV evaluator is not set");
    }

    uint64_t ciphertext_handle = 0;
    CHECK(BfvRotateRows(_evaluator.get(), op0.get(), &ciphertext_handle));
    BfvCiphertext opOut(std::move(ciphertext_handle));
    opOut.sync_metadata();
    return opOut;
}

}  // namespace fhe_ops_lib

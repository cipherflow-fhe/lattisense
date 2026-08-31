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

#include <stdexcept>
#include "types.h"
#include "internal.h"

namespace fhe_ops_lib {

const KeyGenerator& FheContext::key_generator() const {
    if (_key_generator.is_empty()) {
        throw std::runtime_error("key generator is not set");
    }
    return _key_generator;
}

const Encryptor& FheContext::encryptor() const {
    if (_encryptor.is_empty()) {
        throw std::runtime_error("encryptor is not set");
    }
    return _encryptor;
}

const Decryptor& FheContext::decryptor() const {
    if (_decryptor.is_empty()) {
        throw std::runtime_error("decryptor is not set");
    }
    return _decryptor;
}

const SecretKey& FheContext::secret_key() const {
    if (_secret_key.is_empty()) {
        throw std::runtime_error("secret key is not set");
    }
    return _secret_key;
}

const PublicKey& FheContext::public_key() const {
    if (_public_key.is_empty()) {
        throw std::runtime_error("public key is not set");
    }
    return _public_key;
}

const EvaluationKeySet& FheContext::evaluation_key_set() const {
    if (_evaluation_key_set.is_empty()) {
        throw std::runtime_error("evaluation key set is not set");
    }
    return _evaluation_key_set;
}

KeyGenerator::KeyGenerator(const Parameter& parameter) {
    if (parameter.is_empty()) {
        throw std::runtime_error("parameter is not set");
    }

    uint64_t key_generator_handle = 0;
    CHECK(CreateKeyGenerator(parameter.get(), &key_generator_handle));
    _value = key_generator_handle;
    _keep = false;
}

SecretKey::SecretKey(const KeyGenerator& key_generator) {
    if (key_generator.is_empty()) {
        throw std::runtime_error("key generator is not set");
    }

    uint64_t secret_key_handle = 0;
    CHECK(GenSecretKey(key_generator.get(), &secret_key_handle));
    _value = secret_key_handle;
    _keep = false;
}

Bytes SecretKey::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeSecretKey(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

SecretKey SecretKey::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeSecretKey((uint8_t*)data.data(), data.size(), &handle));
    return SecretKey(std::move(handle));
}

PublicKey::PublicKey(const KeyGenerator& key_generator, const SecretKey& secret_key) {
    if (key_generator.is_empty()) {
        throw std::runtime_error("key generator is not set");
    }
    if (secret_key.is_empty()) {
        throw std::runtime_error("secret key is not set");
    }

    uint64_t public_key_handle = 0;
    CHECK(GenPublicKey(key_generator.get(), secret_key.get(), &public_key_handle));
    _value = public_key_handle;
    _keep = false;
}

Bytes PublicKey::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializePublicKey(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

PublicKey PublicKey::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializePublicKey((uint8_t*)data.data(), data.size(), &handle));
    return PublicKey(std::move(handle));
}

EvaluationKey EvaluationKey::copy() const {
    if (is_empty()) {
        throw std::runtime_error("evaluation key is not set");
    }

    uint64_t evaluation_key_handle = 0;
    CHECK(CopyEvaluationKey(get(), &evaluation_key_handle));
    return EvaluationKey(std::move(evaluation_key_handle));
}

Bytes EvaluationKey::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeEvaluationKey(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

EvaluationKey EvaluationKey::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeEvaluationKey((uint8_t*)data.data(), data.size(), &handle));
    return EvaluationKey(std::move(handle));
}

RelinKey::RelinKey(const KeyGenerator& key_generator, const SecretKey& secret_key, int level) {
    if (key_generator.is_empty()) {
        throw std::runtime_error("key generator is not set");
    }
    if (secret_key.is_empty()) {
        throw std::runtime_error("secret key is not set");
    }

    uint64_t relin_key_handle = 0;
    CHECK(GenRelinearizationKey(key_generator.get(), secret_key.get(), level, &relin_key_handle));
    _value = relin_key_handle;
    _keep = false;
}

RelinKey RelinKey::copy() const {
    if (is_empty()) {
        throw std::runtime_error("relinearization key is not set");
    }

    uint64_t relin_key_handle = 0;
    CHECK(CopyRelinearizationKey(get(), &relin_key_handle));
    return RelinKey(std::move(relin_key_handle));
}

int RelinKey::level() const {
    int value = 0;
    CHECK(GetRelinearizationKeyLevel(this->get(), &value));
    return value;
}

Bytes RelinKey::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeRelinearizationKey(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

RelinKey RelinKey::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeRelinearizationKey((uint8_t*)data.data(), data.size(), &handle));
    return RelinKey(std::move(handle));
}

Encryptor::Encryptor(const Parameter& parameter, const PublicKey& public_key) : _type(EncryptorType::PUBLIC_KEY) {
    if (parameter.is_empty()) {
        throw std::runtime_error("parameter is not set");
    }
    if (public_key.is_empty()) {
        throw std::runtime_error("public key is not set");
    }

    uint64_t encryptor_handle = 0;
    CHECK(CreateEncryptorFromPublicKey(parameter.get(), public_key.get(), &encryptor_handle));
    _value = encryptor_handle;
    _keep = false;
}

Encryptor::Encryptor(const Parameter& parameter, const SecretKey& secret_key) : _type(EncryptorType::SECRET_KEY) {
    if (parameter.is_empty()) {
        throw std::runtime_error("parameter is not set");
    }
    if (secret_key.is_empty()) {
        throw std::runtime_error("secret key is not set");
    }

    uint64_t encryptor_handle = 0;
    CHECK(CreateEncryptorFromSecretKey(parameter.get(), secret_key.get(), &encryptor_handle));
    _value = encryptor_handle;
    _keep = false;
}

Decryptor::Decryptor(const Parameter& parameter, const SecretKey& secret_key) {
    if (parameter.is_empty()) {
        throw std::runtime_error("parameter is not set");
    }
    if (secret_key.is_empty()) {
        throw std::runtime_error("secret key is not set");
    }

    uint64_t decryptor_handle = 0;
    CHECK(CreateDecryptor(parameter.get(), secret_key.get(), &decryptor_handle));
    _value = decryptor_handle;
    _keep = false;
}

GaloisKey GaloisKey::copy() const {
    if (is_empty()) {
        throw std::runtime_error("galois key is not set");
    }

    uint64_t galois_key_handle = 0;
    CHECK(CopyGaloisKey(get(), &galois_key_handle));
    return GaloisKey(std::move(galois_key_handle));
}

uint64_t GaloisKey::galois_element() const {
    uint64_t value = 0;
    CHECK(GetGaloisKeyElement(this->get(), &value));
    return value;
}

int GaloisKey::level() const {
    int value = 0;
    CHECK(GetGaloisKeyLevel(this->get(), &value));
    return value;
}

Bytes GaloisKey::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeGaloisKey(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

GaloisKey GaloisKey::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeGaloisKey((uint8_t*)data.data(), data.size(), &handle));
    return GaloisKey(std::move(handle));
}

EvaluationKeySet::EvaluationKeySet(RelinKey&& relin_key, std::map<uint64_t, GaloisKey>&& galois_keys) {
    uint64_t evaluation_key_set_handle = 0;
    CHECK(CreateEvaluationKeySet(0, nullptr, 0, &evaluation_key_set_handle));
    _value = evaluation_key_set_handle;
    _keep = false;
    if (!relin_key.is_empty()) {
        set_relin_key(std::move(relin_key));
    }
    set_galois_keys(std::move(galois_keys));
}

Bytes EvaluationKeySet::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeEvaluationKeySet(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

EvaluationKeySet EvaluationKeySet::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeEvaluationKeySet((uint8_t*)data.data(), data.size(), &handle));
    EvaluationKeySet evaluation_key_set(std::move(handle));
    evaluation_key_set.sync_from_handle();
    return evaluation_key_set;
}

void EvaluationKeySet::sync_from_handle() {
    if (is_empty()) {
        throw std::runtime_error("evaluation key set is not set");
    }

    uint64_t relin_key_handle = 0;
    CHECK(GetEvaluationKeyRelinearizationKey(this->get(), &relin_key_handle));
    _relin_key = relin_key_handle == 0 ? RelinKey() : RelinKey(std::move(relin_key_handle));

    int galois_key_count = 0;
    CHECK(GetEvaluationKeyGaloisKeyCount(this->get(), &galois_key_count));
    std::vector<uint64_t> galois_elements(galois_key_count);
    CHECK(GetEvaluationKeyGaloisKeyElements(this->get(), galois_elements.data(), galois_key_count));

    std::map<uint64_t, GaloisKey> galois_keys;
    for (uint64_t galois_element : galois_elements) {
        uint64_t galois_key_handle = 0;
        CHECK(GetEvaluationKeyGaloisKey(this->get(), galois_element, &galois_key_handle));
        galois_keys.emplace(galois_element, GaloisKey(std::move(galois_key_handle)));
    }
    _galois_keys = std::move(galois_keys);
}

void EvaluationKeySet::set_relin_key(RelinKey&& relin_key) {
    if (relin_key.is_empty()) {
        throw std::runtime_error("relinearization key is not set");
    }
    if (is_empty()) {
        throw std::runtime_error("evaluation key set is not set");
    }
    CHECK(SetEvaluationKeyRelinearizationKey(this->get(), relin_key.get()));
    _relin_key = std::move(relin_key);
}

void EvaluationKeySet::set_galois_key(GaloisKey&& galois_key) {
    if (galois_key.is_empty()) {
        throw std::runtime_error("galois key is not set");
    }
    if (is_empty()) {
        throw std::runtime_error("evaluation key set is not set");
    }
    CHECK(SetEvaluationKeyGaloisKey(this->get(), galois_key.get()));
    _galois_keys.insert_or_assign(galois_key.galois_element(), std::move(galois_key));
}

void EvaluationKeySet::set_galois_keys(std::map<uint64_t, GaloisKey>&& galois_keys) {
    if (is_empty()) {
        throw std::runtime_error("evaluation key set is not set");
    }

    std::vector<uint64_t> galois_key_handles;
    galois_key_handles.reserve(galois_keys.size());
    for (const auto& [_, key] : galois_keys) {
        if (key.is_empty()) {
            throw std::runtime_error("galois key is not set");
        }
        galois_key_handles.push_back(key.get());
    }
    CHECK(SetEvaluationKeyGaloisKeys(this->get(), galois_key_handles.empty() ? nullptr : galois_key_handles.data(),
                                     static_cast<int>(galois_key_handles.size())));
    _galois_keys = std::move(galois_keys);
}

const RelinKey& EvaluationKeySet::relin_key() const {
    return _relin_key;
}

const GaloisKey& EvaluationKeySet::galois_key(uint64_t galois_element) const {
    return _galois_keys.at(galois_element);
}

const std::map<uint64_t, GaloisKey>& EvaluationKeySet::galois_keys() const {
    return _galois_keys;
}

}  // namespace fhe_ops_lib

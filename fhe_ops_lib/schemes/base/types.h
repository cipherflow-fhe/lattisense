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

#ifndef FHE_OPS_LIB_COMMON_TYPES_H
#define FHE_OPS_LIB_COMMON_TYPES_H

#include <cmath>
#include <complex>
#include <inttypes.h>
#include <memory>
#include <utility>
#include <vector>
#include <map>
#include <functional>
#include <type_traits>
#include <gsl/span>

extern "C" {
// Use the sanitized copy of the cgo-generated header. The original liblattigo.h
// contains #line directives with virtual filenames (e.g. "cgo-builtin-export-prolog")
// that NVCC's -MD dep scanner emits as Make prerequisites; since those names are not
// real files, Make rebuilds all .cu files on every invocation. GCC/Clang ignore #line
// arguments in dep scanning so they are unaffected, but using the sanitized header
// universally is simpler. liblattigo_sanitized.h is generated alongside liblattigo.h
// by the go_libs build step.
#include "lattigo/go_sdk/liblattigo_sanitized.h"
}

namespace fhe_ops_lib {

using Byte = uint8_t;
using Bytes = std::vector<Byte>;
using BytesView = gsl::span<const Byte>;

inline Metadata plaintext_metadata(bool is_ringt = true,
                                   bool is_batched = true,
                                   int level = 0,
                                   int log_slots = -1,
                                   double scale = 1.0,
                                   bool is_ntt = true,
                                   int mform_bits = 0) {
    if (is_ringt) {
        level = 0;
        is_ntt = false;
        mform_bits = 0;
    }
    return Metadata{static_cast<uint8_t>(is_ringt),
                    static_cast<uint8_t>(is_batched),
                    0,
                    level,
                    log_slots,
                    scale,
                    static_cast<uint8_t>(is_ntt),
                    mform_bits};
}

inline Metadata ciphertext_metadata(int level,
                                    bool is_ringt = false,
                                    int degree = 1,
                                    bool is_batched = true,
                                    int log_slots = -1,
                                    double scale = 1.0,
                                    bool is_ntt = true,
                                    int mform_bits = 0) {
    return Metadata{static_cast<uint8_t>(is_ringt),
                    static_cast<uint8_t>(is_batched),
                    degree,
                    level,
                    log_slots,
                    scale,
                    static_cast<uint8_t>(is_ntt),
                    mform_bits};
}

inline Metadata evaluation_key_metadata(int level, bool is_ntt = true, int mform_bits = 64) {
    return Metadata{0, 1, 1, level, -1, 1.0, static_cast<uint8_t>(is_ntt), mform_bits};
}

/**
 * @brief Homomorphic Encryption Scheme type
 */
enum class HEScheme { BFV, CKKS };

/**
 * For basic FHE computation objects such as plaintext, ciphertext, secret key, and public key,
 * the C++ SDK uses different types to operate on these objects. Based on the Handle template class,
 * the types wrapped by the C++ SDK include:
 * - `BfvParameter`: Homomorphic parameters, containing N, q, t.
 * - `BfvPlaintext`: BFV plaintext, used for encryption, decryption, and ciphertext-plaintext addition.
 * - `BfvCiphertext`: BFV ciphertext.
 * - `BfvCiphertext`: BFV ciphertext containing three polynomials.
 * - `CkksParameter`: Homomorphic parameters, containing N, q.
 * - `CkksPlaintext`: CKKS plaintext, used for encryption, decryption, and ciphertext-plaintext addition.
 * - `CkksPlaintext`: CKKS plaintext in ring-t form, used for ciphertext-plaintext multiplication.
 * - `CkksCiphertext`: CKKS ciphertext.
 * - `CkksCiphertext`: CKKS ciphertext containing three polynomials.
 * Each object corresponds to a portion of memory resources. Resource allocation and deallocation are
 * managed by the SDK, so direct copying is not allowed. Use `std::move()` to transfer ownership of
 * internal resources, or call the corresponding API functions to copy the content.
 */
class Handle {
public:
    Handle() {
        _value = 0;
        _keep = false;
    }

    Handle(uint64_t&& h, bool k = false) {
        _value = h;
        _keep = k;
    }

    Handle(Handle&& other) {
        _value = other._value;
        _keep = other._keep;
        other._value = 0;
        other._keep = false;
    }

    Handle(const Handle& other) = delete;

    void operator=(Handle&& other) {
        uint64_t temp_value = other._value;
        other._value = _value;
        _value = temp_value;
        bool temp_keep = other._keep;
        other._keep = _keep;
        _keep = temp_keep;
    }

    void operator=(const Handle& other) = delete;

    virtual ~Handle() {
        if (_keep == false && _value != 0) {
            ReleaseHandle(_value);
        }
    };

    const uint64_t& get() const {
        return _value;
    }

    bool is_empty() const {
        return _value == 0;
    }

protected:
    uint64_t _value;
    bool _keep;
};

class Parameter;
class KeyGenerator;

class SecretKey : public Handle {
public:
    SecretKey() = default;
    using Handle::Handle;
    explicit SecretKey(const KeyGenerator& key_generator);

    Bytes serialize() const;

    static SecretKey deserialize(BytesView data);
};
class PublicKey : public Handle {
public:
    PublicKey() = default;
    using Handle::Handle;
    PublicKey(const KeyGenerator& key_generator, const SecretKey& secret_key);

    Bytes serialize() const;

    static PublicKey deserialize(BytesView data);
};
class KeyGenerator : public Handle {
public:
    KeyGenerator() = default;
    using Handle::Handle;
    explicit KeyGenerator(const Parameter& parameter);
};
enum class EncryptorType {
    PUBLIC_KEY,
    SECRET_KEY,
};

class Encryptor : public Handle {
public:
    Encryptor() = default;
    using Handle::Handle;

    Encryptor(const Parameter& parameter, const PublicKey& public_key);
    Encryptor(const Parameter& parameter, const SecretKey& secret_key);

    EncryptorType type() const {
        return _type;
    }

private:
    EncryptorType _type = EncryptorType::PUBLIC_KEY;
};
class Decryptor : public Handle {
public:
    Decryptor() = default;
    using Handle::Handle;
    Decryptor(const Parameter& parameter, const SecretKey& secret_key);
};
class EvaluationKey : public Handle {
public:
    using Handle::Handle;

    EvaluationKey copy() const;

    Bytes serialize() const;

    static EvaluationKey deserialize(BytesView data);
};

class RelinKey : public Handle {
public:
    RelinKey() = default;
    using Handle::Handle;
    RelinKey(const KeyGenerator& key_generator, const SecretKey& secret_key, int level);

    RelinKey copy() const;

    int level() const;

    Bytes serialize() const;

    static RelinKey deserialize(BytesView data);
};

class GaloisKey : public Handle {
public:
    GaloisKey() = default;
    using Handle::Handle;

    GaloisKey copy() const;

    uint64_t galois_element() const;

    int level() const;

    Bytes serialize() const;

    static GaloisKey deserialize(BytesView data);
};

class EvaluationKeySet : public Handle {
public:
    EvaluationKeySet() = default;
    using Handle::Handle;
    EvaluationKeySet(RelinKey&& relin_key, std::map<uint64_t, GaloisKey>&& galois_keys);

    Bytes serialize() const;
    static EvaluationKeySet deserialize(BytesView data);

    void sync_from_handle();
    void set_relin_key(RelinKey&& relin_key);
    void set_galois_key(GaloisKey&& galois_key);
    void set_galois_keys(std::map<uint64_t, GaloisKey>&& galois_keys);
    const RelinKey& relin_key() const;
    const GaloisKey& galois_key(uint64_t galois_element) const;
    const std::map<uint64_t, GaloisKey>& galois_keys() const;

private:
    RelinKey _relin_key;
    std::map<uint64_t, GaloisKey> _galois_keys;
};

class Parameter : public Handle {
public:
    using Handle::Handle;

    virtual int n() const = 0;
    virtual int max_level() const = 0;

    virtual int log_n() const = 0;

    virtual std::vector<uint64_t> q() const = 0;

    virtual std::vector<uint64_t> p() const = 0;

    virtual Bytes serialize() const = 0;
};

/**
 * @brief Homomorphic context class. Contains public keys, secret keys, and other information.
 * - `SecretKey`: Secret key.
 * - `PublicKey`: Encryption public key.
 * - `RelinKey`: Relinearization key.
 * - `GaloisKey`: Galois key (rotation key).
 */
class FheContext {
public:
    FheContext() = default;
    FheContext(FheContext&&) = default;
    FheContext& operator=(FheContext&&) = default;
    FheContext(const FheContext&) = delete;
    FheContext& operator=(const FheContext&) = delete;
    virtual ~FheContext() = default;

    virtual const KeyGenerator& key_generator() const;

    virtual const Encryptor& encryptor() const;

    virtual const Decryptor& decryptor() const;

    virtual const SecretKey& secret_key() const;

    virtual const PublicKey& public_key() const;

    virtual const EvaluationKeySet& evaluation_key_set() const;

    virtual const Parameter& parameter() = 0;

protected:
    mutable KeyGenerator _key_generator;
    mutable Encryptor _encryptor;
    mutable Decryptor _decryptor;
    mutable SecretKey _secret_key;
    mutable PublicKey _public_key;
    mutable EvaluationKeySet _evaluation_key_set;
};

}  // namespace fhe_ops_lib

#endif  // FHE_OPS_LIB_COMMON_TYPES_H

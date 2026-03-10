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

#ifndef CXX_FHE_LIB_H
#define CXX_FHE_LIB_H

#include <cmath>
#include <inttypes.h>
#include <memory>
#include <utility>
#include <vector>
#include <map>
#include <functional>
#include <random>
#include <type_traits>
#include <gsl/span>

extern "C" {
#include "fhe_types_v2.h"
#include "lattigo/go_sdk/liblattigo.h"
}
#include "utils.h"

namespace fhe_ops_lib {

using Byte = uint8_t;
using Bytes = std::vector<Byte>;
using BytesView = gsl::span<const Byte>;
using DoublesView = gsl::span<const double>;

const int MAX_LEVEL = 1024;

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
 * - `BfvPlaintextMul`: BFV plaintext, used for ciphertext-plaintext multiplication.
 * - `BfvCiphertext`: BFV ciphertext.
 * - `BfvCiphertext3`: BFV ciphertext containing three polynomials.
 * - `CkksParameter`: Homomorphic parameters, containing N, q.
 * - `CkksPlaintext`: CKKS plaintext, used for encryption, decryption, and ciphertext-plaintext addition.
 * - `CkksPlaintextRingt`: CKKS plaintext in ring-t form, used for ciphertext-plaintext multiplication.
 * - `CkksCiphertext`: CKKS ciphertext.
 * - `CkksCiphertext3`: CKKS ciphertext containing three polynomials.
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
        _keep = false;
        other._value = 0;
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

class SecretKey : public Handle {
    using Handle::Handle;
};
class PublicKey : public Handle {
    using Handle::Handle;
};
class KeySwitchKey : public Handle {
public:
    using Handle::Handle;
    int get_level() const;
};

class RelinKey : public Handle {
public:
    using Handle::Handle;
    KeySwitchKey extract_key_switch_key() const;
};

class GaloisKey : public Handle {
public:
    using Handle::Handle;
    KeySwitchKey extract_key_switch_key(uint64_t k) const;
};

class BfvContext;
class BfvPlaintextRingt;
class BfvPlaintext;
class BfvPlaintextMul;
class BfvCiphertext;
class BfvCiphertext3;
class BfvCompressedCiphertext;
class CkksContext;
class CkksPlaintext;
class CkksPlaintextRingt;
class CkksPlaintextMul;
class CkksCiphertext3;
class CkksCiphertext;
class CkksCompressedCiphertext;

class DBfvContext;
class CkgContext;
class RkgContext;
class RtgContext;
class E2sContext;
class S2eContext;
class RefreshContext;
class RefreshAndPermuteContext;
class PublicKeyShare;
class E2sPublicShare;
class S2ePublicShare;
class AdditiveShare;
class RelinKeyShare;
class RefreshShare;
class RefreshAndPermuteShare;
class GaloisKeyShare;

class Parameter : public Handle {
public:
    using Handle::Handle;

    virtual int get_n() const = 0;
    virtual int get_max_level() const = 0;
};

/**
 * @brief BFV homomorphic parameters class, containing homomorphic parameters N, q, t.
 */
class BfvParameter : public Parameter {
public:
    using Parameter::Parameter;

    // BfvParameter() = delete;
    static BfvParameter create_fpga_parameter(uint64_t t);
    static BfvParameter create_parameter(uint64_t N, uint64_t t);
    static BfvParameter
    create_custom_parameter(uint64_t N, uint64_t t, const std::vector<uint64_t>& Q, const std::vector<uint64_t>& P);
    static BfvParameter
    set_parameter(uint64_t N, uint64_t t, const std::vector<uint64_t>& Q, const std::vector<uint64_t>& P);

    BfvParameter copy() const;

    /**
     * Print the values of BFV homomorphic parameters.
     * @return void.
     */
    void print() const;

    /**
     * Get the polynomial degree N from the homomorphic parameters.
     * @return The polynomial degree N.
     */
    int get_n() const;

    /**
     * Get the plaintext modulus t from the homomorphic parameters.
     * @return The plaintext modulus t.
     */
    uint64_t get_t() const;

    uint64_t get_q(int index) const;

    uint64_t get_p(int index) const;

    int get_q_count() const;

    int get_p_count() const;

    /**
     * Get the maximum plaintext and ciphertext level from the BFV homomorphic parameters.
     * @return The maximum plaintext and ciphertext level.
     */
    int get_max_level() const;
};

/**
 * @brief CKKS homomorphic parameters class, containing homomorphic parameters N, q.
 */
class CkksParameter : public Parameter {
public:
    using Parameter::Parameter;

    // CkksParameter() = delete;
    static CkksParameter create_fpga_parameter();
    static CkksParameter create_parameter(uint64_t N);
    static CkksParameter
    create_custom_parameter(uint64_t N, const std::vector<uint64_t>& Q, const std::vector<uint64_t>& P);

    CkksParameter copy() const;

    /**
     * Print the values of CKKS homomorphic parameters.
     * @return void.
     */
    void print() const;

    /**
     * Get the polynomial degree N from the homomorphic parameters.
     * @return The polynomial degree N.
     */
    int get_n() const;

    /**
     * Get the maximum plaintext and ciphertext level from the CKKS homomorphic parameters.
     * @return The maximum plaintext and ciphertext level.
     */
    int get_max_level() const;

    int get_p_count() const;

    uint64_t get_p(int index) const;

    uint64_t get_q(int index) const;

    double get_default_scale() const;
};

class CkksBtpParameter : public CkksParameter {
public:
    using CkksParameter::CkksParameter;

    static CkksBtpParameter create_parameter();

    static CkksBtpParameter create_toy_parameter();

    CkksParameter& get_ckks_parameter();

protected:
    CkksParameter _parameter;
};

/**
 * @brief Homomorphic context class. Contains public keys, secret keys, and other information.
 * - `SecretKey`: Secret key.
 * - `PublicKey`: Encryption public key.
 * - `RelinKey`: Relinearization key.
 * - `GaloisKey`: Galois key (rotation key).
 */
class FheContext : public Handle {
public:
    using Handle::Handle;

    /**
     * Extract the secret key from the input context as an independent secret key variable.
     * @return The secret key.
     */
    virtual SecretKey extract_secret_key() const = 0;

    /**
     * Extract the public key from the input context as an independent public key variable.
     * @return The public key.
     */
    virtual PublicKey extract_public_key() const = 0;

    /**
     * Extract the BFV relinearization key from the input context as an independent relinearization key variable.
     * @return The relinearization key.
     */
    virtual RelinKey extract_relin_key() const = 0;

    /**
     * Extract the BFV Galois key from the input context as an independent Galois key variable.
     * @return The Galois key.
     */
    virtual GaloisKey extract_galois_key() const = 0;

    void resize_copies(int n);

    virtual FheContext& get_copy(int index) = 0;

    virtual const Parameter& get_parameter() = 0;

protected:
    std::vector<std::unique_ptr<FheContext>> _copies;
};

/**
 * @brief BFV homomorphic context class. Contains BFV public keys, secret keys, and other information.
 */
class BfvContext : public FheContext {
public:
    using FheContext::FheContext;

    const BfvParameter& get_parameter() override;

    /**
     * Create a new BfvContextHandle with randomly generated secret key, encryption public key, relinearization key, and
     * Galois key.
     * @param param The homomorphic parameters.
     * @return The created context.
     */
    static BfvContext create_random_context(const BfvParameter& param, int level = MAX_LEVEL);

    void gen_rotation_keys(int level = MAX_LEVEL);

    void gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots,
                                         bool include_swap_rows = false,
                                         int level = MAX_LEVEL);

    /**
     * Create an empty BfvContextHandle with null values for the secret key, encryption public key, relinearization key,
     * and Galois key.
     * @param param The homomorphic parameters.
     * @return The created context.
     */
    static BfvContext create_empty_context(const BfvParameter& param);

    /**
     * In multi-threaded scenarios, each thread needs its own context. This method is called on the source context
     * object to generate a child context that does not contain the secret key from the source context, but has the same
     * encryption public key, relinearization key, and Galois key.
     * @return The child context.
     */
    BfvContext make_public_context(bool include_pk = true, bool include_rlk = true, bool include_gk = true) const;

    void generate_public_keys(int level = MAX_LEVEL);

    /**
     * Shallow copy a BfvContextHandle. When multiple threads need to use the same context in parallel, the context
     * should be shallow copied and passed to different threads.
     * @return The copied context.
     */
    BfvContext shallow_copy_context() const;

    SecretKey extract_secret_key() const override;

    PublicKey extract_public_key() const override;

    /**
     * Extract the BFV relinearization key from the input context as an independent relinearization key variable.
     * @return The relinearization key.
     */
    RelinKey extract_relin_key() const override;

    /**
     * Extract the BFV Galois key from the input context as an independent Galois key variable.
     * @return The Galois key.
     */
    GaloisKey extract_galois_key() const override;

    /**
     * Serialize the BfvContext to binary.
     * @return The serialized byte array.
     */
    Bytes serialize() const;

    /**
     * Deserialize a byte array to BfvContext.
     * @param data The byte array.
     * @return The deserialized BfvContext.
     */
    static BfvContext deserialize(BytesView data);

    Bytes serialize_advanced() const;

    static BfvContext deserialize_advanced(BytesView data);

    /**
     * Set a secret key to a context.
     * @param sk The source secret key.
     * @return void.
     */
    void set_context_secret_key(const SecretKey& sk);

    /**
     * Set a public key to a context.
     * @param pk The source encryption public key.
     * @return void.
     */
    void set_context_public_key(const PublicKey& pk);

    /**
     * Set a relinearization key to a context.
     * @param rlk The source relinearization key.
     * @return void.
     */
    void set_context_relin_key(const RelinKey& rlk);

    /**
     * Set a Galois key to a context.
     * @param gk The source Galois key.
     * @return void.
     */
    void set_context_galois_key(const GaloisKey& gk);

    /**
     * Encode message data into a BFV plaintext.
     * @param x_mg The input message data.
     * @param level The level of the output plaintext.
     * @return The encoded plaintext.
     */
    BfvPlaintext encode(const std::vector<uint64_t>& x_mg, int level);

    /**
     * Encode message data into a BFV plaintext for multiplication.
     * @param x_mg The input message data.
     * @param level The level of the output plaintext.
     * @return The encoded plaintext for multiplication.
     */
    BfvPlaintextMul encode_mul(const std::vector<uint64_t>& x_mg, int level);

    /**
     * Encode message data into a BFV plaintext in ring-t form for multiplication.
     * @param x_mg The input message data.
     * @return The encoded plaintext for multiplication.
     */
    BfvPlaintextRingt encode_ringt(const std::vector<uint64_t>& x_mg);

    /**
     * Encode an integer array into a BFV plaintext, with array components directly embedded into plaintext polynomial
     * coefficients. Does not support element-wise multiplication.
     * @param x_mg The input integer array.
     * @param level The level of the output plaintext.
     * @return The encoded plaintext.
     */
    BfvPlaintext encode_coeffs(const std::vector<uint64_t>& x_mg, int level);

    /**
     * Encode an integer array into a BFV plaintext in ring-t form for multiplication, with array components directly
     * embedded into plaintext polynomial coefficients. Does not support element-wise multiplication.
     * @param x_mg The input integer array.
     * @return The encoded plaintext for multiplication.
     */
    BfvPlaintextRingt encode_coeffs_ringt(const std::vector<uint64_t>& x_mg);

    /**
     * Encode an integer array into a BFV plaintext for multiplication, with array components directly embedded into
     * plaintext polynomial coefficients. Does not support element-wise multiplication.
     * @param x_mg The input integer array.
     * @param level The level of the output plaintext.
     * @return The encoded plaintext for multiplication.
     */
    BfvPlaintextMul encode_coeffs_mul(const std::vector<uint64_t>& x_mg, int level);

    // std::vector<BfvPlaintext> bitwise_encode(const std::vector<uint64_t>& x_mg, int level);

    // std::vector<BfvPlaintextRingt> bitwise_encode_ringt(const std::vector<uint64_t>& x_mg);

    /**
     * Decode a BFV plaintext into message data.
     * @param x_pt The input plaintext.
     * @return The decoded message data.
     */
    std::vector<uint64_t> decode(const BfvPlaintext& x_pt);

    /**
     * Decode a BFV plaintext into message data (coefficient encoding).
     * @param x_pt The input plaintext.
     * @return The decoded message data.
     */
    std::vector<uint64_t> decode_coeffs(const BfvPlaintext& x_pt);

    std::vector<uint64_t> decode_ringt(const BfvPlaintextRingt& x_pt);

    /**
     * Create a new ciphertext and allocate space based on input parameters.
     * @param degree The degree of the new ciphertext, degree=1 corresponds to 2 polynomials, degree=2 corresponds to 3
     * polynomials.
     * @param level The level of the new ciphertext.
     * @return The created ciphertext.
     */
    [[deprecated("Please use `BfvCiphertext new_ciphertext(int level)` instead.")]] BfvCiphertext
    new_ciphertext(int degree, int level);

    BfvCiphertext new_ciphertext(int level);

    BfvCiphertext3 new_ciphertext3(int level);

    /**
     * Encrypt a BFV plaintext using the encryption public key.
     * @param x_pt The input plaintext.
     * @return The encrypted ciphertext.
     */
    BfvCiphertext encrypt_asymmetric(const BfvPlaintext& x_pt);

    /**
     * Encrypt a BFV plaintext using the secret key.
     * @param x_pt The input plaintext.
     * @return The encrypted ciphertext.
     */
    BfvCiphertext encrypt_symmetric(const BfvPlaintext& x_pt);

    BfvCompressedCiphertext encrypt_symmetric_compressed(const BfvPlaintext& x_pt);

    BfvCiphertext compressed_ciphertext_to_ciphertext(const BfvCompressedCiphertext& x_ct);

    /**
     * Decrypt a BFV ciphertext using the secret key.
     * @param x_ct The input ciphertext.
     * @return The decrypted plaintext.
     */
    BfvPlaintext decrypt(const BfvCiphertext& x_ct);

    /**
     * Decrypt a degree=2 BFV ciphertext using the secret key.
     * @param x_ct The input ciphertext.
     * @return The decrypted plaintext.
     */
    BfvPlaintext decrypt(const BfvCiphertext3& x_ct);

    /**
     * Convert a BFV plaintext to a BFV plaintext in ring-t form.
     * @param x_pt The input plaintext.
     * @return The plaintext in ring-t form.
     */
    BfvPlaintextRingt plaintext_to_plaintext_ringt(const BfvPlaintext& x_pt);

    BfvContext& get_copy(int index) override;

    /**
     * Compute ciphertext-ciphertext addition.
     * @param x0_ct The input ciphertext.
     * @param x1_ct The input ciphertext.
     * @return The resulting ciphertext from addition.
     */
    BfvCiphertext add(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);

    BfvCiphertext3 add(const BfvCiphertext3& x0_ct, const BfvCiphertext3& x1_ct);

    BfvCiphertext sub(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);

    BfvCiphertext sub_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);

    BfvCiphertext sub_plain_ringt(const BfvCiphertext& x0_ct, const BfvPlaintextRingt& x1_pt);

    BfvCiphertext negate(const BfvCiphertext& x0_ct);

    /**
     * Compute ciphertext-ciphertext addition in-place, storing the result in one of the input ciphertexts.
     * @param x0_ct The input ciphertext, also the output result ciphertext.
     * @param x1_ct The input ciphertext.
     * @return void.
     */
    void add_inplace(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);

    /**
     * Compute ciphertext-plaintext addition.
     * @param x0_ct The input ciphertext.
     * @param x1_pt The input plaintext.
     * @return The resulting ciphertext from addition.
     */
    BfvCiphertext add_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);

    BfvCiphertext add_plain_ringt(const BfvCiphertext& x0_ct, const BfvPlaintextRingt& x1_pt);

    /**
     * Compute ciphertext-plaintext addition in-place, storing the result in the input ciphertext.
     * @param x0_ct The input ciphertext, also the output result ciphertext.
     * @param x1_pt The input plaintext.
     * @return void.
     */
    void add_plain_inplace(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);

    /**
     * Compute ciphertext-ciphertext multiplication, resulting in a ciphertext with 3 polynomials.
     * @param x0_ct The input ciphertext.
     * @param x1_ct The input ciphertext.
     * @return The resulting ciphertext from multiplication.
     */
    BfvCiphertext3 mult(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);

    /**
     * Compute ciphertext-plaintext multiplication.
     * @param x0_ct The input ciphertext.
     * @param x1_pt The input plaintext.
     * @return The resulting ciphertext from multiplication.
     */
    BfvCiphertext mult_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);

    /**
     * Compute ciphertext-plaintext multiplication using ring-t plaintext.
     * @param x0_ct The input ciphertext.
     * @param x1_pt The input plaintext in ring-t form.
     * @return The resulting ciphertext from multiplication.
     */
    BfvCiphertext mult_plain_ringt(const BfvCiphertext& x0_ct, const BfvPlaintextRingt& x1_pt);

    BfvCiphertext mult_scalar(const BfvCiphertext& x0_ct, const int64_t x1_value);

    /**
     * Compute ciphertext-plaintext multiplication using multiplication plaintext.
     * @param x0_ct The input ciphertext.
     * @param x1_pt The input multiplication plaintext.
     * @return The resulting ciphertext from multiplication.
     */
    BfvCiphertext mult_plain_mul(const BfvCiphertext& x0_ct, const BfvPlaintextMul& x1_pt);

    /**
     * Convert a ring-t multiplication plaintext to a standard multiplication plaintext.
     * @param x_pt The input ring-t plaintext.
     * @param level The level of the plaintext.
     * @return The standard multiplication plaintext.
     */
    BfvPlaintextMul ringt_to_mul(const BfvPlaintextRingt& x_pt, int level);

    BfvPlaintext ringt_to_pt(const BfvPlaintextRingt& x_pt, int level);

    /**
     * Perform ciphertext relinearization.
     * @param x_ct The input ciphertext.
     * @return The relinearized ciphertext.
     */
    BfvCiphertext relinearize(const BfvCiphertext3& x_ct);

    /**
     * Perform rescale on a BFV ciphertext, reducing the ciphertext modulus by one component.
     * @param x_ct The input ciphertext.
     * @return The rescaled ciphertext.
     */
    BfvCiphertext rescale(const BfvCiphertext& x_ct);

    /**
     * Perform rotation operation on a ciphertext.
     * @param x_ct The input ciphertext.
     * @param step The rotation step count.
     * @return The rotated ciphertext.
     */
    BfvCiphertext rotate_cols(const BfvCiphertext& x_ct, int32_t step);

    BfvCiphertext advanced_rotate_cols(const BfvCiphertext& x_ct, int32_t step);

    std::map<int32_t, BfvCiphertext> rotate_cols(const BfvCiphertext& x_ct, const std::vector<int32_t>& steps);

    std::map<int32_t, BfvCiphertext> advanced_rotate_cols(const BfvCiphertext& x_ct, const std::vector<int32_t>& steps);

    BfvCiphertext rotate_rows(const BfvCiphertext& x_ct);

private:
    BfvParameter _parameter;
};

class DBfvContext : public BfvContext {
public:
    using BfvContext::BfvContext;

    BfvContext get_bfv_context();

    static DBfvContext create_random_context(const BfvParameter& param, const Bytes& seed, double sigma_smudging);

    // Bytes gen_galois_key_share(const std::vector<int32_t>& rots, bool include_swap_rows = false) const;

    // void aggregate_galois_key_share(const Bytes& data, const std::vector<int32_t>& rots, bool
    // include_swap_rows = false);

    // void set_galois_key(const std::vector<int32_t>& rots, bool include_swap_rows = false);
};

class CkgContext : public Handle {
public:
    using Handle::Handle;

    static CkgContext create_context(const DBfvContext& context);

    PublicKeyShare gen_public_key_share();

    PublicKeyShare aggregate_public_key_share(const PublicKeyShare& x0_share, const PublicKeyShare& x1_share);

    void set_public_key(const PublicKeyShare& share);
};

class RkgContext : public Handle {
public:
    using Handle::Handle;

    static RkgContext create_context(const DBfvContext& context);

    std::pair<RelinKeyShare, SecretKey> gen_relin_key_share_round_one();

    RelinKeyShare gen_relin_key_share_round_two(const SecretKey& eph_sk, const RelinKeyShare& share1);

    RelinKeyShare aggregate_relin_key_share(const RelinKeyShare& x0_share, const RelinKeyShare& x1_share);

    void set_relin_key(const RelinKeyShare& share1, const RelinKeyShare& share2);
};

class RtgContext : public Handle {
public:
    using Handle::Handle;

    static RtgContext create_context(const DBfvContext& context);

    std::vector<GaloisKeyShare> gen_share(const std::vector<int32_t>& rots, bool include_swap_rows = false);

    std::vector<GaloisKeyShare> aggregate_share(const std::vector<GaloisKeyShare>& x0_share,
                                                const std::vector<GaloisKeyShare>& x1_share);

    void
    set_galois_key(const std::vector<int32_t>& rots, bool include_swap_rows, const std::vector<GaloisKeyShare>& share);
};

class E2sContext : public Handle {
public:
    using Handle::Handle;

    static E2sContext create_context(const DBfvContext& context);

    std::pair<E2sPublicShare, AdditiveShare> gen_public_share(const BfvCiphertext& x_ct);

    E2sPublicShare aggregate_public_share(const E2sPublicShare& x0_share, const E2sPublicShare& x1_share);

    AdditiveShare
    get_secret_share(const BfvCiphertext& x_ct, const E2sPublicShare& public_share, const AdditiveShare& secret_share);

    AdditiveShare
    aggregate_secret_share(const DBfvContext& context, const AdditiveShare& x0_share, const AdditiveShare& x1_share);

    BfvPlaintextRingt set_plaintext_ringt(const DBfvContext& context, const AdditiveShare& secret_share);
};

class S2eContext : public Handle {
public:
    using Handle::Handle;

    static S2eContext create_context(const DBfvContext& context);

    S2ePublicShare gen_public_share(const AdditiveShare& secret_share);

    S2ePublicShare aggregate_public_share(const S2ePublicShare& x0_share, const S2ePublicShare& x1_share);

    BfvCiphertext set_ciphertetext(const S2ePublicShare& public_share);
};

class RefreshContext : public Handle {
public:
    using Handle::Handle;

    static RefreshContext create_context(const DBfvContext& context);

    RefreshShare gen_share(const BfvCiphertext& x_ct);

    RefreshShare aggregate_share(const RefreshShare& x0_share, const RefreshShare& x1_share);

    BfvCiphertext finalize(const BfvCiphertext& x_ct, const RefreshShare& share);
};

class RefreshAndPermuteContext : public Handle {
public:
    using Handle::Handle;

    static RefreshAndPermuteContext create_context(const DBfvContext& context);

    RefreshAndPermuteShare gen_share(const BfvCiphertext& x_ct, std::vector<uint64_t>& permute);

    RefreshAndPermuteShare aggregate_share(const RefreshAndPermuteShare& x0_share,
                                           const RefreshAndPermuteShare& x1_share);

    BfvCiphertext
    transform(const BfvCiphertext& x_ct, std::vector<uint64_t>& permute, const RefreshAndPermuteShare& share);
};
/**
 * @brief CKKS homomorphic context class. Contains CKKS public keys, secret keys, and other information.
 */
class CkksContext : public FheContext {
public:
    using FheContext::FheContext;

    static CkksContext create_empty_context(const CkksParameter& param, bool support_big_complex = false);

    /**
     * Create a new CkksContextHandle with randomly generated secret key, encryption public key, relinearization key,
     * and Galois key.
     * @param param The homomorphic parameters.
     * @return The created context.
     */
    static CkksContext
    create_random_context(const CkksParameter& param, int level = MAX_LEVEL, bool support_big_complex = false);

    static CkksContext create_random_context_with_seed(const CkksParameter& param,
                                                       const std::vector<uint8_t>& seed,
                                                       bool support_big_complex = false);

    /**
     * In multi-threaded scenarios, each thread needs its own context. This method is called on the source context
     * object to generate a child context that does not contain the secret key from the source context, but has the same
     * encryption public key, relinearization key, and Galois key.
     * @return The child context.
     */
    CkksContext make_public_context(bool include_pk = true, bool include_rlk = true, bool include_gk = true) const;

    CkksContext shallow_copy_context();

    const CkksParameter& get_parameter() override;

    SecretKey extract_secret_key() const override;

    PublicKey extract_public_key() const override;

    void gen_rotation_keys(int level = MAX_LEVEL);

    void gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots,
                                         bool include_swap_rows = false,
                                         int level = MAX_LEVEL);

    /**
     * Extract the CKKS relinearization key from the input context as an independent relinearization key variable.
     * @return The relinearization key.
     */
    RelinKey extract_relin_key() const override;

    /**
     * Extract the CKKS Galois key from the input context as an independent Galois key variable.
     * @return The Galois key.
     */
    GaloisKey extract_galois_key() const override;

    /**
     * Set a secret key to a context.
     * @param sk The source secret key.
     * @return void.
     */
    void set_context_secret_key(const SecretKey& sk);

    /**
     * Set a public key to a context.
     * @param pk The source encryption public key.
     * @return void.
     */
    void set_context_public_key(const PublicKey& pk);

    /**
     * Set a relinearization key to a context.
     * @param rlk The source relinearization key.
     * @return void.
     */
    void set_context_relin_key(const RelinKey& rlk);

    /**
     * Set a Galois key to a context.
     * @param gk The source Galois key.
     * @return void.
     */
    void set_context_galois_key(const GaloisKey& gk);

    /**
     * Serialize a CKKS context to binary.
     * @return The serialized byte array.
     */
    Bytes serialize() const;

    Bytes serialize_advanced() const;

    /**
     * Deserialize a CKKS context from binary.
     * @param data The byte array.
     * @return The deserialized CkksContext.
     */
    static CkksContext deserialize(BytesView data);

    static CkksContext deserialize_advanced(BytesView data);

    /**
     * Encode message data into a CKKS plaintext.
     * @param x_mg The input message data.
     * @param level The level of the output plaintext.
     * @param scale The encoding scale.
     * @return The encoded plaintext.
     */
    CkksPlaintext encode(const std::vector<double>& x_mg, int level, double scale);

    CkksPlaintext encode_complex(const std::vector<double>& x_mg, int level, double scale);

    /**
     * Encode message data into a CKKS plaintext in ring-t form for multiplication.
     * @param x_mg The input message data.
     * @param scale The encoding scale.
     * @return The encoded plaintext for multiplication.
     */
    CkksPlaintextRingt encode_ringt(const std::vector<double>& x_mg, double scale);

    /**
     * Encode message data into a CKKS plaintext for multiplication.
     * @param x_mg The input message data.
     * @param level The level of the output plaintext.
     * @param scale The encoding scale.
     * @return The encoded plaintext for multiplication.
     */
    CkksPlaintextMul encode_mul(const std::vector<double>& x_mg, int level, double scale);

    /**
     * Encode a floating-point array into a CKKS plaintext, with array components directly embedded into plaintext
     * polynomial coefficients. Does not support element-wise multiplication.
     * @param x_mg The input message data.
     * @param level The level of the output plaintext.
     * @param scale The encoding scale.
     * @return The encoded plaintext.
     */
    CkksPlaintext encode_coeffs(const std::vector<double>& x_mg, int level, double scale);

    /**
     * Encode a floating-point array into a CKKS plaintext in ring-t form for multiplication, with array components
     * directly embedded into plaintext polynomial coefficients. Does not support element-wise multiplication.
     * @param x_mg The input message data.
     * @param level The level of the output plaintext.
     * @param scale The encoding scale.
     * @return The encoded plaintext for multiplication.
     */
    CkksPlaintextRingt encode_coeffs_ringt(const std::vector<double>& x_mg, double scale);

    CkksPlaintextMul encode_coeffs_mul(const std::vector<double>& x_mg, int level, double scale);

    /**
     * Create a new ciphertext and allocate space based on input parameters.
     * @param degree The degree of the new ciphertext, degree=1 corresponds to 2 polynomials, degree=2 corresponds to 3
     * polynomials.
     * @param level The level of the new ciphertext.
     * @param scale The encoding scale.
     * @return The created ciphertext.
     */
    [[deprecated("Please use `CkksCiphertext new_ciphertext(int level, double scale)` instead.")]] CkksCiphertext
    new_ciphertext(int degree, int level, double scale);

    CkksCiphertext new_ciphertext(int level, double scale);

    CkksCiphertext3 new_ciphertext3(int level, double scale);

    /**
     * Decode a CKKS plaintext into message data.
     * @param x_pt The input plaintext.
     * @return The decoded message data.
     */
    std::vector<double> decode(const CkksPlaintext& x_pt);

    std::vector<double> decode_complex(const CkksPlaintext& x_pt);

    /**
     * Decode a CKKS plaintext into message data (coefficient encoding).
     * @param x_pt The input plaintext.
     * @return The decoded message data.
     */
    std::vector<double> decode_coeffs(const CkksPlaintext& x_pt);

    CkksPlaintext recode_big_complex(const CkksPlaintext& x_pt, int level, double scale);

    /**
     * Encrypt a CKKS plaintext using the encryption public key.
     * @param x_pt The input plaintext.
     * @return The encrypted ciphertext.
     */
    CkksCiphertext encrypt_asymmetric(const CkksPlaintext& x_pt);

    /**
     * Encrypt a CKKS plaintext using the secret key.
     * @param x_pt The input plaintext.
     * @return The encrypted ciphertext.
     */
    CkksCiphertext encrypt_symmetric(const CkksPlaintext& x_pt);

    CkksCompressedCiphertext encrypt_symmetric_compressed(const CkksPlaintext& x_pt);

    CkksCiphertext compressed_ciphertext_to_ciphertext(const CkksCompressedCiphertext& x_ct);

    /**
     * Decrypt a CKKS ciphertext using the secret key.
     * @param x_ct The input ciphertext.
     * @return The decrypted plaintext.
     */
    CkksPlaintext decrypt(const CkksCiphertext& x_ct);

    /**
     * Decrypt a degree=2 CKKS ciphertext using the secret key.
     * @param x_ct The input ciphertext.
     * @return The decrypted plaintext.
     */
    CkksPlaintext decrypt(const CkksCiphertext3& x_ct);

    CkksContext& get_copy(int index) override;

    CkksContext& get_extra_level_context();

    /**
     * Compute ciphertext-plaintext addition.
     * @param x0_ct The input ciphertext.
     * @param x1_pt The input plaintext.
     * @return The resulting ciphertext from addition.
     */
    CkksCiphertext add_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt);

    CkksCiphertext add_plain_ringt(const CkksCiphertext& x0_ct, const CkksPlaintextRingt& x1_pt);

    /**
     * Compute ciphertext-ciphertext addition.
     * @param x0_ct The input ciphertext.
     * @param x1_ct The input ciphertext.
     * @return The resulting ciphertext from addition.
     */
    CkksCiphertext add(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct);

    CkksCiphertext3 add(const CkksCiphertext3& x0_ct, const CkksCiphertext3& x1_ct);

    CkksCiphertext sub(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct);

    CkksCiphertext sub_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt);

    CkksCiphertext sub_plain_ringt(const CkksCiphertext& x0_ct, const CkksPlaintextRingt& x1_pt);

    CkksPlaintext ringt_to_pt(const CkksPlaintextRingt& pt_ringt, int level);

    CkksCiphertext negate(const CkksCiphertext& x0_ct);
    /**
     * Compute ciphertext-ciphertext multiplication, resulting in a ciphertext with 3 polynomials.
     * @param x0_ct The input ciphertext.
     * @param x1_ct The input ciphertext.
     * @return The resulting ciphertext from multiplication.
     */
    CkksCiphertext3 mult(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct);

    /**
     * Compute ciphertext-plaintext multiplication.
     * @param x0_ct The input ciphertext.
     * @param x1_pt The input plaintext.
     * @return The resulting ciphertext from multiplication.
     */
    CkksCiphertext mult_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt);

    /**
     * Compute ciphertext-plaintext multiplication using multiplication plaintext.
     * @param x0_ct The input ciphertext.
     * @param x1_pt The input multiplication plaintext.
     * @return The resulting ciphertext from multiplication.
     */
    CkksCiphertext mult_plain_mul(const CkksCiphertext& x0_ct, const CkksPlaintextMul& x1_pt);

    /**
     * Convert a ring-t multiplication plaintext to a standard multiplication plaintext.
     * @param x_pt The input ring-t plaintext.
     * @param level The level of the plaintext.
     * @return The standard multiplication plaintext.
     */
    CkksPlaintextMul ringt_to_mul(const CkksPlaintextRingt& x_pt, int level);

    /**
     * Perform ciphertext relinearization.
     * @param x_ct The input ciphertext.
     * @return The relinearized ciphertext.
     */
    CkksCiphertext relinearize(const CkksCiphertext3& x_ct);

    /**
     * Reduce the level of a CKKS ciphertext by the specified number of levels.
     * @param x_ct The input ciphertext.
     * @param levels The number of levels to drop (default: 1).
     * @return The resulting ciphertext.
     */
    CkksCiphertext drop_level(const CkksCiphertext& x_ct, int levels = 1);

    /**
     * Perform rescale on a CKKS ciphertext.
     * @param x_ct The input ciphertext.
     * @param min_scale The minimum scale value after rescaling.
     * @return The rescaled ciphertext.
     */
    CkksCiphertext rescale(const CkksCiphertext& x_ct, double min_scale);

    /**
     * Perform rotation operation on a ciphertext.
     * @param x_ct The input ciphertext.
     * @param step The rotation step count.
     * @return The rotated ciphertext.
     */
    CkksCiphertext rotate(const CkksCiphertext& x_ct, int32_t step);

    CkksCiphertext advanced_rotate(const CkksCiphertext& x_ct, int32_t step);

    std::map<int32_t, CkksCiphertext> rotate(const CkksCiphertext& x_ct, const std::vector<int32_t>& steps);

    /**
     * Perform polynomial rotation operation on a ciphertext.
     * @param x_ct_h The input ciphertext.
     * @param step The rotation step count.
     * @return The rotated ciphertext.
     */

    CkksCiphertext conjugate(const CkksCiphertext& x_ct);

    std::map<int32_t, CkksCiphertext> advanced_rotate(const CkksCiphertext& x_ct, const std::vector<int32_t>& steps);

    CkksCiphertext poly_eval_relu_function(const CkksCiphertext& x_ct_h, double left, double right, int degree);
    using Operation = std::function<double(double)>;
    CkksCiphertext
    poly_eval_function(Operation op, const CkksCiphertext& x_ct_h, double left, double right, int degree);

    CkksCiphertext poly_eval_step_function(const CkksCiphertext& x_ct,
                                           const double left,
                                           const double right,
                                           const uint64_t degree,
                                           const double threshold);

private:
    std::unique_ptr<CkksContext> _extra_level_context;

protected:
    CkksParameter _parameter;
};

class CkksBtpContext : public CkksContext {
public:
    using CkksContext::CkksContext;

    static CkksBtpContext create_random_context(const CkksBtpParameter& param);

    static CkksBtpContext create_empty_context(const CkksBtpParameter& param);

    void gen_rotation_keys();

    void gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows = false);

    CkksBtpContext make_public_context();

    // cppcheck-suppress duplInheritedMember
    CkksBtpContext shallow_copy_context();

    CkksParameter& get_parameter() override;

    CkksCiphertext bootstrap(const CkksCiphertext& x_ct);

    CkksBtpContext& get_copy(int index) override;

    // cppcheck-suppress duplInheritedMember
    Bytes serialize() const;

    // cppcheck-suppress duplInheritedMember
    static CkksBtpContext deserialize(BytesView data);

    KeySwitchKey extract_swk_dts() const;

    KeySwitchKey extract_swk_std() const;

    // cppcheck-suppress duplInheritedMember
    void set_context_relin_key(const RelinKey& rlk);

    // cppcheck-suppress duplInheritedMember
    void set_context_galois_key(const GaloisKey& glk);

    void set_context_switch_key_dts(const KeySwitchKey& swk);

    void set_context_switch_key_std(const KeySwitchKey& swk);

    void create_bootstrapper();
};

/**
 * @brief BFV plaintext class in ring-t form, used for ciphertext-plaintext multiplication. This interface is not yet
 * publicly available.
 */
class BfvPlaintextRingt : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a BFV plaintext.
     * @return The plaintext level.
     */
    int get_level() const;
};

/**
 * @brief BFV plaintext class, used for ciphertext-plaintext multiplication.
 */
class BfvPlaintextMul : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a BFV plaintext.
     * @return The plaintext level.
     */
    int get_level() const;
};

/**
 * @brief BFV plaintext class, used for ciphertext-plaintext addition.
 */
class BfvPlaintext : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a BFV plaintext.
     * @return The plaintext level.
     */
    int get_level() const;

    void print() const;
};

/**
 * @brief BFV ciphertext class, containing 2 polynomials.
 */
class BfvCiphertext : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a BFV ciphertext.
     * @return The ciphertext level.
     */
    int get_level() const;

    uint64_t get_coeff(int poly_idx, int rns_idx, int coeff_idx) const;

    /**
     * Serialize a BFV ciphertext.
     * @return The serialized binary data.
     */
    Bytes serialize(const BfvParameter& param, int n_drop_bit_0 = 0, int n_drop_bit_1 = 0) const;

    static BfvCiphertext deserialize(BytesView data);

    /**
     * Copy a BFV ciphertext.
     * @return The copied ciphertext.
     */
    BfvCiphertext copy() const;

    void copy_to(const BfvCiphertext& y_ct) const;

    /**
     * Print a BFV ciphertext.
     * @return void.
     */
    void print() const;
};

/**
 * @brief BFV ciphertext class, containing 3 polynomials.
 */
class BfvCiphertext3 : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a BFV ciphertext.
     * @return The ciphertext level.
     */
    int get_level() const;

    void copy_to(const BfvCiphertext3& y_ct) const;
};

class BfvCompressedCiphertext : public Handle {
public:
    using Handle::Handle;

    Bytes serialize(const BfvParameter& param) const;

    static BfvCompressedCiphertext deserialize(BytesView data);
};

/**
 * @brief CKKS plaintext class, used for ciphertext-plaintext addition.
 */
class CkksPlaintext : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a CKKS plaintext.
     * @return The plaintext level.
     */
    int get_level() const;

    uint64_t get_coeff(int rns_idx, int coeff_idx);

    void set_coeff(int rns_idx, int coeff_idx, uint64_t coeff);
};

/**
 * @brief CKKS plaintext class in ring-t form, used for fast ciphertext-plaintext multiplication.
 */
class CkksPlaintextRingt : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a CKKS plaintext.
     * @return The plaintext level.
     */
    int get_level() const;
};

/**
 * @brief CKKS plaintext class, used for ciphertext-plaintext multiplication.
 */
class CkksPlaintextMul : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a CKKS plaintext.
     * @return The plaintext level.
     */
    int get_level() const;
};

/**
 * @brief CKKS ciphertext class, containing 2 polynomials.
 */
class CkksCiphertext : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a CKKS ciphertext.
     * @return The ciphertext level.
     */
    int get_level() const;

    /**
     * Get the scale of a CKKS ciphertext.
     * @return The ciphertext scale.
     */
    double get_scale() const;
    double set_scale(double scale_in) const;
    /**
     * Serialize a CKKS ciphertext.
     * @return The serialized binary data.
     */
    Bytes serialize(const CkksParameter& param) const;

    static CkksCiphertext deserialize(BytesView data);

    /**
     * Copy a CKKS ciphertext.
     * @return The copied ciphertext.
     */
    CkksCiphertext copy() const;

    void copy_to(const CkksCiphertext& y_ct) const;

    /**
     * Print a CKKS ciphertext.
     * @return void.
     */
    void print() const;
};

/**
 * @brief CKKS ciphertext class, containing 3 polynomials.
 */
class CkksCiphertext3 : public Handle {
public:
    using Handle::Handle;

    /**
     * Get the level of a CKKS ciphertext.
     * @return The ciphertext level.
     */
    int get_level() const;

    double get_scale() const;
    double set_scale(double scale_in) const;

    void copy_to(const CkksCiphertext3& y_ct) const;
};

class CkksCompressedCiphertext : public Handle {
public:
    using Handle::Handle;

    Bytes serialize(const CkksParameter& param) const;

    static CkksCompressedCiphertext deserialize(BytesView data);
};

class PublicKeyShare : public Handle {
public:
    using Handle::Handle;

    Bytes serialize() const;

    static PublicKeyShare deserialize(const CkgContext& context, BytesView data);
};

class E2sPublicShare : public Handle {
public:
    using Handle::Handle;

    Bytes serialize() const;

    static E2sPublicShare deserialize(const E2sContext& context, BytesView data);
};

class S2ePublicShare : public Handle {
public:
    using Handle::Handle;

    Bytes serialize() const;

    static S2ePublicShare deserialize(const S2eContext& context, BytesView data);
};

class AdditiveShare : public Handle {
public:
    using Handle::Handle;

    Bytes serialize() const;

    static AdditiveShare deserialize(const DBfvContext& context, BytesView data);
};

class RelinKeyShare : public Handle {
public:
    using Handle::Handle;

    Bytes serialize() const;

    static RelinKeyShare deserialize(const RkgContext& context, BytesView data);
};

class GaloisKeyShare : public Handle {
public:
    using Handle::Handle;

    Bytes serialize() const;

    static GaloisKeyShare deserialize(const RtgContext& context, BytesView data);
};

class RefreshShare : public Handle {
public:
    using Handle::Handle;

    Bytes serialize() const;

    static RefreshShare deserialize(const RefreshContext& context, BytesView data);
};

class RefreshAndPermuteShare : public Handle {
public:
    using Handle::Handle;

    Bytes serialize() const;

    static RefreshAndPermuteShare deserialize(const RefreshAndPermuteContext& context, BytesView data);
};

/**
 * @brief Custom data type for storing user-defined data nodes from mega_ag.json
 *
 * This class extends the Handle base class and adds a void* data member
 * to store custom data payloads that are not part of the standard FHE types.
 * It is designed to be used with the mega_ag execution framework for handling
 * custom operation types (e.g., encode, decode, custom algorithms).
 */
class CustomData : public Handle {
public:
    using Handle::Handle;

    /**
     * @brief Construct a CustomData object with arbitrary typed data
     * @tparam T The type of the custom data
     * @param custom_data The custom data to store (will be heap-allocated and converted to void*)
     * @param k Keep flag (default false)
     *
     * This constructor accepts any type T, creates a heap copy of the data,
     * converts it to void*, and generates a random 64-bit handle value.
     */
    template <typename T>
    CustomData(const T& custom_data, bool k = false)
        : Handle(uint64_t(0), k), data(static_cast<void*>(new typename std::decay<T>::type(custom_data))) {}

    /**
     * @brief Construct a CustomData object with arbitrary typed data (move semantics)
     * @tparam T The type of the custom data
     * @param custom_data The custom data to store (will be moved to heap and converted to void*)
     * @param k Keep flag (default false)
     */
    template <typename T>
    CustomData(T&& custom_data,
               bool k = false,
               typename std::enable_if<!std::is_lvalue_reference<T>::value, int>::type = 0)
        : Handle(uint64_t(0), k),
          data(static_cast<void*>(new typename std::decay<T>::type(std::forward<T>(custom_data)))) {}

    /**
     * @brief Construct a CustomData object with a raw void pointer
     * @param custom_data Pointer to custom user-defined data
     * @param k Keep flag (default false)
     *
     * This constructor accepts a raw void* pointer and generates a random handle.
     */
    explicit CustomData(void* custom_data, bool k = false) : Handle(uint64_t(0), k), data(custom_data) {}

    /**
     * @brief Default constructor
     */
    CustomData() : Handle(), data(nullptr) {}

    /**
     * @brief Move constructor
     */
    CustomData(CustomData&& other) : Handle(std::move(other)), data(other.data) {
        other.data = nullptr;
    }

    /**
     * @brief Move assignment operator
     */
    void operator=(CustomData&& other) {
        Handle::operator=(std::move(other));
        data = other.data;
        other.data = nullptr;
    }

    /**
     * @brief Template helper to get typed custom data
     * @tparam T The type to cast the data pointer to
     * @return T* Typed pointer to the custom data
     */
    template <typename T> T* get_typed_data() const {
        return static_cast<T*>(data);
    }

private:
    void* data;  ///< Pointer to custom user-defined data from mega_ag.json
};

}  // namespace fhe_ops_lib
#endif  // CXX_FHE_LIB_H

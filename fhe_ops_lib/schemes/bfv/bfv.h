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

#ifndef FHE_OPS_LIB_BFV_BFV_H
#define FHE_OPS_LIB_BFV_BFV_H

#include "../base/types.h"
#include "../../utils.h"

namespace fhe_ops_lib {

/**
 * @brief BFV homomorphic parameters class, containing homomorphic parameters N, q, t.
 */
class BfvParameter : public Parameter {
public:
    using Parameter::Parameter;

    static BfvParameter create_parameter(int log_n, uint64_t t);
    static BfvParameter
    create_custom_parameter(int log_n, uint64_t t, const std::vector<uint64_t>& q, const std::vector<uint64_t>& p);

    BfvParameter copy() const;

    Bytes serialize() const override;

    static BfvParameter deserialize(BytesView data);

    void print() const;

    int n() const override;

    int log_n() const override;

    int max_level() const override;

    std::vector<uint64_t> q() const override;

    std::vector<uint64_t> p() const override;

    uint64_t t() const;
};

class BfvEncoder : public Handle {
public:
    using Handle::Handle;
    explicit BfvEncoder(const BfvParameter& parameter);
};

class BfvEvaluator : public Handle {
public:
    using Handle::Handle;
    BfvEvaluator(const BfvParameter& parameter, const EvaluationKeySet& evaluation_key_set);

    void update_evaluation_key_set(const EvaluationKeySet& evaluation_key_set);
};

/**
 * @brief BFV plaintext class.
 */
class BfvPlaintext : public Handle {
public:
    BfvPlaintext() = default;
    BfvPlaintext(uint64_t&& h, bool k = false);
    BfvPlaintext(const BfvParameter& param, Metadata metadata = plaintext_metadata(), bool k = false);

    bool is_ringt() const;
    bool is_batched() const;
    void sync_metadata();

    Metadata metadata() const;

    /**
     * Get the level of a BFV plaintext.
     * @return The plaintext level.
     */
    int level() const;

    Bytes serialize() const;

    static BfvPlaintext deserialize(BytesView data);

private:
    Metadata _metadata{0, 1, 0, 0, 0, 1.0};
};

/**
 * @brief BFV ciphertext class.
 */
class BfvCiphertext : public Handle {
public:
    BfvCiphertext() = default;
    BfvCiphertext(uint64_t&& h, bool k = false);
    BfvCiphertext(const BfvParameter& param, int level, int degree = 1, bool k = false);

    int degree() const;

    /**
     * Get the level of a BFV ciphertext.
     * @return The ciphertext level.
     */
    int level() const;

    Metadata metadata() const;

    void sync_metadata();

    /**
     * Serialize a BFV ciphertext.
     * @return The serialized binary data.
     */
    Bytes serialize() const;

    static BfvCiphertext deserialize(BytesView data);

    /**
     * Copy a BFV ciphertext.
     * @return The copied ciphertext.
     */
    BfvCiphertext copy() const;

    void copy(BfvCiphertext& y_ct) const;

private:
    Metadata _metadata{0, 1, 1, 0, 0, 1.0};
};

/**
 * @brief BFV homomorphic context class. Contains BFV public keys, secret keys, and other information.
 */
class BfvContext : public FheContext {
public:
    BfvContext() = default;

    static BfvContext create_empty_context(const BfvParameter& param);

    /**
     * Create a new BfvContextHandle with randomly generated secret key, encryption public key, relinearization key,
     * and Galois key.
     * @param param The homomorphic parameters.
     * @return The created context.
     */
    static BfvContext create_random_context(const BfvParameter& param,
                                            EncryptorType encryptor_type = EncryptorType::PUBLIC_KEY);

    const BfvParameter& parameter() override;

    const SecretKey& secret_key() const override;

    const PublicKey& public_key() const override;

    void gen_rotation_keys(int level = -1);

    void gen_rotation_keys(const std::vector<int32_t>& rots, bool include_swap_rows = false, int level = -1);

    void set_use_default_rotation_keys(bool use_default_rotation_keys);

    const EvaluationKeySet& evaluation_key_set() const override;

    /**
     * Set a relinearization key to a context.
     * @param rlk The source relinearization key.
     * @return void.
     */
    void set_relin_key(const RelinKey& rlk);

    /**
     * Set a Galois key to a context.
     * @param gk The source Galois key.
     * @return void.
     */
    void set_galois_key(const GaloisKey& gk);

    /**
     * Serialize the BfvContext to binary. Secret key material is not serialized.
     * @return The serialized byte array.
     */
    Bytes serialize() const;

    /**
     * Deserialize a byte array to BfvContext.
     * @param data The byte array.
     * @return The deserialized BfvContext.
     */
    static BfvContext deserialize(BytesView data);

    /**
     * Encode message data into a BFV plaintext according to its attributes.
     * @param message The input message data.
     * @param pt The target plaintext.
     */
    void encode(const std::vector<uint64_t>& message, BfvPlaintext& pt);

    /**
     * Decode a BFV plaintext into message data.
     * @param pt The input plaintext.
     * @param message The decoded message data.
     */
    void decode(const BfvPlaintext& pt, std::vector<uint64_t>& message);

    /**
     * Encrypt a BFV plaintext using the configured encryptor.
     * @param pt The input plaintext.
     * @return The encrypted ciphertext.
     */
    BfvCiphertext encrypt(const BfvPlaintext& pt);

    /**
     * Decrypt a BFV ciphertext using the secret key.
     * @param ct The input ciphertext.
     * @return The decrypted plaintext.
     */
    BfvPlaintext decrypt(const BfvCiphertext& ct);

    /**
     * Compute addition. Plaintext ring-t handling is selected by op1 attributes.
     * @param op0 The first operand.
     * @param op1 The second operand.
     * @return opOut, the addition result.
     */
    BfvCiphertext add(const BfvCiphertext& op0, const BfvCiphertext& op1);

    BfvCiphertext add(const BfvCiphertext& op0, const BfvPlaintext& op1);

    BfvCiphertext add(const BfvCiphertext& op0, int op1);

    BfvCiphertext add(const BfvCiphertext& op0, int64_t op1);

    BfvCiphertext add(const BfvCiphertext& op0, uint64_t op1);

    BfvCiphertext sub(const BfvCiphertext& op0, const BfvCiphertext& op1);

    BfvCiphertext sub(const BfvCiphertext& op0, const BfvPlaintext& op1);

    BfvCiphertext sub(const BfvCiphertext& op0, int op1);

    BfvCiphertext sub(const BfvCiphertext& op0, int64_t op1);

    BfvCiphertext sub(const BfvCiphertext& op0, uint64_t op1);

    /**
     * Compute multiplication. Ciphertext-ciphertext multiplication returns degree-2 opOut.
     * @param op0 The first operand.
     * @param op1 The second operand.
     * @return opOut, the multiplication result.
     */
    BfvCiphertext mult(const BfvCiphertext& op0, const BfvCiphertext& op1);

    BfvCiphertext mult(const BfvCiphertext& op0, const BfvPlaintext& op1);

    BfvCiphertext mult(const BfvCiphertext& op0, int op1);

    BfvCiphertext mult(const BfvCiphertext& op0, int64_t op1);

    BfvCiphertext mult(const BfvCiphertext& op0, uint64_t op1);

    /**
     * Perform ciphertext relinearization.
     * @param op0 The input ciphertext.
     * @return opOut, the relinearized ciphertext.
     */
    BfvCiphertext relinearize(const BfvCiphertext& op0);

    /**
     * Drop levels from a BFV ciphertext.
     * @param op0 The input ciphertext.
     * @param levels The number of levels to drop (default: 1).
     * @return The resulting ciphertext.
     */
    BfvCiphertext drop_level(const BfvCiphertext& op0, int levels = 1);

    /**
     * Perform rescale on a BFV ciphertext.
     * @param op0 The input ciphertext.
     * @return The rescaled ciphertext.
     */
    BfvCiphertext rescale(const BfvCiphertext& op0);

    /**
     * Perform rotation operation on a ciphertext.
     * @param op0 The input ciphertext.
     * @param step The rotation step count.
     * @return opOut, the rotated ciphertext.
     */
    BfvCiphertext rotate_cols(const BfvCiphertext& op0, int32_t step);

    std::map<int32_t, BfvCiphertext> rotate_cols(const BfvCiphertext& op0, const std::vector<int32_t>& steps);

    BfvCiphertext rotate_rows(const BfvCiphertext& op0);

private:
    static const uint8_t CONTEXT_MAGIC[8];

protected:
    BfvParameter _parameter;
    BfvEncoder _encoder;
    BfvEvaluator _evaluator;
    bool _use_default_rotation_keys = true;
};

}  // namespace fhe_ops_lib

#endif  // FHE_OPS_LIB_BFV_BFV_H

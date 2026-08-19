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

#ifndef FHE_OPS_LIB_CKKS_CKKS_H
#define FHE_OPS_LIB_CKKS_CKKS_H

#include <complex>
#include <functional>
#include <map>
#include <vector>
#include "../base/types.h"
#include "../../utils.h"

namespace fhe_ops_lib {

/**
 * @brief CKKS homomorphic parameters class, containing homomorphic parameters N, q.
 */
class CkksParameter : public Parameter {
public:
    using Parameter::Parameter;

    // CkksParameter() = delete;
    static CkksParameter create_parameter(int log_n);
    static CkksParameter create_custom_parameter(int log_n,
                                                 int log_default_scale,
                                                 const std::vector<uint64_t>& q,
                                                 const std::vector<uint64_t>& p);

    CkksParameter copy() const;

    Bytes serialize() const override;

    static CkksParameter deserialize(BytesView data);

    void print() const;

    int n() const override;

    int log_n() const override;

    int max_level() const override;

    std::vector<uint64_t> q() const override;

    std::vector<uint64_t> p() const override;

    int log_max_slots() const;

    int max_slots() const;

    double default_scale() const;

    int log_default_scale() const;
};

class CkksEncoder : public Handle {
public:
    using Handle::Handle;
    explicit CkksEncoder(const CkksParameter& parameter);
};

class CkksEvaluator : public Handle {
public:
    using Handle::Handle;
    CkksEvaluator(const CkksParameter& parameter, const EvaluationKeySet& evaluation_key_set);

    void update_evaluation_key_set(const EvaluationKeySet& evaluation_key_set);
};

class BootstrappingEvaluationKeys : public Handle {
public:
    BootstrappingEvaluationKeys() = default;
    using Handle::Handle;
    BootstrappingEvaluationKeys(const Handle& bootstrapping_parameter, const SecretKey& secret_key);

    BootstrappingEvaluationKeys(EvaluationKey&& evk_n1_to_n2,
                                EvaluationKey&& evk_n2_to_n1,
                                EvaluationKey&& evk_dense_to_sparse,
                                EvaluationKey&& evk_sparse_to_dense,
                                EvaluationKeySet&& evaluation_key_set);

    void sync_from_handle();

    Bytes serialize() const;
    static BootstrappingEvaluationKeys deserialize(BytesView data);

    const EvaluationKey& evk_n1_to_n2() const;
    const EvaluationKey& evk_n2_to_n1() const;
    const EvaluationKey& evk_dense_to_sparse() const;
    const EvaluationKey& evk_sparse_to_dense() const;
    const EvaluationKeySet& evaluation_key_set() const;

    void set_evaluation_key_set(EvaluationKeySet&& evaluation_key_set);
    void set_evk_n1_to_n2(const EvaluationKey& evk);
    void set_evk_n2_to_n1(const EvaluationKey& evk);
    void set_evk_dense_to_sparse(const EvaluationKey& evk);
    void set_evk_sparse_to_dense(const EvaluationKey& evk);
    void set_relin_key(const RelinKey& rlk);
    void set_galois_key(const GaloisKey& gk);

private:
    friend class CkksContext;

    EvaluationKey _evk_n1_to_n2;
    EvaluationKey _evk_n2_to_n1;
    EvaluationKey _evk_dense_to_sparse;
    EvaluationKey _evk_sparse_to_dense;
    EvaluationKeySet _evaluation_key_set;
};

/**
 * @brief CKKS plaintext class.
 */
class CkksPlaintext : public Handle {
public:
    CkksPlaintext() = default;
    CkksPlaintext(uint64_t&& h, bool k = false);
    CkksPlaintext(const CkksParameter& param, Metadata metadata = plaintext_metadata(), bool k = false);

    bool is_ringt() const;
    bool is_batched() const;
    int log_slots() const;
    double scale() const;
    void sync_metadata();
    Metadata metadata() const;

    /**
     * Get the level of a CKKS plaintext.
     * @return The plaintext level.
     */
    int level() const;

    Bytes serialize() const;

    static CkksPlaintext deserialize(BytesView data);

private:
    Metadata _metadata{1, 1, 0, 0, 0, 1.0};
};

/**
 * @brief CKKS ciphertext class.
 */
class CkksCiphertext : public Handle {
public:
    CkksCiphertext() = default;
    CkksCiphertext(uint64_t&& h, bool k = false);
    CkksCiphertext(const CkksParameter& param, int level, int degree = 1, bool k = false);

    int degree() const;

    /**
     * Get the level of a CKKS ciphertext.
     * @return The ciphertext level.
     */
    int level() const;

    /**
     * Get the scale of a CKKS ciphertext.
     * @return The ciphertext scale.
     */
    double scale() const;
    double set_scale(double scale_in);
    void sync_metadata();
    Metadata metadata() const;
    /**
     * Serialize a CKKS ciphertext.
     * @return The serialized binary data.
     */
    Bytes serialize() const;

    static CkksCiphertext deserialize(BytesView data);

    /**
     * Copy a CKKS ciphertext.
     * @return The copied ciphertext.
     */
    CkksCiphertext copy() const;

    void copy(CkksCiphertext& y_ct) const;

private:
    Metadata _metadata{0, 1, 1, 0, 0, 1.0};
};

/**
 * @brief CKKS homomorphic context class. Contains CKKS public keys, secret keys, and other information.
 */
class CkksContext : public FheContext {
public:
    CkksContext() = default;

    static CkksContext create_empty_context(const CkksParameter& param);

    /**
     * Create a new CkksContextHandle with randomly generated secret key, encryption public key, relinearization key,
     * and Galois key.
     * @param param The homomorphic parameters.
     * @return The created context.
     */
    static CkksContext create_random_context(const CkksParameter& param,
                                             EncryptorType encryptor_type = EncryptorType::PUBLIC_KEY,
                                             bool enable_bootstrapping = false);

    const CkksParameter& parameter() override;

    const SecretKey& secret_key() const override;

    const PublicKey& public_key() const override;

    void gen_rotation_keys(int level = -1);

    void gen_rotation_keys(const std::vector<int32_t>& rots, bool include_swap_rows = false, int level = -1);

    void set_use_default_rotation_keys(bool use_default_rotation_keys);

    void create_bootstrapper();

    void set_enable_bootstrapping(bool enable_bootstrapping = true);

    const BootstrappingEvaluationKeys& bootstrapping_evaluation_keys() const;

    CkksCiphertext bootstrap(const CkksCiphertext& op0);

    std::vector<CkksCiphertext> bootstrap(const std::vector<CkksCiphertext>& ops);

    EvaluationKey extract_evk_dts() const;

    EvaluationKey extract_evk_std() const;

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

    void set_bootstrapping_relin_key(const RelinKey& rlk);

    void set_bootstrapping_galois_key(const GaloisKey& gk);

    void set_evk_n1_to_n2(const EvaluationKey& evk);

    void set_evk_n2_to_n1(const EvaluationKey& evk);

    void set_evk_dense_to_sparse(const EvaluationKey& evk);

    void set_evk_sparse_to_dense(const EvaluationKey& evk);

    /**
     * Serialize a CKKS context to binary. Secret key material is not serialized.
     * @return The serialized byte array.
     */
    Bytes serialize() const;

    /**
     * Deserialize a CKKS context from binary.
     * @param data The byte array.
     * @return The deserialized CkksContext.
     */
    static CkksContext deserialize(BytesView data);

    /**
     * Encode message data into a CKKS plaintext according to its attributes.
     * @param message The input message data.
     * @param pt The target plaintext.
     */
    void encode(const std::vector<double>& message, CkksPlaintext& pt);
    void encode(const std::vector<std::complex<double>>& message, CkksPlaintext& pt);

    /**
     * Decode a CKKS plaintext into message data.
     * @param pt The input plaintext.
     * @param message The decoded message data.
     */
    void decode(const CkksPlaintext& pt, std::vector<double>& message);
    void decode(const CkksPlaintext& pt, std::vector<std::complex<double>>& message);

    // CkksPlaintext recode_big_complex(const CkksPlaintext& pt, int level, double scale);

    /**
     * Encrypt a CKKS plaintext using the configured encryptor.
     * @param pt The input plaintext.
     * @return The encrypted ciphertext.
     */
    CkksCiphertext encrypt(const CkksPlaintext& pt);

    // CkksCompressedCiphertext encrypt_symmetric_compressed(const CkksPlaintext& pt);

    // CkksCiphertext compressed_ciphertext_to_ciphertext(const CkksCompressedCiphertext& ct);

    /**
     * Decrypt a CKKS ciphertext using the secret key.
     * @param ct The input ciphertext.
     * @return The decrypted plaintext.
     */
    CkksPlaintext decrypt(const CkksCiphertext& ct);

    /**
     * Compute addition. Plaintext ring-t handling is selected by op1 attributes.
     * @param op0 The first operand.
     * @param op1 The second operand.
     * @return opOut, the addition result.
     */
    CkksCiphertext add(const CkksCiphertext& op0, const CkksCiphertext& op1);

    CkksCiphertext add(const CkksCiphertext& op0, const CkksPlaintext& op1);

    CkksCiphertext add(const CkksCiphertext& op0, double op1);

    CkksCiphertext add(const CkksCiphertext& op0, const std::complex<double>& op1);

    CkksCiphertext sub(const CkksCiphertext& op0, const CkksCiphertext& op1);

    CkksCiphertext sub(const CkksCiphertext& op0, const CkksPlaintext& op1);

    CkksCiphertext sub(const CkksCiphertext& op0, double op1);

    CkksCiphertext sub(const CkksCiphertext& op0, const std::complex<double>& op1);

    /**
     * Compute multiplication. Ciphertext-ciphertext multiplication returns degree-2 opOut.
     * @param op0 The first operand.
     * @param op1 The second operand.
     * @return opOut, the multiplication result.
     */
    CkksCiphertext mult(const CkksCiphertext& op0, const CkksCiphertext& op1);

    CkksCiphertext mult(const CkksCiphertext& op0, const CkksPlaintext& op1);

    CkksCiphertext mult(const CkksCiphertext& op0, double op1);

    CkksCiphertext mult(const CkksCiphertext& op0, const std::complex<double>& op1);

    /**
     * Perform ciphertext relinearization.
     * @param op0 The input ciphertext.
     * @return opOut, the relinearized ciphertext.
     */
    CkksCiphertext relinearize(const CkksCiphertext& op0);

    /**
     * Reduce the level of a CKKS ciphertext by the specified number of levels.
     * @param op0 The input ciphertext.
     * @param levels The number of levels to drop (default: 1).
     * @return The resulting ciphertext.
     */
    CkksCiphertext drop_level(const CkksCiphertext& op0, int levels = 1);

    /**
     * Perform rescale on a CKKS ciphertext.
     * @param op0 The input ciphertext.
     * @return The rescaled ciphertext.
     */
    CkksCiphertext rescale(const CkksCiphertext& op0);

    /**
     * Perform rotation operation on a ciphertext.
     * @param op0 The input ciphertext.
     * @param step The rotation step count.
     * @return The rotated ciphertext.
     */
    CkksCiphertext rotate(const CkksCiphertext& op0, int32_t step);

    std::map<int32_t, CkksCiphertext> rotate(const CkksCiphertext& op0, const std::vector<int32_t>& steps);

    /**
     * Perform conjugation operation on a ciphertext.
     * @param op0 The input ciphertext.
     * @return The conjugated ciphertext.
     */
    CkksCiphertext conjugate(const CkksCiphertext& op0);

    // CkksCiphertext poly_eval_relu_function(const CkksCiphertext& x_ct_h, double left, double right, int degree);
    // using Operation = std::function<double(double)>;
    // CkksCiphertext
    // poly_eval_function(Operation op, const CkksCiphertext& x_ct_h, double left, double right, int degree);

    // CkksCiphertext poly_eval_step_function(const CkksCiphertext& x_ct,
    //                                        const double left,
    //                                        const double right,
    //                                        const uint64_t degree,
    //                                        const double threshold);

private:
    static const uint8_t CONTEXT_MAGIC[8];

protected:
    CkksParameter _parameter;
    CkksEncoder _encoder;
    CkksEvaluator _evaluator;
    bool _use_default_rotation_keys = true;

    bool _enable_bootstrapping = false;
    Handle _btp_parameter;
    BootstrappingEvaluationKeys _bootstrapping_evaluation_keys;
    Handle _btp_evaluator;
};

}  // namespace fhe_ops_lib

#endif  // FHE_OPS_LIB_CKKS_CKKS_H

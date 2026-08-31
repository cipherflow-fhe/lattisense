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

#include "ckks.h"
#include "../base/internal.h"

namespace fhe_ops_lib {

BootstrappingEvaluationKeys::BootstrappingEvaluationKeys(const Handle& bootstrapping_parameter,
                                                         const SecretKey& secret_key) {
    if (bootstrapping_parameter.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping parameter is not set");
    }
    if (secret_key.is_empty()) {
        throw std::runtime_error("CKKS secret key is not set");
    }

    uint64_t btp_evaluation_keys_handle = 0;
    uint64_t evk_n1_to_n2_handle = 0;
    uint64_t evk_n2_to_n1_handle = 0;
    uint64_t evk_dts_handle = 0;
    uint64_t evk_std_handle = 0;
    uint64_t evaluation_key_set_handle = 0;
    CHECK(GenCkksBootstrappingEvaluationKeys(bootstrapping_parameter.get(), secret_key.get(),
                                             &btp_evaluation_keys_handle, &evk_n1_to_n2_handle, &evk_n2_to_n1_handle,
                                             &evk_dts_handle, &evk_std_handle, &evaluation_key_set_handle));
    _value = btp_evaluation_keys_handle;
    _keep = false;
    _evk_n1_to_n2 = EvaluationKey(std::move(evk_n1_to_n2_handle));
    _evk_n2_to_n1 = EvaluationKey(std::move(evk_n2_to_n1_handle));
    _evk_dense_to_sparse = EvaluationKey(std::move(evk_dts_handle));
    _evk_sparse_to_dense = EvaluationKey(std::move(evk_std_handle));
    _evaluation_key_set = EvaluationKeySet(std::move(evaluation_key_set_handle));
    _evaluation_key_set.sync_from_handle();
}

BootstrappingEvaluationKeys::BootstrappingEvaluationKeys(EvaluationKey&& evk_n1_to_n2,
                                                         EvaluationKey&& evk_n2_to_n1,
                                                         EvaluationKey&& evk_dense_to_sparse,
                                                         EvaluationKey&& evk_sparse_to_dense,
                                                         EvaluationKeySet&& evaluation_key_set) {
    uint64_t handle = 0;
    CHECK(CreateCkksBootstrappingEvaluationKeys(evk_n1_to_n2.is_empty() ? 0 : evk_n1_to_n2.get(),
                                                evk_n2_to_n1.is_empty() ? 0 : evk_n2_to_n1.get(),
                                                evk_dense_to_sparse.is_empty() ? 0 : evk_dense_to_sparse.get(),
                                                evk_sparse_to_dense.is_empty() ? 0 : evk_sparse_to_dense.get(),
                                                evaluation_key_set.is_empty() ? 0 : evaluation_key_set.get(), &handle));
    _value = handle;
    _keep = false;
    _evk_n1_to_n2 = std::move(evk_n1_to_n2);
    _evk_n2_to_n1 = std::move(evk_n2_to_n1);
    _evk_dense_to_sparse = std::move(evk_dense_to_sparse);
    _evk_sparse_to_dense = std::move(evk_sparse_to_dense);
    _evaluation_key_set = std::move(evaluation_key_set);
}

void BootstrappingEvaluationKeys::sync_from_handle() {
    if (is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }

    uint64_t evk_n1_to_n2_handle = 0;
    uint64_t evk_n2_to_n1_handle = 0;
    uint64_t evk_dense_to_sparse_handle = 0;
    uint64_t evk_sparse_to_dense_handle = 0;
    uint64_t evaluation_key_set_handle = 0;
    CHECK(GetCkksBootstrappingEvaluationKeys(this->get(), &evk_n1_to_n2_handle, &evk_n2_to_n1_handle,
                                             &evk_dense_to_sparse_handle, &evk_sparse_to_dense_handle,
                                             &evaluation_key_set_handle));
    _evk_n1_to_n2 = evk_n1_to_n2_handle == 0 ? EvaluationKey() : EvaluationKey(std::move(evk_n1_to_n2_handle));
    _evk_n2_to_n1 = evk_n2_to_n1_handle == 0 ? EvaluationKey() : EvaluationKey(std::move(evk_n2_to_n1_handle));
    _evk_dense_to_sparse =
        evk_dense_to_sparse_handle == 0 ? EvaluationKey() : EvaluationKey(std::move(evk_dense_to_sparse_handle));
    _evk_sparse_to_dense =
        evk_sparse_to_dense_handle == 0 ? EvaluationKey() : EvaluationKey(std::move(evk_sparse_to_dense_handle));
    _evaluation_key_set =
        evaluation_key_set_handle == 0 ? EvaluationKeySet() : EvaluationKeySet(std::move(evaluation_key_set_handle));
    if (!_evaluation_key_set.is_empty()) {
        _evaluation_key_set.sync_from_handle();
    }
}

Bytes BootstrappingEvaluationKeys::serialize() const {
    return export_raw_data<uint8_t>([this](uint8_t** raw_data, uint64_t* length) {
        uint64_t data_handle = 0;
        CHECK(SerializeCkksBootstrappingEvaluationKeys(this->get(), raw_data, length, &data_handle));
        return data_handle;
    });
}

BootstrappingEvaluationKeys BootstrappingEvaluationKeys::deserialize(BytesView data) {
    uint64_t handle = 0;
    CHECK(DeserializeCkksBootstrappingEvaluationKeys((uint8_t*)data.data(), data.size(), &handle));
    BootstrappingEvaluationKeys keys(std::move(handle));
    keys.sync_from_handle();
    return keys;
}

const EvaluationKey& BootstrappingEvaluationKeys::evk_n1_to_n2() const {
    return _evk_n1_to_n2;
}

const EvaluationKey& BootstrappingEvaluationKeys::evk_n2_to_n1() const {
    return _evk_n2_to_n1;
}

const EvaluationKey& BootstrappingEvaluationKeys::evk_dense_to_sparse() const {
    return _evk_dense_to_sparse;
}

const EvaluationKey& BootstrappingEvaluationKeys::evk_sparse_to_dense() const {
    return _evk_sparse_to_dense;
}

const EvaluationKeySet& BootstrappingEvaluationKeys::evaluation_key_set() const {
    return _evaluation_key_set;
}

void BootstrappingEvaluationKeys::set_evaluation_key_set(EvaluationKeySet&& evaluation_key_set) {
    if (evaluation_key_set.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation key set is not set");
    }
    if (is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }
    CHECK(SetCkksBootstrappingEvaluationKeySet(this->get(), evaluation_key_set.get()));
    _evaluation_key_set = std::move(evaluation_key_set);
}

void BootstrappingEvaluationKeys::set_evk_n1_to_n2(const EvaluationKey& evk) {
    if (evk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping N1-to-N2 evaluation key is not set");
    }
    if (is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }
    EvaluationKey evk_copy = evk.copy();
    CHECK(SetCkksBootstrappingEvaluationKeyN1ToN2(this->get(), evk_copy.get()));
    _evk_n1_to_n2 = std::move(evk_copy);
}

void BootstrappingEvaluationKeys::set_evk_n2_to_n1(const EvaluationKey& evk) {
    if (evk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping N2-to-N1 evaluation key is not set");
    }
    if (is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }
    EvaluationKey evk_copy = evk.copy();
    CHECK(SetCkksBootstrappingEvaluationKeyN2ToN1(this->get(), evk_copy.get()));
    _evk_n2_to_n1 = std::move(evk_copy);
}

void BootstrappingEvaluationKeys::set_evk_dense_to_sparse(const EvaluationKey& evk) {
    if (evk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping dense-to-sparse evaluation key is not set");
    }
    if (is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }
    EvaluationKey evk_copy = evk.copy();
    CHECK(SetCkksBootstrappingEvaluationKeyDenseToSparse(this->get(), evk_copy.get()));
    _evk_dense_to_sparse = std::move(evk_copy);
}

void BootstrappingEvaluationKeys::set_evk_sparse_to_dense(const EvaluationKey& evk) {
    if (evk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping sparse-to-dense evaluation key is not set");
    }
    if (is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }
    EvaluationKey evk_copy = evk.copy();
    CHECK(SetCkksBootstrappingEvaluationKeySparseToDense(this->get(), evk_copy.get()));
    _evk_sparse_to_dense = std::move(evk_copy);
}

void BootstrappingEvaluationKeys::set_relin_key(const RelinKey& rlk) {
    if (rlk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping relinearization key is not set");
    }
    if (is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }
    if (_evaluation_key_set.is_empty()) {
        _evaluation_key_set = EvaluationKeySet(RelinKey(), {});
    }
    RelinKey rlk_copy = rlk.copy();
    _evaluation_key_set.set_relin_key(std::move(rlk_copy));
    CHECK(SetCkksBootstrappingEvaluationKeySet(this->get(), _evaluation_key_set.get()));
}

void BootstrappingEvaluationKeys::set_galois_key(const GaloisKey& gk) {
    if (gk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping Galois key is not set");
    }
    if (is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }
    if (_evaluation_key_set.is_empty()) {
        _evaluation_key_set = EvaluationKeySet(RelinKey(), {});
    }
    GaloisKey gk_copy = gk.copy();
    _evaluation_key_set.set_galois_key(std::move(gk_copy));
    CHECK(SetCkksBootstrappingEvaluationKeySet(this->get(), _evaluation_key_set.get()));
}

void CkksContext::create_bootstrapper() {
    if (_parameter.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }
    uint64_t handle = 0;
    CHECK(CreateCkksBtpParameterFromResidualParameter(_parameter.get(), &handle));
    _btp_parameter = Handle(std::move(handle));
    if (_secret_key.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }
    _bootstrapping_evaluation_keys = BootstrappingEvaluationKeys(_btp_parameter, _secret_key);
    uint64_t evaluator_handle = 0;
    CHECK(CreateCkksBtpEvaluator(_btp_parameter.get(), _bootstrapping_evaluation_keys.get(), &evaluator_handle));
    _btp_evaluator = Handle(std::move(evaluator_handle));
    _enable_bootstrapping = true;
}

void CkksContext::set_enable_bootstrapping(bool enable_bootstrapping) {
    _enable_bootstrapping = enable_bootstrapping;
    if (!enable_bootstrapping) {
        return;
    }
    if (_parameter.is_empty()) {
        throw std::runtime_error("CKKS parameter is not set");
    }
    if (_btp_parameter.is_empty()) {
        uint64_t handle = 0;
        CHECK(CreateCkksBtpParameterFromResidualParameter(_parameter.get(), &handle));
        _btp_parameter = Handle(std::move(handle));
    }
    if (_bootstrapping_evaluation_keys.is_empty()) {
        _bootstrapping_evaluation_keys = BootstrappingEvaluationKeys({}, {}, {}, {}, EvaluationKeySet(RelinKey(), {}));
    }
}

const BootstrappingEvaluationKeys& CkksContext::bootstrapping_evaluation_keys() const {
    if (_bootstrapping_evaluation_keys.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
    }
    return _bootstrapping_evaluation_keys;
}

const CkksParameter& CkksContext::bootstrapping_parameter() {
    if (_btp_parameter.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping parameter is not set");
    }
    if (_btp_parameter_n2.is_empty()) {
        uint64_t handle = 0;
        CHECK(GetCkksBootstrappingParameterFromBtpParameter(_btp_parameter.get(), &handle));
        _btp_parameter_n2 = CkksParameter(std::move(handle));
    }
    return _btp_parameter_n2;
}

CkksCiphertext CkksContext::bootstrap(const CkksCiphertext& op0) {
    std::vector<CkksCiphertext> ops;
    ops.emplace_back(keep_handle<CkksCiphertext>(op0.get()));
    std::vector<CkksCiphertext> opOuts = bootstrap(ops);
    return std::move(opOuts[0]);
}

std::vector<CkksCiphertext> CkksContext::bootstrap(const std::vector<CkksCiphertext>& ops) {
    if (!_enable_bootstrapping) {
        throw std::runtime_error("CKKS bootstrapping is not enabled");
    }
    if (_btp_evaluator.is_empty()) {
        if (_btp_parameter.is_empty() || _bootstrapping_evaluation_keys.is_empty()) {
            throw std::runtime_error("CKKS bootstrapping evaluation keys are not set");
        }
        uint64_t evaluator_handle = 0;
        CHECK(CreateCkksBtpEvaluator(_btp_parameter.get(), _bootstrapping_evaluation_keys.get(), &evaluator_handle));
        _btp_evaluator = Handle(std::move(evaluator_handle));
    }
    if (ops.empty()) {
        return {};
    }

    std::vector<uint64_t> ciphertext_handles;
    std::vector<uint64_t> ciphertext_out_handles(ops.size(), 0);
    std::vector<double> input_scales;
    ciphertext_handles.reserve(ops.size());
    input_scales.reserve(ops.size());

    for (const CkksCiphertext& op0 : ops) {
        ciphertext_handles.push_back(op0.get());
        input_scales.push_back(op0.scale());
        const_cast<CkksCiphertext&>(op0).set_scale(_parameter.default_scale());
    }

    try {
        CHECK(CkksBootstrapMany(_btp_evaluator.get(), ciphertext_handles.data(),
                                static_cast<int>(ciphertext_handles.size()), ciphertext_out_handles.data()));
    } catch (...) {
        for (size_t i = 0; i < ops.size(); ++i) {
            const_cast<CkksCiphertext&>(ops[i]).set_scale(input_scales[i]);
        }
        throw;
    }

    for (size_t i = 0; i < ops.size(); ++i) {
        const_cast<CkksCiphertext&>(ops[i]).set_scale(input_scales[i]);
    }

    std::vector<CkksCiphertext> opOuts;
    opOuts.reserve(ciphertext_out_handles.size());
    for (size_t i = 0; i < ciphertext_out_handles.size(); ++i) {
        CkksCiphertext opOut(std::move(ciphertext_out_handles[i]));
        opOut.sync_metadata();
        opOut.set_scale(input_scales[i]);
        opOuts.push_back(std::move(opOut));
    }
    return opOuts;
}

EvaluationKey CkksContext::extract_evk_dts() const {
    return keep_handle<EvaluationKey>(bootstrapping_evaluation_keys().evk_dense_to_sparse().get());
}

EvaluationKey CkksContext::extract_evk_std() const {
    return keep_handle<EvaluationKey>(bootstrapping_evaluation_keys().evk_sparse_to_dense().get());
}

void CkksContext::set_bootstrapping_relin_key(const RelinKey& rlk) {
    if (rlk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping relinearization key is not set");
    }
    _bootstrapping_evaluation_keys.set_relin_key(rlk);
}

void CkksContext::set_bootstrapping_galois_key(const GaloisKey& gk) {
    if (gk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping Galois key is not set");
    }
    _bootstrapping_evaluation_keys.set_galois_key(gk);
}

void CkksContext::set_evk_n1_to_n2(const EvaluationKey& evk) {
    if (evk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping N1-to-N2 evaluation key is not set");
    }
    _bootstrapping_evaluation_keys.set_evk_n1_to_n2(evk);
}

void CkksContext::set_evk_n2_to_n1(const EvaluationKey& evk) {
    if (evk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping N2-to-N1 evaluation key is not set");
    }
    _bootstrapping_evaluation_keys.set_evk_n2_to_n1(evk);
}

void CkksContext::set_evk_dense_to_sparse(const EvaluationKey& evk) {
    if (evk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping dense-to-sparse evaluation key is not set");
    }
    _bootstrapping_evaluation_keys.set_evk_dense_to_sparse(evk);
}

void CkksContext::set_evk_sparse_to_dense(const EvaluationKey& evk) {
    if (evk.is_empty()) {
        throw std::runtime_error("CKKS bootstrapping sparse-to-dense evaluation key is not set");
    }
    _bootstrapping_evaluation_keys.set_evk_sparse_to_dense(evk);
}

}  // namespace fhe_ops_lib

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

#ifndef FHE_OPS_LIB_COMMON_INTERNAL_H
#define FHE_OPS_LIB_COMMON_INTERNAL_H

#include <stdexcept>
#include <string>
#include <functional>
#include <vector>
#include <map>
#include "types.h"

namespace fhe_ops_lib {

inline std::string get_error_message() {
    return "lattigo operation failed";
}

inline void CHECK(int status) {
    if (status != 0) {
        throw std::runtime_error(get_error_message());
    }
}

inline void CHECK(ErrorStatus status) {
    if (status.code != 0) {
        std::string message = status.message != nullptr ? status.message : get_error_message();
        if (status.message != nullptr) {
            FreeGoString(status.message);
        }
        throw std::runtime_error(message);
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

template <typename T> T keep_handle(uint64_t handle) {
    return T(std::move(handle), true);
}

inline RelinKey keep_relin_key(const RelinKey& key) {
    uint64_t handle = key.get();
    return RelinKey(std::move(handle), true);
}

inline GaloisKey keep_galois_key(const GaloisKey& key) {
    uint64_t handle = key.get();
    return GaloisKey(std::move(handle), true);
}

inline std::map<uint64_t, GaloisKey> keep_galois_keys(const std::map<uint64_t, GaloisKey>& keys) {
    std::map<uint64_t, GaloisKey> result;
    for (const auto& [galois_element, key] : keys) {
        if (!key.is_empty()) {
            result.emplace(galois_element, keep_galois_key(key));
        }
    }
    return result;
}

inline uint64_t require_handle(const Handle& handle, const char* error_message) {
    if (handle.is_empty()) {
        throw std::runtime_error(error_message);
    }
    return handle.get();
}

[[noreturn]] inline void unsupported_context_handle_api(const char* api_name) {
    throw std::runtime_error(std::string(api_name) + " requires a Go context handle and has not been migrated");
}

inline Handle own_handle(uint64_t handle) {
    return Handle(std::move(handle));
}

}  // namespace fhe_ops_lib

#endif  // FHE_OPS_LIB_COMMON_INTERNAL_H

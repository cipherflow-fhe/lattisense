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

#ifndef FHE_OPS_LIB_COMMON_CUSTOM_DATA_H
#define FHE_OPS_LIB_COMMON_CUSTOM_DATA_H

#include "types.h"

namespace fhe_ops_lib {

class CustomData : public Handle {
public:
    using Handle::Handle;

    template <typename T>
    CustomData(const T& custom_data, bool k = false)
        : Handle(uint64_t(0), k), data(static_cast<void*>(new typename std::decay<T>::type(custom_data))) {}

    template <typename T>
    CustomData(T&& custom_data,
               bool k = false,
               typename std::enable_if<!std::is_lvalue_reference<T>::value, int>::type = 0)
        : Handle(uint64_t(0), k),
          data(static_cast<void*>(new typename std::decay<T>::type(std::forward<T>(custom_data)))) {}

    explicit CustomData(void* custom_data, bool k = false) : Handle(uint64_t(0), k), data(custom_data) {}

    CustomData() : Handle(), data(nullptr) {}

    CustomData(CustomData&& other) : Handle(std::move(other)), data(other.data) {
        other.data = nullptr;
    }

    void operator=(CustomData&& other) {
        Handle::operator=(std::move(other));
        data = other.data;
        other.data = nullptr;
    }

    template <typename T> T* get_typed_data() const {
        return static_cast<T*>(data);
    }

private:
    void* data;
};

}  // namespace fhe_ops_lib

#endif  // FHE_OPS_LIB_COMMON_CUSTOM_DATA_H

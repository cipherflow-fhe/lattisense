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

#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <limits>
#include <string>

template <typename T, int dim> class Array {
public:
    Array() {}

    Array(Array&& other) noexcept {
        swap(_data, other._data);
        swap(_shape, other._shape);
    }

    Array(const Array& other) = delete;

    void operator=(Array&& other) noexcept {
        swap(_data, other._data);
        swap(_shape, other._shape);
    }

    void operator=(const Array& other) = delete;

    Array(const std::array<uint64_t, dim>& s) : _shape(s) {
        uint64_t p = safe_calculate_size(_shape);
        _data = std::vector<T>(p);
    }

    Array(const std::array<uint64_t, dim>& s, T value) : _shape(s) {
        uint64_t p = safe_calculate_size(_shape);
        _data = std::vector<T>(p, value);
    }

    Array<T, dim> copy() const {
        Array<T, dim> result(_shape);
        result.set_data(_data);
        return result;
    }

    uint64_t get_size() const noexcept {
        return _data.size();
    }

    template <int new_dim> Array<T, new_dim> reshape(const std::array<uint64_t, new_dim>& s) {
        std::array<uint64_t, new_dim> new_shape = s;
        uint64_t old_p = safe_calculate_size(_shape);

        int gap_idx = -1;
        uint64_t new_p = 1;
        for (size_t i = 0; i < new_dim; i++) {
            if (new_shape[i] == 0) {
                if (gap_idx >= 0) {
                    throw std::invalid_argument("More than one dimensions have size of 0.");
                }
                gap_idx = i;
            } else {
                if (new_p > std::numeric_limits<uint64_t>::max() / new_shape[i]) {
                    throw std::overflow_error("New shape size calculation would overflow");
                }
                new_p *= new_shape[i];
            }
        }

        if (gap_idx >= 0) {
            if (new_p == 0) {
                throw std::invalid_argument("Cannot infer dimension: new size would be zero");
            }
            if (old_p % new_p != 0) {
                throw std::invalid_argument("Cannot reshape: sizes are not compatible");
            }
            new_shape[gap_idx] = old_p / new_p;
            new_p = old_p;
        }

        if (old_p != new_p) {
            throw std::invalid_argument("Cannot reshape: total size must remain the same");
        }

        Array<T, new_dim> result;
        result.set_shape(new_shape);
        result.move_data(std::move(_data));
        return result;
    }

    std::array<uint64_t, dim> get_shape() const noexcept {
        return _shape;
    }

    void set_shape(const std::array<uint64_t, dim>& s) noexcept {
        _shape = s;
    }

    T* get_data() {
        if (_data.empty()) {
            throw std::runtime_error("Cannot get data pointer from empty array");
        }
        return &_data[0];
    }

    const T* get_data() const {
        if (_data.empty()) {
            throw std::runtime_error("Cannot get data pointer from empty array");
        }
        return &_data[0];
    }

    void set_data(const std::vector<T>& d) {
        _data = d;
    }

    void move_data(std::vector<T>&& d) noexcept {
        _data = std::move(d);
    }

    T get(uint64_t i0) const {
        check_bounds_1d(i0);
        return _data[i0];
    }

    T get(uint64_t i0, uint64_t i1) const {
        check_bounds_2d(i0, i1);
        return _data[i0 * _shape[1] + i1];
    }

    T get(uint64_t i0, uint64_t i1, uint64_t i2) const {
        check_bounds_3d(i0, i1, i2);
        return _data[i0 * _shape[1] * _shape[2] + i1 * _shape[2] + i2];
    }

    T get(uint64_t i0, uint64_t i1, uint64_t i2, uint64_t i3) const {
        check_bounds_4d(i0, i1, i2, i3);
        return _data[i0 * _shape[1] * _shape[2] * _shape[3] + i1 * _shape[2] * _shape[3] + i2 * _shape[3] + i3];
    }

    void set(uint64_t i0, T value) {
        check_bounds_1d(i0);
        _data[i0] = value;
    }

    void set(uint64_t i0, uint64_t i1, T value) {
        check_bounds_2d(i0, i1);
        _data[i0 * _shape[1] + i1] = value;
    }

    void set(uint64_t i0, uint64_t i1, uint64_t i2, T value) {
        check_bounds_3d(i0, i1, i2);
        _data[i0 * _shape[1] * _shape[2] + i1 * _shape[2] + i2] = value;
    }

    void set(uint64_t i0, uint64_t i1, uint64_t i2, uint64_t i3, T value) {
        check_bounds_4d(i0, i1, i2, i3);
        _data[i0 * _shape[1] * _shape[2] * _shape[3] + i1 * _shape[2] * _shape[3] + i2 * _shape[3] + i3] = value;
    }

    std::vector<T> to_array_1d() const {
        return _data;
    }

private:
    std::vector<T> _data;
    std::array<uint64_t, dim> _shape;

    uint64_t safe_calculate_size(const std::array<uint64_t, dim>& shape) const {
        uint64_t size = 1;
        for (uint64_t x : shape) {
            if (x == 0) {
                return 0;
            }
            if (size > std::numeric_limits<uint64_t>::max() / x) {
                throw std::overflow_error("Array size calculation would overflow");
            }
            size *= x;
        }
        return size;
    }

    void check_bounds_1d(uint64_t i0) const {
        if (i0 >= _data.size()) {
            throw std::out_of_range("Index out of bounds: " + std::to_string(i0) +
                                    " >= " + std::to_string(_data.size()));
        }
    }

    void check_bounds_2d(uint64_t i0, uint64_t i1) const {
        // cppcheck-suppress containerOutOfBounds
        if (dim < 2 || i0 >= _shape[0] || i1 >= _shape[1]) {
            throw std::out_of_range("2D index out of bounds: (" + std::to_string(i0) + ", " + std::to_string(i1) + ")");
        }
    }

    void check_bounds_3d(uint64_t i0, uint64_t i1, uint64_t i2) const {
        // cppcheck-suppress containerOutOfBounds
        if (dim < 3 || i0 >= _shape[0] || i1 >= _shape[1] || i2 >= _shape[2]) {
            throw std::out_of_range("3D index out of bounds: (" + std::to_string(i0) + ", " + std::to_string(i1) +
                                    ", " + std::to_string(i2) + ")");
        }
    }

    void check_bounds_4d(uint64_t i0, uint64_t i1, uint64_t i2, uint64_t i3) const {
        // cppcheck-suppress containerOutOfBounds
        if (dim < 4 || i0 >= _shape[0] || i1 >= _shape[1] || i2 >= _shape[2] || i3 >= _shape[3]) {
            throw std::out_of_range("4D index out of bounds: (" + std::to_string(i0) + ", " + std::to_string(i1) +
                                    ", " + std::to_string(i2) + ", " + std::to_string(i3) + ")");
        }
    }
};

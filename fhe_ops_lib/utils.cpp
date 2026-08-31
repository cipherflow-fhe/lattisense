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

#include <cassert>
#include <cmath>
#include <random>
#include <chrono>
#include "utils.h"

using namespace std;

namespace fhe_ops_lib {

void append_u8(std::vector<uint8_t>& data, uint8_t value) {
    data.push_back(value);
}

void append_u64(std::vector<uint8_t>& data, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xff));
    }
}

void append_bytes(std::vector<uint8_t>& data, const std::vector<uint8_t>& bytes) {
    append_u64(data, static_cast<uint64_t>(bytes.size()));
    data.insert(data.end(), bytes.begin(), bytes.end());
}

uint8_t read_u8(gsl::span<const uint8_t> data, size_t& offset, const char* field) {
    if (offset >= data.size()) {
        throw std::runtime_error(std::string("binary data missing ") + field);
    }
    return data[offset++];
}

uint64_t read_u64(gsl::span<const uint8_t> data, size_t& offset, const char* field) {
    if (data.size() - offset < 8) {
        throw std::runtime_error(std::string("binary data missing ") + field);
    }
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(data[offset++]) << (8 * i);
    }
    return value;
}

gsl::span<const uint8_t> read_bytes(gsl::span<const uint8_t> data, size_t& offset, const char* field) {
    uint64_t length = read_u64(data, offset, field);
    if (length > static_cast<uint64_t>(data.size() - offset)) {
        throw std::runtime_error(std::string("binary data has truncated ") + field);
    }
    gsl::span<const uint8_t> result(data.data() + offset, static_cast<size_t>(length));
    offset += static_cast<size_t>(length);
    return result;
}

long long get_current_us() {
    auto now = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch());
    return us.count();
}

void print_message(const uint64_t* msg, const char* name, int count) {
    fprintf(stderr, "%s = [", name);
    for (int i = 0; i < count; i++) {
        fprintf(stderr, "%lu, ", msg[i]);
    }
    fprintf(stderr, "...]\n");
}

void print_double_message(const double* msg, const char* name, int count) {
    fprintf(stderr, "%s = [", name);
    for (int i = 0; i < count; i++) {
        fprintf(stderr, "%f, ", msg[i]);
    }
    fprintf(stderr, "...]\n");
}

void output_message(const uint64_t* msg, const char* name, int count, FILE* fp) {
    for (int i = 0; i < count; i++) {
        fprintf(fp, "%lu\n", msg[i]);
    }
}

bool compare_double_vectors(const vector<double>& a, const vector<double>& b, int length, double tolerance) {
    bool different = false;
    for (int i = 0; i < length; i++) {
        if (fabs(b[i] - a[i]) > tolerance) {
            fprintf(stderr, "Comparison failed: index=%d, left=%.8f, right=%.8f, diff=%.4e\n", i, a[i], b[i],
                    b[i] - a[i]);
            different = true;
        }
    }
    return different;
}

bool compare_double_vectors_w_offset(const vector<double>& a,
                                     const vector<double>& b,
                                     int length,
                                     double tolerance,
                                     int offset,
                                     int n_slot) {
    bool different = false;
    for (int i = 0; i < length; i++) {
        int index = (i + offset + n_slot) % n_slot;
        if (fabs(b[index] - a[index]) > tolerance) {
            fprintf(stderr, "Comparison failed: index=%d, left=%.8f, right=%.8f, diff=%.4e\n", index, a[index],
                    b[index], b[index] - a[index]);
            different = true;
        }
    }
    return different;
}

vector<uint64_t> polynomial_multiplication(int n, int t, const vector<uint64_t>& x, const vector<uint64_t>& y) {
    vector<uint64_t> z(n);
    for (int k = 0; k < n; k++) {
        int64_t s = 0;
        for (int i = 0; i <= k; i++) {
            int j = k - i;
            s += x[i] * y[j];
        }
        for (int i = k + 1; i < n; i++) {
            int j = n + k - i;
            s -= x[i] * y[j];
        }
        z[k] = (uint64_t)((s % (int64_t)t + t) % t);
    }
    return z;
}

static mt19937_64& get_rng() {
    static mt19937_64 rng{random_device{}()};
    return rng;
}

vector<uint64_t> rand_values(int n, uint64_t t) {
    uniform_int_distribution<uint64_t> dist(0, t - 1);
    vector<uint64_t> vals(n);
    for (int i = 0; i < n; i++)
        vals[i] = dist(get_rng());
    return vals;
}

vector<double> rand_double_values(int n, double range) {
    uniform_real_distribution<double> dist(-range, range);
    vector<double> vals(n);
    for (int i = 0; i < n; i++)
        vals[i] = dist(get_rng());
    return vals;
}

vector<double> rand_real_values(int n, double range) {
    return rand_double_values(n, range);
}

vector<complex<double>> rand_complex_values(int n, double range) {
    vector<double> real_values = rand_real_values(n, range);
    vector<double> imag_values = rand_real_values(n, range);
    vector<complex<double>> values(n);
    for (int i = 0; i < n; i++) {
        values[i] = complex<double>(real_values[i], imag_values[i]);
    }
    return values;
}

uint64_t mod_exp(uint64_t x, int power, uint64_t mod) {
    if (power == 0)
        return 1;
    if (power % 2 == 1)
        return x * mod_exp(x * x % mod, power / 2, mod) % mod;
    return mod_exp(x * x % mod, power / 2, mod) % mod;
}

vector<uint64_t> vec_mod_add(const vector<uint64_t>& a, const vector<uint64_t>& b, uint64_t t) {
    assert(a.size() == b.size());
    vector<uint64_t> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = (a[i] + b[i]) % t;
    return r;
}

vector<uint64_t> vec_mod_sub(const vector<uint64_t>& a, const vector<uint64_t>& b, uint64_t t) {
    assert(a.size() == b.size());
    vector<uint64_t> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = (a[i] + t - b[i]) % t;
    return r;
}

vector<uint64_t> vec_mod_mul(const vector<uint64_t>& a, const vector<uint64_t>& b, uint64_t t) {
    assert(a.size() == b.size());
    vector<uint64_t> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = (unsigned __int128)a[i] * b[i] % t;
    return r;
}

vector<uint64_t> vec_mod_neg(const vector<uint64_t>& a, uint64_t t) {
    vector<uint64_t> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] == 0 ? 0 : t - a[i];
    return r;
}

vector<uint64_t> vec_mod_exp(const vector<uint64_t>& a, int power, uint64_t t) {
    vector<uint64_t> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = mod_exp(a[i], power, t);
    return r;
}

vector<uint64_t> vec_rotate_col(const vector<uint64_t>& a, int step) {
    int n = (int)a.size();
    int n_col = n / 2;
    vector<uint64_t> r(n);
    for (int i = 0; i < n; i++) {
        int row = i / n_col;
        int col = i % n_col;
        int src_col = ((col + step) % n_col + n_col) % n_col;
        r[i] = a[row * n_col + src_col];
    }
    return r;
}

vector<uint64_t> vec_rotate_row(const vector<uint64_t>& a) {
    int n = (int)a.size();
    int n_col = n / 2;
    vector<uint64_t> r(n);
    for (int i = 0; i < n; i++)
        r[i] = i < n_col ? a[i + n_col] : a[i - n_col];
    return r;
}

vector<double> vec_add(const vector<double>& a, const vector<double>& b) {
    assert(a.size() == b.size());
    vector<double> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] + b[i];
    return r;
}

vector<double> vec_add(const vector<double>& a, double b) {
    vector<double> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] + b;
    return r;
}

vector<double> vec_sub(const vector<double>& a, const vector<double>& b) {
    assert(a.size() == b.size());
    vector<double> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] - b[i];
    return r;
}

vector<double> vec_sub(const vector<double>& a, double b) {
    vector<double> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] - b;
    return r;
}

vector<double> vec_mul(const vector<double>& a, const vector<double>& b) {
    assert(a.size() == b.size());
    vector<double> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] * b[i];
    return r;
}

vector<double> vec_mul(const vector<double>& a, double b) {
    vector<double> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] * b;
    return r;
}

vector<double> vec_neg(const vector<double>& a) {
    vector<double> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = -a[i];
    return r;
}

vector<double> vec_exp(const vector<double>& a, int power) {
    vector<double> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = std::pow(a[i], power);
    return r;
}

vector<double> vec_rotate(const vector<double>& a, int step) {
    int n = (int)a.size();
    vector<double> r(n);
    for (int i = 0; i < n; i++)
        r[i] = a[((i + step) % n + n) % n];
    return r;
}

vector<complex<double>> vec_add(const vector<complex<double>>& a, const vector<complex<double>>& b) {
    assert(a.size() == b.size());
    vector<complex<double>> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] + b[i];
    return r;
}

vector<complex<double>> vec_add(const vector<complex<double>>& a, complex<double> b) {
    vector<complex<double>> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] + b;
    return r;
}

vector<complex<double>> vec_sub(const vector<complex<double>>& a, const vector<complex<double>>& b) {
    assert(a.size() == b.size());
    vector<complex<double>> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] - b[i];
    return r;
}

vector<complex<double>> vec_sub(const vector<complex<double>>& a, complex<double> b) {
    vector<complex<double>> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] - b;
    return r;
}

vector<complex<double>> vec_mul(const vector<complex<double>>& a, const vector<complex<double>>& b) {
    assert(a.size() == b.size());
    vector<complex<double>> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] * b[i];
    return r;
}

vector<complex<double>> vec_mul(const vector<complex<double>>& a, complex<double> b) {
    vector<complex<double>> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = a[i] * b;
    return r;
}

vector<complex<double>> vec_conj(const vector<complex<double>>& a) {
    vector<complex<double>> r(a.size());
    for (size_t i = 0; i < a.size(); i++)
        r[i] = std::conj(a[i]);
    return r;
}

vector<complex<double>> vec_rotate(const vector<complex<double>>& a, int step) {
    int n = (int)a.size();
    vector<complex<double>> r(n);
    for (int i = 0; i < n; i++)
        r[i] = a[((i + step) % n + n) % n];
    return r;
}

vector<double> polynomial_multiplication(int n, const vector<double>& x, const vector<double>& y) {
    vector<double> r(n, 0.0);
    for (int i = 0; i < (int)x.size(); i++) {
        for (int j = 0; j < (int)y.size(); j++) {
            int k = i + j;
            if (k < n)
                r[k] += x[i] * y[j];
            else
                r[k - n] -= x[i] * y[j];
        }
    }
    return r;
}

}  // namespace fhe_ops_lib

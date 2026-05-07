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

#ifndef CXX_UTILS_H
#define CXX_UTILS_H

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <inttypes.h>
#include <string>
#include <vector>

namespace fhe_ops_lib {

long long get_current_us();

void print_message(const uint64_t* msg, const char* name, int count);

void print_double_message(const double* msg, const char* name, int count);

void output_message(const uint64_t* msg, const char* name, int count, FILE* fp);

bool compare_double_vectors(const std::vector<double>& a, const std::vector<double>& b, int length, double tolerance);

bool compare_double_vectors_w_offset(const std::vector<double>& a,
                                     const std::vector<double>& b,
                                     int length,
                                     double tolerance,
                                     int offset = 0,
                                     int n_slot = 4096);

std::vector<uint64_t>
polynomial_multiplication(int n, int t, const std::vector<uint64_t>& x, const std::vector<uint64_t>& y);

// Generate n random uint64 values in [0, t)
std::vector<uint64_t> rand_values(int n, uint64_t t);

// Generate n random double values in [-range, range)
std::vector<double> rand_double_values(int n, double range = 1.0);

uint64_t mod_exp(uint64_t x, int power, uint64_t mod);

std::vector<uint64_t> vec_mod_add(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b, uint64_t t);
std::vector<uint64_t> vec_mod_sub(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b, uint64_t t);
std::vector<uint64_t> vec_mod_mul(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b, uint64_t t);
std::vector<uint64_t> vec_mod_neg(const std::vector<uint64_t>& a, uint64_t t);
std::vector<uint64_t> vec_mod_exp(const std::vector<uint64_t>& a, int power, uint64_t t);

// Slot rotation helpers (2-row layout, n = 2 * n_col)
// rotate_col: cyclic column shift by step (positive = left, negative = right)
// rotate_row: swap the two rows
std::vector<uint64_t> vec_rotate_col(const std::vector<uint64_t>& a, int step);
std::vector<uint64_t> vec_rotate_row(const std::vector<uint64_t>& a);

std::vector<double> vec_add(const std::vector<double>& a, const std::vector<double>& b);
std::vector<double> vec_sub(const std::vector<double>& a, const std::vector<double>& b);
std::vector<double> vec_mul(const std::vector<double>& a, const std::vector<double>& b);
std::vector<double> vec_neg(const std::vector<double>& a);
std::vector<double> vec_exp(const std::vector<double>& a, int power);
// Left-rotation by step: result[k] = a[(k + step) % n]  (negative step -> right)
std::vector<double> vec_rotate(const std::vector<double>& a, int step);

// Negacyclic polynomial multiplication in R[x]/(x^n + 1)
std::vector<double> polynomial_multiplication(int n, const std::vector<double>& x, const std::vector<double>& y);

}  // namespace fhe_ops_lib
#endif  // CXX_UTILS_H

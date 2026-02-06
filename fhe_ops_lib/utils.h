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

#include <inttypes.h>
#include <cstdio>
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

}  // namespace fhe_ops_lib
#endif  // CXX_UTILS_H

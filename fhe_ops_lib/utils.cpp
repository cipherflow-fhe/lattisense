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

#include <cmath>
#include <sys/time.h>
#include "utils.h"

using namespace std;
using namespace fhe_ops_lib;

long long fhe_ops_lib::get_current_us() {
    struct timeval tm;
    gettimeofday(&tm, 0);
    return tm.tv_sec * 1000000 + tm.tv_usec;
}

void fhe_ops_lib::print_message(const uint64_t* msg, const char* name, int count) {
    fprintf(stderr, "%s = [", name);
    for (int i = 0; i < count; i++) {
        fprintf(stderr, "%lu, ", msg[i]);
    }
    fprintf(stderr, "...]\n");
}

void fhe_ops_lib::print_double_message(const double* msg, const char* name, int count) {
    fprintf(stderr, "%s = [", name);
    for (int i = 0; i < count; i++) {
        fprintf(stderr, "%f, ", msg[i]);
    }
    fprintf(stderr, "...]\n");
}

void fhe_ops_lib::output_message(const uint64_t* msg, const char* name, int count, FILE* fp) {
    for (int i = 0; i < count; i++) {
        fprintf(fp, "%lu\n", msg[i]);
    }
}

bool fhe_ops_lib::compare_double_vectors(const vector<double>& a,
                                         const vector<double>& b,
                                         int length,
                                         double tolerance) {
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

bool fhe_ops_lib::compare_double_vectors_w_offset(const vector<double>& a,
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

vector<uint64_t>
fhe_ops_lib::polynomial_multiplication(int n, int t, const vector<uint64_t>& x, const vector<uint64_t>& y) {
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

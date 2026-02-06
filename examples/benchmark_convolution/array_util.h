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

#include <cmath>
#include <random>
#include <vector>
#include <cstdio>
#include "ndarray.h"

// Generate random array with values in [-scale, scale]
template <int dim> Array<double, dim> gen_random_array(const std::array<uint64_t, dim>& shape, double scale) {
    Array<double, dim> result(shape);
    uint64_t s = result.get_size();
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);

    for (uint64_t i = 0; i < s; i++) {
        result.set(i, scale * dis(gen));
    }
    return result;
}

// Comparison result structure
struct ArrayComparison {
    int dim;
    double max_abs;
    double max_error;
    std::vector<int> max_error_pos;
    double rms;
    double rmse;
};

// Compare two 3D arrays and return comparison statistics
inline ArrayComparison compare(const Array<double, 3>& expected, const Array<double, 3>& output) {
    double max_error = 0.0;
    double max_abs = 0.0;
    int max_error_pos[3] = {0, 0, 0};
    double squared_error = 0.0;
    double squared = 0.0;
    std::array<uint64_t, 3> shape = expected.get_shape();

    for (uint64_t i0 = 0; i0 < shape[0]; i0++) {
        for (uint64_t i1 = 0; i1 < shape[1]; i1++) {
            for (uint64_t i2 = 0; i2 < shape[2]; i2++) {
                double y_pc = expected.get(i0, i1, i2);
                double y = output.get(i0, i1, i2);
                double diff = std::fabs(y_pc - y);
                squared_error += (y_pc - y) * (y_pc - y);
                squared += y_pc * y_pc;
                if (max_error < diff) {
                    max_error = diff;
                    max_error_pos[0] = i0;
                    max_error_pos[1] = i1;
                    max_error_pos[2] = i2;
                }
                if (max_abs < std::fabs(y_pc)) {
                    max_abs = std::fabs(y_pc);
                }
            }
        }
    }

    ArrayComparison result;
    result.dim = 3;
    result.max_abs = max_abs;
    result.max_error = max_error;
    result.max_error_pos = {max_error_pos[0], max_error_pos[1], max_error_pos[2]};
    result.rms = std::sqrt(squared / (shape[0] * shape[1] * shape[2]));
    result.rmse = std::sqrt(squared_error / (shape[0] * shape[1] * shape[2]));

    printf("Max error position: [%d, %d, %d], expected=%.6f, actual=%.6f, error=%.6f\n", max_error_pos[0],
           max_error_pos[1], max_error_pos[2], expected.get(max_error_pos[0], max_error_pos[1], max_error_pos[2]),
           output.get(max_error_pos[0], max_error_pos[1], max_error_pos[2]), max_error);

    return result;
}

// Print first n values of a double array
inline void print_array_values(const double* data, const char* name, int n) {
    printf("%s: ", name);
    for (int i = 0; i < n; i++) {
        printf("%.6f ", data[i]);
    }
    printf("\n");
}

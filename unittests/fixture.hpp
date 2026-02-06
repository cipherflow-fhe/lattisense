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

#include <string>

#include "fhe_lib_v2.h"
#include "cxx_fhe_task.h"
#include "test_config.hpp"

using namespace cxx_sdk_v2;
using namespace std;

// Use paths from CMake-generated configuration
string gpu_base_path = test_config::gpu_base_path;
string cpu_base_path = test_config::cpu_base_path;

class CpuFixture {
public:
    CpuFixture() {}

    ~CpuFixture() {}
};

class BfvCpuFixture : public CpuFixture {
public:
    BfvCpuFixture()
        : n{16384}, t{65537}, param{BfvParameter::create_parameter(n, t)},
          ctx{BfvContext::create_random_context(param)}, n_op{4}, min_level{1}, max_level{param.get_max_level()} {}

protected:
    uint64_t n;
    uint64_t t;
    BfvParameter param;
    BfvContext ctx;
    int n_op;
    int min_level;
    int max_level;
};

class BfvCustomCpuFixture : public CpuFixture {
public:
    BfvCustomCpuFixture() {
        n = 8192;
        t = 65537;
        std::vector<uint64_t> Q = {
            18014398508400641,
            18014398510645249,
            18014398510661633,
        };
        std::vector<uint64_t> P = {
            36028797018652673,
        };

        param = BfvParameter::create_custom_parameter(n, t, Q, P);
        ctx = BfvContext::create_random_context(param);
        n_op = 4;
        min_level = 1;
        max_level = param.get_max_level();
    }

protected:
    uint64_t n;
    uint64_t t;
    BfvParameter param;
    BfvContext ctx;
    int n_op;
    int min_level;
    int max_level;
};

class CkksCpuFixture : public CpuFixture {
public:
    CkksCpuFixture()
        : N{16384}, n_slot{N / 2}, level{5}, param{CkksParameter::create_parameter(N)},
          ctx{CkksContext::create_random_context(param)}, n_op{4}, min_level{1}, max_level{param.get_max_level()},
          default_scale{param.get_default_scale()} {}

protected:
    int N;
    int n_slot;
    int level;
    CkksParameter param;
    CkksContext ctx;
    CkksBtpContext btp_ctx;
    int n_op;
    int min_level;
    int max_level;
    double default_scale;
};

class CkksCustomCpuFixture : public CpuFixture {
public:
    CkksCustomCpuFixture() {
        N = 8192;
        std::vector<uint64_t> Q = {8589852673, 1073692673, 1073643521, 1073872897, 1073971201, 1073479681};
        std::vector<uint64_t> P = {34359754753};

        param = CkksParameter::create_custom_parameter(N, Q, P);
        ctx = CkksContext::create_random_context(param);
        n_slot = N / 2;
        n_op = 4;
        min_level = 0;
        max_level = param.get_max_level();
        default_scale = param.get_default_scale();
    }

protected:
    int N;
    int n_slot;
    CkksParameter param;
    CkksContext ctx;
    int n_op;
    int min_level;
    int max_level;
    double default_scale;
};

class GpuFixture {
public:
    GpuFixture() {}

    ~GpuFixture() {}
};

class BfvGpuFixture : public GpuFixture {
public:
    BfvGpuFixture()
        : n{16384}, t{65537}, param{BfvParameter::create_parameter(n, t)},
          ctx{BfvContext::create_random_context(param)}, n_op{4}, min_level{1}, max_level{param.get_max_level()} {}

protected:
    uint64_t n;
    uint64_t t;
    BfvParameter param;
    BfvContext ctx;
    int n_op;
    int min_level;
    int max_level;
};

class CkksGpuFixture : public GpuFixture {
public:
    CkksGpuFixture()
        : n{16384}, n_slot{n / 2}, param{CkksParameter::create_parameter(n)},
          ctx{CkksContext::create_random_context(param)}, n_op{4}, min_level{0}, max_level{param.get_max_level()},
          default_scale{param.get_default_scale()} {}

protected:
    int n;
    int n_slot;
    CkksParameter param;
    CkksContext ctx;
    int n_op;
    int min_level;
    int max_level;
    double default_scale;
};

vector<vector<int>> all_source_powers = {
    {1, 2},
    {1, 3},
    {1, 3, 4},
    {1, 3},
    {1, 3, 5, 6},
    {1, 4},
    {1, 4, 5},
    {1, 3, 5, 7, 8},
    {1, 4},
    {1, 3, 5, 6, 13, 14},
    {1, 5},
    {1, 4, 7, 8},
    {1, 3, 4, 9, 10, 12, 13},
    {1, 5, 8},
    {1, 5},
    {1, 3, 5, 7, 9, 10, 21, 22},
    {1, 6},
    {1, 6, 7},
    {1, 4, 6, 14, 15},
    {1, 6},
    {1, 3, 4, 9, 11, 16, 17, 19, 20},
    {1, 3, 11, 18},
    {1, 2, 3, 7, 11, 15, 19, 21, 22, 24},
    {1, 7},
    {1, 7, 12},
    {1, 3, 7, 9, 19, 24},
    {1, 7},
    {1, 2, 3, 7, 11, 15, 19, 23, 25, 26, 28},
    {1, 8},
    {1, 3, 4, 9, 11, 16, 21, 23, 28, 29, 31, 32},
    {1, 8, 13},
    {1, 4, 5, 15, 18, 27, 34},
    {1, 8},
    {1, 3, 11, 15, 32},
    {1, 4, 12, 21},
    {1, 3, 4, 9, 11, 16, 20, 25, 27, 32, 33, 35, 36},
    {1, 9},
    {1, 3, 4, 9, 10, 15, 16, 21, 22, 24, 25, 51, 53, 55},
    {1, 9},
    {1, 9, 14},
    {1, 3, 4, 5, 8, 14, 20, 26, 32, 38, 41, 42, 43, 45, 46},
    {1, 3, 6, 10, 24, 26, 39, 41},
    {1, 10},
    {1, 3, 4, 5, 8, 14, 20, 26, 32, 38, 44, 47, 48, 49, 51, 52},
    {1, 10},
    {1, 4, 9, 16, 38, 49},
    {1, 9, 20},
    {1, 4, 19, 33},
    {1, 3, 4, 5, 8, 14, 20, 26, 32, 38, 44, 50, 53, 54, 55, 57, 58},
    {1, 11},
    {1, 3, 8, 9, 14, 32, 36, 51, 53},
    {1, 4, 9, 31, 51},
    {1, 3, 4, 5, 8, 14, 20, 26, 32, 38, 44, 50, 56, 59, 60, 61, 63, 64},
    {1, 11},
    {1, 3, 4, 5, 8, 14, 20, 26, 32, 38, 44, 50, 56, 62, 65, 66, 67, 69, 70},
    {1, 12},
    {1, 10, 26},
    {1, 3, 4, 5, 8, 14, 20, 26, 32, 38, 44, 50, 56, 62, 68, 71, 72, 73, 75, 76},
    {1, 2, 6, 8, 19, 28, 40, 43, 91, 103},
    {1, 12},
    {1, 4, 10, 15, 37, 50, 71},
    {1, 3, 4, 6, 10, 13, 15, 21, 29, 37, 45, 53, 61, 69, 73, 75, 78, 79, 82, 84, 88},
    {1, 5, 24, 37},
    {1, 13},
    {1, 9, 30},
    {1, 13},
    {1, 3, 4, 6, 10, 13, 15, 21, 29, 37, 45, 53, 61, 69, 77, 81, 83, 86, 87, 90, 92, 96},
    {1, 2, 3, 8, 11, 26, 38, 56, 69, 85, 89},
    {1, 14},
    {1, 14},
    {1, 5, 8, 33, 54, 67},
    {1, 11, 37},
    {1, 7, 12, 43, 52},
    {1, 15},
    {1, 3, 8, 13, 15, 16, 49, 53, 84, 88, 108, 114},
    {1, 3, 8, 19, 33, 39, 92, 102},
    {1, 6, 25, 65},
    {1, 15},
    {1, 16},
    {1, 13, 34},
    {1, 16},
    {1, 4, 6, 14, 16, 20, 39, 56, 79, 100, 113, 122, 131},
    {1, 17},
    {1, 12, 52},
    {1, 17},
    {1, 4, 10, 11, 28, 33, 78, 118, 143},
    {1, 2, 4, 9, 15, 27, 38, 43, 46, 97, 107, 127, 147, 157},
    {1, 5, 34, 60},
    {1, 4, 13, 24, 30, 87, 106},
    {1, 8, 11, 64, 102},
    {1, 12, 52},
    {1, 7, 11, 48, 83, 115},
    {1, 15, 54},
    {1, 4, 9, 24, 26, 42, 104, 115, 174, 185},
    {1, 6, 41, 67},
    {1, 14, 61},
    {1, 9, 15, 78, 115},
    {1, 6, 8, 33, 48, 77, 183, 236},
    {1, 7, 48, 85},
    {1, 15, 80},
    {1, 4, 9, 20, 34, 52, 62, 137, 149, 229, 242},
    {1, 18, 65},
    {1, 4, 18, 31, 104, 145, 170},
    {1, 7, 12, 64, 113, 193},
    {1, 7, 48, 126},
    {1, 17, 91},
    {1, 4, 13, 18, 51, 92, 163, 208, 223},
    {1, 9, 23, 108, 181},
    {1, 17, 91},
    {1, 9, 56, 155},
    {1, 19, 102},
    {1, 5, 18, 29, 97, 170, 219, 308},
    {1, 18, 114},
    {1, 6, 8, 21, 60, 93, 104, 154, 378, 414},
    {1, 9, 14, 65, 170, 297},
    {1, 8, 27, 119, 194},
    {1, 8, 61, 164},
    {1, 20, 127},
    {1, 7, 18, 62, 104, 244, 259},
    {1, 20, 127},
    {1, 22, 140},
    {1, 12, 65, 240},
    {1, 10, 34, 165, 270}};
vector<int> all_max_powers = {
    4,   7,   8,   10,  12,  14,  15,   16,   18,   20,   23,   24,   26,   26,   28,   32,   34,   35,  36,  40,  40,
    44,  46,  47,  52,  52,  54,  54,   62,   64,   69,   70,   70,   70,   71,   72,   79,   80,   88,  89,  92,  93,
    98,  104, 108, 108, 112, 114, 116,  119,  121,  126,  128,  130,  140,  142,  146,  152,  154,  154, 162, 164, 165,
    167, 172, 180, 180, 186, 194, 208,  211,  212,  216,  223,  225,  228,  234,  238,  254,  259,  270, 271, 287, 302,
    304, 310, 323, 326, 336, 345, 354,  388,  418,  422,  427,  476,  512,  524,  547,  548,  550,  633, 638, 664, 708,
    714, 726, 797, 805, 873, 902, 1007, 1012, 1016, 1045, 1055, 1094, 1127, 1137, 1254, 1382, 1383, 1475};

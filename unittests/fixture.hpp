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
#include <sstream>
#include <string>
#include <vector>

#include "schemes/bfv/bfv.h"
#include "schemes/ckks/ckks.h"
#include "schemes/ckks/ckks.h"
#include "cxx_fhe_task.h"
#include "test_config.hpp"

using namespace lattisense;
using namespace std;

// ---------------------------------------------------------------------------
// Generic test context structs (used by legacy TEST_CASE style tests)
// ---------------------------------------------------------------------------

struct BfvTestContext {
    string tag;
    BfvParameter param;
    BfvContext ctx;
    int n_op;
    int min_level;
    int max_level;
};

struct CkksTestContext {
    string tag;
    CkksParameter param;
    CkksContext ctx;
    int n_op;
    int min_level;
    int max_level;
    double default_scale;
};

// ===========================================================================
// BFV CPU/GPU+ CKKS CPU/GPU
// ===========================================================================

string cpu_base_path = test_config::cpu_base_path;

struct BfvTestDefaultParams {
    static BfvParameter create() {
        constexpr int logN = 14;
        return BfvParameter::create_parameter(logN, 0x10001);
    }
    static string get_tag() {
        ostringstream ss;
        ss << "bfv_param_default_n" << 16384 << "_t" << hex << (uint64_t)0x10001;
        return ss.str();
    }
};

struct BfvTestCustomParams {
    static BfvParameter create() {
        vector<uint64_t> Q = {0x3FFFFFFFEF8001, 0x4000000011C001, 0x40000000120001};
        vector<uint64_t> P = {0x7FFFFFFFFB4001};
        return BfvParameter::create_custom_parameter(13, 0x10001, Q, P);
    }
    static string get_tag() {
        ostringstream ss;
        ss << "bfv_param_custom_n" << 8192 << "_t" << hex << (uint64_t)0x10001;
        return ss.str();
    }
};

struct CkksTestDefaultParams {
    static constexpr bool has_sparse_slot_cases = true;
    static constexpr bool is_conjugate_invariant = false;
    static CkksParameter create() {
        constexpr int logN = 14;
        return CkksParameter::create_parameter(logN);
    }
    static string get_tag() {
        return "ckks_param_default_n16384";
    }
};

struct CkksTestCustomParams {
    static constexpr bool has_sparse_slot_cases = false;
    static constexpr bool is_conjugate_invariant = false;
    static CkksParameter create() {
        vector<uint64_t> Q = {
            0x1FFFEC001, 0x3FFF4001, 0x3FFE8001, 0x40020001, 0x40038001, 0x3FFC0001,
        };
        vector<uint64_t> P = {0x800004001};
        return CkksParameter::create_custom_parameter(13, 30, Q, P);
    }
    static string get_tag() {
        return "ckks_param_custom_n8192";
    }
};

struct CkksTestCIParams {
    static constexpr bool has_sparse_slot_cases = true;
    static constexpr bool is_conjugate_invariant = true;
    static CkksParameter create() {
        constexpr int logN = 14;
        return CkksParameter::create_parameter(logN, RingType::ConjugateInvariant);
    }
    static string get_tag() {
        return "ckks_param_ci_default_n16384";
    }
};

// Larger residual degrees. The bootstrapping circuit degree is higher than the
// residual's, so these exercise the bootstrapping parameter sets of degree 17.
struct CkksTestDefaultParamsN15 {
    static constexpr bool has_sparse_slot_cases = true;
    static constexpr bool is_conjugate_invariant = false;
    static CkksParameter create() {
        constexpr int logN = 15;
        return CkksParameter::create_parameter(logN);
    }
    static string get_tag() {
        return "ckks_param_default_n32768";
    }
};

struct CkksTestDefaultParamsN16 {
    static constexpr bool has_sparse_slot_cases = true;
    static constexpr bool is_conjugate_invariant = false;
    static CkksParameter create() {
        constexpr int logN = 16;
        return CkksParameter::create_parameter(logN);
    }
    static string get_tag() {
        return "ckks_param_default_n65536";
    }
};

struct CkksTestCIParamsN15 {
    static constexpr bool has_sparse_slot_cases = true;
    static constexpr bool is_conjugate_invariant = true;
    static CkksParameter create() {
        constexpr int logN = 15;
        return CkksParameter::create_parameter(logN, RingType::ConjugateInvariant);
    }
    static string get_tag() {
        return "ckks_param_ci_default_n32768";
    }
};

template <typename P> class BfvFixture {
protected:
    BfvParameter param;
    BfvContext ctx;
    string tag;
    int n_op = 4;
    int min_level = 0;
    int max_level;

public:
    BfvFixture()
        : param(P::create()), ctx(BfvContext::create_random_context(param)), tag(P::get_tag()),
          max_level(param.max_level()) {}
};

template <typename P> class CkksFixture {
protected:
    CkksParameter param;
    CkksContext ctx;
    string tag;
    int n_op = 4;
    int n_slot;
    int min_level = 0;
    int max_level;
    double default_scale;

public:
    CkksFixture()
        : param(P::create()), ctx(CkksContext::create_random_context(param)), tag(P::get_tag()),
          n_slot(param.max_slots()), max_level(param.max_level()), default_scale(param.default_scale()) {}
};

#ifdef LATTISENSE_ENABLE_GPU

string gpu_base_path = test_config::gpu_base_path;

#endif  // LATTISENSE_ENABLE_GPU

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

#include "fhe_lib_v2.h"
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
    int n_slot;
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
        return BfvParameter::create_parameter(16384, 0x10001);
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
        return BfvParameter::create_custom_parameter(8192, 0x10001, Q, P);
    }
    static string get_tag() {
        ostringstream ss;
        ss << "bfv_param_custom_n" << 8192 << "_t" << hex << (uint64_t)0x10001;
        return ss.str();
    }
};

struct CkksTestDefaultParams {
    static CkksParameter create() {
        return CkksParameter::create_parameter(16384);
    }
    static string get_tag() {
        return "ckks_param_default_n16384";
    }
};

struct CkksTestCustomParams {
    static CkksParameter create() {
        vector<uint64_t> Q = {
            0x1FFFEC001, 0x3FFF4001, 0x3FFE8001, 0x40020001, 0x40038001, 0x3FFC0001,
        };
        vector<uint64_t> P = {0x800004001};
        return CkksParameter::create_custom_parameter(8192, Q, P);
    }
    static string get_tag() {
        return "ckks_param_custom_n8192";
    }
};

struct CkksToyBtpParams {
    static CkksBtpParameter create() {
        return CkksBtpParameter::create_toy_parameter();
    }
    static string get_tag() {
        int n = create().get_ckks_parameter().get_n();
        return "ckks_param_btp_n" + to_string(n);
    }
};

struct CkksBtpParams {
    static CkksBtpParameter create() {
        return CkksBtpParameter::create_parameter();
    }
    static string get_tag() {
        int n = create().get_ckks_parameter().get_n();
        return "ckks_param_btp_n" + to_string(n);
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
          max_level(param.get_max_level()) {}
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
          n_slot(param.get_n() / 2), max_level(param.get_max_level()), default_scale(param.get_default_scale()) {}
};

template <typename P> class CkksBtpFixture {
protected:
    CkksBtpParameter btp_param;
    CkksBtpContext btp_ctx;
    string tag;
    int n_op = 4;
    int n_slot;
    double btp_scale;

public:
    CkksBtpFixture()
        : btp_param(P::create()), btp_ctx(CkksBtpContext::create_random_context(btp_param)), tag(P::get_tag()),
          n_slot(btp_param.get_ckks_parameter().get_n() / 2), btp_scale(pow(2.0, 40)) {}
};

#ifdef LATTISENSE_ENABLE_GPU

string gpu_base_path = test_config::gpu_base_path;

#endif  // LATTISENSE_ENABLE_GPU

// ===========================================================================
// BFV FPGA + CKKS FPGA
// ===========================================================================

#ifdef LATTISENSE_ENABLE_FPGA
#    include "cxx_fpga_ops.h"

string fpga_base_path = test_config::fpga_base_path;

class FpgaFixture {
public:
    FpgaFixture() {
        FpgaDevice::init();
    }
    ~FpgaFixture() {
        FpgaDevice::free();
    }
};

struct BfvFpgaTestParams {
    static BfvParameter create() {
        return BfvParameter::create_fpga_parameter(0x1b4001);
    }
    static string get_tag() {
        ostringstream ss;
        int n = create().get_n();
        ss << "bfv_param_fpga_n" << n << "_t" << hex << (uint64_t)0x1b4001;
        return ss.str();
    }
};

struct BfvFpgaPow2TTestParams {
    static BfvParameter create() {
        return BfvParameter::create_fpga_parameter(1 << 10);
    }
    static string get_tag() {
        ostringstream ss;
        int n = create().get_n();
        ss << "bfv_param_fpga_n" << n << "_t" << hex << (uint64_t)(1 << 10);
        return ss.str();
    }
};

struct CkksFpgaTestParams {
    static CkksParameter create() {
        return CkksParameter::create_fpga_parameter();
    }
    static string get_tag() {
        int n = create().get_n();
        return "ckks_param_fpga_n" + to_string(n);
    }
};

template <typename P> class BfvFpgaFixture : public FpgaFixture {
protected:
    BfvParameter param;
    BfvContext ctx;
    string tag;
    int n_op = 4;
    int min_level = 0;
    int max_level;

public:
    BfvFpgaFixture()
        : param(P::create()), ctx(BfvContext::create_random_context(param)), tag(P::get_tag()),
          max_level(param.get_max_level()) {}
};

template <typename P> class CkksFpgaFixture : public FpgaFixture {
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
    CkksFpgaFixture()
        : param(P::create()), ctx(CkksContext::create_random_context(param)), tag(P::get_tag()),
          n_slot(param.get_n() / 2), max_level(param.get_max_level()), default_scale(param.get_default_scale()) {}
};

#endif  // LATTISENSE_ENABLE_FPGA

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

#include <cstdint>

#include "schemes/bfv/bfv.h"
#include "schemes/ckks/ckks.h"

using namespace fhe_ops_lib;
using namespace std;

struct BfvTestParams {
    static BfvParameter create() {
        constexpr int logN = 13;
        constexpr uint64_t t = 65537;
        return BfvParameter::create_parameter(logN, t);
    }
};

struct CkksTestParams {
    static CkksParameter create() {
        constexpr int logN = 14;
        return CkksParameter::create_parameter(logN);
    }
};

template <typename P> class BfvFixture {
protected:
    BfvParameter param;
    BfvContext ctx;
    int level;

public:
    BfvFixture() : param(P::create()), ctx(BfvContext::create_random_context(param)), level(param.max_level()) {}
};

template <typename P> class CkksFixture {
protected:
    CkksParameter param;
    CkksContext ctx;
    int level;
    double scale;

public:
    CkksFixture()
        : param(P::create()), ctx(CkksContext::create_random_context(param)), level(param.max_level()),
          scale(param.default_scale()) {}
};
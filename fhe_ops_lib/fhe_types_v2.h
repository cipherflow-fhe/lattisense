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
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int n;
    uint64_t* data;
} CComponent;

typedef struct {
    int n_component;
    CComponent* components;
} CPolynomial;

typedef struct {
    int level;  // Todo: 添加支持
    CPolynomial poly;
} CPlaintext;

typedef struct {
    int level;
    int degree;
    CPolynomial* polys;
} CCiphertext;

typedef CCiphertext CPublicKey;

typedef struct {
    int n_public_key;
    CPublicKey* public_keys;
} CKeySwitchKey;

typedef CKeySwitchKey CRelinKey;

typedef struct {
    int n_key_switch_key;
    uint64_t* galois_elements;
    CKeySwitchKey* key_switch_keys;
} CGaloisKey;

typedef double (*Operation)(double);
double bridge_func(Operation f, double x);

#ifdef __cplusplus
} /* extern "C" */
#endif

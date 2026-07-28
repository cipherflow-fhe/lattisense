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

typedef enum {
    TYPE_PLAINTEXT,
    TYPE_CIPHERTEXT,
    TYPE_RELIN_KEY,
    TYPE_GALOIS_KEY,
    TYPE_SWITCH_KEY,
    TYPE_CUSTOM,
} DataType;

typedef enum {
    ALGO_BFV,
    ALGO_CKKS,
} Algo;

typedef struct {
    const char* id;
    DataType type;
    void* data;
    int level;
    int size;
} CArgument;

#ifdef __cplusplus
} /* extern "C" */
#endif

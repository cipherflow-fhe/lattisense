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

/** @file */

#pragma once
#include <inttypes.h>
#include <stdbool.h>

#include "c_argument.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fhe_task_handle_st* fhe_task_handle;

fhe_task_handle create_fhe_cpu_task(const char* project_path);

void release_fhe_cpu_task(fhe_task_handle handle);

fhe_task_handle create_fhe_gpu_task(const char* project_path);

void release_fhe_gpu_task(fhe_task_handle handle);

// run func is a C interface for calculating an FHE task. Its users can be SDK in different languages (C++/C/Go, etc.).
// Different homomorphic encryption underlying algorithm libraries (such as CPU/GPU/FPGA implementation libraries of
// homomorphic encryption need to implement this interface. The input of the interface is the arguments of c_sdk,
// including the input and output of the computing task. Specifically, it needs to be implemented in three steps:
//
// 1. Convert the c_sdk data format to the library data format
// 2. Call the library calculation function for calculation
// 3. Convert the library data format back to the c_sdk data format

int run_fhe_cpu_task(fhe_task_handle handle,
                     CArgument* input_args,
                     uint64_t n_in_args,
                     CArgument* output_args,
                     uint64_t n_out_args,
                     Algo algo);

int run_fhe_gpu_task(fhe_task_handle handle,
                     CArgument* input_args,
                     uint64_t n_in_args,
                     CArgument* output_args,
                     uint64_t n_out_args,
                     Algo algo);

#ifdef __cplusplus
}
#endif

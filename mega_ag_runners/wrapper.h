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

/**
 * @brief Progress callback function type for tracking mega_ag execution progress.
 * @param completed Number of compute nodes completed so far.
 * @param total Total number of compute nodes in the mega_ag graph.
 * @param user_data Opaque pointer passed through from the caller.
 *
 * @note Called from worker threads. The caller is responsible for thread-safe handling.
 * @note Throttled internally to at most once per 100ms. The final task always triggers a callback.
 */
typedef void (*progress_callback_t)(int completed, int total, void* user_data);

// ========== CPU Task Functions ==========

fhe_task_handle create_fhe_cpu_task(const char* project_path);

void release_fhe_cpu_task(fhe_task_handle handle);

void bind_cpu_task_custom_executors(fhe_task_handle handle,
                                    const char** custom_types,
                                    void** executors,
                                    uint64_t n_executors);

void bind_cpu_task_abi_bridge_executors(fhe_task_handle handle, void* abi_export_executor, void* abi_import_executor);

int run_fhe_cpu_task(fhe_task_handle handle,
                     CArgument* input_args,
                     uint64_t n_in_args,
                     CArgument* output_args,
                     uint64_t n_out_args,
                     progress_callback_t progress_cb,
                     void* user_data);

// ========== GPU Task Functions ==========

fhe_task_handle create_fhe_gpu_task(const char* project_path);

void release_fhe_gpu_task(fhe_task_handle handle);

void bind_gpu_task_abi_bridge_executors(fhe_task_handle handle, void* abi_export_executor, void* abi_import_executor);

void bind_gpu_task_custom_executors(fhe_task_handle handle,
                                    const char** custom_types,
                                    void** executors,
                                    uint64_t n_executors);

int run_fhe_gpu_task(fhe_task_handle handle,
                     CArgument* input_args,
                     uint64_t n_in_args,
                     CArgument* output_args,
                     uint64_t n_out_args,
                     progress_callback_t progress_cb,
                     void* user_data,
                     int gpu_device);

// ========== FPGA Task Functions ==========

fhe_task_handle create_fhe_fpga_task(const char* project_path);

void release_fhe_fpga_task(fhe_task_handle handle);

void bind_fpga_task_abi_bridge_executors(fhe_task_handle handle, void* abi_export_executor, void* abi_import_executor);

void bind_fpga_task_custom_executors(fhe_task_handle handle,
                                     const char** custom_types,
                                     void** executors,
                                     uint64_t n_executors);

int run_fhe_fpga_task(fhe_task_handle handle,
                      CArgument* input_args,
                      uint64_t n_in_args,
                      CArgument* output_args,
                      uint64_t n_out_args);

#ifdef __cplusplus
}
#endif

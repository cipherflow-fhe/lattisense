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

/** @file mega_ag_executors.h
 * @brief Executor binding for MegaAG compute nodes
 *
 * This module provides a unified interface for binding execution functions
 * to compute nodes for different backends (CPU/GPU/FPGA).
 */

#pragma once

#include "mega_ag.h"
#include <stdexcept>

// ============================================================================
// Backend Executor Function Declarations
// ============================================================================

/**
 * @brief CPU executor binding function
 *
 * In GPU-enabled builds: declared as weak symbol (optional, may be NULL)
 * In CPU-only builds: must be provided by linking cpu_mega_ag_runner
 */
#ifdef LATTISENSE_ENABLE_GPU
extern void bind_cpu_executor(ComputeNode& node, Algo algorithm) __attribute__((weak));
#else
void bind_cpu_executor(ComputeNode& node, Algo algorithm);
#endif

/**
 * @brief GPU executor binding function
 *
 * In GPU-enabled builds: must be provided by linking gpu_mega_ag_runner
 * In CPU-only builds: throws runtime error (stub implementation)
 */
#ifdef LATTISENSE_ENABLE_GPU
void bind_gpu_executor(ComputeNode& node, Algo algorithm);
#else
inline void bind_gpu_executor(ComputeNode& /*node*/, Algo /*algorithm*/) {
    throw std::runtime_error("GPU backend is disabled. Reconfigure with -DLATTISENSE_ENABLE_GPU=ON to enable it.");
}
#endif

// ============================================================================
// ExecutorBinder Class
// ============================================================================

/**
 * @brief ExecutorBinder - Binds execution functions to ComputeNode based on processor type
 *
 * This class separates the executor binding logic from the MegaAG construction,
 * making it easier to maintain and extend for different backends.
 *
 * Supported backends:
 * - CPU: Uses Lattigo-based operations (always available in standard builds)
 * - GPU: Uses HEonGPU library (requires LATTISENSE_ENABLE_GPU=ON)
 * - FPGA: Not yet implemented
 */
class ExecutorBinder {
public:
    /**
     * @brief Bind executor function to a compute node
     *
     * @param node The ComputeNode to bind executor to
     * @param processor The target processor (CPU/GPU/FPGA)
     * @param algorithm The algorithm type (BFV/CKKS)
     *
     * @throws std::runtime_error if:
     *   - Processor type is unsupported
     *   - Backend is not available in current build configuration
     *   - CPU executor is called in GPU-only build without CPU library
     */
    static void bind_executor(ComputeNode& node, Processor processor, Algo algorithm) {
        switch (processor) {
            case Processor::CPU:
#ifdef LATTISENSE_ENABLE_GPU
                // In GPU builds, CPU executor is optional (weak symbol)
                if (bind_cpu_executor) {
                    bind_cpu_executor(node, algorithm);
                } else {
                    throw std::runtime_error("CPU executor is not available in this GPU-only build. "
                                             "Link with cpu_mega_ag_runner library to enable CPU support.");
                }
#else
                // In CPU-only builds, CPU executor must be available
                bind_cpu_executor(node, algorithm);
#endif
                break;

            case Processor::GPU: bind_gpu_executor(node, algorithm); break;

            default: throw std::runtime_error("Unsupported processor type");
        }
    }
};

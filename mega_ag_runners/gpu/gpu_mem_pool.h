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

#ifndef LATTISENSE_DEVICE_MEMORY_H
#define LATTISENSE_DEVICE_MEMORY_H

namespace lattisense {

/// Return the HEonGPU device (and host) memory pools to the CUDA driver.
///
/// The GPU backend pools device memory through a process-wide singleton
/// (heongpu::MemoryPool) which by default reserves 90% of the free device
/// memory for the lifetime of the process. Call this once every object that
/// allocated from the pool has been destroyed, to hand the memory back to the
/// driver so that other processes sharing the GPU can use it. The pool is
/// re-created lazily by the next HEonGPU context generation.
///
/// On a CPU-only build this is a no-op.
void release_device_memory_pool();

} // namespace lattisense

#endif // LATTISENSE_DEVICE_MEMORY_H

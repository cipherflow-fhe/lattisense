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

#ifndef CXX_FPGA_OPS_H
#define CXX_FPGA_OPS_H

extern "C" {
#include "../mega_ag_runners/fpga/fpga_ops_wrapper.h"
}

namespace lattisense {

/**
 * @brief FPGA accelerator device class.
 */
class FpgaDevice {
public:
    FpgaDevice(const FpgaDevice& other) = delete;

    void operator=(const FpgaDevice& other) = delete;

    /**
     * Initializes the FPGA accelerator device.
     * @return None.
     */
    static int init();

    /**
     * Releases the FPGA accelerator device resources.
     * @return None.
     */
    static int free();

private:
    FpgaDevice() {}

    ~FpgaDevice() {
        free();
    }

    static FpgaDevice _instance;  ///< Device singleton object
    static bool _in_use;          ///< Device in-use flag
};

}  // namespace lattisense
#endif  // CXX_FPGA_OPS_H

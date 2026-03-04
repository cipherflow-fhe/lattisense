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

namespace cxx_sdk_v2 {

/**
 * @brief FPGA加速卡设备类。
 */
class FpgaDevice {
public:
    FpgaDevice(const FpgaDevice& other) = delete;

    void operator=(const FpgaDevice& other) = delete;

    /**
     * 初始化FPGA加速卡设备。
     * @return 无。
     */
    static int init();

    /**
     * 释放FPGA加速卡设备资源。
     * @return 无。
     */
    static int free();

private:
    FpgaDevice() {}

    ~FpgaDevice() {
        free();
    }

    static FpgaDevice _instance;  ///< 设备单例对象
    static bool _in_use;          ///< 设备占用符
};

}  // namespace cxx_sdk_v2
#endif  // CXX_FPGA_OPS_H

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

extern "C" {
#include "log/log.h"
}
#include "cxx_fpga_ops.h"
#include "nlohmann/json.hpp"

using namespace std;

namespace lattisense {

FpgaDevice FpgaDevice::_instance;
bool FpgaDevice::_in_use = false;

int FpgaDevice::init() {
    if (_in_use == false) {
        if (c_init_fpga_device_v2() != 0) {
            log_error("FpgaDevice init failed.");
            return 1;
        }
        if (c_preload_projects() != 0) {
            log_error("FpgaDevice preload failed.");
            return 1;
        }
        _in_use = true;
    } else {
        log_trace("FpgaDevice already initialized.");
    }

    return 0;
};

int FpgaDevice::free() {
    if (_in_use == true) {
        if (c_free_fpga_device() != 0) {
            log_error("FpgaDevice free failed.");
            return 1;
        }
        _in_use = false;
    } else {
        log_trace("FpgaDevice is already free.");
    }

    return 0;
}

}  // namespace lattisense

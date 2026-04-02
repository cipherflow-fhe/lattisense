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

#include "runner.h"
#include "check_sig.h"
#include "abi_bridge_executors.h"
#include "nlohmann/json.hpp"
#include <cmath>

using namespace std;

const int FpgaN = 8192;
const vector<seal::Modulus> FpgaQP = {0x7f4e0001, 0x7fb40001, 0x7fd20001, 0x7fea0001,
                                      0x7ff80001, 0x7ffe0001, 0xff5a0001};
const int V2_FPGA_MFORM_BITS = 34;

seal::EncryptionParameters GenBfvFpgaParam(uint64_t plain_modulus) {
    seal::EncryptionParameters param(seal::scheme_type::bfv);
    param.set_poly_modulus_degree(FpgaN);
    param.set_plain_modulus(plain_modulus);
    param.set_coeff_modulus(FpgaQP);

    return param;
}

seal::EncryptionParameters GenCkksFpgaParam() {
    seal::EncryptionParameters param(seal::scheme_type::ckks);
    param.set_poly_modulus_degree(FpgaN);
    param.set_coeff_modulus(FpgaQP);

    return param;
}

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

FheTaskFpga::~FheTaskFpga() {
    if (task_handle != nullptr) {
        release_fhe_fpga_task(task_handle);
    }
}

FheTaskFpga::FheTaskFpga(const std::string& project_path) : FheTask{project_path} {
    task_handle = create_fhe_fpga_task(_project_path.c_str());
    if (task_handle == nullptr) {
        throw std::runtime_error("load fpga project failed.");
    }
    int N = FpgaN;
    int key_mf_nbits = V2_FPGA_MFORM_BITS - int(std::log2(N));
    bind_abi_executors(key_mf_nbits);
}

FheTaskFpga::FheTaskFpga(FheTaskFpga&& other) : FheTask{std::move(other)} {}

void FheTaskFpga::operator=(FheTaskFpga&& other) {
    std::swap(_project_path, other._project_path);
}

void FheTaskFpga::bind_abi_executors(int mf_nbits) {
    ExecutorFunc abi_export = create_seal_abi_export_executor(mf_nbits);
    ExecutorFunc abi_import = create_seal_abi_import_executor();

    bind_fpga_task_abi_bridge_executors(task_handle, reinterpret_cast<void*>(&abi_export),
                                        reinterpret_cast<void*>(&abi_import));
}

uint64_t FheTaskFpga::run(seal::SEALContext* context,
                          const seal::RelinKeys* rlk,
                          const seal::GaloisKeys* glk,
                          const std::vector<SealVectorArgument>& args) {
    int n_in_args = 0, n_out_args = 0;
    n_in_args = ::check_signatures(context, *rlk, *glk, args, _task_signature);
    n_out_args = args.size() - n_in_args;

    nlohmann::json key_signature = _task_signature["key"];

    auto& params = context->key_context_data()->parms();
    auto scheme = params.scheme();
    uint64_t param_id = set_parameter(params);
    set_seal_context(context, param_id);

    if (scheme == seal::scheme_type::bfv) {
        uint64_t t = params.plain_modulus().value();
        if (c_set_t_fpga(t) != 0) {
            throw std::runtime_error("fpga set t falied");
        }
    }

    new_args(n_in_args, n_out_args);

    export_arguments(args, input_args, output_args);

    export_public_keys(rlk, glk, key_signature, input_args);

    int ret =
        run_fhe_fpga_task(task_handle, input_args.data(), input_args.size(), output_args.data(), output_args.size());

    clear_seal_context();

    if (ret != 0) {
        throw std::runtime_error("Failed to run FPGA project");
    }

    return 0;
}

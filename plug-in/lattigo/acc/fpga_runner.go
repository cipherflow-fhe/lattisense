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

package acc

/*
#cgo CFLAGS: -I ${SRCDIR}/../../../fhe_ops_lib -I ${SRCDIR}/../../../mega_ag_runners -I ${SRCDIR}/../../../mega_ag_runners/fpga
#cgo CXXFLAGS: -I ${SRCDIR}/../../../fhe_ops_lib -I ${SRCDIR}/../../../mega_ag_runners -I ${SRCDIR}/../../../mega_ag_runners/fpga -I ${SRCDIR}/../../../lib
#cgo LDFLAGS: -L${SRCDIR}/../../../build/mega_ag_runners/fpga -L${SRCDIR}/../../../build/fhe_ops_lib -lfpga_mega_ag_runner -lfhe_ops_lib -Wl,-rpath,../../../build/mega_ag_runners/fpga -Wl,-rpath,../../../build/fhe_ops_lib

#include "structs_v2.h"
#include "stdlib.h"
#include "fpga_ops_wrapper.h"
#include "wrapper.h"
#include "../../sigsetup.h"

extern void* create_lattigo_abi_export_executor(int algo, int mf_nbits, int key_mf_nbits);
extern void* create_lattigo_abi_import_executor(int algo);
extern void  release_lattigo_executor(void* executor);
extern void  set_lattigo_params_handle(uintptr_t h);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

var (
	FpgaQ    = []uint64{0x7f4e0001, 0x7fb40001, 0x7fd20001, 0x7fea0001, 0x7ff80001, 0x7ffe0001}
	FpgaLogN = 13

	BfvFpgaParametersLiteral = bfv.ParametersLiteral{
		LogN:  FpgaLogN,
		T:     0x1b4001,
		Q:     FpgaQ,
		P:     []uint64{0xff5a0001},
		Sigma: rlwe.DefaultSigma,
	}

	CkksFpgaParametersLiteral = ckks.ParametersLiteral{
		LogN:         FpgaLogN,
		Q:            FpgaQ,
		P:            []uint64{0xff5a0001},
		Sigma:        rlwe.DefaultSigma,
		DefaultScale: float64(1 << 31),
	}

	FpgaMFormNBits = 34
)

// FpgaDevice FPGA accelerator device class (singleton pattern)
type FpgaDevice struct {
	inUse bool
}

var (
	fpgaDeviceInstance *FpgaDevice
	fpgaDeviceOnce     sync.Once
)

func Sigsetup() {
	C.sigsetup()
}

// GetFpgaDevice returns the FPGA device singleton
func GetFpgaDevice() *FpgaDevice {
	fpgaDeviceOnce.Do(func() {
		fpgaDeviceInstance = &FpgaDevice{
			inUse: false,
		}
	})
	return fpgaDeviceInstance
}

// Init initializes the FPGA accelerator device
func (d *FpgaDevice) Init() error {
	if !d.inUse {
		r0 := C.c_init_fpga_device_v2()
		if r0 != 0 {
			return fmt.Errorf("FPGA Init fail - c_init_fpga_device_v2 ret %d", r0)
		}

		r1 := C.c_preload_projects()
		if r1 != 0 {
			return fmt.Errorf("FPGA Preload fail - c_preload_projects ret %d", r1)
		}
		d.inUse = true
	}
	return nil
}

// Free releases the FPGA accelerator device resources
func (d *FpgaDevice) Free() error {
	if d.inUse {
		r := C.c_free_fpga_device()
		if r != 0 {
			return fmt.Errorf("FPGA Free failed -- %d", r)
		}
		d.inUse = false
	}
	return nil
}

type FheTaskFpga struct {
	task_handle    C.fhe_task_handle
	task_signature map[string]interface{}
	algo           C.Algo
}

func NewFheTaskFpga(project_path string) (*FheTaskFpga, error) {
	task := new(FheTaskFpga)
	_, err := os.Stat(project_path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%s not exists", project_path)
	}

	task_signature_path := fmt.Sprintf("%s/task_signature.json", project_path)
	task_signature_file, err := os.OpenFile(task_signature_path, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	defer task_signature_file.Close()

	err = json.NewDecoder(task_signature_file).Decode(&task.task_signature)
	if err != nil {
		return nil, err
	}

	// Load mega_ag.json for algorithm
	mega_ag_path := fmt.Sprintf("%s/mega_ag.json", project_path)
	mega_ag_file, err := os.Open(mega_ag_path)
	if err != nil {
		return nil, err
	}
	defer mega_ag_file.Close()

	var mega_ag_json map[string]interface{}
	if err = json.NewDecoder(mega_ag_file).Decode(&mega_ag_json); err != nil {
		return nil, err
	}
	algo_str := mega_ag_json["algorithm"].(string)
	switch algo_str {
	case "BFV":
		task.algo = C.ALGO_BFV
	case "CKKS":
		task.algo = C.ALGO_CKKS
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algo_str)
	}

	task.task_handle = C.create_fhe_fpga_task(C.CString(project_path))
	if task.task_handle == nil {
		return nil, fmt.Errorf("load fpga project failed")
	}

	exportExecutor := C.create_lattigo_abi_export_executor(C.int(task.algo), C.int(FpgaMFormNBits), C.int(FpgaMFormNBits-FpgaLogN))
	importExecutor := C.create_lattigo_abi_import_executor(C.int(task.algo))
	C.bind_fpga_task_abi_bridge_executors(task.task_handle, exportExecutor, importExecutor)
	C.release_lattigo_executor(exportExecutor)
	C.release_lattigo_executor(importExecutor)

	runtime.KeepAlive(task)

	return task, nil
}

func (task FheTaskFpga) Run(param interface{}, rlk *rlwe.RelinearizationKey, glk *rlwe.RotationKeySet, args []GoVectorArgument) error {

	n_int_args := check_signatures(param, rlk, glk, args, task.task_signature)
	n_out_args := len(args) - n_int_args

	key_signature := task.task_signature["key"].(map[string]interface{})

	switch param := param.(type) {
	case bfv.Parameters:
		r := C.c_set_t_fpga(C.uint64_t(param.T()))
		if r != 0 {
			panic(fmt.Sprintf("set t fail - c_set_t_fpga ret %d", r))
		}
	}

	c_input_args := make([]C.CArgument, n_int_args)
	c_output_args := make([]C.CArgument, n_out_args)

	export_arguments(args, c_input_args, c_output_args)

	export_public_key_arguments(rlk, glk, key_signature, &c_input_args)

	// Set params_handle so the EXPORT_TO_ABI executor can use it.
	var paramsHandle uintptr
	switch p := param.(type) {
	case bfv.Parameters:
		paramsHandle = pin_bfv_params(p)
	case ckks.Parameters:
		paramsHandle = pin_ckks_params(p)
	}
	C.set_lattigo_params_handle(C.uintptr_t(paramsHandle))

	ret := C.run_fhe_fpga_task(task.task_handle, &c_input_args[0], C.uint64_t(len(c_input_args)), &c_output_args[0], C.uint64_t(len(c_output_args)))

	C.set_lattigo_params_handle(0)

	if int(ret) != 0 {
		return fmt.Errorf("func fpga run fail - func_fpga ret %d", int(ret))
	}

	runtime.KeepAlive(&rlk)
	runtime.KeepAlive(&glk)
	runtime.KeepAlive(&args)

	return nil

}

func (task FheTaskFpga) Free() error {
	clearPinnedHandles()

	if task.task_handle != nil {
		C.release_fhe_fpga_task(task.task_handle)
	}
	return nil
}

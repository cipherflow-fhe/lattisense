package acc

/*
#cgo CFLAGS: -I ${SRCDIR}/../../../abi -I ${SRCDIR}/../../../mega_ag_runners -I ${SRCDIR}/../../../lib
#cgo CXXFLAGS: -I ${SRCDIR}/../../../abi -I ${SRCDIR}/../../../mega_ag_runners -I ${SRCDIR}/../../../lib
#cgo LDFLAGS: -L${SRCDIR}/../../../build/mega_ag_runners/gpu -L${SRCDIR}/../../../build/abi -lgpu_mega_ag_runner -labi -Wl,-rpath,../../../build/mega_ag_runners/gpu -Wl,-rpath,../../../build/abi

#include "c_structs.h"
#include "stdlib.h"
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

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

const (
	DefaultGpuDevice = 0
	GpuMFormNBits    = 0
)

type FheTaskGpu struct {
	task_handle    C.fhe_task_handle
	task_signature map[string]interface{}
	param_json     map[string]interface{}
	algo           C.Algo
}

func NewFheTaskGpu(project_path string) (*FheTaskGpu, error) {
	task := new(FheTaskGpu)
	_, err := os.Stat(project_path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%s not exists", project_path)
	}

	task_signature_path := fmt.Sprintf("%s/task_signature.json", project_path)
	task_signature_file, err := os.Open(task_signature_path)
	if err != nil {
		return nil, err
	}
	defer task_signature_file.Close()

	err = json.NewDecoder(task_signature_file).Decode(&task.task_signature)
	if err != nil {
		return nil, err
	}

	algo_str := task.task_signature["algorithm"].(string)
	switch algo_str {
	case "BFV":
		task.algo = C.ALGO_BFV
	case "CKKS":
		task.algo = C.ALGO_CKKS
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algo_str)
	}

	param_path := fmt.Sprintf("%s/fhe_parameter.json", project_path)
	param_file, err := os.Open(param_path)
	if err != nil {
		return nil, err
	}
	defer param_file.Close()

	decoder := json.NewDecoder(param_file)
	decoder.UseNumber()
	err = decoder.Decode(&task.param_json)
	if err != nil {
		return nil, err
	}

	task.task_handle = C.create_fhe_gpu_task(C.CString(project_path))

	exportExecutor := C.create_lattigo_abi_export_executor(C.int(task.algo), C.int(GpuMFormNBits), C.int(GpuMFormNBits))
	importExecutor := C.create_lattigo_abi_import_executor(C.int(task.algo))
	C.bind_gpu_task_abi_bridge_executors(task.task_handle, exportExecutor, importExecutor)
	C.release_lattigo_executor(exportExecutor)
	C.release_lattigo_executor(importExecutor)

	runtime.KeepAlive(task)

	return task, nil
}

func (task FheTaskGpu) Run(param interface{}, rlk *rlwe.RelinearizationKey, glk *rlwe.RotationKeySet, args []GoVectorArgument) error {

	n_in_args := check_signatures(param, rlk, glk, args, task.task_signature)
	n_out_args := len(args) - n_in_args

	check_parameter(param, task.param_json)

	key_signature := task.task_signature["key"].(map[string]interface{})

	c_input_args := make([]C.CArgument, n_in_args)
	c_output_args := make([]C.CArgument, n_out_args)

	export_arguments(args, c_input_args, c_output_args)
	export_public_key_arguments(rlk, glk, key_signature, &c_input_args)

	// Build and set params_handle so the EXPORT_TO_ABI executor can use it.
	var paramsHandle uintptr
	switch p := param.(type) {
	case bfv.Parameters:
		paramsHandle = pin_bfv_params(p)
	case ckks.Parameters:
		paramsHandle = pin_ckks_params(p)
	default:
		return fmt.Errorf("unsupported param type for GPU run")
	}
	C.set_lattigo_params_handle(C.uintptr_t(paramsHandle))

	ret := C.run_fhe_gpu_task(task.task_handle, &c_input_args[0], C.uint64_t(len(c_input_args)), &c_output_args[0], C.uint64_t(len(c_output_args)), nil, nil, C.int(DefaultGpuDevice))

	C.set_lattigo_params_handle(0)

	if int(ret) != 0 {
		return fmt.Errorf("Failed to run GPU project\n")
	}

	runtime.KeepAlive(&rlk)
	runtime.KeepAlive(&glk)
	runtime.KeepAlive(&args)

	return nil
}

func (task FheTaskGpu) Free() error {
	clearPinnedHandles()

	if task.task_handle != nil {
		C.release_fhe_gpu_task(task.task_handle)
	}
	return nil
}

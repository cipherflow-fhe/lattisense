package acc

/*
#cgo CFLAGS: -I ../../../fhe_ops_lib -I ../../../mega_ag_runners
#cgo LDFLAGS: -L${SRCDIR}/../../../build/mega_ag_runners/gpu -L${SRCDIR}/../../../build/fhe_ops_lib -lgpu_mega_ag_runner -lfhe_ops_lib -Wl,-rpath,../../../build/mega_ag_runners/gpu -Wl,-rpath,../../../build/fhe_ops_lib

#include "structs_v2.h"
#include "stdlib.h"
#include "wrapper.h"
#include "../../sigsetup.h"
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

var (
	GpuMFormNBits = 0
)

type FheTaskGpu struct {
	task_handle    C.fhe_task_handle
	task_signature map[string]interface{}
	param_json     map[string]interface{}
}

func NewFheTaskGpu(project_path string) (*FheTaskGpu, error) {
	task := new(FheTaskGpu)
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

	// Load mega_ag.json for parameter checking
	mega_ag_path := fmt.Sprintf("%s/mega_ag.json", project_path)
	mega_ag_file, err := os.Open(mega_ag_path)
	if err != nil {
		return nil, err
	}
	defer mega_ag_file.Close()

	var mega_ag_json map[string]interface{}
	decoder := json.NewDecoder(mega_ag_file)
	decoder.UseNumber() // Use json.Number to preserve precision
	err = decoder.Decode(&mega_ag_json)
	if err != nil {
		return nil, err
	}
	task.param_json = mega_ag_json["parameter"].(map[string]interface{})

	task.task_handle = C.create_fhe_gpu_task(C.CString(project_path))

	runtime.KeepAlive(task)

	return task, nil
}

func (task FheTaskGpu) Run(param interface{}, rlk *rlwe.RelinearizationKey, glk *rlwe.RotationKeySet, args []GoVectorArgument) error {

	n_in_args := check_signatures(param, rlk, glk, args, task.task_signature, true)
	n_out_args := len(args) - n_in_args

	// Check parameter
	check_parameter(param, task.param_json)

	key_signature := task.task_signature["key"].(map[string]interface{})

	var algo C.Algo
	var rlwe_param rlwe.Parameters
	switch param := param.(type) {
	case bfv.Parameters:
		algo = C.ALGO_BFV
		rlwe_param = param.Parameters
	case ckks.Parameters:
		algo = C.ALGO_CKKS
		rlwe_param = param.Parameters
	}

	c_input_args := make([]C.CArgument, n_in_args)
	c_output_args := make([]C.CArgument, n_out_args)

	export_arguments(rlwe_param, args, c_input_args, n_in_args, c_output_args, n_out_args, GpuMFormNBits)

	export_public_key_arguments(rlwe_param, rlk, glk, key_signature, &c_input_args, GpuMFormNBits)

	ret := C.run_fhe_gpu_task(task.task_handle, &c_input_args[0], C.uint64_t(len(c_input_args)), &c_output_args[0], C.uint64_t(len(c_output_args)), algo)

	if int(ret) != 0 {
		return fmt.Errorf("Failed to run GPU project\n")
	}

	if rlk != nil {
		runtime.KeepAlive(&rlk)
	}

	if glk != nil {
		runtime.KeepAlive(&glk)
	}

	runtime.KeepAlive(&args)

	return nil

}

func (task FheTaskGpu) Free() error {
	clearHandles()

	if task.task_handle != nil {
		C.release_fhe_gpu_task(task.task_handle)
	}
	return nil
}

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
#cgo CFLAGS: -I ../../../fhe_ops_lib -I ../../../mega_ag_runners

#include "fhe_types_v2.h"
#include "c_argument.h"
#include <stdlib.h>
#include <stdint.h>
*/
import "C"
import (
	"reflect"
	"runtime/cgo"
	"sort"
	"unsafe"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// ---------------------------------------------------------------------------
// GoVectorArgument — Go analogue of CxxVectorArgument in cxx_argument.h
// ---------------------------------------------------------------------------

type GoVectorArgument struct {
	ArgId string
	Data  []interface{}
}

func NewGoVectorArgument(ArgId string, dataXd interface{}) GoVectorArgument {
	var flattenedData []interface{}
	flattenData(reflect.ValueOf(dataXd), &flattenedData)
	return GoVectorArgument{ArgId: ArgId, Data: flattenedData}
}

func flattenData(value reflect.Value, flattenedData *[]interface{}) {
	switch value.Kind() {
	case reflect.Array, reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			flattenData(value.Index(i), flattenedData)
		}
	default:
		*flattenedData = append(*flattenedData, value.Interface())
	}
}

// ---------------------------------------------------------------------------
// Pinned handle registry
// ---------------------------------------------------------------------------

var pinnedHandles []cgo.Handle

func clearPinnedHandles() {
	for _, h := range pinnedHandles {
		h.Delete()
	}
	pinnedHandles = nil
}

func pinObject(obj interface{}) C.uintptr_t {
	h := cgo.NewHandle(obj)
	pinnedHandles = append(pinnedHandles, h)
	return C.uintptr_t(h)
}

// ---------------------------------------------------------------------------
// CArgument construction — GoVectorArgument → CArgument (pinned-handle mode)
// Mirrors export_cxx_argument / export_cxx_arguments in cxx_argument.h.
// CArgument.data is a malloc'd uintptr_t[] of pinned cgo.Handle values.
// Each handle holds a raw Lattigo object pointer.
// All export metadata (params, mf_nbits, level, galois_element) is passed
// by the C++ EXPORT_TO_ABI executor when it calls GoLattigoExportHandle.
// ---------------------------------------------------------------------------

func export_argument(src *GoVectorArgument) C.CArgument {
	var dest C.CArgument
	dest.id = C.CString(src.ArgId)

	size := len(src.Data)
	if size == 0 {
		panic("GoVectorArgument.Data is empty: " + src.ArgId)
	}

	var dataType C.DataType
	var level int

	switch obj := src.Data[0].(type) {
	case *bfv.Ciphertext:
		dataType = C.TYPE_CIPHERTEXT
		level = obj.Level()
	case *ckks.Ciphertext:
		dataType = C.TYPE_CIPHERTEXT
		level = obj.Level()
	case *bfv.Plaintext:
		dataType = C.TYPE_PLAINTEXT
		level = obj.Level()
	case *ckks.Plaintext:
		dataType = C.TYPE_PLAINTEXT
		level = obj.Level()
	case *bfv.PlaintextRingT:
		dataType = C.TYPE_PLAINTEXT
		level = obj.Level()
	case *bfv.PlaintextMul:
		dataType = C.TYPE_PLAINTEXT
		level = obj.Level()
	default:
		panic("unsupported operand type in export_argument: " + src.ArgId)
	}

	dest._type = dataType
	dest.size = C.int(size)
	dest.level = C.int(level)

	handleArr := (*C.uintptr_t)(C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0))) * C.size_t(size)))
	handleSlice := unsafe.Slice(handleArr, size)
	for i := 0; i < size; i++ {
		handleSlice[i] = pinObject(src.Data[i])
	}

	dest.data = unsafe.Pointer(handleArr)
	return dest
}

func export_arguments(args []GoVectorArgument, c_input_args []C.CArgument, c_output_args []C.CArgument) {
	for i := range c_input_args {
		c_input_args[i] = export_argument(&args[i])
	}
	for i := range c_output_args {
		c_output_args[i] = export_argument(&args[len(c_input_args)+i])
	}
}

func export_public_key_arguments(rlk *rlwe.RelinearizationKey, glk *rlwe.RotationKeySet, key_signature map[string]interface{}, input_args *[]C.CArgument) {
	rlk_level := int(key_signature["rlk"].(float64))
	if rlk_level >= 0 && rlk != nil {
		handleArr := (*C.uintptr_t)(C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0)))))
		*handleArr = pinObject(rlk)

		var arg C.CArgument
		arg.id = C.CString("rlk_ntt")
		arg._type = C.TYPE_RELIN_KEY
		arg.size = 1
		arg.level = C.int(rlk_level)
		arg.data = unsafe.Pointer(handleArr)
		*input_args = append(*input_args, arg)
	}

	if glk != nil {
		glk_map, ok := key_signature["glk"].(map[string]interface{})
		if ok && len(glk_map) > 0 {
			galoisElemStrs := make([]string, 0, len(glk_map))
			for k := range glk_map {
				galoisElemStrs = append(galoisElemStrs, k)
			}
			sort.Strings(galoisElemStrs)

			glk_level := -1
			for _, v := range glk_map {
				lvl := int(v.(float64))
				if lvl > glk_level {
					glk_level = lvl
				}
			}

			for range galoisElemStrs {
				handleArr := (*C.uintptr_t)(C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0)))))
				*handleArr = pinObject(glk)

				var arg C.CArgument
				arg.id = C.CString("glk_ntt")
				arg._type = C.TYPE_GALOIS_KEY
				arg.size = 1
				arg.level = C.int(glk_level)
				arg.data = unsafe.Pointer(handleArr)
				*input_args = append(*input_args, arg)
			}
		}
	}
}

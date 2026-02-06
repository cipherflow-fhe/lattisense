package acc

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func check_key_signature(rlk *rlwe.RelinearizationKey, glk *rlwe.RotationKeySet, key_signature map[string]interface{}) {
	if rlk != nil {
		level := int(key_signature["rlk"].(float64))
		if level > rlk.Keys[0].LevelQ() {
			panic(fmt.Sprintf("The relinearization key level %d does not match the signature level %d", rlk.Keys[0].LevelQ(), level))
		}
	}

	if glk != nil {
		for galois_elem_str, level := range key_signature["glk"].(map[string]interface{}) {
			galois_elem, err := strconv.ParseUint(galois_elem_str, 10, 64)
			if err != nil {
				panic(fmt.Sprintf("galois_elem %s is not an integer", galois_elem_str))
			}
			if glk.Keys[uint64(galois_elem)] == nil {
				panic(fmt.Sprintf("The rotation key glk_%d is not prepared", galois_elem))
			}
			if int(level.(float64)) > glk.Keys[uint64(galois_elem)].LevelQ() {
				panic(fmt.Sprintf("The rotation key glk_%d level %d does not match the signature level %d", galois_elem, glk.Keys[uint64(galois_elem)].LevelQ(), int(level.(float64))))
			}
		}
	}
}

func check_with_sig(arg GoVectorArgument, expected_id string, expected_type string, expected_shape []interface{}, expected_level int) {
	if arg.ArgId != expected_id {
		panic(fmt.Sprintf("For argument %s, expected id is %s, but input id is %s.", arg.ArgId, expected_id, arg.ArgId))
	}

	expected_size := 1
	for _, dim := range expected_shape {
		expected_size *= int(dim.(float64))
	}
	if len(arg.Data) != expected_size {
		panic(fmt.Sprintf("For argument %s, expected size is %d, but input size is %d.", arg.ArgId, expected_size, len(arg.Data)))
	}

	if reflect.TypeOf(arg.Data).Kind() != reflect.Slice {
		panic(fmt.Sprintf("For argument %s, type is not a slice.", arg.ArgId))
	}

	for i := range arg.Data {
		operand := arg.Data[i]
		switch operand := operand.(type) {
		case *bfv.Ciphertext:
			if expected_type != "ct" {
				panic(fmt.Sprintf("For argument %s, expected type is %s, but input type is ct.", arg.ArgId, expected_type))
			}
			if expected_level != operand.Level() {
				panic(fmt.Sprintf("For argument %s, expected level is %d, but input level is %d.", arg.ArgId, expected_level, operand.Level()))
			}
		case *bfv.Plaintext:
			if expected_type != "pt" {
				panic(fmt.Sprintf("For argument %s, expected type is %s, but input type is pt.", arg.ArgId, expected_type))
			}
			if expected_level != operand.Level() {
				panic(fmt.Sprintf("For argument %s, expected level is %d, but input level is %d.", arg.ArgId, expected_level, operand.Level()))
			}
		case *bfv.PlaintextRingT:
			if expected_type != "pt_ringt" {
				panic(fmt.Sprintf("For argument %s, expected type is %s, but input type is pt_ring.", arg.ArgId, expected_type))
			}
			if expected_level != operand.Level() {
				panic(fmt.Sprintf("For argument %s, expected level is %d, but input level is %d.", arg.ArgId, expected_level, operand.Level()))
			}
		case *bfv.PlaintextMul:
			if expected_type != "pt_mul" {
				panic(fmt.Sprintf("For argument %s, expected type is %s, but input type is pt_mul.", arg.ArgId, expected_type))
			}
			if expected_level != operand.Level() {
				panic(fmt.Sprintf("For argument %s, expected level is %d, but input level is %d.", arg.ArgId, expected_level, operand.Level()))
			}
		case *ckks.Ciphertext:
			if expected_type != "ct" {
				panic(fmt.Sprintf("For argument %s, expected type is %s, but input type is ct.", arg.ArgId, expected_type))
			}
			if expected_level != operand.Level() {
				panic(fmt.Sprintf("For argument %s, expected level is %d, but input level is %d.", arg.ArgId, expected_level, operand.Level()))
			}
		case *ckks.Plaintext:
			if expected_type != "pt" {
				panic(fmt.Sprintf("For argument %s, expected type is %s, but input type is pt.", arg.ArgId, expected_type))
			}
			if expected_level != operand.Level() {
				panic(fmt.Sprintf("For argument %s, expected level is %d, but input level is %d.", arg.ArgId, expected_level, operand.Level()))
			}
		default:
			panic("Unsupported operand type")
		}
	}

}

func check_parameter(params interface{}, param_json map[string]interface{}) {
	if _, ok := param_json["n"]; !ok {
		panic("Parameter JSON missing 'n' field")
	}
	if _, ok := param_json["q"]; !ok {
		panic("Parameter JSON missing 'q' field")
	}

	// Parse N using json.Number
	n_val, err := param_json["n"].(json.Number).Int64()
	if err != nil {
		panic(fmt.Sprintf("Failed to parse n: %v", err))
	}
	expected_n := int(n_val)

	expected_q_interface := param_json["q"].([]interface{})
	expected_q := make([]uint64, len(expected_q_interface))
	for i, v := range expected_q_interface {
		val, err := v.(json.Number).Int64()
		if err != nil {
			panic(fmt.Sprintf("Failed to parse Q[%d]: %v", i, err))
		}
		expected_q[i] = uint64(val)
	}

	switch params := params.(type) {
	case bfv.Parameters:
		actual_n := params.N()
		if actual_n != expected_n {
			panic(fmt.Sprintf("BFV parameter N mismatch: expected %d, got %d", expected_n, actual_n))
		}

		// Check t for BFV
		if t_val, ok := param_json["t"]; ok {
			expected_t, err := t_val.(json.Number).Int64()
			if err != nil {
				panic(fmt.Sprintf("Failed to parse t: %v", err))
			}
			actual_t := params.T()
			if actual_t != uint64(expected_t) {
				panic(fmt.Sprintf("BFV parameter t mismatch: expected %d, got %d", expected_t, actual_t))
			}
		}

		// Check Q moduli
		actual_q := params.Q()

		if len(actual_q) != len(expected_q) {
			panic(fmt.Sprintf("BFV parameter Q count mismatch: expected %d, got %d", len(expected_q), len(actual_q)))
		}

		for i := 0; i < len(expected_q); i++ {
			if actual_q[i] != expected_q[i] {
				panic(fmt.Sprintf("BFV parameter Q[%d] mismatch: expected %d, got %d", i, expected_q[i], actual_q[i]))
			}
		}

		// Check P moduli if specified
		if p_val, ok := param_json["p"]; ok {
			expected_p_interface := p_val.([]interface{})
			expected_p := make([]uint64, len(expected_p_interface))
			for i, v := range expected_p_interface {
				val, err := v.(json.Number).Int64()
				if err != nil {
					panic(fmt.Sprintf("Failed to parse P[%d]: %v", i, err))
				}
				expected_p[i] = uint64(val)
			}

			actual_p := params.P()

			if len(actual_p) != len(expected_p) {
				panic(fmt.Sprintf("BFV parameter P count mismatch: expected %d, got %d", len(expected_p), len(actual_p)))
			}

			for i := 0; i < len(expected_p); i++ {
				if actual_p[i] != expected_p[i] {
					panic(fmt.Sprintf("BFV parameter P[%d] mismatch: expected %d, got %d", i, expected_p[i], actual_p[i]))
				}
			}
		}

	case ckks.Parameters:
		actual_n := params.N()
		if actual_n != expected_n {
			panic(fmt.Sprintf("CKKS parameter N mismatch: expected %d, got %d", expected_n, actual_n))
		}

		// Check Q moduli
		actual_q := params.Q()

		if len(actual_q) != len(expected_q) {
			panic(fmt.Sprintf("CKKS parameter Q count mismatch: expected %d, got %d", len(expected_q), len(actual_q)))
		}

		for i := 0; i < len(expected_q); i++ {
			if actual_q[i] != expected_q[i] {
				panic(fmt.Sprintf("CKKS parameter Q[%d] mismatch: expected %d, got %d", i, expected_q[i], actual_q[i]))
			}
		}

		// Check P moduli if specified
		if p_val, ok := param_json["p"]; ok {
			expected_p_interface := p_val.([]interface{})
			expected_p := make([]uint64, len(expected_p_interface))
			for i, v := range expected_p_interface {
				val, err := v.(json.Number).Int64()
				if err != nil {
					panic(fmt.Sprintf("Failed to parse P[%d]: %v", i, err))
				}
				expected_p[i] = uint64(val)
			}

			actual_p := params.P()

			if len(actual_p) != len(expected_p) {
				panic(fmt.Sprintf("CKKS parameter P count mismatch: expected %d, got %d", len(expected_p), len(actual_p)))
			}

			for i := 0; i < len(expected_p); i++ {
				if actual_p[i] != expected_p[i] {
					panic(fmt.Sprintf("CKKS parameter P[%d] mismatch: expected %d, got %d", i, expected_p[i], actual_p[i]))
				}
			}
		}

	default:
		panic("Unknown parameter type for parameter checking")
	}
}

func check_signatures(param interface{}, rlk *rlwe.RelinearizationKey, glk *rlwe.RotationKeySet, args []GoVectorArgument, task_signature map[string]interface{}, online_phase bool) int {
	switch param.(type) {
	case bfv.Parameters:
		if task_signature["algorithm"].(string) != "BFV" {
			panic(fmt.Sprintf("task_signature algo type %s does not match bfv.Parameters", task_signature["type"].(string)))
		}
	case ckks.Parameters:
		if task_signature["algorithm"].(string) != "CKKS" {
			panic(fmt.Sprintf("task_signature algo type %s does not match ckks.Parameters", task_signature["type"].(string)))
		}
	default:
		panic("param type is not supported")
	}

	check_key_signature(rlk, glk, task_signature["key"].(map[string]interface{}))

	var data_signature []interface{}
	if online_phase {
		data_signature = task_signature["online"].([]interface{})
	} else {
		data_signature = task_signature["offline"].([]interface{})
	}

	n_in_args := 0
	for i, arg := range args {
		expected_id := data_signature[i].(map[string]interface{})["id"].(string)
		expected_type := data_signature[i].(map[string]interface{})["type"].(string)
		expected_shape := data_signature[i].(map[string]interface{})["size"].([]interface{})
		expected_level := int(data_signature[i].(map[string]interface{})["level"].(float64))
		check_with_sig(arg, expected_id, expected_type, expected_shape, expected_level)

		phase := data_signature[i].(map[string]interface{})["phase"].(string)
		if phase == "in" || phase == "offline" {
			n_in_args++
		}
	}

	return n_in_args
}

package acc

/*
#cgo CFLAGS: -I ../../../fhe_ops_lib -I ../../../mega_ag_runners

#include "fhe_types_v2.h"
#include "wrapper.h"
*/
import "C"
import (
	"reflect"
	"runtime/cgo"
	"sort"
	"strconv"
	"unsafe"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
)

var handles []cgo.Handle

func clearHandles() {
	for _, handle := range handles {
		handle.Delete()
	}
	handles = nil
}

func export_component(src *[]uint64, dest *C.CComponent) {
	N := len(*src)
	dest.n = C.int(N)

	handle := cgo.NewHandle(*src)
	handles = append(handles, handle)

	dest.data = (*C.ulong)(unsafe.Pointer(&(*src)[0]))
}

func export_polynomial(src *ring.Poly, dest *C.CPolynomial) {
	n_component := src.Level() + 1
	dest.n_component = C.int(n_component)
	dest.components = (*C.CComponent)(C.malloc(C.size_t(unsafe.Sizeof(C.CComponent{})) * C.ulong(n_component)))
	component_slice := unsafe.Slice(dest.components, n_component)
	for i := 0; i < n_component; i++ {
		export_component(&src.Coeffs[i], &component_slice[i])
	}
}

func export_bfv_ciphertext(src *bfv.Ciphertext, dest *C.CCiphertext) {
	dest.level = C.int(src.Level())
	dest.degree = C.int(src.Degree())
	dest.polys = (*C.CPolynomial)(C.malloc(C.size_t(unsafe.Sizeof(C.CPolynomial{})) * C.ulong(src.Degree()+1)))
	poly_slice := unsafe.Slice(dest.polys, src.Degree()+1)
	for i := 0; i < src.Degree()+1; i++ {
		export_polynomial(src.Value[i], &poly_slice[i])
	}
}

func export_bfv_plaintext_ringt(src *bfv.PlaintextRingT, dest *C.CPlaintext) {
	dest.level = 0
	export_polynomial(src.Value, &dest.poly)
}

func export_bfv_plaintext(src *bfv.Plaintext, dest *C.CPlaintext) {
	dest.level = C.int(src.Level())
	export_polynomial(src.Value, &dest.poly)
}

func export_bfv_plaintext_mul(params rlwe.Parameters, src *bfv.PlaintextMul, dest *C.CPlaintext, mf_nbits int) {
	dest.level = C.int(src.Level())
	src_value_copy := src.Value.CopyNew()
	params.RingQ().InvMFormLvl(src.Level(), src_value_copy, src_value_copy)

	if mf_nbits != 0 {
		params.RingQ().MulByPow2(src_value_copy, mf_nbits, src_value_copy)
	}

	export_polynomial(src_value_copy, &dest.poly)
}

func export_ckks_ciphertext(src *ckks.Ciphertext, dest *C.CCiphertext) {
	dest.level = C.int(src.Level())
	dest.degree = C.int(src.Degree())
	dest.polys = (*C.CPolynomial)(C.malloc(C.size_t(unsafe.Sizeof(C.CPolynomial{})) * C.ulong(src.Degree()+1)))
	poly_slice := unsafe.Slice(dest.polys, src.Degree()+1)
	for i := 0; i < src.Degree()+1; i++ {
		export_polynomial(src.Value[i], &poly_slice[i])
	}
}

func export_ckks_plaintext(src *ckks.Plaintext, dest *C.CPlaintext) {
	dest.level = C.int(src.Level())
	export_polynomial(src.Value, &dest.poly)
}

func export_polynomial_qp(src *ringqp.Poly, dest *C.CPolynomial, level int) {
	var n_q_component int
	if level == -1 {
		n_q_component = src.LevelQ() + 1
	} else {
		n_q_component = level + 1
	}
	n_p_component := src.LevelP() + 1
	n_component := n_q_component + n_p_component
	dest.n_component = C.int(n_component)
	dest.components = (*C.CComponent)(C.malloc(C.size_t(unsafe.Sizeof(C.CComponent{})) * C.ulong(n_component)))
	component_slice := unsafe.Slice(dest.components, n_component)
	for i := 0; i < n_q_component; i++ {
		export_component(&src.Q.Coeffs[i], &component_slice[i])
	}
	for i := 0; i < n_p_component; i++ {
		export_component(&src.P.Coeffs[i], &component_slice[n_q_component+i])
	}
}

func export_public_key(src *rlwe.CiphertextQP, dest *C.CPublicKey, level int) {
	dest.level = C.int(level)
	dest.degree = C.int(1)
	dest.polys = (*C.CPolynomial)(C.malloc(C.size_t(unsafe.Sizeof(C.CPolynomial{})) * C.ulong(2)))
	poly_slice := unsafe.Slice(dest.polys, 2)
	for i := 0; i < 2; i++ {
		export_polynomial_qp(&src.Value[i], &poly_slice[i], level)
	}
}

func export_key_switch_key(params rlwe.Parameters, src *rlwe.SwitchingKey, dest *C.CKeySwitchKey, level int, mf_nbits int) {
	var n_public_key int
	if level == -1 {
		n_public_key = len(src.Value)
	} else {
		n_public_key = (level + 1 + src.LevelP()) / (src.LevelP() + 1)
	}

	gcv2 := src.GadgetCiphertext.CopyNew()
	ringq := params.RingQ()
	ringp := params.RingP()

	for i := 0; i < len(src.Value); i++ {
		for j := 0; j < len(src.Value[i][0].Value); j++ {
			ringq.InvMForm(src.Value[i][0].Value[j].Q, gcv2.Value[i][0].Value[j].Q)
			ringp.InvMForm(src.Value[i][0].Value[j].P, gcv2.Value[i][0].Value[j].P)

			if mf_nbits != 0 {
				ringq.MulByPow2(gcv2.Value[i][0].Value[j].Q, mf_nbits, gcv2.Value[i][0].Value[j].Q)
				ringp.MulByPow2(gcv2.Value[i][0].Value[j].P, mf_nbits, gcv2.Value[i][0].Value[j].P)
			}
		}
	}

	dest.n_public_key = C.int(n_public_key)
	dest.public_keys = (*C.CPublicKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CPublicKey{})) * C.ulong(n_public_key)))
	public_key_slice := unsafe.Slice(dest.public_keys, n_public_key)
	for i := 0; i < n_public_key; i++ {
		export_public_key(&gcv2.Value[i][0], &public_key_slice[i], level)
	}
}

func export_relin_key(params rlwe.Parameters, src *rlwe.RelinearizationKey, dest *C.CRelinKey, level int, mf_nbits int) {
	export_key_switch_key(params, src.Keys[0], dest, level, mf_nbits)
}

func export_galois_key(params rlwe.Parameters, src *rlwe.RotationKeySet, dest *C.CGaloisKey, level int, mf_nbits int) {
	n_key_switch_key := int(dest.n_key_switch_key)
	// dest.n_key_switch_key = C.int(n_key_switch_key)
	// dest.steps = (*C.int)(C.malloc(C.size_t(unsafe.Sizeof(C.int(0))) * C.ulong(n_key_switch_key)))
	dest.key_switch_keys = (*C.CKeySwitchKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CKeySwitchKey{})) * C.ulong(n_key_switch_key)))
	gl_slice := unsafe.Slice(dest.galois_elements, n_key_switch_key)
	key_switch_key_slice := unsafe.Slice(dest.key_switch_keys, n_key_switch_key)
	for i := range gl_slice {
		// step_slice[i] = C.int(galEls[i])
		export_key_switch_key(params, src.Keys[uint64(gl_slice[i])], &key_switch_key_slice[i], level, mf_nbits)
	}
}

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

func export_argument(params rlwe.Parameters, src *GoVectorArgument, mf_nbits int) (dest C.CArgument) {
	dest.id = C.CString(src.ArgId)
	if reflect.TypeOf(src.Data).Kind() == reflect.Slice {
		operand0 := src.Data[0]
		size := len(src.Data)
		switch operand0 := operand0.(type) {
		case *bfv.Ciphertext:
			dest._type = C.TYPE_CIPHERTEXT
			dest.size = C.int(size)
			dest.level = C.int(operand0.Level())
			dest.data = unsafe.Pointer((*C.CCiphertext)(C.malloc(C.size_t(unsafe.Sizeof(C.CCiphertext{})) * C.ulong(size))))
			data_slice := unsafe.Slice((*C.CCiphertext)(dest.data), size)
			for i := 0; i < size; i++ {
				input_ct := src.Data[i].(*bfv.Ciphertext)
				export_bfv_ciphertext(input_ct, &data_slice[i])
			}

		case *bfv.Plaintext:
			dest._type = C.TYPE_PLAINTEXT
			dest.size = C.int(size)
			dest.level = C.int(operand0.Level())
			dest.data = unsafe.Pointer((*C.CPlaintext)(C.malloc(C.size_t(unsafe.Sizeof(C.CPlaintext{})) * C.ulong(size))))
			data_slice := unsafe.Slice((*C.CPlaintext)(dest.data), size)
			for i := 0; i < size; i++ {
				input_pt := src.Data[i].(*bfv.Plaintext)
				export_bfv_plaintext(input_pt, &data_slice[i])
			}

		case *bfv.PlaintextRingT:
			dest._type = C.TYPE_PLAINTEXT
			dest.size = C.int(size)
			dest.level = C.int(operand0.Level())
			dest.data = unsafe.Pointer((*C.CPlaintext)(C.malloc(C.size_t(unsafe.Sizeof(C.CPlaintext{})) * C.ulong(size))))
			data_slice := unsafe.Slice((*C.CPlaintext)(dest.data), size)
			for i := 0; i < size; i++ {
				input_pt_ringt := src.Data[i].(*bfv.PlaintextRingT)
				export_bfv_plaintext_ringt(input_pt_ringt, &data_slice[i])
			}

		case *bfv.PlaintextMul:
			dest._type = C.TYPE_PLAINTEXT
			dest.size = C.int(size)
			dest.level = C.int(operand0.Level())
			dest.data = unsafe.Pointer((*C.CPlaintext)(C.malloc(C.size_t(unsafe.Sizeof(C.CPlaintext{})) * C.ulong(size))))
			data_slice := unsafe.Slice((*C.CPlaintext)(dest.data), size)
			for i := 0; i < size; i++ {
				input_pt_mul := src.Data[i].(*bfv.PlaintextMul)
				export_bfv_plaintext_mul(params, input_pt_mul, &data_slice[i], mf_nbits)
			}

		case *ckks.Ciphertext:
			dest._type = C.TYPE_CIPHERTEXT
			dest.size = C.int(size)
			dest.level = C.int(operand0.Level())
			dest.data = unsafe.Pointer((*C.CCiphertext)(C.malloc(C.size_t(unsafe.Sizeof(C.CCiphertext{})) * C.ulong(size))))
			data_slice := unsafe.Slice((*C.CCiphertext)(dest.data), size)
			for i := 0; i < size; i++ {
				input_ct := src.Data[i].(*ckks.Ciphertext)
				export_ckks_ciphertext(input_ct, &data_slice[i])
			}

		case *ckks.Plaintext:
			dest._type = C.TYPE_PLAINTEXT
			dest.size = C.int(size)
			dest.level = C.int(operand0.Level())
			dest.data = unsafe.Pointer((*C.CPlaintext)(C.malloc(C.size_t(unsafe.Sizeof(C.CPlaintext{})) * C.ulong(size))))
			data_slice := unsafe.Slice((*C.CPlaintext)(dest.data), size)
			for i := 0; i < size; i++ {
				input_pt := src.Data[i].(*ckks.Plaintext)
				export_ckks_plaintext(input_pt, &data_slice[i])
			}

		default:
			panic("Unsupported operand type")
		}

	} else {
		panic("type of GoVectorArzgument.Data is not a slice")
	}

	return
}

func export_arguments(params rlwe.Parameters, args []GoVectorArgument, c_input_args []C.CArgument, n_int_args int, c_output_args []C.CArgument, n_out_args int, mf_nbits int) {
	for i := 0; i < n_int_args; i++ {
		c_input_args[i] = export_argument(params, &args[i], mf_nbits)
	}

	for i := 0; i < n_out_args; i++ {
		c_output_args[i] = export_argument(params, &args[n_int_args+i], mf_nbits)
	}
}

func export_public_key_arguments(params rlwe.Parameters, rlk *rlwe.RelinearizationKey, glk *rlwe.RotationKeySet, key_signature map[string]interface{}, input_args *[]C.CArgument, mf_nbits int) {
	rlk_level := int(key_signature["rlk"].(float64))
	if rlk_level >= 0 {
		var rlk_arg C.CArgument
		rlk_arg.id = C.CString("rlk_ntt")
		rlk_arg._type = C.TYPE_RELIN_KEY
		rlk_arg.size = 1
		rlk_arg.level = C.int(rlk_level)
		rlk_arg.data = unsafe.Pointer((*C.CRelinKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CRelinKey{})) * C.ulong(1))))

		rlk_data_slice := unsafe.Slice((*C.CRelinKey)(rlk_arg.data), 1)
		export_relin_key(params, rlk, &rlk_data_slice[0], rlk_level, mf_nbits)
		*input_args = append(*input_args, rlk_arg)
	}

	if len(key_signature["glk"].(map[string]interface{})) > 0 {
		var glk_arg C.CArgument
		glk_level := -1
		glk_gal_els := make([]uint64, 0)

		glk_map := key_signature["glk"].(map[string]interface{})

		// Extract keys and sort them to maintain consistent order
		keys := make([]string, 0, len(glk_map))
		for key := range glk_map {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			val := glk_map[key]
			level := int(val.(float64))
			glk_level = max(glk_level, level)
			galois_elem, _ := strconv.ParseUint(key, 10, 64)
			glk_gal_els = append(glk_gal_els, galois_elem)
		}

		glk_arg.id = C.CString("glk_ntt")
		glk_arg._type = C.TYPE_GALOIS_KEY
		glk_arg.size = 1
		glk_arg.level = C.int(glk_level)

		c_glk := unsafe.Pointer((*C.CGaloisKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CGaloisKey{})) * C.ulong(1))))
		glk_data_slice := unsafe.Slice((*C.CGaloisKey)(c_glk), 1)

		glk_data_slice[0].n_key_switch_key = C.int(len(glk_gal_els))
		glk_data_slice[0].galois_elements = (*C.ulong)(C.malloc(C.size_t(unsafe.Sizeof(C.ulong(0))) * C.ulong(len(glk_gal_els))))
		gl_slice := unsafe.Slice(glk_data_slice[0].galois_elements, len(glk_gal_els))

		for i := range gl_slice {
			gl_slice[i] = C.ulong(glk_gal_els[i])
		}

		glk_arg.data = c_glk
		export_galois_key(params, glk, &glk_data_slice[0], glk_level, mf_nbits)
		*input_args = append(*input_args, glk_arg)
	}
}

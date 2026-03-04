package acc

/*
#cgo CFLAGS: -I ../../../fhe_ops_lib -I ../../../mega_ag_runners

#include "fhe_types_v2.h"
#include "structs_v2.h"
#include "wrapper.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime/cgo"
	"unsafe"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
)

func export_component(src *[]uint64, dest *C.CComponent) {
	N := len(*src)
	dest.n = C.int(N)
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

// ---------------------------------------------------------------------------
// C-callable export functions (//export) — called by abi_bridge_executors.cc
// ---------------------------------------------------------------------------

//export ExportLattigoBfvCiphertext
func ExportLattigoBfvCiphertext(src_handle C.uintptr_t, dest *C.CCiphertext) {
	src := cgo.Handle(src_handle).Value().(*bfv.Ciphertext)
	dest.level = C.int(src.Level())
	dest.degree = C.int(src.Degree())
	dest.polys = (*C.CPolynomial)(C.malloc(C.size_t(unsafe.Sizeof(C.CPolynomial{})) * C.ulong(src.Degree()+1)))
	poly_slice := unsafe.Slice(dest.polys, src.Degree()+1)
	for i := 0; i < src.Degree()+1; i++ {
		export_polynomial(src.Value[i], &poly_slice[i])
	}
}

//export ExportLattigoCkksCiphertext
func ExportLattigoCkksCiphertext(src_handle C.uintptr_t, dest *C.CCiphertext) {
	src := cgo.Handle(src_handle).Value().(*ckks.Ciphertext)
	dest.level = C.int(src.Level())
	dest.degree = C.int(src.Degree())
	dest.polys = (*C.CPolynomial)(C.malloc(C.size_t(unsafe.Sizeof(C.CPolynomial{})) * C.ulong(src.Degree()+1)))
	poly_slice := unsafe.Slice(dest.polys, src.Degree()+1)
	for i := 0; i < src.Degree()+1; i++ {
		export_polynomial(src.Value[i], &poly_slice[i])
	}
}

//export ExportLattigoBfvPlaintext
func ExportLattigoBfvPlaintext(src_handle C.uintptr_t, dest *C.CPlaintext) {
	src := cgo.Handle(src_handle).Value().(*bfv.Plaintext)
	dest.level = C.int(src.Level())
	export_polynomial(src.Value, &dest.poly)
}

//export ExportLattigoCkksPlaintext
func ExportLattigoCkksPlaintext(src_handle C.uintptr_t, dest *C.CPlaintext) {
	src := cgo.Handle(src_handle).Value().(*ckks.Plaintext)
	dest.level = C.int(src.Level())
	export_polynomial(src.Value, &dest.poly)
}

//export ExportLattigoBfvPlaintextRingT
func ExportLattigoBfvPlaintextRingT(src_handle C.uintptr_t, dest *C.CPlaintext) {
	src := cgo.Handle(src_handle).Value().(*bfv.PlaintextRingT)
	dest.level = 0
	export_polynomial(src.Value, &dest.poly)
}

//export ExportLattigoBfvPlaintextMul
func ExportLattigoBfvPlaintextMul(params_handle C.uintptr_t, src_handle C.uintptr_t, mf_nbits C.int, dest *C.CPlaintext) {
	params := cgo.Handle(params_handle).Value().(rlwe.Parameters)
	src := cgo.Handle(src_handle).Value().(*bfv.PlaintextMul)
	dest.level = C.int(src.Level())
	src_value_copy := src.Value.CopyNew()
	params.RingQ().InvMFormLvl(src.Level(), src_value_copy, src_value_copy)
	if int(mf_nbits) != 0 {
		params.RingQ().MulByPow2(src_value_copy, int(mf_nbits), src_value_copy)
	}
	export_polynomial(src_value_copy, &dest.poly)
}

//export ExportLattigoRelinKey
func ExportLattigoRelinKey(params_handle C.uintptr_t, src_handle C.uintptr_t, level C.int, key_mf_nbits C.int, dest *C.CRelinKey) {
	params := cgo.Handle(params_handle).Value().(rlwe.Parameters)
	src := cgo.Handle(src_handle).Value().(*rlwe.RelinearizationKey)
	export_key_switch_key(params, src.Keys[0], dest, int(level), int(key_mf_nbits))
}

//export ExportLattigoGaloisKey
func ExportLattigoGaloisKey(params_handle C.uintptr_t, src_handle C.uintptr_t, galois_element C.uint64_t, level C.int, key_mf_nbits C.int, dest *C.CGaloisKey) {
	params := cgo.Handle(params_handle).Value().(rlwe.Parameters)
	src := cgo.Handle(src_handle).Value().(*rlwe.RotationKeySet)
	galElem := C.ulong(galois_element)
	dest.n_key_switch_key = 1
	dest.galois_elements = (*C.ulong)(C.malloc(C.size_t(unsafe.Sizeof(C.ulong(0)))))
	*dest.galois_elements = galElem
	n_key_switch_key := int(dest.n_key_switch_key)
	dest.key_switch_keys = (*C.CKeySwitchKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CKeySwitchKey{})) * C.ulong(n_key_switch_key)))
	gl_slice := unsafe.Slice(dest.galois_elements, n_key_switch_key)
	key_switch_key_slice := unsafe.Slice(dest.key_switch_keys, n_key_switch_key)
	for i := range gl_slice {
		export_key_switch_key(params, src.Keys[uint64(gl_slice[i])], &key_switch_key_slice[i], int(level), int(key_mf_nbits))
	}
}

func import_component(src *C.CComponent, dest *[]uint64) {
	N := int(src.n)

	// *dest = unsafe.Slice((*uint64)(unsafe.Pointer(src.data)), N)

	src_slice := unsafe.Slice((*uint64)(unsafe.Pointer(src.data)), N)
	copy(*dest, src_slice)
}

func import_polynomial(src *C.CPolynomial, dest *ring.Poly) {
	component_slice := unsafe.Slice(src.components, src.n_component)
	for i := 0; i < int(src.n_component); i++ {
		import_component(&component_slice[i], &dest.Coeffs[i])
	}
}

//export ImportLattigoBfvCiphertext
func ImportLattigoBfvCiphertext(dest_handle C.uintptr_t, src *C.CCiphertext) {
	dest := cgo.Handle(dest_handle).Value().(*bfv.Ciphertext)
	degree := int(src.degree)
	poly_slice := unsafe.Slice(src.polys, degree+1)
	for i := 0; i < degree+1; i++ {
		import_polynomial(&poly_slice[i], dest.Value[i])
	}
}

//export ImportLattigoCkksCiphertext
func ImportLattigoCkksCiphertext(dest_handle C.uintptr_t, src *C.CCiphertext) {
	dest := cgo.Handle(dest_handle).Value().(*ckks.Ciphertext)
	degree := int(src.degree)
	poly_slice := unsafe.Slice(src.polys, degree+1)
	for i := 0; i < degree+1; i++ {
		import_polynomial(&poly_slice[i], dest.Value[i])
	}
}

// ---------------------------------------------------------------------------
// Go-callable parameter handle helpers — accept native Go types,
// for use within the same package.
// ---------------------------------------------------------------------------

func pin_bfv_params(p bfv.Parameters) uintptr {
	h := cgo.NewHandle(p.Parameters)
	pinnedHandles = append(pinnedHandles, h)
	return uintptr(h)
}

func pin_ckks_params(p ckks.Parameters) uintptr {
	h := cgo.NewHandle(p.Parameters)
	pinnedHandles = append(pinnedHandles, h)
	return uintptr(h)
}

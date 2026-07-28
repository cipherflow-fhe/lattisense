package acc

/*
#cgo CFLAGS: -I ../../../abi -I ../../../mega_ag_runners

#include "c_types.h"
#include "c_structs.h"
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
	// dest.data = (*C.ulong)(unsafe.Pointer(&(*src)[0]))
	dest.data = (*C.ulong)(C.malloc(C.size_t(N) * C.size_t(unsafe.Sizeof(C.ulong(0)))))
	copy(unsafe.Slice((*uint64)(unsafe.Pointer(dest.data)), N), *src)
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

// wrap_c_components_as_ring_poly creates a ring.Poly whose Coeffs slices
// point directly into C-allocated CComponent data. This allows ring
// operations (InvMForm, MulByPow2, etc.) to transform C memory in-place
// without an additional copy.
func wrap_c_components_as_ring_poly(comps []C.CComponent) *ring.Poly {
	poly := &ring.Poly{Coeffs: make([][]uint64, len(comps))}
	for i := range comps {
		poly.Coeffs[i] = unsafe.Slice((*uint64)(unsafe.Pointer(comps[i].data)), int(comps[i].n))
	}
	return poly
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

	// Export directly from src (single copy: Go → C)
	dest.n_public_key = C.int(n_public_key)
	dest.public_keys = (*C.CPublicKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CPublicKey{})) * C.ulong(n_public_key)))
	public_key_slice := unsafe.Slice(dest.public_keys, n_public_key)
	for i := 0; i < n_public_key; i++ {
		export_public_key(&src.Value[i][0], &public_key_slice[i], level)
	}

	// Transform C memory in-place (avoids CopyNew double-copy)
	diff := mf_nbits - 64
	if diff != 0 {
		ringq := params.RingQ()
		ringp := params.RingP()

		// Determine Q/P component counts
		var n_q_component int
		if level == -1 {
			n_q_component = src.Value[0][0].Value[0].LevelQ() + 1
		} else {
			n_q_component = level + 1
		}

		for i := 0; i < n_public_key; i++ {
			pk_poly_slice := unsafe.Slice(public_key_slice[i].polys, 2)
			for j := 0; j < 2; j++ {
				comp_slice := unsafe.Slice(pk_poly_slice[j].components, int(pk_poly_slice[j].n_component))
				q_poly := wrap_c_components_as_ring_poly(comp_slice[:n_q_component])
				p_poly := wrap_c_components_as_ring_poly(comp_slice[n_q_component:])

				if diff == -64 {
					ringq.InvMForm(q_poly, q_poly)
					ringp.InvMForm(p_poly, p_poly)
				} else if diff > 0 {
					ringq.MulByPow2(q_poly, diff, q_poly)
					ringp.MulByPow2(p_poly, diff, p_poly)
				} else {
					ringq.InvMForm(q_poly, q_poly)
					ringq.MulByPow2(q_poly, 64+diff, q_poly)
					ringp.InvMForm(p_poly, p_poly)
					ringp.MulByPow2(p_poly, 64+diff, p_poly)
				}
			}
		}
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
	export_polynomial(src.Value, &dest.poly)
	// Transform C memory in-place (avoids CopyNew double-copy)
	if int(mf_nbits) != 64 {
		comp_slice := unsafe.Slice(dest.poly.components, int(dest.poly.n_component))
		c_poly := wrap_c_components_as_ring_poly(comp_slice)
		params.RingQ().InvMFormLvl(src.Level(), c_poly, c_poly)
		if int(mf_nbits) != 0 {
			params.RingQ().MulByPow2(c_poly, int(mf_nbits), c_poly)
		}
	}
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

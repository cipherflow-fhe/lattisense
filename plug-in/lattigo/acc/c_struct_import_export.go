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

func malloc_uint64s(n int) *C.uint64_t {
	return (*C.uint64_t)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.uint64_t(0)))))
}

func uint64_ptr_at(data *C.uint64_t, offset int) *C.uint64_t {
	return (*C.uint64_t)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + uintptr(offset)*unsafe.Sizeof(C.uint64_t(0))))
}

func uint64_slice(data *C.uint64_t, n int) []uint64 {
	return unsafe.Slice((*uint64)(unsafe.Pointer(data)), n)
}

func ring_degree(src *ring.Poly) int {
	return len(src.Coeffs[0])
}

func switching_key_ring_degree(src *rlwe.SwitchingKey) int {
	return len(src.Value[0][0].Value[0].Q.Coeffs[0])
}

func switching_key_decomp_rns(level_q int, level_p int) int {
	return (level_q + level_p + 1) / (level_p + 1)
}

func poly_view_from_flat_rns(data *C.uint64_t, rns_size int, ring_degree int) *ring.Poly {
	poly := &ring.Poly{Coeffs: make([][]uint64, rns_size)}
	for rns_idx := 0; rns_idx < rns_size; rns_idx++ {
		poly.Coeffs[rns_idx] = uint64_slice(uint64_ptr_at(data, rns_idx*ring_degree), ring_degree)
	}
	return poly
}

func export_plaintext_poly(src *ring.Poly, dest *C.CPlaintext) {
	level := src.Level()
	ringDegree := ring_degree(src)
	rnsSize := level + 1

	dest.level = C.int(level)
	dest.ring_degree = C.int(ringDegree)
	dest.data = malloc_uint64s(rnsSize * ringDegree)

	for rnsIdx := 0; rnsIdx < rnsSize; rnsIdx++ {
		copy(uint64_slice(uint64_ptr_at(dest.data, rnsIdx*ringDegree), ringDegree), src.Coeffs[rnsIdx])
	}
}

func import_ciphertext_polys(src *C.CCiphertext, dest []*ring.Poly) {
	cipherSize := int(src.cipher_size)
	level := int(src.level)
	ringDegree := int(src.ring_degree)
	rnsSize := level + 1

	for polyIdx := 0; polyIdx < cipherSize; polyIdx++ {
		for rnsIdx := 0; rnsIdx < rnsSize; rnsIdx++ {
			offset := (polyIdx*rnsSize + rnsIdx) * ringDegree
			copy(dest[polyIdx].Coeffs[rnsIdx], uint64_slice(uint64_ptr_at(src.data, offset), ringDegree))
		}
	}
}

func export_ciphertext_polys(src []*ring.Poly, level int, cipherSize int, dest *C.CCiphertext) {
	ringDegree := ring_degree(src[0])
	rnsSize := level + 1

	dest.level = C.int(level)
	dest.cipher_size = C.int(cipherSize)
	dest.ring_degree = C.int(ringDegree)
	dest.data = malloc_uint64s(cipherSize * rnsSize * ringDegree)

	for polyIdx := 0; polyIdx < cipherSize; polyIdx++ {
		for rnsIdx := 0; rnsIdx < rnsSize; rnsIdx++ {
			offset := (polyIdx*rnsSize + rnsIdx) * ringDegree
			copy(uint64_slice(uint64_ptr_at(dest.data, offset), ringDegree), src[polyIdx].Coeffs[rnsIdx])
		}
	}
}

func export_qp_poly(src *ringqp.Poly, data *C.uint64_t, level_q int, level_p int, ring_degree int) {
	qSize := level_q + 1
	pSize := level_p + 1
	for rnsIdx := 0; rnsIdx < qSize; rnsIdx++ {
		copy(uint64_slice(uint64_ptr_at(data, rnsIdx*ring_degree), ring_degree), src.Q.Coeffs[rnsIdx])
	}
	for rnsIdx := 0; rnsIdx < pSize; rnsIdx++ {
		copy(uint64_slice(uint64_ptr_at(data, (qSize+rnsIdx)*ring_degree), ring_degree), src.P.Coeffs[rnsIdx])
	}
}

func export_switching_key(params rlwe.Parameters, src *rlwe.SwitchingKey, dest *C.CSwitchingKey, level_q int, level_p int, mf_nbits int) {
	ringDegree := switching_key_ring_degree(src)
	decompRns := switching_key_decomp_rns(level_q, level_p)

	qSize := level_q + 1
	pSize := level_p + 1
	rnsSize := qSize + pSize

	dest.level_q = C.int(level_q)
	dest.level_p = C.int(level_p)
	dest.ring_degree = C.int(ringDegree)
	dest.data = malloc_uint64s(decompRns * 2 * rnsSize * ringDegree)

	for decompIdx := 0; decompIdx < decompRns; decompIdx++ {
		for polyIdx := 0; polyIdx < 2; polyIdx++ {
			offset := ((decompIdx*2 + polyIdx) * rnsSize) * ringDegree
			export_qp_poly(&src.Value[decompIdx][0].Value[polyIdx], uint64_ptr_at(dest.data, offset), level_q, level_p, ringDegree)
		}
	}

	diff := mf_nbits - 64
	if diff == 0 {
		return
	}

	ringq := params.RingQ()
	ringp := params.RingP()
	for decompIdx := 0; decompIdx < decompRns; decompIdx++ {
		for polyIdx := 0; polyIdx < 2; polyIdx++ {
			offset := ((decompIdx*2 + polyIdx) * rnsSize) * ringDegree
			qPoly := poly_view_from_flat_rns(uint64_ptr_at(dest.data, offset), qSize, ringDegree)
			pPoly := poly_view_from_flat_rns(uint64_ptr_at(dest.data, offset+qSize*ringDegree), pSize, ringDegree)

			if diff == -64 {
				ringq.InvMForm(qPoly, qPoly)
				ringp.InvMForm(pPoly, pPoly)
			} else if diff > 0 {
				ringq.MulByPow2(qPoly, diff, qPoly)
				ringp.MulByPow2(pPoly, diff, pPoly)
			} else {
				ringq.InvMForm(qPoly, qPoly)
				ringq.MulByPow2(qPoly, 64+diff, qPoly)
				ringp.InvMForm(pPoly, pPoly)
				ringp.MulByPow2(pPoly, 64+diff, pPoly)
			}
		}
	}
}

func export_galois_key(params rlwe.Parameters, src *rlwe.RotationKeySet, dest *C.CGaloisKey, galois_element uint64, level_q int, mf_nbits int) {
	switchingKey := src.Keys[galois_element]
	level_p := switchingKey.LevelP()

	dest.n_switching_key = 1
	dest.galois_elements = malloc_uint64s(1)
	*dest.galois_elements = C.uint64_t(galois_element)
	dest.switching_keys = (*C.CSwitchingKey)(C.malloc(C.size_t(unsafe.Sizeof(C.CSwitchingKey{}))))

	export_switching_key(params, switchingKey, dest.switching_keys, level_q, level_p, mf_nbits)
}

// ---------------------------------------------------------------------------
// C-callable export functions (//export) — called by abi_bridge_executors.cc
// ---------------------------------------------------------------------------

//export ExportLattigoBfvCiphertext
func ExportLattigoBfvCiphertext(src_handle C.uintptr_t, dest *C.CCiphertext) {
	src := cgo.Handle(src_handle).Value().(*bfv.Ciphertext)
	export_ciphertext_polys(src.Value, src.Level(), src.Degree()+1, dest)
}

//export ExportLattigoCkksCiphertext
func ExportLattigoCkksCiphertext(src_handle C.uintptr_t, dest *C.CCiphertext) {
	src := cgo.Handle(src_handle).Value().(*ckks.Ciphertext)
	export_ciphertext_polys(src.Value, src.Level(), src.Degree()+1, dest)
}

//export ExportLattigoBfvPlaintext
func ExportLattigoBfvPlaintext(src_handle C.uintptr_t, dest *C.CPlaintext) {
	src := cgo.Handle(src_handle).Value().(*bfv.Plaintext)
	export_plaintext_poly(src.Value, dest)
}

//export ExportLattigoCkksPlaintext
func ExportLattigoCkksPlaintext(src_handle C.uintptr_t, dest *C.CPlaintext) {
	src := cgo.Handle(src_handle).Value().(*ckks.Plaintext)
	export_plaintext_poly(src.Value, dest)
}

//export ExportLattigoBfvPlaintextRingT
func ExportLattigoBfvPlaintextRingT(src_handle C.uintptr_t, dest *C.CPlaintext) {
	src := cgo.Handle(src_handle).Value().(*bfv.PlaintextRingT)
	export_plaintext_poly(src.Value, dest)
}

//export ExportLattigoBfvPlaintextMul
func ExportLattigoBfvPlaintextMul(params_handle C.uintptr_t, src_handle C.uintptr_t, mf_nbits C.int, dest *C.CPlaintext) {
	params := cgo.Handle(params_handle).Value().(rlwe.Parameters)
	src := cgo.Handle(src_handle).Value().(*bfv.PlaintextMul)
	export_plaintext_poly(src.Value, dest)
	if int(mf_nbits) != 64 {
		cPoly := poly_view_from_flat_rns(dest.data, int(dest.level)+1, int(dest.ring_degree))
		params.RingQ().InvMFormLvl(src.Level(), cPoly, cPoly)
		if int(mf_nbits) != 0 {
			params.RingQ().MulByPow2(cPoly, int(mf_nbits), cPoly)
		}
	}
}

//export ExportLattigoRelinKey
func ExportLattigoRelinKey(params_handle C.uintptr_t, src_handle C.uintptr_t, level C.int, key_mf_nbits C.int, dest *C.CRelinKey) {
	params := cgo.Handle(params_handle).Value().(rlwe.Parameters)
	src := cgo.Handle(src_handle).Value().(*rlwe.RelinearizationKey)
	export_switching_key(params, src.Keys[0], dest, int(level), src.Keys[0].LevelP(), int(key_mf_nbits))
}

//export ExportLattigoGaloisKey
func ExportLattigoGaloisKey(params_handle C.uintptr_t, src_handle C.uintptr_t, galois_element C.uint64_t, level C.int, key_mf_nbits C.int, dest *C.CGaloisKey) {
	params := cgo.Handle(params_handle).Value().(rlwe.Parameters)
	src := cgo.Handle(src_handle).Value().(*rlwe.RotationKeySet)
	export_galois_key(params, src, dest, uint64(galois_element), int(level), int(key_mf_nbits))
}

//export ImportLattigoBfvCiphertext
func ImportLattigoBfvCiphertext(dest_handle C.uintptr_t, src *C.CCiphertext) {
	dest := cgo.Handle(dest_handle).Value().(*bfv.Ciphertext)
	import_ciphertext_polys(src, dest.Value)
}

//export ImportLattigoCkksCiphertext
func ImportLattigoCkksCiphertext(dest_handle C.uintptr_t, src *C.CCiphertext) {
	dest := cgo.Handle(dest_handle).Value().(*ckks.Ciphertext)
	import_ciphertext_polys(src, dest.Value)
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

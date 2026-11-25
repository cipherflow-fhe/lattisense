# Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import functools
import math
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List

from frontend.types import RingType

GALOIS_GEN = 5


class DftType(Enum):
    HomomorphicEncode = auto()
    HomomorphicDecode = auto()


class DftFormat(Enum):
    Standard = auto()
    RepackImagAsReal = auto()


@dataclass
class DftMatrixLiteral:
    type: DftType
    log_slots: int
    levels: List[int]
    format: DftFormat = DftFormat.Standard
    bit_reversed: bool = False
    log_bsgs_ratio: int = 0
    real: bool = False

    def depth(self, actual: bool = True) -> int:
        if actual:
            return len(self.levels)
        return sum(self.levels)

    def _compute_bootstrapping_dft_index_map(self, log_n: int) -> Dict[int, Dict[int, bool]]:
        log_slots = self.log_slots
        max_depth = self.depth(actual=False)

        level = log_slots
        merge = [0] * max_depth
        for i in range(max_depth):
            depth = int(math.ceil(level / (max_depth - i)))
            if self.type == DftType.HomomorphicEncode:
                merge[i] = depth
            else:
                merge[max_depth - i - 1] = depth
            level -= depth

        rotation_map: Dict[int, Dict[int, bool]] = {}
        level = log_slots
        for i in range(max_depth):
            if (
                log_slots < log_n - 1
                and self.type == DftType.HomomorphicDecode
                and i == 0
                and self.format == DftFormat.RepackImagAsReal
            ):
                rotation_map[i] = _gen_wfft_repack_index_map(log_slots)
                rotation_map[i] = _next_level_fft_index_map(
                    rotation_map[i], log_slots, 2 << log_slots, level, self.type, self.bit_reversed
                )
                next_level = level - 1
                for _ in range(merge[i] - 1):
                    rotation_map[i] = _next_level_fft_index_map(
                        rotation_map[i], log_slots, 2 << log_slots, next_level, self.type, self.bit_reversed
                    )
                    next_level -= 1
            else:
                rotation_map[i] = _gen_wfft_index_map(log_slots, level, self.type, self.bit_reversed)
                next_level = level - 1
                for _ in range(merge[i] - 1):
                    rotation_map[i] = _next_level_fft_index_map(
                        rotation_map[i], log_slots, 1 << log_slots, next_level, self.type, self.bit_reversed
                    )
                    next_level -= 1

            level -= merge[i]

        return rotation_map

    def _compute_real_dft_index_map(self, log_n: int) -> Dict[int, Dict[int, bool]]:
        log_slots = self.log_slots
        n = 1 << log_slots
        max_depth = self.depth(actual=False)

        # Builds the LogSlots butterfly stages in application order, merging the
        # phase-removal map (encode) or its inverse (decode) into the last/first
        # butterfly stage, exactly as realdft.go genDiagonals does.
        stages: List[set] = []
        if self.type == DftType.HomomorphicEncode:
            m = 1
            while m < n // 2:
                stages.append(_build_layer_diags(n, m))
                m <<= 1
            stages.append(_mul_diag_sets(n, _phase_entries_diags(n), _build_layer_diags(n, n // 2)))
        else:
            stages.append(
                _mul_diag_sets(n, _transpose_diag_set(n, _build_layer_diags(n, n // 2)), _phase_inv_entries_diags(n))
            )
            m = n // 4
            while m >= 1:
                stages.append(_transpose_diag_set(n, _build_layer_diags(n, m)))
                m >>= 1

        # Distributes the stages across the rescale groups (level collapsing),
        # with the same merge order as the standard DFT.
        merge = [0] * max_depth
        level = log_slots
        for i in range(max_depth):
            depth = int(math.ceil(level / (max_depth - i)))
            if self.type == DftType.HomomorphicEncode:
                merge[i] = depth
            else:
                merge[max_depth - i - 1] = depth
            level -= depth

        rotation_map: Dict[int, Dict[int, bool]] = {}
        start = 0
        for i in range(max_depth):
            merged = set(stages[start + merge[i] - 1])
            for k in range(start + merge[i] - 2, start - 1, -1):
                merged = _mul_diag_sets(n, merged, stages[k])
            rotation_map[i] = {key: True for key in merged}
            start += merge[i]

        return rotation_map

    def rotations(self, log_n: int) -> List[int]:
        log_slots = self.log_slots
        slots = 1 << log_slots
        dslots = slots
        rotations: List[int] = []

        if self.real:
            index = self._compute_real_dft_index_map(log_n)
            for pvec in index.values():
                n1 = _find_best_bsgs_split(pvec, dslots, self.log_bsgs_ratio)
                _add_matrix_rot_to_list(pvec, rotations, n1, slots, False)
            return rotations

        if log_slots < log_n - 1 and self.format == DftFormat.RepackImagAsReal:
            dslots <<= 1
            if self.type == DftType.HomomorphicEncode:
                rotations.append(slots)

        index = self._compute_bootstrapping_dft_index_map(log_n)
        for i, pvec in index.items():
            n1 = _find_best_bsgs_split(pvec, dslots, self.log_bsgs_ratio)
            repack = (
                self.type == DftType.HomomorphicDecode
                and log_slots < log_n - 1
                and i == 0
                and self.format == DftFormat.RepackImagAsReal
            )
            _add_matrix_rot_to_list(pvec, rotations, n1, slots, repack)

        return rotations

    def galois_elements(self, log_n: int) -> List[int]:
        ring_type = RingType.ConjugateInvariant if self.real else RingType.Standard
        return [_galois_element(rotation, log_n, ring_type) for rotation in self.rotations(log_n)]


@dataclass(frozen=True)
class BtpCircuitParams:
    """!Shape of the bootstrapping circuit."""

    slots_to_coeffs_factorization: List[List[int]]
    coeffs_to_slots_factorization: List[List[int]]
    eval_mod_log_scale: int

    @property
    def depth(self) -> int:
        """!Levels the circuit consumes.

        One level is consumed per factorization factor, plus the EvalMod depth
        log2(max(mod1_degree, 2K-1)) + double_angle, with mod1_degree=30, K=16 and
        double_angle=3.
        """
        mod1_depth = max(30, 2 * 16 - 1).bit_length() + 3
        return len(self.slots_to_coeffs_factorization) + mod1_depth + len(self.coeffs_to_slots_factorization)


# Shape of the bootstrapping circuit, indexed by the circuit ring degree.
BTP_CIRCUIT_PARAMS: Dict[int, BtpCircuitParams] = {
    16: BtpCircuitParams(
        slots_to_coeffs_factorization=[[39], [39], [39]],
        coeffs_to_slots_factorization=[[56], [56], [56], [56]],
        eval_mod_log_scale=60,
    ),
}

# Residual ring degree -> circuit ring degree. The circuit always runs in the
# standard ring of degree 16; for a residual of log_n 14 or 15 it needs the
# evk_n1_to_n2 / evk_n2_to_n1 switchkeys, while a residual of log_n 16 shares the
# ring. The residual parameter sets keep a modulus that leaves room for the
# circuit within the 128-bit security bound of degree 16 (1761 bits of log2(QP)):
# with the circuit's 821 bits and the key-switching primes, the residual chains
# hold 359 bits for log_n 14, 536 for 15 and 558 for 16.
BTP_LOG_N_BY_RESIDUAL_LOG_N: Dict[int, int] = {
    14: 16,
    15: 16,
    16: 16,
}


@dataclass
class BootstrappingParameters:
    log_n: int
    log_slots: int
    slots_to_coeffs: DftMatrixLiteral
    coeffs_to_slots: DftMatrixLiteral
    circuit: BtpCircuitParams

    @classmethod
    def default(cls, residual_log_n: int, ring_type: RingType = RingType.Standard) -> 'BootstrappingParameters':
        """!Bootstrapping parameters for a residual parameter set.

        The circuit runs at the degree of BTP_LOG_N_BY_RESIDUAL_LOG_N for both ring
        types. When that degree differs from the residual's, the two rings are
        linked by the evk_n1_to_n2 / evk_n2_to_n1 switchkeys; when it is the
        residual degree itself, as for a residual of log_n 16, no switch is needed.
        A conjugate invariant residual bootstraps natively in the CI ring via the
        real DFT (full packing, log_slots == log_n), so no domain switch keys are
        involved.
        """
        return _default_params(residual_log_n, ring_type)

    def galois_elements(self) -> List[int]:
        if not hasattr(self, '_galois_cache'):
            ring_type = RingType.ConjugateInvariant if self.log_slots == self.log_n else RingType.Standard
            keys = {_galois_element(1 << i, self.log_n, ring_type) for i in range(self.log_slots, self.log_n - 1)}
            keys.update(self.coeffs_to_slots.galois_elements(self.log_n))
            keys.update(self.slots_to_coeffs.galois_elements(self.log_n))
            if ring_type != RingType.ConjugateInvariant:
                keys.add(_galois_element_for_complex_conjugation(self.log_n))
            self._galois_cache = sorted(keys)
        return self._galois_cache

    def rotations(self) -> List[int]:
        if not hasattr(self, '_rotations_cache'):
            rotations = {1 << i for i in range(self.log_slots, self.log_n - 1)}
            rotations.update(self.coeffs_to_slots.rotations(self.log_n))
            rotations.update(self.slots_to_coeffs.rotations(self.log_n))
            self._rotations_cache = sorted(rotations)
        return self._rotations_cache


@functools.lru_cache(maxsize=None)
def _default_params(residual_log_n: int, ring_type: RingType = RingType.Standard) -> 'BootstrappingParameters':
    """!Cached construction of BootstrappingParameters, shared per (residual_log_n, ring_type)."""
    boot_log_n = BTP_LOG_N_BY_RESIDUAL_LOG_N.get(residual_log_n)
    if boot_log_n is None:
        raise ValueError(
            f'No bootstrapping parameter set for a residual of log_n={residual_log_n} '
            f'(supported: {sorted(BTP_LOG_N_BY_RESIDUAL_LOG_N)}).'
        )

    circuit = BTP_CIRCUIT_PARAMS[boot_log_n]

    ci = ring_type == RingType.ConjugateInvariant
    log_slots = boot_log_n if ci else boot_log_n - 1
    return BootstrappingParameters(
        log_n=boot_log_n,
        log_slots=log_slots,
        slots_to_coeffs=DftMatrixLiteral(
            type=DftType.HomomorphicDecode,
            log_slots=log_slots,
            format=DftFormat.RepackImagAsReal,
            log_bsgs_ratio=1,
            levels=[len(level) for level in circuit.slots_to_coeffs_factorization],
            real=ci,
        ),
        coeffs_to_slots=DftMatrixLiteral(
            type=DftType.HomomorphicEncode,
            log_slots=log_slots,
            format=DftFormat.RepackImagAsReal,
            log_bsgs_ratio=1,
            levels=[len(level) for level in circuit.coeffs_to_slots_factorization],
            real=ci,
        ),
        circuit=circuit,
    )


def _galois_element(rotation: int, log_n: int, ring_type: RingType = RingType.Standard) -> int:
    modulus = 1 << (log_n + (2 if ring_type == RingType.ConjugateInvariant else 1))
    return pow(GALOIS_GEN, rotation & (modulus - 1), modulus)


def _galois_element_for_complex_conjugation(log_n: int) -> int:
    return (1 << (log_n + 1)) - 1


def _bsgs_index(diag_keys: Dict[int, bool], slots: int, n1: int):
    index: Dict[int, List[int]] = {}
    rot_n1_map: Dict[int, bool] = {}
    rot_n2_map: Dict[int, bool] = {}

    for rot in diag_keys:
        rot &= slots - 1
        idx_n1 = ((rot // n1) * n1) & (slots - 1)
        idx_n2 = rot & (n1 - 1)
        index.setdefault(idx_n1, []).append(idx_n2)
        rot_n1_map[idx_n1] = True
        rot_n2_map[idx_n2] = True

    return index, sorted(rot_n1_map.keys()), sorted(rot_n2_map.keys())


def _find_best_bsgs_split(diag_matrix: Dict[int, bool], max_n: int, log_max_ratio: int) -> int:
    max_ratio = float(1 << log_max_ratio)
    n1 = 1
    while n1 < max_n:
        _, rot_n1, rot_n2 = _bsgs_index(diag_matrix, max_n, n1)
        nb_n1, nb_n2 = len(rot_n1) - 1, len(rot_n2) - 1

        if nb_n1 == 0:
            if nb_n2 > 0:
                return n1 // 2
            n1 <<= 1
            continue

        ratio = nb_n2 / nb_n1
        if ratio == max_ratio:
            return n1
        if ratio > max_ratio:
            return n1 // 2

        n1 <<= 1

    return 1


def _add_matrix_rot_to_list(pvec: Dict[int, bool], rotations: List[int], n1: int, slots: int, repack: bool) -> None:
    if len(pvec.keys()) < 3:
        for j in pvec:
            if j not in rotations:
                rotations.append(j)
        return

    for j in pvec:
        index = (j // n1) * n1
        if repack:
            index &= 2 * slots - 1
        else:
            index &= slots - 1

        if index != 0 and index not in rotations:
            rotations.append(index)

        index = j & (n1 - 1)
        if index != 0 and index not in rotations:
            rotations.append(index)


def _gen_wfft_repack_index_map(log_l: int) -> Dict[int, bool]:
    return {0: True, 1 << log_l: True}


def _gen_wfft_index_map(log_l: int, level: int, dft_type: DftType, bit_reversed: bool) -> Dict[int, bool]:
    if (dft_type == DftType.HomomorphicEncode and not bit_reversed) or (
        dft_type == DftType.HomomorphicDecode and bit_reversed
    ):
        rot = 1 << (level - 1)
    else:
        rot = 1 << (log_l - level)

    return {0: True, rot: True, (1 << log_l) - rot: True}


def _next_level_fft_index_map(
    vec: Dict[int, bool], log_l: int, n: int, next_level: int, dft_type: DftType, bit_reversed: bool
) -> Dict[int, bool]:
    if (dft_type == DftType.HomomorphicEncode and not bit_reversed) or (
        dft_type == DftType.HomomorphicDecode and bit_reversed
    ):
        rot = (1 << (next_level - 1)) & (n - 1)
    else:
        rot = (1 << (log_l - next_level)) & (n - 1)

    new_vec: Dict[int, bool] = {}
    for i in vec:
        new_vec[i] = True
        new_vec[(i + rot) & (n - 1)] = True
        new_vec[(i - rot) & (n - 1)] = True

    return new_vec


# Real-DFT diagonal helpers (faithful port of circuits/ckks/realdft/realdft.go).
# Only the diagonal indices matter here: the actual coefficients are irrelevant
# because only DiagonalsIndexList() feeds the galois elements.

_PART_REAL = 0
_PART_RE = 1
_PART_IM = 2


def _units_stage(m: int) -> List[tuple]:
    """!Real-representation units at stage m: (r, pair) where pair marks a
    conjugate pair of complex sub-vectors."""
    units = [(0, False)]
    s = 1
    while s < m:
        nxt: List[tuple] = []
        for r, pair in units:
            if not pair:
                if r == 0:
                    nxt.append((0, False))
                    nxt.append((s, False))
                else:
                    nxt.append((s >> 1, True))
            else:
                nxt.append((r, True))
                nxt.append((s - r, True))
        units = nxt
        s <<= 1
    return units


def _coords_stage(n: int, s: int) -> List[tuple]:
    """!Ordering of the N real coordinates at stage S as (r, part, j)."""
    span = n // s
    out: List[tuple] = []
    for r, pair in _units_stage(s):
        if not pair:
            for j in range(span):
                out.append((r, _PART_REAL, j))
        else:
            for j in range(span):
                out.append((r, _PART_RE, j))
            for j in range(span):
                out.append((r, _PART_IM, j))
    return out


def _index_map(coords: List[tuple]) -> Dict[tuple, int]:
    return {c: i for i, c in enumerate(coords)}


def _build_layer_diags(n: int, m: int) -> set:
    """!Diagonal indices of the butterfly layer S_{2m} (buildLayer in realdft.go)."""
    span = n // (2 * m)
    in_pos = _index_map(_coords_stage(n, m))
    out_pos = _index_map(_coords_stage(n, 2 * m))
    diags: set = set()

    def add(oc: tuple, ic: tuple) -> None:
        diags.add((in_pos[ic] - out_pos[oc]) % n)

    # G_real (r = 0)
    for j in range(span):
        add((0, _PART_REAL, j), (0, _PART_REAL, j))
        add((0, _PART_REAL, j), (0, _PART_REAL, j + span))
        add((m, _PART_REAL, j), (0, _PART_REAL, j))
        add((m, _PART_REAL, j), (0, _PART_REAL, j + span))

    # G_split (r = m/2), only for m >= 2
    if m >= 2:
        for j in range(span):
            add((m // 2, _PART_RE, j), (m // 2, _PART_REAL, j))
            add((m // 2, _PART_IM, j), (m // 2, _PART_REAL, j + span))

    # G_r (1 <= r < m/2); the zero entries of each 4x4 block are omitted.
    for r in range(1, m // 2):
        for j in range(span):
            ins = (
                (r, _PART_RE, j),
                (r, _PART_RE, j + span),
                (r, _PART_IM, j),
                (r, _PART_IM, j + span),
            )
            rows = (
                ((r, _PART_RE, j), (ins[0], ins[1], ins[3])),
                ((r, _PART_IM, j), (ins[1], ins[2], ins[3])),
                ((m - r, _PART_RE, j), (ins[0], ins[1], ins[3])),
                ((m - r, _PART_IM, j), (ins[1], ins[2], ins[3])),
            )
            for oc, ics in rows:
                for ic in ics:
                    add(oc, ic)

    return diags


def _phase_entries_diags(n: int) -> set:
    """!Diagonal indices of the phase-removal map P (phaseEntries in realdft.go)."""
    pos = _index_map(_coords_stage(n, n))
    diags: set = set()

    def add(row: int, col: int) -> None:
        diags.add((col - row) % n)

    add(pos[(0, _PART_REAL, 0)], pos[(0, _PART_REAL, 0)])
    add(pos[(n // 2, _PART_REAL, 0)], pos[(n // 2, _PART_REAL, 0)])

    for r in range(1, n // 2):
        pr = pos[(r, _PART_RE, 0)]
        pi = pos[(r, _PART_IM, 0)]
        add(pr, pr)
        add(pr, pi)
        add(pi, pr)
        add(pi, pi)

    return diags


def _phase_inv_entries_diags(n: int) -> set:
    """!Diagonal indices of P^{-1}; its support coincides with P, only the
    coefficients differ (and only the diagonal indices matter here)."""
    return _phase_entries_diags(n)


def _mul_diag_sets(n: int, a: set, b: set) -> set:
    """!Diagonal indices of the product A*B: {(a + b) mod n}."""
    return {(x + y) % n for x in a for y in b}


def _transpose_diag_set(n: int, a: set) -> set:
    """!Diagonal indices of the transpose: {-a mod n}."""
    return {(-x) % n for x in a}

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

    def rotations(self, log_n: int) -> List[int]:
        log_slots = self.log_slots
        slots = 1 << log_slots
        dslots = slots
        rotations: List[int] = []

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
        return [_galois_element(rotation, log_n) for rotation in self.rotations(log_n)]


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

        The circuit runs in the **standard** ring with the degree of
        BTP_LOG_N_BY_RESIDUAL_LOG_N. When that degree differs from the residual's,
        the two rings are linked by the evk_n1_to_n2 / evk_n2_to_n1 switchkeys; when
        it is the residual degree itself, as for a residual of log_n 16, no switch
        is needed. A conjugate invariant residual shares the primitive root order
        with a circuit of exactly residual log_n + 1, so only the residual degrees
        whose mapped degree satisfies that can use it.
        """
        boot_log_n = BTP_LOG_N_BY_RESIDUAL_LOG_N.get(residual_log_n)
        if boot_log_n is None:
            raise ValueError(
                f'No bootstrapping parameter set for a residual of log_n={residual_log_n} '
                f'(supported: {sorted(BTP_LOG_N_BY_RESIDUAL_LOG_N)}).'
            )
        if ring_type == RingType.ConjugateInvariant and boot_log_n != residual_log_n + 1:
            raise ValueError(
                f'The conjugate invariant ring pins the circuit to residual log_n + 1 '
                f'({residual_log_n + 1}), which cannot hold the circuit within the security bound, so '
                f'a conjugate invariant residual of log_n={residual_log_n} cannot be bootstrapped.'
            )

        circuit = BTP_CIRCUIT_PARAMS[boot_log_n]

        log_slots = boot_log_n - 1
        return cls(
            log_n=boot_log_n,
            log_slots=log_slots,
            slots_to_coeffs=DftMatrixLiteral(
                type=DftType.HomomorphicDecode,
                log_slots=log_slots,
                format=DftFormat.RepackImagAsReal,
                log_bsgs_ratio=1,
                levels=[len(level) for level in circuit.slots_to_coeffs_factorization],
            ),
            coeffs_to_slots=DftMatrixLiteral(
                type=DftType.HomomorphicEncode,
                log_slots=log_slots,
                format=DftFormat.RepackImagAsReal,
                log_bsgs_ratio=1,
                levels=[len(level) for level in circuit.coeffs_to_slots_factorization],
            ),
            circuit=circuit,
        )

    def galois_elements(self) -> List[int]:
        keys = {_galois_element(1 << i, self.log_n) for i in range(self.log_slots, self.log_n - 1)}
        keys.update(self.coeffs_to_slots.galois_elements(self.log_n))
        keys.update(self.slots_to_coeffs.galois_elements(self.log_n))
        keys.add(_galois_element_for_complex_conjugation(self.log_n))
        return sorted(keys)


def bootstrapping_galois_elements(residual_log_n: int, ring_type: RingType = RingType.Standard) -> List[int]:
    return BootstrappingParameters.default(residual_log_n, ring_type).galois_elements()


def bootstrapping_rotations(residual_log_n: int, ring_type: RingType = RingType.Standard) -> List[int]:
    params = BootstrappingParameters.default(residual_log_n, ring_type)
    rotations = set()
    for i in range(params.log_slots, params.log_n - 1):
        rotations.add(1 << i)
    rotations.update(params.coeffs_to_slots.rotations(params.log_n))
    rotations.update(params.slots_to_coeffs.rotations(params.log_n))
    return sorted(rotations)


def bootstrapping_log_n(residual_log_n: int, ring_type: RingType = RingType.Standard) -> int:
    """!Bootstrapping (circuit) ring degree log2, see BootstrappingParameters.default."""
    return BootstrappingParameters.default(residual_log_n, ring_type).log_n


def _galois_element(rotation: int, log_n: int) -> int:
    modulus = 1 << (log_n + 1)
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

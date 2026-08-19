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

GALOIS_GEN = 5
DEFAULT_BTP_LOG_N = 16


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


@dataclass
class BootstrappingParameters:
    log_n: int
    log_slots: int
    slots_to_coeffs: DftMatrixLiteral
    coeffs_to_slots: DftMatrixLiteral

    @classmethod
    def default(cls, residual_log_n: int, btp_log_n: int = DEFAULT_BTP_LOG_N) -> 'BootstrappingParameters':
        log_slots = btp_log_n - 1
        if residual_log_n > btp_log_n:
            raise ValueError(f'Default CKKS bootstrapping only supports residual log_n <= {btp_log_n}.')
        return cls(
            log_n=btp_log_n,
            log_slots=log_slots,
            slots_to_coeffs=DftMatrixLiteral(
                type=DftType.HomomorphicDecode,
                log_slots=log_slots,
                format=DftFormat.RepackImagAsReal,
                log_bsgs_ratio=1,
                levels=[1, 1, 1],
            ),
            coeffs_to_slots=DftMatrixLiteral(
                type=DftType.HomomorphicEncode,
                log_slots=log_slots,
                format=DftFormat.RepackImagAsReal,
                log_bsgs_ratio=1,
                levels=[1, 1, 1, 1],
            ),
        )

    def galois_elements(self) -> List[int]:
        keys = {_galois_element(1 << i, self.log_n) for i in range(self.log_slots, self.log_n - 1)}
        keys.update(self.coeffs_to_slots.galois_elements(self.log_n))
        keys.update(self.slots_to_coeffs.galois_elements(self.log_n))
        keys.add(_galois_element_for_complex_conjugation(self.log_n))
        return sorted(keys)


def bootstrapping_galois_elements(residual_log_n: int) -> List[int]:
    return BootstrappingParameters.default(residual_log_n).galois_elements()


def bootstrapping_rotations(residual_log_n: int) -> List[int]:
    params = BootstrappingParameters.default(residual_log_n)
    rotations = set()
    for i in range(params.log_slots, params.log_n - 1):
        rotations.add(1 << i)
    rotations.update(params.coeffs_to_slots.rotations(params.log_n))
    rotations.update(params.slots_to_coeffs.rotations(params.log_n))
    return sorted(rotations)


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

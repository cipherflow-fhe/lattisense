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
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List


class LinearTransformType(Enum):
    CoeffsToSlots = auto()
    SlotsToCoeffs = auto()


class SineType(Enum):
    Sin = auto()
    Cos1 = auto()
    Cos2 = auto()


@dataclass
class EvalModParams:
    """Parameters for the EvalMod step of bootstrapping."""

    q: int
    level_start: int
    scaling_factor: float
    sine_type: SineType
    message_ratio: float
    k: int
    sine_deg: int
    double_angle: int
    arcsine_deg: int

    def q_diff(self) -> float:
        """Return Q / ClosestPow2. This is the error introduced by the approximate division by Q."""
        return self.q / 2 ** round(math.log2(self.q))

    def depth(self) -> int:
        """Return the depth of the SineEval, including double angle formula."""
        if self.sine_type == SineType.Cos1:
            d = int(math.ceil(math.log2(max(self.sine_deg, 2 * self.k - 1) + 1)))
        else:
            d = int(math.ceil(math.log2(self.sine_deg + 1)))
        d += self.double_angle
        d += int(math.ceil(math.log2(self.arcsine_deg + 1)))
        return d


@dataclass
class EncodingMatrixParams:
    """Parameters for CoeffsToSlots / SlotsToCoeffs encoding matrix."""

    linear_transform_type: LinearTransformType
    repack_imag_2_real: bool
    level_start: int
    bit_reversed: bool
    bsgs_ratio: float
    scaling_factor: List[List[float]]
    log_n: int = 0
    log_slots: int = 0

    def depth(self, actual: bool = True) -> int:
        """Return the number of levels allocated.

        If actual is True, returns the number of moduli consumed.
        If actual is False, returns the factorization depth.
        """
        if actual:
            return len(self.scaling_factor)
        else:
            return sum(len(level) for level in self.scaling_factor)

    def levels(self) -> List[int]:
        """Return the index of the Qi used in this encoding matrix."""
        lvls: List[int] = []
        true_depth = self.depth(actual=True)
        for i in range(true_depth):
            for _ in self.scaling_factor[true_depth - 1 - i]:
                lvls.append(self.level_start - i)
        return lvls

    def compute_bootstrapping_dft_index_map(self) -> Dict[int, Dict[int, bool]]:
        """Compute the full DFT rotation index map for bootstrapping."""
        log_slots = self.log_slots
        log_n = self.log_n
        lt_type = self.linear_transform_type
        repack_imag_2_real = self.repack_imag_2_real
        bit_reversed = self.bit_reversed
        max_depth = self.depth(actual=False)

        level = log_slots
        merge = [0] * max_depth
        for i in range(max_depth):
            depth = int(math.ceil(level / (max_depth - i)))
            if lt_type == LinearTransformType.CoeffsToSlots:
                merge[i] = depth
            else:
                merge[max_depth - i - 1] = depth
            level -= depth

        rotation_map: Dict[int, Dict[int, bool]] = {}
        level = log_slots
        for i in range(max_depth):
            if log_slots < log_n - 1 and lt_type == LinearTransformType.SlotsToCoeffs and i == 0 and repack_imag_2_real:
                rotation_map[i] = _gen_wfft_repack_index_map(log_slots, level)
                rotation_map[i] = _next_level_fft_index_map(
                    rotation_map[i], log_slots, 2 << log_slots, level, lt_type, bit_reversed
                )
                next_level = level - 1
                for j in range(merge[i] - 1):
                    rotation_map[i] = _next_level_fft_index_map(
                        rotation_map[i], log_slots, 2 << log_slots, next_level, lt_type, bit_reversed
                    )
                    next_level -= 1
            else:
                rotation_map[i] = _gen_wfft_index_map(log_slots, level, lt_type, bit_reversed)
                next_level = level - 1
                for j in range(merge[i] - 1):
                    rotation_map[i] = _next_level_fft_index_map(
                        rotation_map[i], log_slots, 1 << log_slots, next_level, lt_type, bit_reversed
                    )
                    next_level -= 1

            level -= merge[i]

        return rotation_map

    def rotations(self) -> List[int]:
        """Return the list of rotations performed during the encoding matrix operation."""
        log_slots = self.log_slots
        log_n = self.log_n
        lt_type = self.linear_transform_type

        rots: List[int] = []
        slots = 1 << log_slots
        dslots = slots

        if log_slots < log_n - 1 and self.repack_imag_2_real:
            dslots <<= 1
            if lt_type == LinearTransformType.CoeffsToSlots:
                rots.append(slots)

        index = self.compute_bootstrapping_dft_index_map()
        for i in index:
            pvec = index[i]
            n1 = _find_best_bsgs_split(pvec, dslots, self.bsgs_ratio)
            repack = (
                lt_type == LinearTransformType.SlotsToCoeffs
                and log_slots < log_n - 1
                and i == 0
                and self.repack_imag_2_real
            )
            _add_matrix_rot_to_list(pvec, rots, n1, slots, repack)

        return rots


def _bsgs_index(diag_keys: Dict[int, bool], slots: int, n1: int):
    index: Dict[int, List[int]] = {}
    rot_n1_map: Dict[int, bool] = {}
    rot_n2_map: Dict[int, bool] = {}

    for rot in diag_keys:
        rot &= slots - 1
        idx_n1 = ((rot // n1) * n1) & (slots - 1)
        idx_n2 = rot & (n1 - 1)

        if idx_n1 not in index:
            index[idx_n1] = [idx_n2]
        else:
            index[idx_n1].append(idx_n2)

        rot_n1_map[idx_n1] = True
        rot_n2_map[idx_n2] = True

    rot_n1 = list(rot_n1_map.keys())
    rot_n2 = list(rot_n2_map.keys())
    return index, rot_n1, rot_n2


def _find_best_bsgs_split(diag_matrix: Dict[int, bool], max_n: int, max_ratio: float) -> int:
    n1 = 1
    while n1 < max_n:
        _, rot_n1, rot_n2 = _bsgs_index(diag_matrix, max_n, n1)
        nb_n1, nb_n2 = len(rot_n1) - 1, len(rot_n2) - 1

        if nb_n2 / nb_n1 == max_ratio:
            return n1
        if nb_n2 / nb_n1 > max_ratio:
            return n1 // 2

        n1 <<= 1

    return 1


def _add_matrix_rot_to_list(pvec: Dict[int, bool], rots: List[int], n1: int, slots: int, repack: bool):
    if len(list(pvec.keys())) < 3:
        for j in pvec:
            if j not in rots:
                rots.append(j)
    else:
        for j in pvec:
            index = (j // n1) * n1
            if repack:
                index &= 2 * slots - 1
            else:
                index &= slots - 1

            if index != 0 and index not in rots:
                rots.append(index)

            index = j & (n1 - 1)
            if index != 0 and index not in rots:
                rots.append(index)


def _gen_wfft_repack_index_map(log_l: int, level: int) -> Dict[int, bool]:
    return {0: True, (1 << log_l): True}


def _gen_wfft_index_map(log_l: int, level: int, lt_type: LinearTransformType, bit_reversed: bool) -> Dict[int, bool]:
    if (lt_type == LinearTransformType.CoeffsToSlots and (not bit_reversed)) or (
        lt_type == LinearTransformType.SlotsToCoeffs and bit_reversed
    ):
        rot = 1 << (level - 1)
    else:
        rot = 1 << (log_l - level)

    return {0: True, rot: True, ((1 << log_l) - rot): True}


def _next_level_fft_index_map(
    vec: Dict[int, bool], log_l: int, n: int, next_level: int, lt_type: LinearTransformType, bit_reversed: bool
) -> Dict[int, bool]:
    if (lt_type == LinearTransformType.CoeffsToSlots and (not bit_reversed)) or (
        lt_type == LinearTransformType.SlotsToCoeffs and bit_reversed
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

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

import json
import math
import os
import random
import string
from typing import List, Optional

import networkx as nx
from enum import Enum

from frontend.bootstrap_params import (
    LinearTransformType,
    SineType,
    EncodingMatrixParams,
    EvalModParams,
)

DEFAULT_LEVEL = -1

random_ids = set()
data_node_count = 0
compute_node_count = 0

g_swk_node_dict: dict[str, 'SwitchKeyNode'] = {}
g_dag = nx.DiGraph()
g_param: Optional['Param'] = None

GALOIS_GEN = 5
SEAL_GALOIS_GEN = 3


class Algo(Enum):
    BFV = 'BFV'
    CKKS = 'CKKS'


class DataType(Enum):
    Plaintext = 'pt'
    PlaintextRingt = 'pt_ringt'
    PlaintextMul = 'pt_mul'
    Ciphertext = 'ct'
    Ciphertext3 = 'ct3'
    SwitchKey = 'swk'
    RelinKey = 'rlk'
    GaloisKey = 'glk'


class OperationType(Enum):
    Add = 'add'
    Sub = 'sub'
    Neg = 'neg'
    Mult = 'mult'
    Relin = 'relin'
    Rescale = 'rescale'
    DropLevel = 'drop_level'
    RnsSpDecomp = 'rns_sp_decomp'
    RotateCol = 'rotate_col'
    RotateRow = 'rotate_row'
    ToNtt = 'to_ntt'
    ToMForm = 'to_mf'
    ToMul = 'to_mul'
    ToInvNtt = 'to_inv_ntt'
    CmpacSum = 'cmpac_sum'
    CmpSum = 'cmp_sum'
    Bootstrap = 'bootstrap'
    FpgaKernel = 'fpga_kernel'


class Lib(Enum):
    Lattigo = 'lattigo'
    SEAL = 'seal'


def gen_data_node_index() -> int:
    global data_node_count
    data_node_count += 1
    return data_node_count - 1


def gen_compute_node_index() -> int:
    global compute_node_count
    compute_node_count += 1
    return compute_node_count - 1


def get_glk_col(steps: int, poly_degree: int):
    def convert2naf(x: int):
        xh = x >> 1
        x3 = x + xh
        c = xh ^ x3
        n_pos = x3 & c
        n_minus = xh & c
        return bin(n_pos)[2:], bin(n_minus)[2:]

    r_pos, r_neg = convert2naf(steps)

    mask = (poly_degree >> 1) - 1
    glk_col_pos_idx = []
    for idx, digit in enumerate(r_pos):
        if int(digit) == 0:
            continue

        step_idx = len(r_pos) - idx - 1
        step = 2**step_idx & mask
        if step == 0:
            continue

        glk_col_pos_idx.append(step_idx)

    glk_col_neg_idx = []
    for idx, digit in enumerate(r_neg):
        if int(digit) == 0:
            continue

        step_idx = len(r_neg) - idx - 1
        step = (poly_degree >> 1) - (2**step_idx & mask)

        glk_col_neg_idx.append(step_idx)

    return glk_col_pos_idx, glk_col_neg_idx


def get_galois_element_for_column_rotation_by(rot: int, poly_degree: int, galois_gen=GALOIS_GEN):
    poly_degree_mask = (poly_degree << 1) - 1
    return pow(galois_gen, rot & poly_degree_mask, poly_degree << 1)


def get_galois_element_for_row_rotation(poly_degree: int):
    return (poly_degree << 1) - 1


def random_id():
    while True:
        asc = ''.join(random.choices(string.ascii_lowercase, k=12))
        if asc not in random_ids:
            random_ids.add(asc)
            break
    return asc


class Param:
    def __init__(self, algo: Algo, n: int = 8192):
        self.algo: Algo = algo
        self.n: int = n
        self.p: list[int] = []
        self.q: list[int] = []
        self.max_level: int = -1

    def get_max_sp_level(self):
        return len(self.p) - 1

    def _load_parameter(self):
        parameter_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'parameter.json')

        with open(parameter_path, 'r') as f:
            parameters = json.load(f)

        if self.algo.value not in parameters:
            raise ValueError(f'Unsupported algorithm type: {self.algo.value}')

        algo_params = parameters[self.algo.value]
        if str(self.n) not in algo_params:
            raise ValueError(f'Unsupported n value for algorithm {self.algo.value}: {self.n}')

        return algo_params[str(self.n)]


class BfvParam(Param):
    def __init__(self, n: int = 8192):
        super().__init__(Algo.BFV, n)
        self.t: int = -1

    @classmethod
    def create_default_param(cls, n: int):
        instance = cls(n)

        param_json = instance._load_parameter()

        for p in param_json['p']:
            instance.p.append(p)
        for q in param_json['q']:
            instance.q.append(q)
        instance.t = param_json['t']

        instance.max_level = param_json['max_level']

        return instance

    @classmethod
    def create_custom_param(cls, n: int, q: List[int], p: List[int], t: int):
        instance = cls(n)
        instance.q = q
        instance.p = p
        instance.t = t
        instance.max_level = len(q) - 1
        return instance

    @classmethod
    def create_fpga_param(cls, t: int = 0x1B4001):
        instance = cls(n=8192)
        instance.q = [0x7F4E0001, 0x7FB40001, 0x7FD20001, 0x7FEA0001, 0x7FF80001, 0x7FFE0001]
        instance.p = [0xFF5A0001]
        instance.t = t
        instance.max_level = len(instance.q) - 1
        return instance


class CkksParam(Param):
    def __init__(self, n: int = 8192, slots: int = 0, scale: float = 0.0):
        super().__init__(Algo.CKKS, n)
        if slots == 0:
            self.slots: int = n // 2
        else:
            self._validate_slots(slots)
            self.slots: int = slots
        self.scale: float = scale

    def _validate_slots(self, slots: int):
        if slots % 2 != 0:
            raise ValueError(f'slots must be a multiple of 2, got {slots}')
        if slots <= 0 or slots > self.n // 2:
            raise ValueError(f'slots must be in range (0, {self.n // 2}], got {slots}')

    def set_slots(self, slots: int):
        self._validate_slots(slots)
        self.slots = slots

    def set_scale(self, scale: float):
        self.scale = scale

    @classmethod
    def create_default_param(cls, n: int):
        instance = cls(n)

        param_json = instance._load_parameter()

        for p in param_json['p']:
            instance.p.append(p)
        for q in param_json['q']:
            instance.q.append(q)

        instance.max_level = param_json['max_level']
        instance.slots = param_json['slots']
        instance.scale = param_json['scale']

        return instance

    @classmethod
    def create_custom_param(cls, n: int, q: List[int], p: List[int], slots: int = 0, scale: float = 0.0):
        instance = cls(n, slots, scale)
        instance.q = q
        instance.p = p
        instance.max_level = len(q) - 1
        return instance

    @classmethod
    def create_fpga_param(cls):
        instance = cls(n=8192)
        instance.q = [0x7F4E0001, 0x7FB40001, 0x7FD20001, 0x7FEA0001, 0x7FF80001, 0x7FFE0001]
        instance.p = [0xFF5A0001]
        instance.max_level = len(instance.q) - 1
        instance.scale = 1 << 31
        return instance


class CkksBtpParam(CkksParam):
    """CKKS bootstrap parameter class. Set sparse packing via create_sparse_param()
    or by inheriting from CkksParam.set_slots(); trace compensation is handled by
    the bootstrap op via rotations_for_bootstrapping().
    """

    def __init__(self, n: int = 1 << 16):
        super().__init__(n)
        self.cts_params: EncodingMatrixParams = None
        self.stc_params: EncodingMatrixParams = None
        self.eval_mod_params: EvalModParams = None
        self.btp_output_level: int = -1
        self.btp_cts_start_level: int = -1
        self.btp_eval_mod_start_level: int = -1
        self.btp_stc_start_level: int = -1

    def is_sparse(self) -> bool:
        return self.slots < (self.n // 2)

    @classmethod
    def create_toy_param(cls):
        """Create CKKS Toy Bootstrap parameters (N16QP1546H192H32 with n=8192)."""
        instance = cls(n=8192)

        instance.q = [
            0x10000000006E0001,  # 60 Q0
            0x10000140001,  # 40
            0xFFFFE80001,  # 40
            0xFFFFC40001,  # 40
            0x100003E0001,  # 40
            0xFFFFB20001,  # 40
            0x10000500001,  # 40
            0xFFFF940001,  # 40
            0xFFFF8A0001,  # 40
            0xFFFF820001,  # 40
            0x7FFFE60001,  # 39 StC
            0x7FFFE40001,  # 39 StC
            0x7FFFE00001,  # 39 StC
            0xFFFFFFFFF840001,  # 60 Sine (double angle)
            0x1000000000860001,  # 60 Sine (double angle)
            0xFFFFFFFFF6A0001,  # 60 Sine
            0x1000000000980001,  # 60 Sine
            0xFFFFFFFFF5A0001,  # 60 Sine
            0x1000000000B00001,  # 60 Sine
            0x1000000000CE0001,  # 60 Sine
            0xFFFFFFFFF2A0001,  # 60 Sine
            0x100000000060001,  # 56 CtS
            0xFFFFFFFFF00001,  # 56 CtS
            0xFFFFFFFFD80001,  # 56 CtS
            0x1000000002A0001,  # 56 CtS
        ]
        instance.p = [
            0x1FFFFFFFFFE00001,  # 61
            0x1FFFFFFFFFC80001,  # 61
            0x1FFFFFFFFFB40001,  # 61
            0x1FFFFFFFFF500001,  # 61
            0x1FFFFFFFFF420001,  # 61
        ]
        instance.max_level = len(instance.q) - 1
        instance.scale = 1 << 40

        instance.stc_params = EncodingMatrixParams(
            linear_transform_type=LinearTransformType.SlotsToCoeffs,
            repack_imag_2_real=True,
            level_start=12,
            bsgs_ratio=2.0,
            bit_reversed=False,
            scaling_factor=[
                [0x7FFFE60001],
                [0x7FFFE40001],
                [0x7FFFE00001],
            ],
        )

        instance.eval_mod_params = EvalModParams(
            q=0x10000000006E0001,
            level_start=20,
            sine_type=SineType.Cos1,
            message_ratio=256.0,
            k=16,
            sine_deg=30,
            double_angle=3,
            arcsine_deg=0,
            scaling_factor=1 << 60,
        )

        instance.cts_params = EncodingMatrixParams(
            linear_transform_type=LinearTransformType.CoeffsToSlots,
            repack_imag_2_real=True,
            level_start=24,
            bsgs_ratio=2.0,
            bit_reversed=False,
            scaling_factor=[
                [0x100000000060001],
                [0xFFFFFFFFF00001],
                [0xFFFFFFFFD80001],
                [0x1000000002A0001],
            ],
        )

        instance.btp_output_level = 9

        return instance

    @classmethod
    def create_default_param(cls):
        """Create CKKS Bootstrap parameters (N16QP1546H192H32 with n=65536)."""
        instance = cls(n=1 << 16)

        instance.q = [
            0x10000000006E0001,  # 60 Q0
            0x10000140001,  # 40
            0xFFFFE80001,  # 40
            0xFFFFC40001,  # 40
            0x100003E0001,  # 40
            0xFFFFB20001,  # 40
            0x10000500001,  # 40
            0xFFFF940001,  # 40
            0xFFFF8A0001,  # 40
            0xFFFF820001,  # 40
            0x7FFFE60001,  # 39 StC
            0x7FFFE40001,  # 39 StC
            0x7FFFE00001,  # 39 StC
            0xFFFFFFFFF840001,  # 60 Sine (double angle)
            0x1000000000860001,  # 60 Sine (double angle)
            0xFFFFFFFFF6A0001,  # 60 Sine
            0x1000000000980001,  # 60 Sine
            0xFFFFFFFFF5A0001,  # 60 Sine
            0x1000000000B00001,  # 60 Sine
            0x1000000000CE0001,  # 60 Sine
            0xFFFFFFFFF2A0001,  # 60 Sine
            0x100000000060001,  # 56 CtS
            0xFFFFFFFFF00001,  # 56 CtS
            0xFFFFFFFFD80001,  # 56 CtS
            0x1000000002A0001,  # 56 CtS
        ]
        instance.p = [
            0x1FFFFFFFFFE00001,  # 61
            0x1FFFFFFFFFC80001,  # 61
            0x1FFFFFFFFFB40001,  # 61
            0x1FFFFFFFFF500001,  # 61
            0x1FFFFFFFFF420001,  # 61
        ]
        instance.max_level = len(instance.q) - 1
        instance.scale = 1 << 40

        instance.stc_params = EncodingMatrixParams(
            linear_transform_type=LinearTransformType.SlotsToCoeffs,
            repack_imag_2_real=True,
            level_start=12,
            bsgs_ratio=2.0,
            bit_reversed=False,
            scaling_factor=[
                [0x7FFFE60001],
                [0x7FFFE40001],
                [0x7FFFE00001],
            ],
        )

        instance.eval_mod_params = EvalModParams(
            q=0x10000000006E0001,
            level_start=20,
            sine_type=SineType.Cos1,
            message_ratio=256.0,
            k=16,
            sine_deg=30,
            double_angle=3,
            arcsine_deg=0,
            scaling_factor=1 << 60,
        )

        instance.cts_params = EncodingMatrixParams(
            linear_transform_type=LinearTransformType.CoeffsToSlots,
            repack_imag_2_real=True,
            level_start=24,
            bsgs_ratio=2.0,
            bit_reversed=False,
            scaling_factor=[
                [0x100000000060001],
                [0xFFFFFFFFF00001],
                [0xFFFFFFFFD80001],
                [0x1000000002A0001],
            ],
        )

        instance.btp_output_level = 9

        return instance

    # Lattigo's genWfftIndexMap panics below this (CTS/STC depth exceeds slots).
    _MIN_LOG_SLOTS = 4

    @classmethod
    def create_sparse_param(cls, log_slots: int, n: int = 1 << 16):
        """Create sparse CKKS bootstrap params: 2^log_slots active slots."""
        max_log_slots = int(math.log2(n)) - 2
        if log_slots < cls._MIN_LOG_SLOTS or log_slots > max_log_slots:
            raise ValueError(f'log_slots must be in [{cls._MIN_LOG_SLOTS}, {max_log_slots}] for n={n}, got {log_slots}')
        instance = cls.create_default_param() if n == (1 << 16) else cls.create_toy_param()
        instance.set_slots(1 << log_slots)
        return instance

    @classmethod
    def create_toy_sparse_param(cls, log_slots: int):
        """Sparse toy params (n=8192). Insecure; for development only."""
        return cls.create_sparse_param(log_slots, n=1 << 13)

    def rotations_for_bootstrapping(self) -> list[int]:
        log_n = int(math.log2(self.n))
        log_slots = int(math.log2(self.slots))

        self.cts_params.log_n = log_n
        self.cts_params.log_slots = log_slots
        self.stc_params.log_n = log_n
        self.stc_params.log_slots = log_slots

        rots: list[int] = []

        # SubSum rotations: needed when using sparse encoding (log_slots < log_n - 1)
        for i in range(log_slots, log_n - 1):
            if (1 << i) not in rots:
                rots.append(1 << i)

        rots += self.cts_params.rotations()
        rots += self.stc_params.rotations()

        return list(set(rots))


def set_fhe_param(param: 'Param') -> None:
    """Set the global FHE parameters.

    Must be called before any FHE operations.
    This function sets the global parameter object used by all subsequent FHE operations.

    @param param: FHE parameter object containing algorithm type, polynomial degree n, moduli, etc.

    Example:
        param = Param.create_default_param(algo='BFV', n=16384)
        set_fhe_param(param)
    """
    global g_param
    g_param = param


class Argument:
    """
    @class Argument
    @brief Describes input, output, and offline input data arguments for a task.
    """

    def __init__(self, arg_id: str, data: 'DataNode | list') -> None:
        """
        @brief Constructor.
        @param arg_id: Custom argument ID.
        @param data: Data. Can be a single data node, a list/tuple of data nodes, or nested lists/tuples.
        """

        if not isinstance(arg_id, str):
            raise ValueError(f'Argument id should be str. Please check your argument-id "{arg_id}".')
        self.id = arg_id
        if not data:
            raise ValueError('Argument data can not be none. Please check your argument-id.')
        if isinstance(data, DataNode):
            self.data: list = [data]
        else:
            assert isinstance(data, list)
            self.data = data


class DataNode:
    """
    @class DataNode
    @brief Data node base class.

    Base class for all data nodes, containing only basic attributes: type, id, index.
    """

    def __init__(self, type, id='') -> None:
        """
        @brief Constructor.
        @param type: Node type.
        @param id: Node ID.
        """
        self.type = type
        self.id: str = id
        if self.id == '':
            self.id = random_id()
        self.index: int = gen_data_node_index()

    def __repr__(self) -> str:
        return self.id


class FheDataNode(DataNode):
    """
    @class FheDataNode
    @brief FHE data node type; use its subclasses in practice.

    Contains FHE data types such as plaintext, ciphertext, keys, etc.
    Has FHE-related attributes like level, degree, is_ntt.
    """

    def __init__(
        self,
        type: DataType,
        id='',
        degree=-1,
        level=DEFAULT_LEVEL,
    ) -> None:
        """
        @brief Constructor.
        @param type: DataType enum value.
        @param id: Custom node ID.
        @param degree: Polynomial degree.
        @param level: Data level.
        """
        super().__init__(type=type, id=id)
        self.level: int = level
        self.degree: int = degree
        self.is_ntt = False
        self.is_mform = False
        self.sp_level: int | None = None

    def to_json_dict(self) -> dict:
        d = {
            'id': self.id,
            'type': self.type.value,
            'level': self.level,
            'degree': self.degree,
            'is_ntt': self.is_ntt,
            'is_mform': self.is_mform,
        }
        if self.sp_level is not None:
            d['sp_level'] = self.sp_level
        if isinstance(self, BfvCompressedPlaintextRingtNode):
            d['is_compressed'] = self.is_compressed
        if isinstance(self, CiphertextNode):
            d['poly1_rns_sp_decomped'] = self.poly1_rns_sp_decomped
        if isinstance(self, GaloisKeyNode):
            d['galois_element'] = self.galois_element
        return d


class CustomDataNode(DataNode):
    """
    @class CustomDataNode
    @brief Custom data node type.

    Allows users to create data nodes with custom types and attributes.
    """

    def __init__(self, type: str, id='', attributes: dict | None = None) -> None:
        """
        @brief Constructor.
        @param type: String identifier for the custom data type.
        @param id: Node ID.
        @param attributes: Custom attribute dictionary; can contain arbitrary key-value pairs.
        """
        super().__init__(type=type, id=id)
        self.attributes = attributes if attributes is not None else {}

    def __repr__(self) -> str:
        return f'(custom_{self.type}, {self.id})'

    def to_json_dict(self) -> dict:
        d = {
            'id': self.id,
            'type': self.type,
            'is_custom': True,
        }
        if self.attributes:
            d['attributes'] = self.attributes
        return d


class PlaintextNode(FheDataNode):
    """
    @class PlaintextNode
    @brief Plaintext type.
    """

    def __init__(self, type, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(type, id, 0, level)


class BfvPlaintextNode(PlaintextNode):
    """
    @class BfvPlaintextNode
    @brief BFV plaintext type.
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Plaintext, id, level)


class BfvPlaintextRingtNode(PlaintextNode):
    """
    @class BfvPlaintextRingtNode
    @brief Plaintext in ring-t representation, used for ciphertext-plaintext multiplication.
    """

    def __init__(self, id='') -> None:
        super().__init__(DataType.PlaintextRingt, id, 0)


class BfvCompressedPlaintextRingtNode(BfvPlaintextRingtNode):
    """
    @class BfvCompressedPlaintextRingtNode
    @brief Compressed plaintext in ring-t representation, used for ciphertext-plaintext multiplication.
    """

    def __init__(self, id='', compressed_block_info: list | None = None) -> None:
        super().__init__(id)
        assert compressed_block_info is not None
        self.compressed_block_info = compressed_block_info
        self.is_compressed = True


class BfvPlaintextMulNode(PlaintextNode):
    """
    @class BfvPlaintextMulNode
    @brief Plaintext type for ciphertext-plaintext multiplication.
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.PlaintextMul, id, level)
        self.is_ntt = True
        self.is_mform = True


class CkksPlaintextNode(PlaintextNode):
    """
    @class CkksPlaintextNode
    @brief CKKS plaintext type.
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Plaintext, id, level)
        self.is_ntt = True


class CkksPlaintextRingtNode(PlaintextNode):
    """
    @class CkksPlaintextRingtNode
    @brief CKKS plaintext in ring-t representation, used for ciphertext-plaintext multiplication.
    """

    def __init__(self, id='') -> None:
        super().__init__(DataType.PlaintextRingt, id, 0)
        self.is_ntt = False


class CkksPlaintextMulNode(PlaintextNode):
    """
    @class CkksPlaintextMulNode
    @brief CKKS plaintext type for ciphertext-plaintext multiplication.
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.PlaintextMul, id, level)
        self.is_ntt = True
        self.is_mform = True


class CiphertextNode(FheDataNode):
    """
    @class CiphertextNode
    @brief Ciphertext type.
    """

    def __init__(self, type=DataType.Ciphertext, id='', degree=1, level=DEFAULT_LEVEL) -> None:
        super().__init__(type, id, degree, level)
        self.poly1_rns_sp_decomped: bool = False


class BfvCiphertextNode(CiphertextNode):
    """
    @class BfvCiphertextNode
    @brief BFV ciphertext type, containing 2 polynomials.
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext, id, 1, level)


class BfvCiphertext3Node(CiphertextNode):
    """
    @class BfvCiphertext3Node
    @brief BFV ciphertext type, containing 3 polynomials.
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext3, id, 2, level)


class CkksCiphertextNode(CiphertextNode):
    """
    @class CkksCiphertextNode
    @brief CKKS ciphertext type, containing 2 polynomials.
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext, id, 1, level)
        self.is_ntt = True


class CkksCiphertext3Node(CiphertextNode):
    """
    @class CkksCiphertext3Node
    @brief CKKS ciphertext type, containing 3 polynomials.
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext3, id, 2, level)
        self.is_ntt = True


class SwitchKeyNode(FheDataNode):
    """
    @class SwitchKeyNode
    @brief Switch key type.
    """

    def __init__(self, id='', level=DEFAULT_LEVEL, sp_level=DEFAULT_LEVEL, type=DataType.SwitchKey) -> None:
        super().__init__(type=type, id=id, degree=1, level=level)
        self.is_ntt = True
        self.is_mform = True
        self.sp_level = sp_level


class RelinKeyNode(SwitchKeyNode):
    """
    @class RelinKeyNode
    @brief Relinearization key type.
    """

    def __init__(self, level=DEFAULT_LEVEL) -> None:
        assert g_param is not None
        super().__init__(id='rlk_ntt', level=level, sp_level=g_param.get_max_sp_level(), type=DataType.RelinKey)


class GaloisKeyNode(SwitchKeyNode):
    """
    @class GaloisKeyNode
    @brief Galois key type.
    """

    def __init__(self, id, level=DEFAULT_LEVEL) -> None:
        assert g_param is not None
        super().__init__(id=id, level=level, sp_level=g_param.get_max_sp_level(), type=DataType.GaloisKey)
        self.galois_element = (
            int(self.id.split('_')[-1]) if 'col' in self.id else get_galois_element_for_row_rotation(g_param.n)
        )


class ComputeNode:
    """
    @class ComputeNode
    @brief Compute node base class.

    Base class for all compute nodes, containing only basic attributes: type, id, index.
    """

    def __init__(self, type) -> None:
        """
        @brief Constructor.
        @param type: Operation type.
        """
        self.type = type
        self.id = random_id()
        self.index: int = gen_compute_node_index()

    def __repr__(self):
        return f'({self.type}, {self.id})'


class FheComputeNode(ComputeNode):
    """
    @class FheComputeNode
    @brief FHE compute node type.

    Contains FHE operation types with attributes like compressed_block_info.
    """

    def __init__(self, type: OperationType) -> None:
        """
        @brief Constructor.
        @param type: OperationType enum value.
        """
        super().__init__(type=type)
        self.compressed_block_info: list | None = None

    def __repr__(self):
        return f'({self.type.value}, {self.id})'

    def to_json_dict(self, dag: nx.DiGraph) -> dict:
        d = {
            'id': self.id,
            'type': self.type.value,
            'inputs': [y.index for y in dag.predecessors(self)],
            'outputs': [s.index for s in dag.successors(self)],
        }
        if isinstance(self, RotateColUnitNode):
            d['step'] = self.step
            if self.lib != Lib.Lattigo:
                d['lib'] = self.lib.value
        elif isinstance(self, RotateRowUnitNode):
            if self.lib != Lib.Lattigo:
                d['lib'] = self.lib.value
        elif isinstance(self, (CmpSumComputeNode, CmpacSumComputeNode)):
            d['sum_cnt'] = self.sum_cnt
            d['pt_type'] = self.pt_type.value if isinstance(self.pt_type, DataType) else self.pt_type
        if self.compressed_block_info is not None:
            d['compressed_block_info'] = self.compressed_block_info
        return d


class CustomComputeNode(ComputeNode):
    """
    @class CustomComputeNode
    @brief Custom compute node type.

    Allows users to create compute nodes with custom attributes and metadata.
    """

    def __init__(self, type: str, attributes: dict | None = None) -> None:
        """
        @brief Constructor.
        @param type: String identifier for the custom operation type.
        @param attributes: Custom attribute dictionary; can contain arbitrary key-value pairs.
        """
        super().__init__(type=type)
        self.attributes = attributes if attributes is not None else {}

    def __repr__(self):
        return f'(custom_{self.type}, {self.id})'

    def to_json_dict(self, dag: nx.DiGraph) -> dict:
        d = {
            'id': self.id,
            'type': self.type,
            'is_custom': True,
            'inputs': [y.index for y in dag.predecessors(self)],
            'outputs': [s.index for s in dag.successors(self)],
        }
        if self.attributes:
            d['attributes'] = self.attributes
        return d


class CmpSumComputeNode(FheComputeNode):
    """
    @class CmpSumComputeNode
    @brief CmpSum compute node type.
    """

    def __init__(self, sum_cnt) -> None:
        super().__init__(type=OperationType.CmpSum)
        self.sum_cnt = sum_cnt
        self.pt_type: DataType | str = ''


class CmpacSumComputeNode(FheComputeNode):
    """
    @class CmpacSumComputeNode
    @brief CmpacSum compute node type.
    """

    def __init__(self, sum_cnt) -> None:
        super().__init__(type=OperationType.CmpacSum)
        self.sum_cnt = sum_cnt
        self.pt_type: DataType | str = ''


class RotateColUnitNode(FheComputeNode):
    """
    @class RotateColUnitNode
    @brief Column rotation unit type.
    """

    def __init__(self, step: int, lib=Lib.Lattigo) -> None:
        super().__init__(type=OperationType.RotateCol)
        self.step = step
        self.lib = lib


class RotateRowUnitNode(FheComputeNode):
    """
    @class RotateRowUnitNode
    @brief Row rotation unit type.
    """

    def __init__(self, lib=Lib.Lattigo) -> None:
        super().__init__(type=OperationType.RotateRow)
        self.lib = lib


class FpgaKernelNode(FheComputeNode):
    """
    @class FpgaKernelComputeNode
    @brief FPGA kernel composite compute node type.

    Represents a composite FPGA sub-project operator in a heterogeneous computation graph.
    Used in the top-level mega_ag to encapsulate one FPGA sub-project partition.
    """

    def __init__(self) -> None:
        super().__init__(type=OperationType.FpgaKernel)


def add(
    x: BfvCiphertextNode
    | BfvPlaintextNode
    | BfvPlaintextRingtNode
    | CkksCiphertextNode
    | CkksPlaintextNode
    | CkksPlaintextRingtNode,
    y: BfvCiphertextNode
    | BfvPlaintextNode
    | BfvPlaintextRingtNode
    | CkksCiphertextNode
    | CkksPlaintextNode
    | CkksPlaintextRingtNode,
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Addition

    Define an addition computation step. Supported types: ct+ct, ct+pt, pt+ct.
    @param x Input data node.
    @param y Input data node.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    if (
        not isinstance(x, BfvPlaintextRingtNode)
        and not isinstance(y, BfvPlaintextRingtNode)
        and not isinstance(x, CkksPlaintextRingtNode)
        and not isinstance(y, CkksPlaintextRingtNode)
    ):
        assert x.level == y.level and x.is_ntt == y.is_ntt

    op = FheComputeNode(OperationType.Add)

    if x.type == DataType.Ciphertext and y.type == DataType.Ciphertext:
        if x.id == y.id:
            g_dag.add_edges_from([(x, op)])
        else:
            g_dag.add_edges_from([(x, op), (y, op)])
    elif x.type == DataType.Ciphertext and y.type in [DataType.Plaintext, DataType.PlaintextRingt]:
        g_dag.add_edges_from([(x, op), (y, op)])
    elif x.type in [DataType.Plaintext, DataType.PlaintextRingt] and y.type == DataType.Ciphertext:
        g_dag.add_edges_from([(y, op), (x, op)])
    else:
        raise ValueError(f'Unsupported input types "{x.type.value}" and "{y.type.value}" for addition.')

    z = CiphertextNode()
    if isinstance(x, BfvCiphertextNode) or isinstance(x, BfvPlaintextNode) or isinstance(x, BfvPlaintextRingtNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    elif isinstance(x, CkksCiphertextNode) or isinstance(x, CkksPlaintextNode) or isinstance(x, CkksPlaintextRingtNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    else:
        raise ValueError()
    z.is_ntt = x.is_ntt
    g_dag.add_edge(op, z)
    return z


def sub(
    x: BfvCiphertextNode | CkksCiphertextNode,
    y: BfvCiphertextNode
    | BfvPlaintextNode
    | BfvPlaintextRingtNode
    | CkksCiphertextNode
    | CkksPlaintextNode
    | CkksPlaintextRingtNode,
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Subtraction

    Define a subtraction computation step. Supported types: ct-ct, ct-pt.
    @param x Input data node.
    @param y Input data node.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    if not isinstance(y, BfvPlaintextRingtNode) and not isinstance(y, CkksPlaintextRingtNode):
        assert x.level == y.level and x.is_ntt == y.is_ntt

    op = FheComputeNode(OperationType.Sub)
    g_dag.add_edges_from([(x, op), (y, op)])
    if (
        (x.type == DataType.Ciphertext and y.type == DataType.Ciphertext)
        or (x.type == DataType.Ciphertext and y.type == DataType.Plaintext)
        or (x.type == DataType.Ciphertext and y.type == DataType.PlaintextRingt)
    ):
        pass
    else:
        raise ValueError(f'Unsupported input types "{x.type.value}" and "{y.type.value}" for addition.')

    z = CiphertextNode()
    if isinstance(x, BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    elif isinstance(x, CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    else:
        raise ValueError()
    z.is_ntt = x.is_ntt
    g_dag.add_edge(op, z)
    return z


def neg(
    x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    global g_dag
    op = FheComputeNode(OperationType.Neg)
    g_dag.add_edges_from([(x, op)])

    z = CiphertextNode()
    if isinstance(x, BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    elif isinstance(x, CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    else:
        raise ValueError()
    z.is_ntt = x.is_ntt
    g_dag.add_edge(op, z)
    return z


def to_mul(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode:
    global g_dag
    assert x.level >= 0 and not x.is_ntt and not x.is_mform
    op = FheComputeNode(OperationType.ToMul)
    g_dag.add_edges_from([(x, op)])
    z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    z.is_ntt = True
    z.is_mform = True
    g_dag.add_edge(op, z)
    return z


def to_ntt(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode:
    global g_dag
    assert x.level >= 0 and not x.is_ntt
    op = FheComputeNode(OperationType.ToNtt)
    g_dag.add_edges_from([(x, op)])
    z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    z.is_ntt = True
    g_dag.add_edge(op, z)
    return z


def to_mform(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode:
    global g_dag
    assert x.level >= 0 and not x.is_mform
    op = FheComputeNode(OperationType.ToMForm)
    g_dag.add_edges_from([(x, op)])
    z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    z.is_ntt = x.is_ntt
    z.is_mform = True
    g_dag.add_edge(op, z)
    return z


def to_inv_ntt(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode:
    global g_dag
    assert x.level >= 0 and x.is_ntt
    op = FheComputeNode(OperationType.ToInvNtt)
    g_dag.add_edges_from([(x, op)])
    z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    g_dag.add_edge(op, z)
    return z


def mult(
    x: BfvCiphertextNode
    | BfvPlaintextNode
    | BfvPlaintextRingtNode
    | BfvPlaintextMulNode
    | CkksCiphertextNode
    | CkksPlaintextNode
    | CkksPlaintextRingtNode
    | CkksPlaintextMulNode,
    y: BfvCiphertextNode
    | BfvPlaintextNode
    | BfvPlaintextRingtNode
    | BfvPlaintextMulNode
    | CkksCiphertextNode
    | CkksPlaintextNode
    | CkksPlaintextRingtNode
    | CkksPlaintextMulNode,
    output_id: Optional[str] = None,
    start_block_idx: int | None = None,
) -> BfvCiphertextNode | BfvCiphertext3Node | CkksCiphertextNode | CkksCiphertext3Node:
    """!Multiplication

    Define a multiplication computation step. Supported types: ct*ct, ct*pt_ringt, pt_ringt*ct, ct*pt_mul, pt_mul*ct.
    @param x Input data node.
    @param y Input data node.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    op = FheComputeNode(OperationType.Mult)

    if x.type == DataType.Ciphertext and y.type == DataType.Ciphertext:
        assert x.level == y.level
        assert x.degree == y.degree == 1
        assert x.is_ntt == y.is_ntt
        z_degree = 2
        z_ntt = x.is_ntt
        if x.id == y.id:
            g_dag.add_edges_from([(x, op)])
        else:
            g_dag.add_edges_from([(x, op), (y, op)])
    elif x.type == DataType.Ciphertext and y.type in [
        DataType.Plaintext,
        DataType.PlaintextRingt,
        DataType.PlaintextMul,
    ]:
        assert x.level == y.level or y.level == 0
        assert x.degree == 1
        z_degree = 1
        z_ntt = x.is_ntt
        g_dag.add_edges_from([(x, op), (y, op)])
        if isinstance(y, BfvCompressedPlaintextRingtNode):
            assert start_block_idx is not None
            op.compressed_block_info = [y.compressed_block_info[start_block_idx]]
    elif (
        x.type in [DataType.Plaintext, DataType.PlaintextRingt, DataType.PlaintextMul] and y.type == DataType.Ciphertext
    ):
        assert x.level == y.level or x.level == 0
        assert y.degree == 1
        z_degree = 1
        z_ntt = y.is_ntt
        g_dag.add_edges_from([(y, op), (x, op)])
        if isinstance(x, BfvCompressedPlaintextRingtNode):
            assert start_block_idx is not None
            op.compressed_block_info = [x.compressed_block_info[start_block_idx]]
    else:
        raise ValueError(f'Unsupported input types "{x.type.value}" and "{y.type.value}" for multiplication.')

    z = CiphertextNode()
    if (
        isinstance(x, BfvCiphertextNode)
        or isinstance(x, BfvPlaintextNode)
        or isinstance(x, BfvPlaintextRingtNode)
        or isinstance(x, BfvPlaintextMulNode)
    ):
        if z_degree == 1:
            z = BfvCiphertextNode(
                id=random_id() if output_id is None else output_id,
                level=x.level,
            )
        else:
            assert z_degree == 2
            z = BfvCiphertext3Node(
                id=random_id() if output_id is None else output_id,
                level=x.level,
            )
    elif (
        isinstance(x, CkksCiphertextNode)
        or isinstance(x, CkksPlaintextNode)
        or isinstance(x, CkksPlaintextRingtNode)
        or isinstance(x, CkksPlaintextMulNode)
    ):
        if z_degree == 1:
            z = CkksCiphertextNode(
                id=random_id() if output_id is None else output_id,
                level=x.level,
            )
        else:
            assert z_degree == 2
            z = CkksCiphertext3Node(
                id=random_id() if output_id is None else output_id,
                level=x.level,
            )

    else:
        raise ValueError()
    z.is_ntt = z_ntt
    g_dag.add_edge(op, z)

    return z


def relin(
    x: BfvCiphertext3Node | CkksCiphertext3Node, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Relinearization

    Define a relinearization computation step.
    @param x Input data node.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    if x.type != DataType.Ciphertext3:
        raise ValueError(f'Unsupported input type "{x.type.value}" for relinerization.')

    rlk = 'rlk_ntt'
    global g_swk_node_dict
    if rlk not in g_swk_node_dict:
        g_swk_node_dict[rlk] = RelinKeyNode(level=x.level)
    elif x.level > g_swk_node_dict[rlk].level:
        g_swk_node_dict[rlk].level = x.level
    op = FheComputeNode(OperationType.Relin)
    g_dag.add_edges_from([(x, op), (g_swk_node_dict[rlk], op)])

    z = CiphertextNode()
    if isinstance(x, BfvCiphertext3Node):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    elif isinstance(x, CkksCiphertext3Node):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    else:
        raise ValueError()
    z.is_ntt = x.is_ntt
    g_dag.add_edge(op, z)

    return z


def mult_relin(
    x: BfvCiphertextNode | CkksCiphertextNode, y: BfvCiphertextNode | CkksCiphertextNode, output_id=None
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Ciphertext multiplication with relinearization

    Define a ciphertext multiplication followed by relinearization step.
    @param x Input data node.
    @param y Input data node.
    @param output_id Output node ID.
    @return Result data node.
    """
    ct3 = mult(x, y, f'{output_id}_ct3' if output_id is not None else None)
    assert isinstance(ct3, (BfvCiphertext3Node, CkksCiphertext3Node))
    return relin(ct3, output_id)


def rescale(
    x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Rescale

    Define a rescale (modulus switching) computation step.
    @param x Input data node.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rescale.')
    op = FheComputeNode(OperationType.Rescale)
    g_dag.add_edges_from([(x, op)])
    z = CiphertextNode()
    if isinstance(x, BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level - 1)
    elif isinstance(x, CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level - 1)
    else:
        raise ValueError()
    z.is_ntt = x.is_ntt
    g_dag.add_edge(op, z)
    return z


def drop_level(x: CkksCiphertextNode, drop_level: int = 1, output_id: Optional[str] = None) -> CkksCiphertextNode:
    """!Drop level

    Define a drop-level computation step.
    @param x Input data node.
    @param drop_level Number of levels to drop.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for drop level.')
    if x.level < drop_level:
        raise ValueError('Dropped levels must not be larger than input level.')

    input = [x]
    z: CkksCiphertextNode | None = None
    for lv in range(drop_level):
        op = FheComputeNode(OperationType.DropLevel)
        g_dag.add_edges_from([(i, op) for i in input])
        if lv != drop_level - 1:
            z = CkksCiphertextNode(id=random_id(), level=input[0].level - 1)
        else:
            z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=input[0].level - 1)
        g_dag.add_edge(op, z)
        if lv != drop_level - 1:
            input = [z]
    assert z is not None
    return z


def rns_sp_decomp(x: CiphertextNode, output_id: Optional[str] = None) -> CiphertextNode:
    global g_dag
    op = FheComputeNode(OperationType.RnsSpDecomp)
    g_dag.add_edges_from([(x, op)])
    y = CiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    y.is_ntt = x.is_ntt
    y.poly1_rns_sp_decomped = True
    g_dag.add_edge(op, y)
    return y


def rotate_cols(
    x: BfvCiphertextNode | CkksCiphertextNode,
    steps: list[int] | int,
    output_id: Optional[str] = None,
) -> list[BfvCiphertextNode | CkksCiphertextNode]:
    """!Ciphertext rotation

    Define a ciphertext rotation computation step.
    @param x Input data node.
    @param steps Rotation steps (positive = left rotation, negative = right rotation).
    @param output_id Output node ID.
    @return Result data node.
    """

    global g_dag, g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using rotation operations.')

    rot_type = 'hybrid'
    assert rot_type in ['hybrid', 'hoisted']
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')

    if isinstance(steps, int):
        steps = [steps]

    output = list()
    ct1_ntt_sp = dict()
    rotated_input = dict()

    for step in steps:
        glk_col_pos_idx, glk_col_neg_idx = get_glk_col(step, g_param.n)
        sub_steps = list()
        for idx in glk_col_pos_idx:
            sub_steps.append(2**idx)
        for idx in glk_col_neg_idx:
            sub_steps.append(-1 * (2**idx))

        sub_steps_sum = 0
        rotated_input[sub_steps_sum] = x
        for sub_step in sub_steps:
            # skip for rotate in place
            if math.fabs(sub_step) % (g_param.n / 2) == 0:
                continue

            if sub_steps_sum + sub_step not in rotated_input:
                gal_elem = get_galois_element_for_column_rotation_by(sub_step, g_param.n)

                glk = f'glk_ntt_col_{gal_elem}'

                global g_swk_node_dict
                if glk not in g_swk_node_dict:
                    g_swk_node_dict[glk] = GaloisKeyNode(id=glk, level=x.level)
                elif x.level > g_swk_node_dict[glk].level:
                    g_swk_node_dict[glk].level = x.level

                if rot_type == 'hoisted':
                    if sub_steps_sum not in ct1_ntt_sp:
                        ct1_ntt_sp[sub_steps_sum] = rns_sp_decomp(rotated_input[sub_steps_sum])

                    op = RotateColUnitNode(sub_step)
                    g_dag.add_edges_from([(ct1_ntt_sp[sub_steps_sum], op), (g_swk_node_dict[glk], op)])
                    if sub_step != sub_steps[-1]:
                        z = CiphertextNode()
                        if isinstance(x, BfvCiphertextNode):
                            z = BfvCiphertextNode(level=x.level)
                        elif isinstance(x, CkksCiphertextNode):
                            z = CkksCiphertextNode(level=x.level)
                        else:
                            raise ValueError()
                        z.is_ntt = x.is_ntt
                    else:
                        z = CiphertextNode()
                        if isinstance(x, BfvCiphertextNode):
                            z = BfvCiphertextNode(
                                id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level
                            )
                        elif isinstance(x, CkksCiphertextNode):
                            z = CkksCiphertextNode(
                                id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level
                            )
                        else:
                            raise ValueError()
                        z.is_ntt = x.is_ntt
                    g_dag.add_edge(op, z)

                    rotated_input[sub_steps_sum + sub_step] = z

                elif rot_type == 'hybrid':
                    op = RotateColUnitNode(sub_step)
                    g_dag.add_edges_from([(rotated_input[sub_steps_sum], op), (g_swk_node_dict[glk], op)])
                    if sub_step != sub_steps[-1]:
                        z = CiphertextNode()
                        if isinstance(x, BfvCiphertextNode):
                            z = BfvCiphertextNode(level=x.level)
                        elif isinstance(x, CkksCiphertextNode):
                            z = CkksCiphertextNode(level=x.level)
                        else:
                            raise ValueError()
                        z.is_ntt = x.is_ntt
                    else:
                        z = CiphertextNode()
                        if isinstance(x, BfvCiphertextNode):
                            z = BfvCiphertextNode(
                                id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level
                            )
                        elif isinstance(x, CkksCiphertextNode):
                            z = CkksCiphertextNode(
                                id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level
                            )
                        else:
                            raise ValueError()
                        z.is_ntt = x.is_ntt
                    g_dag.add_edge(op, z)

                    rotated_input[sub_steps_sum + sub_step] = z

            sub_steps_sum += sub_step

        output.append(rotated_input[sub_steps_sum])

    return output


def advanced_rotate_cols(
    x: BfvCiphertextNode | CkksCiphertextNode,
    steps: list[int] | int,
    output_id: Optional[str] = None,
    out_ct_type: str = 'ct',
) -> list[BfvCiphertextNode | CkksCiphertextNode]:
    """!Ciphertext rotation

    Define a ciphertext rotation step after preparing the Galois key for the given rotation steps.
    @param x Input data node.
    @param steps Rotation steps (positive = left rotation, negative = right rotation).
    @param output_id Output node ID.
    @param out_ct_type Output ciphertext type; supported types are 'ct', 'ct-ntt', 'ct-ntt-mf'.
    @return Result data node.
    """

    global g_dag, g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using rotation operations.')

    rot_type = 'hybrid'
    assert rot_type in ['hybrid', 'hoisted']
    assert out_ct_type in ['ct', 'ct-ntt', 'ct-ntt-mf']
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')

    if isinstance(steps, int):
        steps = [steps]

    output = list()
    y = rns_sp_decomp(x, f'decomped_{x.id}') if rot_type == 'hoisted' else x

    for step in steps:
        gal_elem = get_galois_element_for_column_rotation_by(step, g_param.n)
        glk = f'glk_ntt_col_{gal_elem}'

        global g_swk_node_dict
        if glk not in g_swk_node_dict:
            g_swk_node_dict[glk] = GaloisKeyNode(id=glk, level=x.level)
        elif x.level > g_swk_node_dict[glk].level:
            g_swk_node_dict[glk].level = x.level

        op = RotateColUnitNode(step)
        g_dag.add_edges_from([(y, op), (g_swk_node_dict[glk], op)])

        z = CiphertextNode()
        if isinstance(x, BfvCiphertextNode):
            z = BfvCiphertextNode(id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level)
            z.is_ntt = 'ntt' in out_ct_type
        elif isinstance(x, CkksCiphertextNode):
            z = CkksCiphertextNode(id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level)
            z.is_ntt = x.is_ntt
        else:
            raise ValueError()

        z.is_mform = 'mf' in out_ct_type
        g_dag.add_edge(op, z)
        output.append(z)
    return output


def rotate_rows(
    x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    global g_dag
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')
    glk = 'glk_ntt_row'

    global g_swk_node_dict
    if glk not in g_swk_node_dict:
        g_swk_node_dict[glk] = GaloisKeyNode(id=glk, level=x.level)
    elif x.level > g_swk_node_dict[glk].level:
        g_swk_node_dict[glk].level = x.level

    op = RotateRowUnitNode()
    g_dag.add_edges_from([(x, op), (g_swk_node_dict[glk], op)])

    z = CiphertextNode()
    if isinstance(x, BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    elif isinstance(x, CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    else:
        raise ValueError()
    z.is_ntt = x.is_ntt
    g_dag.add_edge(op, z)

    return z


def seal_rotate_rows(
    x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    global g_dag
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')
    glk = 'glk_ntt_row'

    global g_swk_node_dict
    if glk not in g_swk_node_dict:
        g_swk_node_dict[glk] = GaloisKeyNode(id=glk, level=x.level)
    elif x.level > g_swk_node_dict[glk].level:
        g_swk_node_dict[glk].level = x.level

    op = RotateRowUnitNode(lib=Lib.SEAL)
    g_dag.add_edges_from([(x, op), (g_swk_node_dict[glk], op)])

    z = CiphertextNode()
    if isinstance(x, BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    elif isinstance(x, CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    else:
        raise ValueError()
    z.is_ntt = x.is_ntt
    g_dag.add_edge(op, z)

    return z


def seal_rotate_cols(
    x: BfvCiphertextNode | CkksCiphertextNode, steps: list[int] | int, output_id: Optional[str] = None
) -> list[BfvCiphertextNode | CkksCiphertextNode]:
    """!Ciphertext rotation (SEAL)

    Define a ciphertext rotation computation step using SEAL library.
    @param x Input data node.
    @param steps Rotation steps (positive = left rotation, negative = right rotation).
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using rotation operations.')

    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')

    if isinstance(steps, int):
        steps = [steps]

    output = list()
    rotated_input = dict()

    for step in steps:
        glk_col_pos_idx, glk_col_neg_idx = get_glk_col(step, g_param.n)
        sub_steps = list()
        for idx in glk_col_pos_idx:
            sub_steps.append(2**idx)
        for idx in glk_col_neg_idx:
            sub_steps.append(-1 * (2**idx))

        sub_steps_sum = 0
        rotated_input[sub_steps_sum] = x
        for sub_step in sub_steps:
            if sub_steps_sum + sub_step not in rotated_input:
                galEl = get_galois_element_for_column_rotation_by(sub_step, g_param.n, galois_gen=SEAL_GALOIS_GEN)
                glk = f'glk_ntt_col_{galEl}'

                global g_swk_node_dict
                if glk not in g_swk_node_dict:
                    g_swk_node_dict[glk] = GaloisKeyNode(id=glk, level=x.level)
                elif x.level > g_swk_node_dict[glk].level:
                    g_swk_node_dict[glk].level = x.level

                op = RotateColUnitNode(sub_step, lib=Lib.SEAL)
                g_dag.add_edges_from([(rotated_input[sub_steps_sum], op), (g_swk_node_dict[glk], op)])
                if sub_step != sub_steps[-1]:
                    z = CiphertextNode()
                    if isinstance(x, BfvCiphertextNode):
                        z = BfvCiphertextNode(level=x.level)
                    elif isinstance(x, CkksCiphertextNode):
                        z = CkksCiphertextNode(level=x.level)
                    else:
                        raise ValueError()
                    z.is_ntt = x.is_ntt
                else:
                    z = CiphertextNode()
                    if isinstance(x, BfvCiphertextNode):
                        z = BfvCiphertextNode(
                            id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level
                        )
                    elif isinstance(x, CkksCiphertextNode):
                        z = CkksCiphertextNode(
                            id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level
                        )
                    else:
                        raise ValueError()
                    z.is_ntt = x.is_ntt
                g_dag.add_edge(op, z)

                rotated_input[sub_steps_sum + sub_step] = z

            sub_steps_sum += sub_step

        output.append(rotated_input[sub_steps_sum])

    return output


def seal_advanced_rotate_cols(
    x: BfvCiphertextNode | CkksCiphertextNode, steps: list[int] | int, output_id: Optional[str] = None
) -> list[BfvCiphertextNode | CkksCiphertextNode]:
    """!Advanced ciphertext rotation (SEAL)

    Define a ciphertext rotation computation step using SEAL library with direct rotation keys.
    @param x Input data node.
    @param steps Rotation steps (positive = left rotation, negative = right rotation).
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using rotation operations.')

    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')

    if isinstance(steps, int):
        steps = [steps]

    output = list()
    for step in steps:
        galEl = get_galois_element_for_column_rotation_by(step, g_param.n, galois_gen=SEAL_GALOIS_GEN)
        glk = f'glk_ntt_col_{galEl}'

        global g_swk_node_dict
        if glk not in g_swk_node_dict:
            g_swk_node_dict[glk] = GaloisKeyNode(id=glk, level=x.level)
        elif x.level > g_swk_node_dict[glk].level:
            g_swk_node_dict[glk].level = x.level

        op = RotateColUnitNode(step, lib=Lib.SEAL)
        g_dag.add_edges_from([(x, op), (g_swk_node_dict[glk], op)])

        z = CiphertextNode()
        if isinstance(x, BfvCiphertextNode):
            z = BfvCiphertextNode(id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level)
        elif isinstance(x, CkksCiphertextNode):
            z = CkksCiphertextNode(id=random_id() if output_id is None else f'{output_id}_step{step}', level=x.level)
        else:
            raise ValueError()
        z.is_ntt = x.is_ntt
        g_dag.add_edge(op, z)

        output.append(z)

    return output


def ct_pt_mult_accumulate_add_ct_slice(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextRingtNode | BfvPlaintextNode | CkksPlaintextRingtNode | CkksPlaintextNode]
    | list[tuple[BfvCompressedPlaintextRingtNode, int]],
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    global g_dag
    assert len(x) == len(y) + 1

    level = x[0].level

    sum_cnt = len(x) - 1
    assert sum_cnt in [1, 2, 4, 8, 16]

    op = CmpacSumComputeNode(sum_cnt)

    y_compressed: bool = isinstance(y[0], tuple)

    for xi in x:
        assert xi.type == DataType.Ciphertext and xi.level == level
    for yi in y:
        if not y_compressed:
            if isinstance(yi, (BfvPlaintextRingtNode, CkksPlaintextRingtNode)):
                op.pt_type = DataType.PlaintextRingt
            elif isinstance(yi, (BfvPlaintextNode, CkksPlaintextNode)):
                op.pt_type = DataType.Plaintext
        elif isinstance(yi, tuple):
            assert isinstance(yi[0], BfvCompressedPlaintextRingtNode) and isinstance(yi[1], int)
            assert yi[0].type == DataType.PlaintextRingt and yi[0].level == 0 and yi[0].is_compressed

    if y_compressed:
        op.compressed_block_info = [yi[0].compressed_block_info[yi[1]] for yi in y]  # type: ignore[union-attr]
    for i in range(len(x)):
        g_dag.add_edge(x[i], op)

    if not y_compressed:
        for i in range(len(y)):
            g_dag.add_edge(y[i], op)
    else:
        g_dag.add_edge(y[0][0], op)  # type: ignore[index]

    z = CiphertextNode()
    if isinstance(x[0], BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=level)
    elif isinstance(x[0], CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=level)
    else:
        raise ValueError()
    z.is_ntt = x[0].is_ntt
    g_dag.add_edge(op, z)
    return z


def ct_pt_mult_accumulate_slice(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextRingtNode | BfvPlaintextNode | CkksPlaintextRingtNode | CkksPlaintextNode]
    | list[tuple[BfvCompressedPlaintextRingtNode, int]],
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    global g_dag
    assert len(x) == len(y)

    level = x[0].level

    sum_cnt = len(x)
    assert sum_cnt in [1, 2, 4, 8, 16]

    op = CmpSumComputeNode(sum_cnt)

    y_compressed: bool = isinstance(y[0], tuple)

    for xi in x:
        assert xi.type == DataType.Ciphertext and xi.level == level
    for yi in y:
        if not y_compressed:
            if isinstance(yi, (BfvPlaintextRingtNode, CkksPlaintextRingtNode)):
                op.pt_type = DataType.PlaintextRingt
            elif isinstance(yi, (BfvPlaintextNode, CkksPlaintextNode)):
                op.pt_type = DataType.Plaintext
        elif isinstance(yi, tuple):
            assert isinstance(yi[0], BfvCompressedPlaintextRingtNode) and isinstance(yi[1], int)
            assert yi[0].type == DataType.PlaintextRingt and yi[0].level == 0 and yi[0].is_compressed

    if y_compressed:
        op.compressed_block_info = [yi[0].compressed_block_info[yi[1]] for yi in y]  # type: ignore[union-attr]
    for i in range(len(x)):
        g_dag.add_edge(x[i], op)

    if not y_compressed:
        for i in range(len(y)):
            g_dag.add_edge(y[i], op)
    else:
        g_dag.add_edge(y[0][0], op)  # type: ignore[index]

    z = CiphertextNode()
    if isinstance(x[0], BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=level)
    elif isinstance(x[0], CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=level)
    else:
        raise ValueError()
    z.is_ntt = x[0].is_ntt
    g_dag.add_edge(op, z)

    return z


def ct_pt_mult_accumulate(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextRingtNode | CkksPlaintextRingtNode] | BfvCompressedPlaintextRingtNode,
    output_mform: bool | None = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Ciphertext-plaintext vector dot product

    Define a ciphertext-plaintext vector dot product step. Prefer this when vector length meets requirements for better performance.
    @param x Input ciphertext vector.
    @param y Input plaintext vector; must have the same length as the ciphertext vector.
    @return Result data node.
    """
    y_compressed: bool = isinstance(y, BfvCompressedPlaintextRingtNode)
    if y_compressed:
        assert len(x) == len(y.compressed_block_info)

    n_processed_mult: int
    if len(x) >= 16 and isinstance(x[0], (BfvCiphertextNode, CkksCiphertextNode)):
        x_ct_slice = []
        w_pt_slice = []
        for i in range(16):
            x_ct_slice.append(x[i])
            w_pt_slice.append(y[i] if not y_compressed else (y, i))

        partial_sum = ct_pt_mult_accumulate_slice(x_ct_slice, w_pt_slice)
        n_processed_mult = 16

    elif len(x) >= 8 and isinstance(x[0], (BfvCiphertextNode, CkksCiphertextNode)):
        x_ct_slice = []
        w_pt_slice = []
        for i in range(8):
            x_ct_slice.append(x[i])
            w_pt_slice.append(y[i] if not y_compressed else (y, i))

        partial_sum = ct_pt_mult_accumulate_slice(x_ct_slice, w_pt_slice)
        n_processed_mult = 8
    else:
        partial_sum = mult(x[0], y[0]) if not y_compressed else mult(x[0], y, start_block_idx=0)
        n_processed_mult = 1

    n_input: int = len(x)
    # n_processed_mult: int = 1

    while n_processed_mult < n_input:
        slice_size = next(x for x in [16, 8, 4, 2, 1] if n_input - n_processed_mult >= x)
        x_ct_slice = []
        w_pt_slice = []
        for i in range(slice_size):
            x_ct_slice.append(x[n_processed_mult + i])
            w_pt_slice.append(y[n_processed_mult + i] if not y_compressed else (y, n_processed_mult + i))
        x_ct_slice.append(partial_sum)
        partial_sum = ct_pt_mult_accumulate_add_ct_slice(x_ct_slice, w_pt_slice)
        n_processed_mult += slice_size

    if output_mform is True or (output_mform is None and x[0].is_mform):
        assert isinstance(partial_sum, BfvCiphertextNode)
        partial_sum = to_mform(partial_sum)

    assert isinstance(partial_sum, (BfvCiphertextNode, CkksCiphertextNode))
    return partial_sum


def ct_pt_mult_accumulate_1(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextRingtNode | CkksPlaintextRingtNode],
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Ciphertext-plaintext vector dot product

    Define a ciphertext-plaintext vector dot product step. Prefer this when vector length meets requirements for better performance.
    @param x Input ciphertext vector.
    @param y Input plaintext vector; must have the same length as the ciphertext vector.
    @return Result data node.
    """
    partial_sum: CiphertextNode | None = None
    n_input: int = len(x)
    n_processed_mult: int = 0

    while n_processed_mult < n_input:
        slice_size = next(x for x in [8, 4, 2, 1] if n_input - n_processed_mult >= x)
        x_ct_slice = []
        w_pt_slice = []
        for i in range(slice_size):
            x_ct_slice.append(x[n_processed_mult + i])
            w_pt_slice.append(y[n_processed_mult + i])
        cc = ct_pt_mult_accumulate_slice(x_ct_slice, w_pt_slice)
        if partial_sum is None:
            partial_sum = cc
        else:
            partial_sum = add(partial_sum, cc)
        n_processed_mult += slice_size

    if x[0].is_mform:
        assert isinstance(partial_sum, BfvCiphertextNode)
        partial_sum = to_mform(partial_sum)

    assert partial_sum is not None
    return partial_sum


def bootstrap(x: CkksCiphertextNode, output_id: Optional[str] = None) -> CkksCiphertextNode:
    global g_dag, g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using bootstrap operation.')
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for bootstrap.')
    if x.level != 0:
        raise ValueError(f'Unsupported input level "{x.level}" for bootstrap.')

    op = FheComputeNode(OperationType.Bootstrap)
    g_dag.add_edge(x, op)

    global g_swk_node_dict
    rlk = 'rlk_ntt'
    if rlk not in g_swk_node_dict:
        g_swk_node_dict[rlk] = RelinKeyNode(level=g_param.max_level)
    else:
        g_swk_node_dict[rlk].level = g_param.max_level
    g_dag.add_edge(g_swk_node_dict[rlk], op)

    assert isinstance(g_param, CkksBtpParam)
    rots = g_param.rotations_for_bootstrapping()
    for rot in rots:
        gal_elem = get_galois_element_for_column_rotation_by(rot, g_param.n)
        glk = f'glk_ntt_col_{gal_elem}'
        if glk not in g_swk_node_dict:
            g_swk_node_dict[glk] = GaloisKeyNode(id=glk, level=g_param.max_level)
        else:
            g_swk_node_dict[glk].level = g_param.max_level
        g_dag.add_edge(g_swk_node_dict[glk], op)

    glk = 'glk_ntt_row'
    if glk not in g_swk_node_dict:
        g_swk_node_dict[glk] = GaloisKeyNode(id=glk, level=g_param.max_level)
    else:
        g_swk_node_dict[glk].level = g_param.max_level
    g_dag.add_edge(g_swk_node_dict[glk], op)

    swk_dts, swk_std = 'swk_dts', 'swk_std'
    if swk_dts not in g_swk_node_dict:
        g_swk_node_dict[swk_dts] = SwitchKeyNode(id=swk_dts, level=0, sp_level=g_param.get_max_sp_level())
    if swk_std not in g_swk_node_dict:
        g_swk_node_dict[swk_std] = SwitchKeyNode(
            id=swk_std, level=g_param.max_level, sp_level=g_param.get_max_sp_level()
        )
    g_dag.add_edges_from([(g_swk_node_dict[swk_dts], op), (g_swk_node_dict[swk_std], op)])

    z = CkksCiphertextNode(id=random_id() if output_id is None else output_id)
    z.is_ntt = x.is_ntt
    assert isinstance(g_param, CkksBtpParam)
    z.level = g_param.btp_output_level
    g_dag.add_edge(op, z)

    return z


def custom_compute(
    inputs: list[DataNode],
    output: DataNode,
    type: str,
    attributes: dict | None = None,
):
    """!Create custom compute node

    Allows users to define custom compute operations and add them to the computation graph.

    @param inputs List of input data nodes.
    @param output Output data node (specifies the type and attributes of the output node).
    @param type String identifier for the custom operation type.
    @param attributes Custom attribute dictionary; can contain arbitrary key-value pairs (e.g., parameters, config).
    """
    global g_dag

    if not inputs:
        raise ValueError('At least one input data node is required for custom compute.')
    if output is None:
        raise ValueError('Output data node is required for custom compute.')

    op = CustomComputeNode(type=type, attributes=attributes)

    for input_node in inputs:
        g_dag.add_edge(input_node, op)

    g_dag.add_edge(op, output)

    return


def _build_fpga_kernels(
    all_output_list: list,
    all_offline_list: list,
    parameter: dict,
) -> list[tuple['FpgaKernelNode', dict, dict]]:
    """Partition g_dag at CustomComputeNode boundaries and replace each FPGA partition with a
    FpgaKernelNode. Returns a list of (kernel_node, sub_mag, sub_sig) for each partition.

    If offline inputs exist, a global offline FpgaKernelNode is prepended to the result.
    Its outputs are new FheDataNode copies (FPGA-resident) that replace the original offline
    data nodes as inputs to online kernels in g_dag.

    After this call g_dag contains FpgaKernelNodes connected to boundary FheDataNodes;
    interior FheComputeNodes and data nodes have been removed.
    """
    assert g_param is not None

    result: list[tuple[FpgaKernelNode, dict, dict]] = []

    node_partition: dict = {}

    for node in nx.topological_sort(g_dag):
        if isinstance(node, FheDataNode):
            compute_preds = [p for p in g_dag.predecessors(node) if isinstance(p, (FheComputeNode, CustomComputeNode))]
            if not compute_preds:
                node_partition[node] = -1  # global / offline input, no barrier crossed yet
            else:
                pred = compute_preds[0]
                node_partition[node] = (
                    node_partition[pred]
                    if isinstance(pred, FheComputeNode)
                    else node_partition[pred] + 1  # crosses a CPU barrier
                )
        elif isinstance(node, FheComputeNode):
            preds = [
                node_partition[p]
                for p in g_dag.predecessors(node)
                if isinstance(p, FheDataNode) and node_partition.get(p, -1) >= 0
            ]
            node_partition[node] = max(preds) if preds else 0
        elif isinstance(node, CustomComputeNode):
            preds = [
                node_partition[p]
                for p in g_dag.predecessors(node)
                if isinstance(p, FheDataNode) and node_partition.get(p, -1) >= 0
            ]
            node_partition[node] = max(preds) if preds else 0

    # Group FheComputeNodes by partition ID. Gaps are possible when custom nodes are chained.
    partitions: dict[int, list] = {}
    for node, pid in node_partition.items():
        if isinstance(node, FheComputeNode):
            partitions.setdefault(pid, []).append(node)

    all_output_set = set(all_output_list)
    all_offline_set = set(all_offline_list)

    for pid in sorted(partitions):
        compute_set = set(partitions[pid])

        # Collect all FheDataNodes referenced by this partition's compute nodes.
        partition_data: set = set()
        for cn in compute_set:
            for n in g_dag.predecessors(cn):
                if isinstance(n, FheDataNode):
                    partition_data.add(n)
            for n in g_dag.successors(cn):
                if isinstance(n, FheDataNode):
                    partition_data.add(n)

        inputs: list = []
        offline_inputs: list = []
        outputs: list = []
        interior: set = set()
        for dn in partition_data:
            fhe_preds = [p for p in g_dag.predecessors(dn) if isinstance(p, FheComputeNode)]
            produced_here = any(p in compute_set for p in fhe_preds)
            if not produced_here:
                inputs.append(dn)
                if dn in all_offline_set:
                    offline_inputs.append(dn)
            else:
                succs = list(g_dag.successors(dn))
                if dn in all_output_set or any(isinstance(s, CustomComputeNode) for s in succs):
                    outputs.append(dn)
                else:
                    interior.add(dn)

        # Sort inputs to match the canonical key ordering used by the FPGA linker:
        #   CT/PT → RLK → GLK (by galois_element string) → SWK
        # This mirrors the all_input_list_with_key ordering so that the FPGA_KERNEL's
        # input list in the JSON is already in the expected polyvec layout order.
        def _input_sort_key(dn):
            if isinstance(dn, RelinKeyNode):
                return (1, '')
            elif isinstance(dn, GaloisKeyNode):
                return (2, str(dn.galois_element))
            elif isinstance(dn, SwitchKeyNode):
                return (3, '')
            else:
                return (0, '')

        inputs.sort(key=_input_sort_key)

        # Build key signature for this partition.
        rlk_level = -1
        glk_level: dict[str, int] = {}
        for dn in inputs:
            if isinstance(dn, RelinKeyNode):
                rlk_level = dn.level
            elif isinstance(dn, GaloisKeyNode):
                glk_level[str(dn.galois_element)] = dn.level

        # Create FpgaKernelNode — its index doubles as the sub-project directory name.
        kernel = FpgaKernelNode()

        sub_mag = {
            'name': f'Kernel {kernel.index}',
            'algorithm': g_param.algo.value,
            'parameter': parameter,
            'data': {dn.index: dn.to_json_dict() for dn in nx.topological_sort(g_dag) if dn in partition_data},
            'compute': {cn.index: cn.to_json_dict(g_dag) for cn in nx.topological_sort(g_dag) if cn in compute_set},
            'inputs': [dn.index for dn in inputs],
            'outputs': [dn.index for dn in outputs],
            'offline_inputs': [dn.index for dn in offline_inputs],
        }
        sub_sig = {
            'algorithm': g_param.algo.value,
            'key': {'rlk': rlk_level, 'glk': glk_level},
            'online': [],
            'offline': [],
        }

        # Rewire g_dag: replace this partition with the FpgaKernelNode.
        for dn in inputs:
            g_dag.add_edge(dn, kernel)
        for dn in outputs:
            g_dag.add_edge(kernel, dn)
        for cn in compute_set:
            g_dag.remove_node(cn)
        for dn in interior:
            g_dag.remove_node(dn)

        result.append((kernel, sub_mag, sub_sig))

    return result


def process_custom_task(
    input_args: list[Argument] | None = None,
    output_args: list[Argument] | None = None,
    offline_input_args: list[Argument] | None = None,
    output_instruction_path: str | None = None,
    fpga_acc: bool = True,
) -> dict:
    """!Process custom task

    Convert a custom task into the required output files based on its input and output data arguments.
    If offline input data nodes are present, a set of instruction files for loading offline input data will be generated,
    used to load all offline data once before the online computation.

    Note: set_fhe_param() must be called before invoking this function.

    @param input_args List of all input arguments for the custom task.
    @param output_args List of all output arguments for the custom task.
    @param offline_input_args List of all offline input arguments (excluding online input data nodes).
    @param output_instruction_path Directory to store the task output files.
    @param fpga_acc Whether to generate for FPGA accelerator.
    @return The task abstract computation graph.
    """

    def flatten(x: list | DataNode) -> list[DataNode]:
        if isinstance(x, list):
            result: list[DataNode] = []
            for a in x:
                result += flatten(a)
            return result
        return [x]

    def shape(x: list) -> list[int]:
        if not isinstance(x, list):
            return []

        sub_shape = shape(x[0]) if x else []
        if isinstance(sub_shape, int):
            return [len(x)]

        return [len(x)] + sub_shape

    def process_data_args(args: list[Argument] | None, phase: str) -> tuple[list[DataNode], list[dict]]:
        all_data_list = []
        sig_data_list = []
        if args is None:
            return all_data_list, sig_data_list
        for arg in args:
            arg_data_list = flatten(arg.data)
            shape_list = shape(arg.data)
            if not arg_data_list:
                raise ValueError(f'No data for arg id "{arg.id}".')
            node = {}
            if arg.id in used_id:
                raise ValueError(f'Same id "{arg.id}" for different Arguments.')
            node['id'] = arg.id
            node['type'] = (
                arg_data_list[0].type.value if isinstance(arg_data_list[0].type, DataType) else arg_data_list[0].type
            )
            node['size'] = shape_list
            if isinstance(arg_data_list[0], FheDataNode):
                node['level'] = arg_data_list[0].level
            node['phase'] = phase

            used_id.append(arg.id)
            all_data_list += arg_data_list
            sig_data_list.append(node)

        return all_data_list, sig_data_list

    # Check global param is set
    global g_swk_node_dict, g_dag, g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before calling process_custom_task().')

    used_id = []

    slots_for_task: Optional[int] = g_param.slots if isinstance(g_param, CkksParam) else None

    all_input_list, input_sigdata_list = process_data_args(input_args, 'in')
    all_output_list, output_sigdata_list = process_data_args(output_args, 'out')
    all_offline_list, offline_sigdata_list = process_data_args(offline_input_args, 'offline')
    all_input_list += all_offline_list

    rlk_signature = -1 if 'rlk_ntt' not in g_swk_node_dict else g_swk_node_dict['rlk_ntt'].level
    if rlk_signature != -1:
        all_input_list.append(g_swk_node_dict['rlk_ntt'])
    glk_signature = {}
    for k, v in g_swk_node_dict.items():
        if 'col' in k:
            glk_signature[int(k.split('_')[-1])] = v.level
            all_input_list.append(v)
        elif 'row' in k:
            glk_signature[get_galois_element_for_row_rotation(g_param.n)] = v.level
            all_input_list.append(v)

    ckks_btp_swk_signature = {}
    for k, v in g_swk_node_dict.items():
        if 'swk' in k:
            ckks_btp_swk_signature[k] = (v.level, v.sp_level)
            all_input_list.append(v)
    all_input_list_with_key = all_input_list

    interface_json = {
        'algorithm': g_param.algo.value,
        'key': {'rlk': rlk_signature, 'glk': glk_signature},
        'online': input_sigdata_list + output_sigdata_list,
        'offline': offline_sigdata_list,
    }
    if len(ckks_btp_swk_signature) != 0:
        interface_json['key']['ckks_btp_swk'] = ckks_btp_swk_signature

    mag = {}
    mag['name'] = 'Acc task'
    mag['algorithm'] = g_param.algo.value
    data = {}
    mag['data'] = data
    compute = {}
    mag['compute'] = compute
    mag['inputs'] = [x.index for x in all_input_list_with_key]
    mag['outputs'] = [x.index for x in all_output_list]
    mag['offline_inputs'] = [x.index for x in all_offline_list]

    parameter = {'n': g_param.n, 'max_level': g_param.max_level, 'q': g_param.q, 'p': g_param.p}
    if g_param.algo == Algo.BFV:
        parameter['t'] = g_param.t
    if isinstance(g_param, CkksParam):
        # slots_for_task was computed above (with optional sparse inference).
        assert slots_for_task is not None
        parameter['slots'] = slots_for_task
        parameter['scale'] = g_param.scale
    if isinstance(g_param, CkksBtpParam):
        parameter['btp_cts_start_level'] = g_param.cts_params.level_start
        parameter['btp_cts_depth'] = g_param.cts_params.depth()
        parameter['btp_cts_bsgs_ratio'] = g_param.cts_params.bsgs_ratio
        parameter['btp_eval_mod_q'] = g_param.eval_mod_params.q
        parameter['btp_eval_mod_start_level'] = g_param.eval_mod_params.level_start
        parameter['btp_eval_mod_scaling_factor'] = g_param.eval_mod_params.scaling_factor
        parameter['btp_eval_mod_sine_type'] = g_param.eval_mod_params.sine_type.name
        parameter['btp_eval_mod_message_ratio'] = g_param.eval_mod_params.message_ratio
        parameter['btp_eval_mod_k'] = g_param.eval_mod_params.k
        parameter['btp_eval_mod_sine_deg'] = g_param.eval_mod_params.sine_deg
        parameter['btp_eval_mod_double_angle'] = g_param.eval_mod_params.double_angle
        parameter['btp_eval_mod_arcsine_deg'] = g_param.eval_mod_params.arcsine_deg
        parameter['btp_stc_start_level'] = g_param.stc_params.level_start
        parameter['btp_stc_depth'] = g_param.stc_params.depth()
        parameter['btp_stc_bsgs_ratio'] = g_param.stc_params.bsgs_ratio
        parameter['btp_output_level'] = g_param.btp_output_level

    mag['parameter'] = parameter

    for x in all_input_list_with_key:
        if x not in g_dag.nodes():
            raise RuntimeError(
                f'Input data node "{x.id}" is not in the computation graph. '
                f'This usually happens when you reuse data nodes from a previous '
                f'process_custom_task() call. The computation graph is cleared after each call. '
                f'\n\nSolution: Create new data nodes for each task.\n'
                f'Example: Instead of reusing variables like x, y:\n'
                f'  # Wrong: reusing nodes\n'
                f'  x = BfvCiphertextNode("x", level=3)\n'
                f'  process_custom_task(..., fpga_acc=True)  # First call\n'
                f'  process_custom_task(..., fpga_acc=False)  # Error! x is no longer in graph\n'
                f'\n'
                f'  # Correct: create new nodes for each task\n'
                f'  x_fpga = BfvCiphertextNode("x", level=3)\n'
                f'  process_custom_task(..., fpga_acc=True)\n'
                f'  x_cpu = BfvCiphertextNode("x", level=3)  # New nodes\n'
                f'  process_custom_task(..., fpga_acc=False)\n'
                f'\n'
                f'Or better: use a function to build the graph:\n'
                f'  def build_graph():\n'
                f'      x = BfvCiphertextNode("x", level=3)\n'
                f'      y = BfvCiphertextNode("y", level=3)\n'
                f'      z = mult_relin(x, y, "z")\n'
                f'      return x, y, z\n'
                f'  \n'
                f'  x1, y1, z1 = build_graph()\n'
                f'  process_custom_task(..., fpga_acc=True)\n'
                f'  x2, y2, z2 = build_graph()\n'
                f'  process_custom_task(..., fpga_acc=False)'
            )
        if not g_dag.succ[x]:
            raise ValueError(f'Input data node "{x.id}" is not used for any computation.')

    if fpga_acc:
        # FPGA supports only n = 8192 now
        if g_param.n != 8192:
            raise ValueError('FPGA mode only supports n = 8192')
        kernel_mags = _build_fpga_kernels(all_output_list, all_offline_list, parameter)
    else:
        kernel_mags = []

    for node in g_dag.nodes():
        if isinstance(node, CustomComputeNode):
            op = node
            if op.index in compute:
                raise ValueError(f'Same index "{op.index}" for different computation nodes.')
            compute[op.index] = op.to_json_dict(g_dag)

        elif isinstance(node, FheComputeNode):
            op = node
            if op.index in compute:
                raise ValueError(f'Same index "{op.index}" for different computation nodes.')
            compute[op.index] = op.to_json_dict(g_dag)

        elif isinstance(node, FheDataNode):
            datum = node
            if datum.index in data:
                raise ValueError(f'Same index "{datum.index}" for different data nodes.')
            if not g_dag.succ[datum]:
                if datum not in all_output_list:
                    raise ValueError(
                        f'Data node "{datum.index}" is not used for any computation, nor is it an output data node.'
                    )
            data[datum.index] = datum.to_json_dict()

        elif isinstance(node, CustomDataNode):
            datum = node
            if datum.index in data:
                raise ValueError(f'Same index "{datum.index}" for different data nodes.')
            if not g_dag.succ[datum]:
                if datum not in all_output_list:
                    raise ValueError(
                        f'Data node "{datum.index}" is not used for any computation, nor is it an output data node.'
                    )
            data[datum.index] = datum.to_json_dict()

    assert output_instruction_path is not None, 'output_instruction_path must be provided'
    if not os.path.exists(output_instruction_path):
        os.makedirs(output_instruction_path)

    with open(
        os.path.join(output_instruction_path, 'task_signature.json'),
        'w',
        encoding='utf-8',
    ) as f:
        json.dump(interface_json, f, indent=4)

    with open(os.path.join(output_instruction_path, 'mega_ag.json'), 'w', encoding='utf-8') as f:
        json.dump(mag, f, indent=4)

    if kernel_mags:
        try:
            from .fpga_backend import run_fpga_linker
        except ImportError:
            from fpga_backend import run_fpga_linker
        for kernel, sub_mag, sub_sig in kernel_mags:
            sub_dir = os.path.join(output_instruction_path, str(kernel.index))
            os.makedirs(sub_dir, exist_ok=True)
            with open(os.path.join(sub_dir, 'mega_ag.json'), 'w', encoding='utf-8') as f:
                json.dump(sub_mag, f, indent=4)
            with open(os.path.join(sub_dir, 'task_signature.json'), 'w', encoding='utf-8') as f:
                json.dump(sub_sig, f, indent=4)
            run_fpga_linker(sub_dir)

    g_swk_node_dict.clear()
    g_dag.clear()
    global data_node_count, compute_node_count, random_ids
    data_node_count = 0
    compute_node_count = 0
    random_ids = set()

    return mag

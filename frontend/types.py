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

from __future__ import annotations

import json
import math
import os
import random
import string
from enum import Enum
from typing import List

import networkx as nx

from frontend.bootstrap_params import (
    LinearTransformType,
    SineType,
    EncodingMatrixParams,
    EvalModParams,
)


class Processor(Enum):
    CPU = 'cpu'
    FPGA = 'fpga'
    GPU = 'gpu'


DEFAULT_LEVEL = -1

random_ids = set()
data_node_count = 0
compute_node_count = 0

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
    ExportToAbi = 'export_to_abi'
    ImportFromAbi = 'import_from_abi'
    LoadToBackend = 'load_to_backend'
    StoreFromBackend = 'store_from_backend'


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


def reset_node_state() -> None:
    global random_ids, data_node_count, compute_node_count
    random_ids = set()
    data_node_count = 0
    compute_node_count = 0


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

    def to_json_dict(self) -> dict:
        return {'n': self.n, 'max_level': self.max_level, 'q': self.q, 'p': self.p}

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

    def to_json_dict(self) -> dict:
        d = super().to_json_dict()
        d['t'] = self.t
        return d


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

    def to_json_dict(self) -> dict:
        d = super().to_json_dict()
        d['slots'] = self.slots
        d['scale'] = self.scale
        return d


class CkksBtpParam(CkksParam):
    """
    @class CkksBtpParam
    @brief CKKS Bootstrap parameter class.

    Contains additional parameters required for CKKS bootstrapping.
    """

    def __init__(self, n: int = 1 << 16):
        super().__init__(n)
        self.cts_params: EncodingMatrixParams = None
        self.stc_params: EncodingMatrixParams = None
        self.eval_mod_params: EvalModParams = None
        self.btp_output_level: int = -1

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

    def to_json_dict(self) -> dict:
        d = super().to_json_dict()
        d['btp_cts_start_level'] = self.cts_params.level_start
        d['btp_cts_depth'] = self.cts_params.depth()
        d['btp_cts_bsgs_ratio'] = self.cts_params.bsgs_ratio
        d['btp_eval_mod_q'] = self.eval_mod_params.q
        d['btp_eval_mod_start_level'] = self.eval_mod_params.level_start
        d['btp_eval_mod_scaling_factor'] = self.eval_mod_params.scaling_factor
        d['btp_eval_mod_sine_type'] = self.eval_mod_params.sine_type.name
        d['btp_eval_mod_message_ratio'] = self.eval_mod_params.message_ratio
        d['btp_eval_mod_k'] = self.eval_mod_params.k
        d['btp_eval_mod_sine_deg'] = self.eval_mod_params.sine_deg
        d['btp_eval_mod_double_angle'] = self.eval_mod_params.double_angle
        d['btp_eval_mod_arcsine_deg'] = self.eval_mod_params.arcsine_deg
        d['btp_stc_start_level'] = self.stc_params.level_start
        d['btp_stc_depth'] = self.stc_params.depth()
        d['btp_stc_bsgs_ratio'] = self.stc_params.bsgs_ratio
        d['btp_output_level'] = self.btp_output_level
        return d

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


def _current_param():
    import sys

    for module_name in ('inference.lattisense.frontend.custom_task', 'frontend.custom_task'):
        custom_task = sys.modules.get(module_name)
        if custom_task is not None and getattr(custom_task, 'g_param', None) is not None:
            return custom_task.g_param
    try:
        from . import custom_task
    except ImportError:
        import custom_task
    return custom_task.g_param


class RelinKeyNode(SwitchKeyNode):
    """
    @class RelinKeyNode
    @brief Relinearization key type.
    """

    def __init__(self, level=DEFAULT_LEVEL) -> None:
        param = _current_param()
        assert param is not None
        super().__init__(id='rlk_ntt', level=level, sp_level=param.get_max_sp_level(), type=DataType.RelinKey)


class GaloisKeyNode(SwitchKeyNode):
    """
    @class GaloisKeyNode
    @brief Galois key type.
    """

    def __init__(self, id, level=DEFAULT_LEVEL) -> None:
        param = _current_param()
        assert param is not None
        super().__init__(id=id, level=level, sp_level=param.get_max_sp_level(), type=DataType.GaloisKey)
        self.galois_element = int(self.id.split('_')[-1]) if 'col' in self.id else (param.n << 1) - 1


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


class _CompoundComputeNode:
    def __init__(self, on_cpu: bool, ops: list[dict], ext_inputs: list, ext_outputs: list) -> None:
        self.index = gen_compute_node_index()
        self.id = f'compound_compute_{self.index}'
        self.ops = ops
        self._ext_inputs = ext_inputs
        self._ext_outputs = ext_outputs
        self.on_cpu = on_cpu
        self.priority = 0

    def __repr__(self):
        return f'(compound_compute, {self.id})'

    def to_json_dict(self, dag: nx.DiGraph) -> dict:
        return {
            'id': self.id,
            'ops': self.ops,
            'inputs': [d.index for d in self._ext_inputs],
            'outputs': [d.index for d in self._ext_outputs],
        }


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


KEY_DATA_TYPES: frozenset[DataType] = frozenset(
    {
        DataType.RelinKey,
        DataType.GaloisKey,
        DataType.SwitchKey,
    }
)
BRIDGE_OP_TYPES: frozenset[OperationType] = frozenset(
    {
        OperationType.ExportToAbi,
        OperationType.ImportFromAbi,
        OperationType.LoadToBackend,
        OperationType.StoreFromBackend,
    }
)


def _type_str(node) -> str:
    t = node.type
    return t.value if hasattr(t, 'value') else t


def is_key_data_node(node) -> bool:
    return node.type in KEY_DATA_TYPES


def is_custom_compute(node) -> bool:
    return isinstance(node, CustomComputeNode)


def is_custom_data_node(node) -> bool:
    return isinstance(node, CustomDataNode)


def is_bridge_compute(node) -> bool:
    return isinstance(node, BridgeComputeNode)


def is_compute_node(node) -> bool:
    return isinstance(node, (ComputeNode, _CompoundComputeNode))


def is_data_node(node) -> bool:
    return isinstance(node, DataNode)


class BridgeDataNode(DataNode):
    is_custom: bool = False

    def __init__(self, node_type: DataType | str) -> None:
        super().__init__(type=node_type)
        self.level: int = -1
        self.degree: int = -1
        self.is_ntt: bool = False
        self.is_mform: bool = False
        self.sp_level: int | None = None
        self.poly1_rns_sp_decomped: bool = False
        self.galois_element: int | None = None

    def __repr__(self) -> str:
        return f'(bridge_data, {self.id})'

    def to_json_dict(self) -> dict:
        if self.is_custom:
            d = {
                'id': self.id,
                'type': _type_str(self),
                'is_custom': True,
            }
            attributes = getattr(self, 'attributes', {})
            if attributes:
                d['attributes'] = attributes
        else:
            d = {
                'id': self.id,
                'type': _type_str(self),
                'level': self.level,
                'degree': self.degree,
                'is_ntt': self.is_ntt,
                'is_mform': self.is_mform,
            }
            if self.sp_level is not None:
                d['sp_level'] = self.sp_level
            if self.type in (DataType.Ciphertext, DataType.Ciphertext3):
                d['poly1_rns_sp_decomped'] = self.poly1_rns_sp_decomped
            if self.galois_element is not None:
                d['galois_element'] = self.galois_element
        return d


class ABIDataNode(BridgeDataNode):
    @classmethod
    def create_from(cls, src: DataNode) -> 'ABIDataNode':
        node = cls(src.type)
        _copy_bridge_data_attrs(node, src)
        return node


class BackendDataNode(BridgeDataNode):
    def __init__(self, node_type: DataType | str, processor: Processor) -> None:
        assert processor in (Processor.GPU, Processor.FPGA)
        super().__init__(node_type)
        self.processor = processor

    @classmethod
    def create_from(cls, src: DataNode, processor: Processor) -> 'BackendDataNode':
        node = cls(src.type, processor)
        _copy_bridge_data_attrs(node, src)
        return node


def _copy_bridge_data_attrs(dst: BridgeDataNode, src: DataNode) -> None:
    if is_custom_data_node(src):
        dst.is_custom = True
        dst.attributes = dict(getattr(src, 'attributes', {}))
    else:
        dst.level = getattr(src, 'level', -1)
        dst.degree = getattr(src, 'degree', -1)
        dst.is_ntt = getattr(src, 'is_ntt', False)
        dst.is_mform = getattr(src, 'is_mform', False)
        dst.sp_level = getattr(src, 'sp_level', None)
        dst.poly1_rns_sp_decomped = getattr(src, 'poly1_rns_sp_decomped', False)
        dst.galois_element = getattr(src, 'galois_element', None)


class BridgeComputeNode(ComputeNode):
    def __init__(self, op_type: OperationType) -> None:
        assert op_type in BRIDGE_OP_TYPES
        super().__init__(type=op_type)

    def __repr__(self) -> str:
        return f'(bridge_{self.type.value}, {self.id})'

    def to_json_dict(self, dag) -> dict:
        return {
            'id': self.id,
            'type': self.type.value,
            'inputs': [p.index for p in dag.predecessors(self)],
            'outputs': [s.index for s in dag.successors(self)],
        }


class ExportToAbiNode(BridgeComputeNode):
    def __init__(self) -> None:
        super().__init__(OperationType.ExportToAbi)


class ImportFromAbiNode(BridgeComputeNode):
    def __init__(self) -> None:
        super().__init__(OperationType.ImportFromAbi)


class LoadToBackendNode(BridgeComputeNode):
    def __init__(self, processor: Processor) -> None:
        self.processor = processor
        super().__init__(OperationType.LoadToBackend)


class StoreFromBackendNode(BridgeComputeNode):
    def __init__(self, processor: Processor) -> None:
        self.processor = processor
        super().__init__(OperationType.StoreFromBackend)

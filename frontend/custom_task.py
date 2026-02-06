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
import sys
from typing import List, Optional

import networkx as nx
from enum import Enum

TRANSLATOR_DEV = True
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


def get_rotations_for_bootstrapping(poly_degree: int):
    if poly_degree == 1 << 13:
        return [
            1,
            2,
            3,
            4,
            8,
            12,
            16,
            24,
            32,
            48,
            64,
            128,
            192,
            256,
            512,
            768,
            1024,
            2048,
            3072,
            3584,
            3840,
            3904,
            3968,
            4032,
            4064,
            4080,
            4084,
            4088,
            4092,
        ]
    elif poly_degree == 1 << 16:
        return [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            16,
            24,
            32,
            64,
            96,
            128,
            160,
            192,
            224,
            256,
            384,
            512,
            768,
            1024,
            1536,
            2048,
            3072,
            4096,
            6144,
            8192,
            12288,
            16384,
            20480,
            24576,
            28672,
            30720,
            31232,
            31744,
            32000,
            32256,
            32512,
            32640,
            32672,
            32704,
            32736,
            32744,
            32752,
            32760,
            32764,
        ]
    else:
        raise ValueError()


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
        self.t: int = -1
        self.max_level: int = -1
        self.scale: float = 0.0

    @classmethod
    def create_bfv_default_param(cls, n: int):
        instance = cls(Algo.BFV, n)

        param_json = instance._load_parameter()

        for p in param_json['p']:
            instance.p.append(p)
        for q in param_json['q']:
            instance.q.append(q)
        instance.t = param_json['t']

        instance.max_level = param_json['max_level']

        return instance

    @classmethod
    def create_ckks_default_param(cls, n: int):
        instance = cls(Algo.CKKS, n)

        param_json = instance._load_parameter()

        for p in param_json['p']:
            instance.p.append(p)
        for q in param_json['q']:
            instance.q.append(q)

        instance.max_level = param_json['max_level']

        return instance

    @classmethod
    def create_bfv_custom_param(cls, n: int, q: List[int], p: List[int], t: int):
        instance = cls(Algo.BFV, n)
        instance.q = q
        instance.p = p
        instance.t = t
        instance.max_level = len(q) - 1
        return instance

    @classmethod
    def create_ckks_custom_param(cls, n: int, q: List[int], p: List[int]):
        instance = cls(Algo.CKKS, n)
        instance.q = q
        instance.p = p
        instance.max_level = len(q) - 1
        return instance

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


class CkksBtpParam(Param):
    """
    @class CkksBtpParam
    @brief CKKS bootstrap parameter class

    Contains additional parameters required for CKKS bootstrapping.
    """

    def __init__(self, n: int = 1 << 16):
        super().__init__(Algo.CKKS, n)
        self.btp_output_level: int = -1
        self.btp_cts_start_level: int = -1
        self.btp_eval_mod_start_level: int = -1
        self.btp_stc_start_level: int = -1

    @classmethod
    def create_toy_param(cls):
        """Create CKKS toy bootstrap parameters (N16QP1546H192H32 with n=8192)"""
        instance = cls(n=8192)

        instance.q = [
            0x10000000006E0001,
            0x10000140001,
            0xFFFFE80001,
            0xFFFFC40001,
            0x100003E0001,
            0xFFFFB20001,
            0x10000500001,
            0xFFFF940001,
            0xFFFF8A0001,
            0xFFFF820001,
            0x7FFFE60001,
            0x7FFFE40001,
            0x7FFFE00001,
            0xFFFFFFFFF840001,
            0x1000000000860001,
            0xFFFFFFFFF6A0001,
            0x1000000000980001,
            0xFFFFFFFFF5A0001,
            0x1000000000B00001,
            0x1000000000CE0001,
            0xFFFFFFFFF2A0001,
            0x100000000060001,
            0xFFFFFFFFF00001,
            0xFFFFFFFFD80001,
            0x1000000002A0001,
        ]
        instance.p = [
            0x1FFFFFFFFFE00001,
            0x1FFFFFFFFFC80001,
            0x1FFFFFFFFFB40001,
            0x1FFFFFFFFF500001,
            0x1FFFFFFFFF420001,
        ]
        instance.max_level = len(instance.q) - 1
        instance.scale = math.pow(2.0, 40)

        instance.btp_output_level = 9
        instance.btp_cts_start_level = 24
        instance.btp_eval_mod_start_level = 20
        instance.btp_stc_start_level = 12

        return instance

    @classmethod
    def create_default_param(cls):
        """Create CKKS bootstrap parameters (N16QP1546H192H32 with n=65536)"""
        instance = cls(n=1 << 16)

        instance.q = [
            0x10000000006E0001,
            0x10000140001,
            0xFFFFE80001,
            0xFFFFC40001,
            0x100003E0001,
            0xFFFFB20001,
            0x10000500001,
            0xFFFF940001,
            0xFFFF8A0001,
            0xFFFF820001,
            0x7FFFE60001,
            0x7FFFE40001,
            0x7FFFE00001,
            0xFFFFFFFFF840001,
            0x1000000000860001,
            0xFFFFFFFFF6A0001,
            0x1000000000980001,
            0xFFFFFFFFF5A0001,
            0x1000000000B00001,
            0x1000000000CE0001,
            0xFFFFFFFFF2A0001,
            0x100000000060001,
            0xFFFFFFFFF00001,
            0xFFFFFFFFD80001,
            0x1000000002A0001,
        ]
        instance.p = [
            0x1FFFFFFFFFE00001,
            0x1FFFFFFFFFC80001,
            0x1FFFFFFFFFB40001,
            0x1FFFFFFFFF500001,
            0x1FFFFFFFFF420001,
        ]
        instance.max_level = len(instance.q) - 1
        instance.scale = math.pow(2.0, 40)

        instance.btp_output_level = 9
        instance.btp_cts_start_level = 24
        instance.btp_eval_mod_start_level = 20
        instance.btp_stc_start_level = 12

        return instance


def set_fhe_param(param: 'Param') -> None:
    """Set global FHE parameters

    This function must be called before invoking any FHE operations.
    It sets the global parameter object used by all subsequent FHE operations.

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
    @brief Class describing task input data parameters, output data parameters, and offline input data parameters.
    """

    def __init__(self, arg_id: str, data: 'DataNode | list') -> None:
        """
        @brief Constructor
        @param arg_id: Custom argument ID
        @param data: Data. Can be a single data node, a list of data nodes, a tuple of data nodes, or nested lists/tuples of data nodes.
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
    @brief Base class for data nodes

    Base class for all data nodes, containing only the most basic attributes: type, id, index
    """

    def __init__(self, type, id='') -> None:
        """
        @brief Constructor
        @param type: Node type
        @param id: Node ID
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
    @brief FHE data node type; subclasses should be used for concrete usage

    Contains data types used in FHE computation, such as plaintext, ciphertext, keys, etc.
    Has FHE-related attributes including level, degree, is_ntt, etc.
    """

    def __init__(
        self,
        type: DataType,
        id='',
        degree=-1,
        level=DEFAULT_LEVEL,
    ) -> None:
        """
        @brief Constructor
        @param type: DataType enumeration type
        @param id: Custom node ID
        @param degree: Polynomial degree
        @param level: Data level
        """
        super().__init__(type=type, id=id)
        self.level: int = level
        self.degree: int = degree
        self.is_ntt = False
        self.is_mform = False
        self.sp_level: int = None


class PlaintextNode(FheDataNode):
    """
    @class PlaintextNode
    @brief Plaintext type
    """

    def __init__(self, type, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(type, id, 0, level)


class BfvPlaintextNode(PlaintextNode):
    """
    @class BfvPlaintextNode
    @brief BFV plaintext type
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Plaintext, id, level)


class BfvPlaintextRingtNode(PlaintextNode):
    """
    @class BfvPlaintextRingtNode
    @brief Plaintext type in ring-t, used for ciphertext-plaintext multiplication
    """

    def __init__(self, id='') -> None:
        super().__init__(DataType.PlaintextRingt, id, 0)


class BfvCompressedPlaintextRingtNode(BfvPlaintextRingtNode):
    """
    @class BfvCompressedPlaintextRingtNode
    @brief Compressed plaintext type in ring-t, used for ciphertext-plaintext multiplication
    """

    def __init__(self, id='', compressed_block_info: list = None) -> None:
        super().__init__(id)
        assert compressed_block_info is not None
        self.compressed_block_info = compressed_block_info
        self.is_compressed = True


class BfvPlaintextMulNode(PlaintextNode):
    """
    @class BfvPlaintextMulNode
    @brief Plaintext type for ciphertext-plaintext multiplication
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.PlaintextMul, id, level)
        self.is_ntt = True
        self.is_mform = True


class CkksPlaintextNode(PlaintextNode):
    """
    @class CkksPlaintextNode
    @brief CKKS plaintext type
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Plaintext, id, level)
        self.is_ntt = True


class CkksPlaintextRingtNode(PlaintextNode):
    """
    @class CkksPlaintextRingtNode
    @brief CKKS plaintext type in ring-t, used for ciphertext-plaintext multiplication
    """

    def __init__(self, id='') -> None:
        super().__init__(DataType.PlaintextRingt, id, 0)
        self.is_ntt = False


class CkksPlaintextMulNode(PlaintextNode):
    """
    @class CkksPlaintextMulNode
    @brief CKKS plaintext type for ciphertext-plaintext multiplication
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.PlaintextMul, id, level)
        self.is_ntt = True
        self.is_mform = True


class CiphertextNode(FheDataNode):
    """
    @class CiphertextNode
    @brief Ciphertext type
    """

    def __init__(self, type=DataType.Ciphertext, id='', degree=1, level=DEFAULT_LEVEL) -> None:
        super().__init__(type, id, degree, level)
        self.poly1_rns_sp_decomped: bool = False


class BfvCiphertextNode(CiphertextNode):
    """
    @class BfvCiphertextNode
    @brief BFV ciphertext type containing 2 polynomials
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext, id, 1, level)


class BfvCiphertext3Node(CiphertextNode):
    """
    @class BfvCiphertext3Node
    @brief BFV ciphertext type containing 3 polynomials
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext3, id, 2, level)


class CkksCiphertextNode(CiphertextNode):
    """
    @class CkksCiphertextNode
    @brief CKKS ciphertext type containing 2 polynomials
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext, id, 1, level)
        self.is_ntt = True


class CkksCiphertext3Node(CiphertextNode):
    """
    @class CkksCiphertext3Node
    @brief CKKS ciphertext type containing 3 polynomials
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext3, id, 2, level)
        self.is_ntt = True


class SwitchKeyNode(FheDataNode):
    """
    @class SwitchKeyNode
    @brief Switch key type
    """

    def __init__(self, id='', level=DEFAULT_LEVEL, sp_level=DEFAULT_LEVEL, type=DataType.SwitchKey) -> None:
        super().__init__(type=type, id=id, degree=1, level=level)
        self.is_ntt = True
        self.is_mform = True
        self.sp_level = sp_level


class RelinKeyNode(SwitchKeyNode):
    """
    @class RelinKeyNode
    @brief Relinearization key type
    """

    def __init__(self, level=DEFAULT_LEVEL) -> None:
        super().__init__(id='rlk_ntt', level=level, sp_level=g_param.get_max_sp_level(), type=DataType.RelinKey)


class GaloisKeyNode(SwitchKeyNode):
    """
    @class GaloisKeyNode
    @brief Galois key type
    """

    def __init__(self, id, level=DEFAULT_LEVEL) -> None:
        super().__init__(id=id, level=level, sp_level=g_param.get_max_sp_level(), type=DataType.GaloisKey)
        self.galois_element = (
            int(self.id.split('_')[-1]) if 'col' in self.id else get_galois_element_for_row_rotation(g_param.n)
        )


class ComputeNode:
    """
    @class ComputeNode
    @brief Base class for compute nodes

    Base class for all compute nodes, containing only the most basic attributes: type, id, index
    """

    def __init__(self, type) -> None:
        """
        @brief Constructor
        @param type: Operation type
        """
        self.type = type
        self.id = random_id()
        self.index: int = gen_compute_node_index()

    def __repr__(self):
        return f'({self.type}, {self.id})'


class FheComputeNode(ComputeNode):
    """
    @class FheComputeNode
    @brief FHE compute node type

    Contains operation types used in FHE computation, with FHE-related attributes such as compressed_block_info.
    """

    def __init__(self, type: OperationType) -> None:
        """
        @brief Constructor
        @param type: OperationType enumeration type
        """
        super().__init__(type=type)
        self.compressed_block_info: list = None

    def __repr__(self):
        return f'({self.type.value}, {self.id})'


class CmpSumComputeNode(FheComputeNode):
    """
    @class CmpSumComputeNode
    @brief CmpSum compute node type
    """

    def __init__(self, sum_cnt) -> None:
        super().__init__(type=OperationType.CmpSum)
        self.sum_cnt = sum_cnt
        self.pt_type = ''


class CmpacSumComputeNode(FheComputeNode):
    """
    @class CmpacSumComputeNode
    @brief CmpacSum compute node type
    """

    def __init__(self, sum_cnt) -> None:
        super().__init__(type=OperationType.CmpacSum)
        self.sum_cnt = sum_cnt
        self.pt_type = ''


class RotateColUnitNode(FheComputeNode):
    """
    @class RotateColUnitNode
    @brief Column rotation unit type
    """

    def __init__(self, step: int, lib=Lib.Lattigo) -> None:
        super().__init__(type=OperationType.RotateCol)
        self.step = step
        self.lib = lib


class RotateRowUnitNode(FheComputeNode):
    """
    @class RotateRowUnitNode
    @brief Row rotation unit type
    """

    def __init__(self, lib=Lib.Lattigo) -> None:
        super().__init__(type=OperationType.RotateRow)
        self.lib = lib


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

    Define an addition computation step. Supported types include ct+ct, ct+pt, pt+ct.
    @param x Input data node.
    @param y Input data node.
    @param output_id ID of the result data node.
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

    Define a subtraction computation step. Supported types include ct-ct, ct-pt.
    @param x Input data node.
    @param y Input data node.
    @param output_id ID of the result data node.
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
    start_block_idx: int = None,
) -> BfvCiphertextNode | BfvCiphertext3Node | CkksCiphertextNode | CkksCiphertext3Node:
    """!Multiplication

    Define a multiplication computation step. Supported types include ct * ct, ct * pt_ringt, pt_ringt * ct, ct * pt_mul, pt_mul * ct.
    @param x Input data node.
    @param y Input data node.
    @param output_id ID of the result data node.
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
    @param output_id ID of the result data node.
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

    Define a ciphertext multiplication followed by relinearization computation step.
    @param x Input data node.
    @param y Input data node.
    @param output_id ID of the result data node.
    @return Result data node.
    """
    return relin(mult(x, y, f'{output_id}_ct3' if output_id is not None else None), output_id)


def rescale(
    x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Modulus switching (rescale)

    Define a modulus switching computation step.
    @param x Input data node.
    @param output_id ID of the result data node.
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
    """!Level switching (drop level)

    Define a level switching computation step.
    @param x Input data node.
    @param drop_level Number of levels to drop.
    @param output_id ID of the result data node.
    @return Result data node.
    """
    global g_dag
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for drop level.')
    if x.level < drop_level:
        raise ValueError('Dropped levels must not be larger than input level.')

    input = [x]
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
    @param steps Number of rotation steps (positive for left rotation, negative for right rotation).
    @param output_id ID of the result data node.
    @return Result data node.
    """

    global g_dag, g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using rotation operations.')

    rot_type = 'hybrid'
    assert rot_type in ['hybrid', 'hoisted']
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')

    if type(steps) is int:
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

    Define a ciphertext rotation computation step after preparing the rotation keys corresponding to the rotation steps.
    @param x Input data node.
    @param steps Number of rotation steps (positive for left rotation, negative for right rotation).
    @param output_id ID of the result data node.
    @param out_ct_type Output ciphertext type. Supported types include 'ct', 'ct-ntt', 'ct-ntt-mf'.
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

    if type(steps) is int:
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
    @param steps Number of rotation steps (positive for left rotation, negative for right rotation).
    @param output_id ID of the result data node.
    @return Result data node.
    """
    global g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using rotation operations.')

    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')

    if type(steps) is int:
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
    @param steps Number of rotation steps (positive for left rotation, negative for right rotation).
    @param output_id ID of the result data node.
    @return Result data node.
    """
    global g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using rotation operations.')

    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')

    if type(steps) is int:
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
        op.compressed_block_info = [yi[0].compressed_block_info[yi[1]] for yi in y]
    for i in range(len(x)):
        g_dag.add_edge(x[i], op)

    if not y_compressed:
        for i in range(len(y)):
            g_dag.add_edge(y[i], op)
    else:
        g_dag.add_edge(y[0][0], op)

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
        op.compressed_block_info = [yi[0].compressed_block_info[yi[1]] for yi in y]
    for i in range(len(x)):
        g_dag.add_edge(x[i], op)

    if not y_compressed:
        for i in range(len(y)):
            g_dag.add_edge(y[i], op)
    else:
        g_dag.add_edge(y[0][0], op)

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
    """!Plaintext-ciphertext vector inner product

    Define a plaintext-ciphertext vector inner product computation step. Should be preferred for performance when vector length meets the requirements.
    @param x Input ciphertext vector.
    @param y Input plaintext vector, must have the same length as the ciphertext vector.
    @return Result data node.
    """
    y_compressed: bool = isinstance(y, BfvCompressedPlaintextRingtNode)
    if y_compressed:
        assert len(x) == len(y.compressed_block_info)

    if len(x) >= 16 and isinstance(x[0], (BfvCiphertextNode, CkksCiphertextNode)):
        x_ct_slice = []
        w_pt_slice = []
        for i in range(16):
            x_ct_slice.append(x[i])
            w_pt_slice.append(y[i] if not y_compressed else (y, i))

        partial_sum = ct_pt_mult_accumulate_slice(x_ct_slice, w_pt_slice)
        n_processed_mult: int = 16

    elif len(x) >= 8 and isinstance(x[0], (BfvCiphertextNode, CkksCiphertextNode)):
        x_ct_slice = []
        w_pt_slice = []
        for i in range(8):
            x_ct_slice.append(x[i])
            w_pt_slice.append(y[i] if not y_compressed else (y, i))

        partial_sum = ct_pt_mult_accumulate_slice(x_ct_slice, w_pt_slice)
        n_processed_mult: int = 8
    else:
        partial_sum = mult(x[0], y[0]) if not y_compressed else mult(x[0], y, start_block_idx=0)
        n_processed_mult: int = 1

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
        partial_sum = to_mform(partial_sum)

    return partial_sum


def ct_pt_mult_accumulate_1(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextRingtNode | CkksPlaintextRingtNode],
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Plaintext-ciphertext vector inner product (variant 1)

    Define a plaintext-ciphertext vector inner product computation step. Should be preferred for performance when vector length meets the requirements.
    @param x Input ciphertext vector.
    @param y Input plaintext vector, must have the same length as the ciphertext vector.
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
        partial_sum = to_mform(partial_sum)

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

    rots = get_rotations_for_bootstrapping(g_param.n)
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
    z.level = g_param.btp_output_level
    g_dag.add_edge(op, z)

    return z


def process_custom_task(
    input_args: list[Argument] = None,
    output_args: list[Argument] = None,
    offline_input_args: list[Argument] = None,
    output_instruction_path: str = None,
) -> dict:
    """!Process custom task

    Convert a custom task into a set of task-related files based on its input and output data parameters.
    If there are offline input data nodes, a set of instruction files for loading offline input data will be generated,
    which are used to load all offline input data at once before online computation.

    Note: set_fhe_param() must be called to set global FHE parameters before calling this function.

    @param input_args List of all input arguments for the custom task.
    @param output_args List of all output arguments for the custom task.
    @param offline_input_args List of all offline input arguments for the custom task (does not include input data nodes).
    @param output_instruction_path Directory path for storing the custom task files.
    @return Abstract computation graph for the task.
    """

    def flatten(x: list):
        if type(x) is list:
            result = []
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

    def process_data_args(args: list[Argument], phase: str) -> tuple[list, list[dict]]:
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

    if True:
        parameter = {'n': g_param.n, 'max_level': g_param.max_level, 'q': g_param.q, 'p': g_param.p}
        if isinstance(g_param, CkksBtpParam):
            parameter['scale'] = g_param.scale
            parameter['btp_cts_start_level'] = g_param.btp_cts_start_level
            parameter['btp_eval_mod_start_level'] = g_param.btp_eval_mod_start_level
            parameter['btp_stc_start_level'] = g_param.btp_stc_start_level
            parameter['btp_output_level'] = g_param.btp_output_level

        if g_param.algo == Algo.BFV:
            parameter['t'] = g_param.t

        mag['parameter'] = parameter

    for x in all_input_list_with_key:
        if x not in g_dag.nodes():
            raise RuntimeError(
                f'Input data node "{x.id}" is not in the computation graph.\n'
                f'The computation graph is cleared after each process_custom_task() call.\n\n'
                f'Solution: Create new data nodes for each task.\n\n'
                f'Recommended: Use a builder function:\n'
                f'  def build_graph():\n'
                f'      x = BfvCiphertextNode("x", level=3)\n'
                f'      y = BfvCiphertextNode("y", level=3)\n'
                f'      z = mult_relin(x, y, "z")\n'
                f'      return x, y, z\n'
                f'  \n'
                f'  inputs1 = build_graph()\n'
                f'  process_custom_task(...)\n'
                f'  \n'
                f'  inputs2 = build_graph()  # Create new nodes\n'
                f'  process_custom_task(...)'
            )
        if not g_dag.succ[x]:
            raise ValueError(f'Input data node "{x.id}" is not used for any computation.')

    for node in g_dag.nodes():
        if isinstance(node, FheComputeNode):
            op: FheComputeNode = node
            if op.index in compute:
                raise ValueError(f'Same index "{op.index}" for different computation nodes.')

            compute[op.index] = {
                'id': op.id,
                'type': op.type.value,
                'inputs': [y.index for y in g_dag.predecessors(op)],
                'outputs': [s.index for s in g_dag.successors(op)],
            }
            if isinstance(op, RotateColUnitNode):
                compute[op.index]['step'] = op.step
                if op.lib != Lib.Lattigo:
                    compute[op.index]['lib'] = op.lib.value
            elif isinstance(op, RotateRowUnitNode):
                if op.lib != Lib.Lattigo:
                    compute[op.index]['lib'] = op.lib.value
            elif isinstance(op, CmpSumComputeNode) or isinstance(op, CmpacSumComputeNode):
                compute[op.index]['sum_cnt'] = op.sum_cnt
                compute[op.index]['pt_type'] = op.pt_type.value
            if op.compressed_block_info is not None:
                compute[op.index]['compressed_block_info'] = op.compressed_block_info

        elif isinstance(node, FheDataNode):
            datum: FheDataNode = node
            if datum.index in data:
                raise ValueError(f'Same index "{datum.index}" for different data nodes.')
            if not g_dag.succ[datum]:
                if datum not in all_output_list:
                    raise ValueError(
                        f'Data node "{datum.index}" is not used for any computation, nor is it an output data node.'
                    )
            data[datum.index] = {
                'id': datum.id,
                'type': datum.type.value,
                'level': datum.level,
                'degree': datum.degree,
                'is_ntt': datum.is_ntt,
                'is_mform': datum.is_mform,
            }
            if datum.sp_level is not None:
                data[datum.index]['sp_level'] = datum.sp_level
            if isinstance(datum, BfvCompressedPlaintextRingtNode):
                data[datum.index]['is_compressed'] = datum.is_compressed
            if isinstance(datum, CiphertextNode):
                data[datum.index]['poly1_rns_sp_decomped'] = datum.poly1_rns_sp_decomped
            if isinstance(datum, GaloisKeyNode):
                data[datum.index]['galois_element'] = datum.galois_element

    if not os.path.exists(output_instruction_path):
        os.makedirs(output_instruction_path)
    with open(os.path.join(output_instruction_path, 'mega_ag.json'), 'w', encoding='utf-8') as f:
        json.dump(mag, f, indent=4)

    with open(
        os.path.join(output_instruction_path, 'task_signature.json'),
        'w',
        encoding='utf-8',
    ) as f:
        json.dump(interface_json, f, indent=4)

    g_swk_node_dict.clear()
    g_dag.clear()

    return mag

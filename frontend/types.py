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
from dataclasses import dataclass
from enum import Enum
from typing import List

import networkx as nx


class Processor(Enum):
    CPU = 'cpu'
    GPU = 'gpu'


random_ids = set()

GALOIS_GEN = 5


class Algo(Enum):
    BFV = 'BFV'
    CKKS = 'CKKS'


class DataType(Enum):
    Plaintext = 'pt'
    Ciphertext = 'ct'
    EvaluationKey = 'evk'
    RelinKey = 'rlk'
    GaloisKey = 'glk'


class OperationType(Enum):
    Add = 'add'
    Sub = 'sub'
    Mult = 'mult'
    Relin = 'relin'
    Rescale = 'rescale'
    DropLevel = 'drop_level'
    RotateCol = 'rotate_col'
    RotateRow = 'rotate_row'
    Conjugate = 'conjugate'
    CmpacSum = 'cmpac_sum'
    CmpSum = 'cmp_sum'
    Bootstrap = 'bootstrap'
    EncodeRingt = 'encode_ringt'
    ExportToAbi = 'export_to_abi'
    ImportFromAbi = 'import_from_abi'
    LoadToBackend = 'load_to_backend'
    StoreFromBackend = 'store_from_backend'


@dataclass
class Metadata:
    is_ringt: bool = False
    is_batched: bool = True
    degree: int = 0
    level: int = 0
    log_slots: int = -1
    scale: float = 1.0
    is_ntt: bool = True
    mform_bits: int = 0

    def copy(self) -> 'Metadata':
        return Metadata(
            is_ringt=self.is_ringt,
            is_batched=self.is_batched,
            degree=self.degree,
            level=self.level,
            log_slots=self.log_slots,
            scale=self.scale,
            is_ntt=self.is_ntt,
            mform_bits=self.mform_bits,
        )

    def to_json_dict(self) -> dict:
        return {
            'is_ringt': self.is_ringt,
            'is_batched': self.is_batched,
            'degree': self.degree,
            'level': self.level,
            'log_slots': self.log_slots,
            'scale': self.scale,
            'is_ntt': self.is_ntt,
            'mform_bits': self.mform_bits,
        }


def reset_node_state() -> None:
    global random_ids
    random_ids = set()


def random_id():
    while True:
        asc = ''.join(random.choices(string.ascii_lowercase, k=12))
        if asc not in random_ids:
            random_ids.add(asc)
            break
    return asc


class Param:
    def __init__(self, algo: Algo, log_n: int):
        self.algo: Algo = algo
        self.log_n: int = log_n
        self.n: int = 1 << log_n
        self.p: list[int] = []
        self.q: list[int] = []
        self.max_level: int = -1

    def get_max_sp_level(self):
        return len(self.p) - 1

    def to_json_dict(self) -> dict:
        return {'log_n': self.log_n, 'max_level': self.max_level, 'q': self.q, 'p': self.p}

    def _load_parameter(self):
        parameter_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'parameter.json')

        with open(parameter_path, 'r') as f:
            parameters = json.load(f)

        if self.algo.value not in parameters:
            raise ValueError(f'Unsupported algorithm type: {self.algo.value}')

        algo_params = parameters[self.algo.value]
        if str(self.log_n) not in algo_params:
            raise ValueError(f'Unsupported log_n value for algorithm {self.algo.value}: {self.log_n}')

        return algo_params[str(self.log_n)]


class BfvParam(Param):
    def __init__(self, log_n: int):
        super().__init__(Algo.BFV, log_n)
        self.t: int = -1

    @classmethod
    def create_default_param(cls, log_n: int):
        instance = cls(log_n)

        param_json = instance._load_parameter()

        for p in param_json['p']:
            instance.p.append(p)
        for q in param_json['q']:
            instance.q.append(q)
        instance.t = param_json['t']

        instance.max_level = param_json['max_level']

        return instance

    @classmethod
    def create_custom_param(cls, log_n: int, q: List[int], p: List[int], t: int):
        instance = cls(log_n)
        instance.q = q
        instance.p = p
        instance.t = t
        instance.max_level = len(q) - 1
        return instance

    def to_json_dict(self) -> dict:
        d = super().to_json_dict()
        d['t'] = self.t
        return d


class CkksParam(Param):
    def __init__(self, log_n: int, log_scale: int = 0):
        super().__init__(Algo.CKKS, log_n)
        self.log_default_scale: int = log_scale
        self.default_scale: float = 1 << log_scale
        self.enable_bootstrapping: bool = False

    def set_log_scale(self, log_scale: int):
        self.log_default_scale = log_scale
        self.default_scale = 1 << log_scale

    @classmethod
    def create_default_param(cls, log_n: int):
        instance = cls(log_n)

        param_json = instance._load_parameter()

        for p in param_json['p']:
            instance.p.append(p)
        for q in param_json['q']:
            instance.q.append(q)

        instance.max_level = param_json['max_level']
        instance.log_default_scale = param_json['log_default_scale']
        instance.default_scale = 1 << instance.log_default_scale

        return instance

    @classmethod
    def create_custom_param(cls, log_n: int, q: List[int], p: List[int], log_scale: int = 0):
        instance = cls(log_n, log_scale)
        instance.q = q
        instance.p = p
        instance.max_level = len(q) - 1
        return instance

    def to_json_dict(self) -> dict:
        d = super().to_json_dict()
        d['log_default_scale'] = self.log_default_scale
        d['enable_bootstrapping'] = self.enable_bootstrapping
        return d


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

    Base class for all data nodes, containing only basic attributes: type and id.
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

    def __repr__(self) -> str:
        return self.id


class FheDataNode(DataNode):
    """
    @class FheDataNode
    @brief FHE data node type; use its subclasses in practice.
    """

    def __init__(self, type: DataType, metadata: Metadata, id='') -> None:
        super().__init__(type=type, id=id)
        self.metadata = metadata

    def to_json_dict(self) -> dict:
        d = {
            'type': self.type.value,
        }
        d.update(self.metadata.to_json_dict())
        if hasattr(self, 'sp_level'):
            d['sp_level'] = self.sp_level
        if hasattr(self, 'key_role'):
            d['key_role'] = self.key_role
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

    def __init__(self, type, id='', level=0, is_ringt=True, is_batched=True) -> None:
        if is_ringt and level != 0:
            raise ValueError('ring-t plaintext level must be 0')
        metadata = Metadata(
            is_ringt=is_ringt,
            is_batched=is_batched,
            degree=0,
            level=level,
            is_ntt=not is_ringt,
            mform_bits=0,
        )
        super().__init__(type=type, metadata=metadata, id=id)


class BfvPlaintextNode(PlaintextNode):
    """
    @class BfvPlaintextNode
    @brief BFV plaintext type.
    """

    @staticmethod
    def _validate_log_slots(log_slots: int, param: BfvParam) -> None:
        if log_slots < 0:
            raise ValueError(f'log_slots must be non-negative, got {log_slots}')
        slots = 1 << log_slots
        if slots > param.n:
            raise ValueError(f'slots must be in range (0, {param.n}], got {slots}')

    def __init__(self, id='', level=0, is_ringt=True, is_batched=True, log_slots: int = -1) -> None:
        param = _current_param()
        if param is None:
            raise RuntimeError('Please call set_fhe_param() before creating BFV plaintext.')
        if not isinstance(param, BfvParam):
            raise ValueError('BFV plaintext requires BFV parameters.')
        if log_slots == -1:
            log_slots = int(math.log2(param.n))
        self._validate_log_slots(log_slots, param)
        super().__init__(DataType.Plaintext, id, level, is_ringt, is_batched)
        self.metadata.log_slots = log_slots


class CkksPlaintextNode(PlaintextNode):
    """
    @class CkksPlaintextNode
    @brief CKKS plaintext type.
    """

    @staticmethod
    def _validate_log_slots(log_slots: int, param: CkksParam) -> None:
        if log_slots < 0:
            raise ValueError(f'log_slots must be non-negative, got {log_slots}')
        slots = 1 << log_slots
        if slots > param.n // 2:
            raise ValueError(f'slots must be in range (0, {param.n // 2}], got {slots}')

    def __init__(
        self,
        id='',
        level=0,
        is_ringt=True,
        is_batched=True,
        log_slots: int = -1,
        scale: float = 0.0,
    ) -> None:
        param = _current_param()
        if param is None:
            raise RuntimeError('Please call set_fhe_param() before creating CKKS plaintext.')
        if not isinstance(param, CkksParam):
            raise ValueError('CKKS plaintext requires CKKS parameters.')
        if log_slots == -1:
            log_slots = int(math.log2(param.n // 2))
        if scale == 0.0:
            scale = param.default_scale
        self._validate_log_slots(log_slots, param)
        super().__init__(DataType.Plaintext, id, level, is_ringt, is_batched)
        self.metadata.log_slots = log_slots
        self.metadata.scale = scale


class CiphertextNode(FheDataNode):
    """
    @class CiphertextNode
    @brief Ciphertext type.
    """

    def __init__(self, level, type=DataType.Ciphertext, id='', degree=1) -> None:
        metadata = Metadata(is_ringt=False, is_batched=True, degree=degree, level=level)
        super().__init__(type=type, metadata=metadata, id=id)


class BfvCiphertextNode(CiphertextNode):
    """
    @class BfvCiphertextNode
    @brief BFV ciphertext type, containing 2 polynomials.
    """

    def __init__(self, level, id='', degree=1, log_slots: int = -1) -> None:
        param = _current_param()
        if param is None:
            raise RuntimeError('Please call set_fhe_param() before creating BFV ciphertext.')
        if not isinstance(param, BfvParam):
            raise ValueError('BFV ciphertext requires BFV parameters.')
        if log_slots == -1:
            log_slots = int(math.log2(param.n))
        BfvPlaintextNode._validate_log_slots(log_slots, param)
        super().__init__(level=level, type=DataType.Ciphertext, id=id, degree=degree)
        self.metadata.log_slots = log_slots


class CkksCiphertextNode(CiphertextNode):
    """
    @class CkksCiphertextNode
    @brief CKKS ciphertext type, containing 2 polynomials.
    """

    def __init__(self, level, id='', degree=1, log_slots: int = -1, scale: float = 0.0) -> None:
        param = _current_param()
        if param is None:
            raise RuntimeError('Please call set_fhe_param() before creating CKKS ciphertext.')
        if not isinstance(param, CkksParam):
            raise ValueError('CKKS ciphertext requires CKKS parameters.')
        if log_slots == -1:
            log_slots = int(math.log2(param.n // 2))
        if scale == 0.0:
            scale = param.default_scale
        CkksPlaintextNode._validate_log_slots(log_slots, param)
        super().__init__(level=level, type=DataType.Ciphertext, id=id, degree=degree)
        self.metadata.log_slots = log_slots
        self.metadata.scale = scale


def _current_param():
    try:
        from . import custom_task
    except ImportError:
        import custom_task
    return custom_task.g_param


class EvaluationKeyNode(FheDataNode):
    """
    @class EvaluationKeyNode
    @brief Evaluation key type.
    """

    def __init__(self, level, id='', type=DataType.EvaluationKey, key_role: str = '') -> None:
        param = _current_param()
        assert param is not None
        metadata = Metadata(is_ringt=False, is_batched=True, degree=1, level=level, mform_bits=64)
        super().__init__(type=type, metadata=metadata, id=id)
        self.sp_level = param.get_max_sp_level()
        if key_role == 'bootstrap':
            self.sp_level = -1
        if key_role:
            self.key_role = key_role


class RelinKeyNode(EvaluationKeyNode):
    """
    @class RelinKeyNode
    @brief Relinearization key type.
    """

    def __init__(self, level, id='rlk_ntt', key_role: str = '') -> None:
        param = _current_param()
        assert param is not None
        super().__init__(id=id, level=level, type=DataType.RelinKey, key_role=key_role)


class GaloisKeyNode(EvaluationKeyNode):
    """
    @class GaloisKeyNode
    @brief Galois key type.
    """

    def __init__(self, id, level, key_role: str = '') -> None:
        param = _current_param()
        assert param is not None
        super().__init__(id=id, level=level, type=DataType.GaloisKey, key_role=key_role)
        self.galois_element = int(self.id.split('_')[-1]) if 'col' in self.id else (param.n << 1) - 1


class ComputeNode:
    """
    @class ComputeNode
    @brief Compute node base class.

    Base class for all compute nodes, containing only basic attributes: type and id.
    """

    def __init__(self, type) -> None:
        """
        @brief Constructor.
        @param type: Operation type.
        """
        self.type = type
        self.id = random_id()

    def __repr__(self):
        return f'({self.type}, {self.id})'


class _CompoundComputeNode:
    def __init__(self, on_cpu: bool, ops: list[dict], ext_inputs: list, ext_outputs: list) -> None:
        self.id = random_id()
        self.ops = ops
        self._ext_inputs = ext_inputs
        self._ext_outputs = ext_outputs
        self.on_cpu = on_cpu
        self.priority = 0

    def __repr__(self):
        return f'(compound_compute, {self.id})'

    def to_json_dict(self, dag: nx.DiGraph) -> dict:
        return {
            'ops': self.ops,
            'inputs': [d.id for d in self._ext_inputs],
            'outputs': [d.id for d in self._ext_outputs],
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

    def __repr__(self):
        return f'({self.type.value}, {self.id})'

    def to_json_dict(self, dag: nx.DiGraph) -> dict:
        d = {
            'type': self.type.value,
            'inputs': [y.id for y in dag.predecessors(self)],
            'outputs': [s.id for s in dag.successors(self)],
        }
        if isinstance(self, RotateColNode):
            d['steps'] = self.steps
            d['use_default_rotation_keys'] = self.use_default_rotation_keys
        elif isinstance(self, DropLevelNode):
            d['drop_level'] = self.drop_level
        elif isinstance(self, (CmpSumComputeNode, CmpacSumComputeNode)):
            d['sum_cnt'] = self.sum_cnt
        if hasattr(self, 'scalar'):
            d['scalar'] = [self.scalar.real, self.scalar.imag] if isinstance(self.scalar, complex) else self.scalar
        return d


class CustomComputeNode(ComputeNode):
    """
    @class CustomComputeNode
    @brief Opaque custom compute node type.

    Allows users to create compute nodes with custom attributes and metadata.
    The runtime does not know the operation semantics; users bind executors explicitly.
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
            'type': self.type,
            'is_custom': True,
            'inputs': [y.id for y in dag.predecessors(self)],
            'outputs': [s.id for s in dag.successors(self)],
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


class CmpacSumComputeNode(FheComputeNode):
    """
    @class CmpacSumComputeNode
    @brief CmpacSum compute node type.
    """

    def __init__(self, sum_cnt) -> None:
        super().__init__(type=OperationType.CmpacSum)
        self.sum_cnt = sum_cnt


class RotateColNode(FheComputeNode):
    """
    @class RotateColNode
    @brief Column rotation node type.
    """

    def __init__(self, steps: list[int] | int, use_default_rotation_keys: bool = True) -> None:
        super().__init__(type=OperationType.RotateCol)
        self.steps = [steps] if isinstance(steps, int) else steps
        self.use_default_rotation_keys = use_default_rotation_keys


class RotateRowNode(FheComputeNode):
    """
    @class RotateRowNode
    @brief Row rotation node type.
    """

    def __init__(self) -> None:
        super().__init__(type=OperationType.RotateRow)


class DropLevelNode(FheComputeNode):
    """
    @class DropLevelNode
    @brief Drop-level node type.
    """

    def __init__(self, drop_level: int = 1) -> None:
        super().__init__(type=OperationType.DropLevel)
        self.drop_level = drop_level


class ConjugateNode(FheComputeNode):
    """
    @class ConjugateNode
    @brief Conjugate node type.
    """

    def __init__(self) -> None:
        super().__init__(type=OperationType.Conjugate)


KEY_DATA_TYPES: frozenset[DataType] = frozenset(
    {
        DataType.RelinKey,
        DataType.GaloisKey,
        DataType.EvaluationKey,
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
        self.metadata = Metadata(degree=-1, level=-1)
        self.sp_level: int | None = None
        self.galois_element: int | None = None
        self.key_role: str = ''

    def __repr__(self) -> str:
        return f'(bridge_data, {self.id})'

    def to_json_dict(self) -> dict:
        if self.is_custom:
            d = {
                'type': _type_str(self),
                'is_custom': True,
            }
            attributes = getattr(self, 'attributes', {})
            if attributes:
                d['attributes'] = attributes
        else:
            d = {
                'type': _type_str(self),
            }
            d.update(self.metadata.to_json_dict())
            if self.sp_level is not None:
                d['sp_level'] = self.sp_level
            if self.galois_element is not None:
                d['galois_element'] = self.galois_element
            if self.key_role:
                d['key_role'] = self.key_role
        return d


class ABIDataNode(BridgeDataNode):
    @classmethod
    def create_from(cls, src: DataNode, metadata: Metadata | None = None) -> 'ABIDataNode':
        node = cls(src.type)
        _copy_bridge_data_attrs(node, src, metadata)
        return node


class BackendDataNode(BridgeDataNode):
    def __init__(self, node_type: DataType | str, processor: Processor) -> None:
        assert processor == Processor.GPU
        super().__init__(node_type)
        self.processor = processor

    @classmethod
    def create_from(cls, src: DataNode, processor: Processor, metadata: Metadata | None = None) -> 'BackendDataNode':
        node = cls(src.type, processor)
        _copy_bridge_data_attrs(node, src, metadata)
        return node


def _copy_bridge_data_attrs(dst: BridgeDataNode, src: DataNode, metadata: Metadata | None = None) -> None:
    if is_custom_data_node(src):
        dst.is_custom = True
        dst.attributes = dict(getattr(src, 'attributes', {}))
    else:
        dst.metadata = metadata.copy() if metadata is not None else src.metadata.copy()
        dst.sp_level = getattr(src, 'sp_level', None)
        dst.galois_element = getattr(src, 'galois_element', None)
        dst.key_role = getattr(src, 'key_role', '')


class BridgeComputeNode(ComputeNode):
    def __init__(self, op_type: OperationType) -> None:
        assert op_type in BRIDGE_OP_TYPES
        super().__init__(type=op_type)

    def __repr__(self) -> str:
        return f'(bridge_{self.type.value}, {self.id})'

    def to_json_dict(self, dag) -> dict:
        return {
            'type': self.type.value,
            'inputs': [p.id for p in dag.predecessors(self)],
            'outputs': [s.id for s in dag.successors(self)],
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

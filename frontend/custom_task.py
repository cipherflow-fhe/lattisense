import json
import math
import os
import random
import string
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
    def create_bfv_fpga_param(cls, t: int = 0x1B4001):
        instance = cls(Algo.BFV, n=8192)
        instance.q = [0x7F4E0001, 0x7FB40001, 0x7FD20001, 0x7FEA0001, 0x7FF80001, 0x7FFE0001]
        instance.p = [0xFF5A0001]
        instance.t = t
        instance.max_level = len(instance.q) - 1
        return instance

    @classmethod
    def create_ckks_custom_param(cls, n: int, q: List[int], p: List[int]):
        instance = cls(Algo.CKKS, n)
        instance.q = q
        instance.p = p
        instance.max_level = len(q) - 1
        return instance

    @classmethod
    def create_ckks_fpga_param(cls):
        instance = cls(Algo.CKKS, n=8192)
        instance.q = [0x7F4E0001, 0x7FB40001, 0x7FD20001, 0x7FEA0001, 0x7FF80001, 0x7FFE0001]
        instance.p = [0xFF5A0001]
        instance.max_level = len(instance.q) - 1
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
    @brief CKKS Bootstrap参数类

    包含CKKS Bootstrap所需的额外参数
    """

    def __init__(self, n: int = 1 << 16):
        super().__init__(Algo.CKKS, n)
        self.btp_output_level: int = -1
        self.btp_cts_start_level: int = -1
        self.btp_eval_mod_start_level: int = -1
        self.btp_stc_start_level: int = -1

    @classmethod
    def create_toy_param(cls):
        """创建CKKS Toy Bootstrap参数 (N16QP1546H192H32 with n=8192)"""
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
        """创建CKKS Bootstrap参数 (N16QP1546H192H32 with n=65536)"""
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
    """设置全局FHE参数

    必须在调用任何FHE操作之前调用此函数。
    此函数会设置全局参数对象,用于后续所有FHE操作。

    @param param: FHE参数对象,包含算法类型、多项式度数n、模数等信息

    Example:
        param = Param.create_default_param(algo='BFV', n=16384)
        set_fhe_param(param)
    """
    global g_param
    g_param = param


class Argument:
    """
    @class Argument
    @brief 描述任务输入数据参数、输出数据参数、离线输入数据参数的类。
    """

    def __init__(self, arg_id: str, data: 'DataNode | list') -> None:
        """
        @brief 构造函数
        @param arg_id: 自定义参数id
        @param data: 数据。可以是单个数据节点、数据节点list、数据节点tuple、或多级的数据节点list或tuple。
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
    @brief 数据节点基类

    所有数据节点的基类, 只包含最基础的属性: type, id, index
    """

    def __init__(self, type, id='') -> None:
        """
        @brief 构造函数
        @param type: 节点类型
        @param id: 节点id
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
    @brief FHE数据节点类型, 具体使用时应当使用其子类

    包含FHE计算中的数据类型, 如明文、密文、密钥等。
    具有level、degree、is_ntt等FHE相关属性。
    """

    def __init__(
        self,
        type: DataType,
        id='',
        degree=-1,
        level=DEFAULT_LEVEL,
    ) -> None:
        """
        @brief 构造函数
        @param type: DataType枚举类型
        @param id: 自定义节点id
        @param degree: 多项式度数
        @param level: 数据level
        """
        super().__init__(type=type, id=id)
        self.level: int = level
        self.degree: int = degree
        self.is_ntt = False
        self.is_mform = False
        self.sp_level: int = None


class CustomDataNode(DataNode):
    """
    @class CustomDataNode
    @brief 自定义数据节点类型

    允许用户创建带有自定义类型和属性的数据节点。
    """

    def __init__(self, type: str, id='', attributes: dict = None) -> None:
        """
        @brief 构造函数
        @param type: 自定义数据类型的字符串标识
        @param id: 节点id
        @param attributes: 自定义属性字典, 可以包含任意键值对
        """
        super().__init__(type=type, id=id)
        self.attributes = attributes if attributes is not None else {}

    def __repr__(self) -> str:
        return f'(custom_{self.type}, {self.id})'


class PlaintextNode(FheDataNode):
    """
    @class PlaintextNode
    @brief 明文类型
    """

    def __init__(self, type, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(type, id, 0, level)


class BfvPlaintextNode(PlaintextNode):
    """
    @class PlaintextNode
    @brief 明文类型
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Plaintext, id, level)


class BfvPlaintextRingtNode(PlaintextNode):
    """
    @class PlaintextRingtNode
    @brief 环t上的明文类型, 用于密文乘明文
    """

    def __init__(self, id='') -> None:
        super().__init__(DataType.PlaintextRingt, id, 0)


class BfvCompressedPlaintextRingtNode(BfvPlaintextRingtNode):
    """
    @class PlaintextRingtNode
    @brief 环t上的明文类型, 用于密文乘明文
    """

    def __init__(self, id='', compressed_block_info: list = None) -> None:
        super().__init__(id)
        assert compressed_block_info is not None
        self.compressed_block_info = compressed_block_info
        self.is_compressed = True


class BfvPlaintextMulNode(PlaintextNode):
    """
    @class PlaintextMulNode
    @brief 明文类型, 用于密文乘明文
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.PlaintextMul, id, level)
        self.is_ntt = True
        self.is_mform = True


class CkksPlaintextNode(PlaintextNode):
    """
    @class PlaintextNode
    @brief 明文类型
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Plaintext, id, level)
        self.is_ntt = True


class CkksPlaintextRingtNode(PlaintextNode):
    """
    @class PlaintextRingtNode
    @brief 环t上的明文类型, 用于密文乘明文
    """

    def __init__(self, id='') -> None:
        super().__init__(DataType.PlaintextRingt, id, 0)
        self.is_ntt = False


class CkksPlaintextMulNode(PlaintextNode):
    """
    @class PlaintextMulNode
    @brief 明文类型, 用于密文乘明文
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.PlaintextMul, id, level)
        self.is_ntt = True
        self.is_mform = True


class CiphertextNode(FheDataNode):
    """
    @class PlaintextNode
    @brief 明文类型
    """

    def __init__(self, type=DataType.Ciphertext, id='', degree=1, level=DEFAULT_LEVEL) -> None:
        super().__init__(type, id, degree, level)
        self.poly1_rns_sp_decomped: bool = False


class BfvCiphertextNode(CiphertextNode):
    """
    @class CiphertextNode
    @brief 密文类型, 包含2个多项式
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext, id, 1, level)


class BfvCiphertext3Node(CiphertextNode):
    """
    @class Ciphertext3Node
    @brief 密文类型, 包含3个多项式
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext3, id, 2, level)


class CkksCiphertextNode(CiphertextNode):
    """
    @class CiphertextNode
    @brief 密文类型, 包含2个多项式
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext, id, 1, level)
        self.is_ntt = True


class CkksCiphertext3Node(CiphertextNode):
    """
    @class CiphertextNode
    @brief 密文类型, 包含2个多项式
    """

    def __init__(self, id='', level=DEFAULT_LEVEL) -> None:
        super().__init__(DataType.Ciphertext3, id, 2, level)
        self.is_ntt = True


class SwitchKeyNode(FheDataNode):
    """
    @class SwitchingKeyNode
    @brief swk类型
    """

    def __init__(self, id='', level=DEFAULT_LEVEL, sp_level=DEFAULT_LEVEL, type=DataType.SwitchKey) -> None:
        super().__init__(type=type, id=id, degree=1, level=level)
        self.is_ntt = True
        self.is_mform = True
        self.sp_level = sp_level


class RelinKeyNode(SwitchKeyNode):
    """
    @class RelinKeyNode
    @brief rlk类型
    """

    def __init__(self, level=DEFAULT_LEVEL) -> None:
        super().__init__(id='rlk_ntt', level=level, sp_level=g_param.get_max_sp_level(), type=DataType.RelinKey)


class GaloisKeyNode(SwitchKeyNode):
    """
    @class GaloisKeyNode
    @brief glk类型
    """

    def __init__(self, id, level=DEFAULT_LEVEL) -> None:
        super().__init__(id=id, level=level, sp_level=g_param.get_max_sp_level(), type=DataType.GaloisKey)
        self.galois_element = (
            int(self.id.split('_')[-1]) if 'col' in self.id else get_galois_element_for_row_rotation(g_param.n)
        )


class ComputeNode:
    """
    @class ComputeNode
    @brief 计算节点基类

    所有计算节点的基类, 只包含最基础的属性: type, id, index
    """

    def __init__(self, type) -> None:
        """
        @brief 构造函数
        @param type: 操作类型
        """
        self.type = type
        self.id = random_id()
        self.index: int = gen_compute_node_index()

    def __repr__(self):
        return f'({self.type}, {self.id})'


class FheComputeNode(ComputeNode):
    """
    @class FheComputeNode
    @brief FHE计算节点类型

    包含FHE计算中的操作类型, 具有compressed_block_info等FHE相关属性。
    """

    def __init__(self, type: OperationType) -> None:
        """
        @brief 构造函数
        @param type: OperationType枚举类型
        """
        super().__init__(type=type)
        self.compressed_block_info: list = None

    def __repr__(self):
        return f'({self.type.value}, {self.id})'


class CustomComputeNode(ComputeNode):
    """
    @class CustomComputeNode
    @brief 自定义计算节点类型

    允许用户创建带有自定义属性和元数据的计算节点。
    """

    def __init__(self, type: str, attributes: dict = None) -> None:
        """
        @brief 构造函数
        @param type: 自定义操作类型的字符串标识
        @param attributes: 自定义属性字典, 可以包含任意键值对
        """
        super().__init__(type=type)
        self.attributes = attributes if attributes is not None else {}

    def __repr__(self):
        return f'(custom_{self.type}, {self.id})'


class CmpSumComputeNode(FheComputeNode):
    """
    @class CmpSumComputeNode
    @brief CmpSum计算节点类型
    """

    def __init__(self, sum_cnt) -> None:
        super().__init__(type=OperationType.CmpSum)
        self.sum_cnt = sum_cnt
        self.pt_type = ''


class CmpacSumComputeNode(FheComputeNode):
    """
    @class CmpacSumComputeNode
    @brief CmpacSum计算节点类型
    """

    def __init__(self, sum_cnt) -> None:
        super().__init__(type=OperationType.CmpacSum)
        self.sum_cnt = sum_cnt
        self.pt_type = ''


class RotateColUnitNode(FheComputeNode):
    """
    @class RotateColUnitNode
    @brief 旋转单元类型
    """

    def __init__(self, step: int, lib=Lib.Lattigo) -> None:
        super().__init__(type=OperationType.RotateCol)
        self.step = step
        self.lib = lib


class RotateRowUnitNode(FheComputeNode):
    """
    @class RotateRowUnitNode
    @brief 旋转单元类型
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
    """!加法

    定义一个加法计算步骤。支持类型包括ct+ct, ct+pt, pt+ct。
    @param x 输入数据节点。
    @param y 输入数据节点。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
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
    """!减法

    定义一个减法计算步骤。支持类型包括ct-ct, ct-pt。
    @param x 输入数据节点。
    @param y 输入数据节点。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
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
    """!乘法

    定义一个乘法计算步骤。支持类型包括ct * ct, ct * pt_ringt, pt_ringt * ct, ct * pt_mul, pt_mul * ct。
    @param x 输入数据节点。
    @param y 输入数据节点。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
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
    """!重线性化

    定义一个重线性化计算步骤。
    @param x 输入数据节点。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
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
    """!密文乘法并重线性化

    定义一个密文乘法并重线性化计算步骤。
    @param x 输入数据节点。
    @param y 输入数据节点。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
    """
    return relin(mult(x, y, f'{output_id}_ct3' if output_id is not None else None), output_id)


def rescale(
    x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!模数切换

    定义一个模数切换计算步骤。
    @param x 输入数据节点。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
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
    """!level切换

    定义一个level切换计算步骤。
    @param x 输入数据节点。
    @param drop_level 需要减少的level数量。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
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
    """!密文旋转

    定义一个密文旋转计算步骤。
    @param x 输入数据节点。
    @param step 旋转的步数(正数为左旋, 负数为右旋)。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
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
    """!密文旋转

    在准备好旋转步数所对应的旋转公钥后, 定义一个密文旋转计算步骤。
    @param x 输入数据节点。
    @param step 旋转的步数(正数为左旋, 负数为右旋)。
    @param output_id 结果计算节点的id。
    @param out_ct_type 输出密文的类型, 支持的类型包括 'ct', 'ct_ntt', 'ct-ntt-mf'。
    @return 结果计算节点。
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
    """!密文旋转

    定义一个密文旋转计算步骤。
    @param x 输入数据节点。
    @param step 旋转的步数(正数为左旋, 负数为右旋)。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
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
    """!密文旋转

    定义一个密文旋转计算步骤。
    @param x 输入数据节点。
    @param step 旋转的步数(正数为左旋, 负数为右旋)。
    @param output_id 结果计算节点的id。
    @return 结果计算节点。
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
    """!明密文向量内积运算

    定义一个明密文向量内积计算步骤, 在向量长度满足条件的前提下, 当优先使用以提升性能。
    @param x 输入密文向量。
    @param y 输入明文向量, 长度要求与密文向量相同。
    @return 结果计算节点。
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
    """!明密文向量内积运算

    定义一个明密文向量内积计算步骤, 在向量长度满足条件的前提下, 当优先使用以提升性能。
    @param x 输入密文向量。
    @param y 输入明文向量, 长度要求与密文向量相同。
    @return 结果计算节点。
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


def custom_compute(
    inputs: list[DataNode],
    output: DataNode,
    type: str,
    attributes: dict = None,
):
    """!创建自定义计算节点

    允许用户定义自定义的计算操作, 并将其加入计算图。

    @param inputs 输入数据节点列表
    @param output 输出数据节点（指定输出节点的类型和属性）
    @param type 自定义操作类型的字符串标识
    @param attributes 自定义属性字典, 可以包含任意键值对（例如: 参数、配置等）
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


def process_custom_task(
    input_args: list[Argument] = None,
    output_args: list[Argument] = None,
    offline_input_args: list[Argument] = None,
    output_instruction_path: str = None,
    fpga_acc: bool = True,
) -> dict:
    """!处理自定义任务

    根据自定义任务的输入和输出数据参数, 把自定义任务转化成一系列任务所需文件。
    如果有离线输入数据节点, 则会产生一组载入离线输入数据的指令文件, 用于在在线计算前, 一次性载入离线输入数据。

    注意: 在调用此函数之前,必须先调用 set_fhe_param() 设置全局FHE参数。

    @param input_args 自定义任务的全部输入参数列表。
    @param output_args 自定义任务的全部输出参数列表。
    @param offline_input_args 自定义任务的全部离线输入参数列表, 不包含输入数据节点。
    @param output_instruction_path 自定义任务的任务文件存储目录。
    @param fpga_acc FPGA加速卡任务标识
    @return 任务抽象计算图。
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

    for node in g_dag.nodes():
        if isinstance(node, CustomComputeNode):
            op: CustomComputeNode = node
            if op.index in compute:
                raise ValueError(f'Same index "{op.index}" for different computation nodes.')

            compute[op.index] = {
                'id': op.id,
                'type': op.type,
                'is_custom': True,
                'inputs': [y.index for y in g_dag.predecessors(op)],
                'outputs': [s.index for s in g_dag.successors(op)],
            }
            if op.attributes:
                compute[op.index]['attributes'] = op.attributes

        elif isinstance(node, FheComputeNode):
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

        elif isinstance(node, CustomDataNode):
            datum: CustomDataNode = node
            if datum.index in data:
                raise ValueError(f'Same index "{datum.index}" for different data nodes.')
            if not g_dag.succ[datum]:
                if datum not in all_output_list:
                    raise ValueError(
                        f'Data node "{datum.index}" is not used for any computation, nor is it an output data node.'
                    )
            data[datum.index] = {
                'id': datum.id,
                'type': datum.type,
                'is_custom': True,
            }
            if datum.attributes:
                data[datum.index]['attributes'] = datum.attributes

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

    if fpga_acc:
        # FPGA supports only n = 8192 now
        if g_param.n != 8192:
            raise ValueError('FPGA mode only supports n = 8192')
        try:
            from .fpga_backend import run_fpga_linker
        except ImportError:
            from fpga_backend import run_fpga_linker
        run_fpga_linker(output_instruction_path, TRANSLATOR_DEV)

    g_swk_node_dict.clear()
    g_dag.clear()

    return mag

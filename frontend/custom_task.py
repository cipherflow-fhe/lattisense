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
from typing import Optional

import networkx as nx

from frontend.types import (
    Algo,
    Argument,
    BfvCiphertext3Node,
    BfvCiphertextNode,
    BfvCompressedPlaintextRingtNode,
    BfvParam,
    BfvPlaintextMulNode,
    BfvPlaintextNode,
    BfvPlaintextRingtNode,
    CiphertextNode,
    CkksBtpParam,
    CkksCiphertext3Node,
    CkksCiphertextNode,
    CkksParam,
    CkksPlaintextMulNode,
    CkksPlaintextNode,
    CkksPlaintextRingtNode,
    CmpSumComputeNode,
    CmpacSumComputeNode,
    ComputeNode,
    CustomComputeNode,
    CustomDataNode,
    DEFAULT_LEVEL,
    DataNode,
    DataType,
    EncodeRingtComputeNode,
    FheComputeNode,
    FheDataNode,
    FpgaKernelNode,
    GALOIS_GEN,
    GaloisKeyNode,
    Lib,
    OperationType,
    Param,
    PlaintextNode,
    Processor,
    RelinKeyNode,
    RotateColUnitNode,
    RotateRowUnitNode,
    SEAL_GALOIS_GEN,
    SwitchKeyNode,
    gen_compute_node_index,
    gen_data_node_index,
    random_id,
    reset_node_state,
)

g_swk_node_dict: dict[str, 'SwitchKeyNode'] = {}
g_dag = nx.DiGraph()
g_param: Optional['Param'] = None


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


def mult_by_i(x: CkksCiphertextNode, output_id: Optional[str] = None) -> CkksCiphertextNode:
    global g_dag
    if not isinstance(x, CkksCiphertextNode):
        raise ValueError(f'Unsupported input type "{x.type.value}" for mult_by_i.')
    op = FheComputeNode(OperationType.MultByi)
    g_dag.add_edges_from([(x, op)])

    z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    z.is_ntt = x.is_ntt
    g_dag.add_edge(op, z)
    return z


def div_by_i(x: CkksCiphertextNode, output_id: Optional[str] = None) -> CkksCiphertextNode:
    global g_dag
    if not isinstance(x, CkksCiphertextNode):
        raise ValueError(f'Unsupported input type "{x.type.value}" for div_by_i.')
    op = FheComputeNode(OperationType.DivByi)
    g_dag.add_edges_from([(x, op)])

    z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.level)
    z.is_ntt = x.is_ntt
    g_dag.add_edge(op, z)
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
    """!Create opaque custom compute node

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


def encode_ringt(x: CustomDataNode, scale: float, output_id: Optional[str] = None) -> CkksPlaintextRingtNode:
    """!Create a CKKS ring-T plaintext from custom input data.

    The op is represented as a normal compute node in the graph. GPU runtime
    executes it with HEonGPU when the task is compiled for Processor.GPU.
    """
    global g_dag

    if not isinstance(x, CustomDataNode):
        raise ValueError('encode_ringt expects a CustomDataNode input.')

    op = EncodeRingtComputeNode(scale=scale)
    z = CkksPlaintextRingtNode(id=random_id() if output_id is None else output_id)
    g_dag.add_edge(x, op)
    g_dag.add_edge(op, z)
    return z


def process_custom_task(
    input_args: list[Argument] | None = None,
    output_args: list[Argument] | None = None,
    offline_input_args: list[Argument] | None = None,
    output_instruction_path: str | None = None,
    processor: Processor = Processor.CPU,
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
    @param processor Target processor backend (Processor.CPU, Processor.GPU, or Processor.FPGA).
    @return The task abstract computation graph.
    """
    global g_swk_node_dict, g_dag, g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before calling process_custom_task().')

    try:
        from .linker.task_context import _TaskContext
    except ImportError:
        from linker.task_context import _TaskContext
    ctx = _TaskContext.build(
        input_args, output_args, offline_input_args, g_swk_node_dict, name='Acc task', algorithm=g_param.algo
    )

    # Validate all input nodes exist in g_dag and feed at least one operation
    for x in ctx.inputs:
        if x not in g_dag.nodes():
            raise RuntimeError(
                f'Input data node "{x.id}" is not in the computation graph. '
                f'This usually happens when you reuse data nodes from a previous '
                f'process_custom_task() call. The computation graph is cleared after each call. '
                f'\n\nSolution: Create new data nodes for each task.\n'
                f'Example: Instead of reusing variables like x, y:\n'
                f'  # Wrong: reusing nodes across calls\n'
                f'  x = BfvCiphertextNode("x", level=3)\n'
                f'  process_custom_task(..., processor=Processor.CPU)  # First call — graph cleared\n'
                f'  process_custom_task(..., processor=Processor.CPU)  # Error! x is no longer in graph\n'
                f'\n'
                f'  # Correct: create new nodes for each call\n'
                f'  x1 = BfvCiphertextNode("x", level=3)\n'
                f'  process_custom_task(..., processor=Processor.CPU)\n'
                f'  x2 = BfvCiphertextNode("x", level=3)  # New nodes for second call\n'
                f'  process_custom_task(..., processor=Processor.CPU)\n'
                f'\n'
                f'Or better: use a function to build the graph:\n'
                f'  def build_graph():\n'
                f'      x = BfvCiphertextNode("x", level=3)\n'
                f'      y = BfvCiphertextNode("y", level=3)\n'
                f'      z = mult_relin(x, y, "z")\n'
                f'      return x, y, z\n'
                f'  \n'
                f'  x1, y1, z1 = build_graph()\n'
                f'  process_custom_task(..., processor=Processor.CPU)\n'
                f'  x2, y2, z2 = build_graph()\n'
                f'  process_custom_task(..., processor=Processor.CPU)'
            )
        if not g_dag.succ[x]:
            raise ValueError(f'Input data node "{x.id}" is not used for any computation.')

    # Validate all non-output data nodes have consumers
    output_set = set(ctx.outputs)
    for node in g_dag.nodes():
        if isinstance(node, (FheDataNode, CustomDataNode)):
            if not g_dag.succ[node] and node not in output_set:
                raise ValueError(
                    f'Data node "{node.index}" is not used for any computation, nor is it an output data node.'
                )

    # FPGA: partition g_dag into kernel MAGs before serializing the top-level graph
    if processor == Processor.FPGA:
        if g_param.n != 8192:
            raise ValueError('FPGA mode only supports n = 8192')

    try:
        from .linker import serialize_dag, serialize_signature
    except ImportError:
        from linker import serialize_dag, serialize_signature

    _meta = {'name': ctx.name, 'algorithm': ctx.algorithm.value}
    mag = serialize_dag(
        g_dag,
        inputs=ctx.inputs,
        outputs=ctx.outputs,
        offline_inputs=ctx.offline,
        meta=_meta,
    )

    assert output_instruction_path is not None, 'output_instruction_path must be provided'
    os.makedirs(output_instruction_path, exist_ok=True)

    with open(os.path.join(output_instruction_path, 'fhe_parameter.json'), 'w', encoding='utf-8') as f:
        json.dump(g_param.to_json_dict(), f, indent=4)

    with open(os.path.join(output_instruction_path, 'task_signature.json'), 'w', encoding='utf-8') as f:
        json.dump(serialize_signature(ctx), f, indent=4)

    with open(os.path.join(output_instruction_path, 'mega_ag.json'), 'w', encoding='utf-8') as f:
        json.dump(mag, f, indent=4)

    if processor == Processor.FPGA:
        try:
            from .fpga_backend import compile_fpga_mega_ag, run_fpga_linker
        except ImportError:
            from fpga_backend import compile_fpga_mega_ag, run_fpga_linker

        compiled_dag, kernel_mags = compile_fpga_mega_ag(g_dag, g_param, ctx)
        compiled = serialize_dag(
            compiled_dag,
            inputs=ctx.inputs,
            outputs=ctx.outputs,
            offline_inputs=ctx.offline,
            meta=_meta,
            use_ops=True,
        )
        with open(os.path.join(output_instruction_path, 'compiled_mega_ag.json'), 'w', encoding='utf-8') as f:
            json.dump(compiled, f, indent=2)

        for kernel, sub_mag, sub_sig in kernel_mags:
            sub_dir = os.path.join(output_instruction_path, str(kernel.index))
            os.makedirs(sub_dir, exist_ok=True)
            with open(os.path.join(sub_dir, 'mega_ag.json'), 'w', encoding='utf-8') as f:
                json.dump(sub_mag, f, indent=4)
            with open(os.path.join(sub_dir, 'task_signature.json'), 'w', encoding='utf-8') as f:
                json.dump(sub_sig, f, indent=4)
            run_fpga_linker(sub_dir)
    elif processor in (Processor.GPU, Processor.CPU):
        try:
            from .linker import compile_mega_ag
        except ImportError:
            from linker import compile_mega_ag
        compiled_dag = compile_mega_ag(g_dag, processor, ctx)
        compiled = serialize_dag(
            compiled_dag,
            inputs=ctx.inputs,
            outputs=ctx.outputs,
            offline_inputs=ctx.offline,
            meta=_meta,
            use_ops=True,
        )
        with open(os.path.join(output_instruction_path, 'compiled_mega_ag.json'), 'w', encoding='utf-8') as f:
            json.dump(compiled, f, indent=2)

    g_swk_node_dict.clear()
    g_dag.clear()
    reset_node_state()

    return mag

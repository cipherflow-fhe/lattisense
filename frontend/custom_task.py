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
import os
from typing import Optional

import networkx as nx

from frontend.bootstrap_params import bootstrapping_galois_elements
from frontend.types import (
    Argument,
    BfvCiphertextNode,
    BfvParam,
    BfvPlaintextNode,
    CiphertextNode,
    CkksCiphertextNode,
    CkksParam,
    CkksPlaintextNode,
    CmpSumComputeNode,
    CmpacSumComputeNode,
    ConjugateNode,
    CustomComputeNode,
    CustomDataNode,
    DataNode,
    DataType,
    DropLevelNode,
    EvaluationKeyNode,
    FheComputeNode,
    FheDataNode,
    GALOIS_GEN,
    GaloisKeyNode,
    OperationType,
    Param,
    Processor,
    RelinKeyNode,
    RotateColNode,
    RotateRowNode,
    random_id,
    reset_node_state,
)

g_evk_node_dict: dict[str, 'EvaluationKeyNode'] = {}
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


def get_galois_element_for_column_rotation_by(rot: int, poly_degree: int, galois_gen=GALOIS_GEN):
    poly_degree_mask = (poly_degree << 1) - 1
    return pow(galois_gen, rot & poly_degree_mask, poly_degree << 1)


def get_galois_element_for_row_rotation(poly_degree: int):
    return (poly_degree << 1) - 1


def get_default_column_rotation_steps(log_n: int) -> list[int]:
    rotations = [1 << i for i in range(log_n - 1)]
    rotations.extend(-1 * (1 << i) for i in range(log_n - 2))
    return rotations


def get_default_column_rotation_substeps(step: int) -> list[int]:
    xh = step >> 1
    x3 = step + xh
    changed_bits = xh ^ x3
    pos_bits = x3 & changed_bits
    neg_bits = xh & changed_bits

    substeps = []
    for idx in range(pos_bits.bit_length() - 1, -1, -1):
        if pos_bits & (1 << idx):
            substeps.append(1 << idx)
    for idx in range(neg_bits.bit_length() - 1, -1, -1):
        if neg_bits & (1 << idx):
            substeps.append(-(1 << idx))
    return substeps


def _ckks_scalar_mul_scale_factor(scalar: int | float | complex, level: int) -> float:
    global g_param
    if not isinstance(g_param, CkksParam):
        raise ValueError('CKKS scalar multiplication requires CKKS parameters.')
    if isinstance(scalar, complex):
        is_gaussian_integer = scalar.real == int(scalar.real) and scalar.imag == int(scalar.imag)
    else:
        is_gaussian_integer = scalar == int(scalar)
    return 1.0 if is_gaussian_integer else float(g_param.q[level])


def add(
    x: BfvCiphertextNode | BfvPlaintextNode | CkksCiphertextNode | CkksPlaintextNode | int | float | complex,
    y: BfvCiphertextNode | BfvPlaintextNode | CkksCiphertextNode | CkksPlaintextNode | int | float | complex,
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Addition

    Define an addition computation step. Supported types: ct+ct, ct+pt, pt+ct, ct+scalar, scalar+ct.
    @param x Input data node or scalar.
    @param y Input data node or scalar.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    if isinstance(x, CiphertextNode):
        op0 = x
        op1 = y
    elif isinstance(y, CiphertextNode):
        op0 = y
        op1 = x
    else:
        raise ValueError('Addition expects one ciphertext input.')

    op = FheComputeNode(OperationType.Add)
    if isinstance(op1, DataNode):
        if op1.type == DataType.Ciphertext:
            assert (
                op0.metadata.level == op1.metadata.level
                and op0.metadata.degree == op1.metadata.degree
                and op0.metadata.is_ntt == op1.metadata.is_ntt
                and op0.metadata.mform_bits == op1.metadata.mform_bits
            )
            if op0.id == op1.id:
                g_dag.add_edge(op0, op)
            else:
                g_dag.add_edges_from([(op0, op), (op1, op)])
        elif op1.type == DataType.Plaintext:
            if not op1.metadata.is_ringt:
                assert (
                    op0.metadata.level == op1.metadata.level
                    and op0.metadata.is_ntt == op1.metadata.is_ntt
                    and op0.metadata.mform_bits == op1.metadata.mform_bits
                )
            g_dag.add_edges_from([(op0, op), (op1, op)])
        else:
            raise ValueError(f'Unsupported input type "{op1.type.value}" for addition.')
    else:
        op.scalar = op1
        g_dag.add_edge(op0, op)

    output_node_id = random_id() if output_id is None else output_id
    if isinstance(op0, BfvCiphertextNode):
        z = BfvCiphertextNode(level=op0.metadata.level, id=output_node_id, degree=op0.metadata.degree)
    elif isinstance(op0, CkksCiphertextNode):
        z = CkksCiphertextNode(level=op0.metadata.level, id=output_node_id, degree=op0.metadata.degree)
    else:
        raise ValueError('Unsupported ciphertext scheme for addition.')
    z.metadata = op0.metadata.copy()
    if isinstance(op1, DataNode):
        z.metadata.log_slots = max(op0.metadata.log_slots, op1.metadata.log_slots)
    g_dag.add_edge(op, z)
    return z


def sub(
    x: BfvCiphertextNode | CkksCiphertextNode,
    y: BfvCiphertextNode | BfvPlaintextNode | CkksCiphertextNode | CkksPlaintextNode | int | float | complex,
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Subtraction

    Define a subtraction computation step. Supported types: ct-ct, ct-pt, ct-scalar.
    @param x Input ciphertext node.
    @param y Input data node or scalar.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for subtraction.')

    op = FheComputeNode(OperationType.Sub)
    if isinstance(y, DataNode):
        if y.type == DataType.Ciphertext:
            assert (
                x.metadata.level == y.metadata.level
                and x.metadata.degree == y.metadata.degree
                and x.metadata.is_ntt == y.metadata.is_ntt
                and x.metadata.mform_bits == y.metadata.mform_bits
            )
        elif y.type == DataType.Plaintext:
            if not y.metadata.is_ringt:
                assert (
                    x.metadata.level == y.metadata.level
                    and x.metadata.is_ntt == y.metadata.is_ntt
                    and x.metadata.mform_bits == y.metadata.mform_bits
                )
        else:
            raise ValueError(f'Unsupported input type "{y.type.value}" for subtraction.')
        g_dag.add_edges_from([(x, op), (y, op)])
    else:
        op.scalar = y
        g_dag.add_edge(x, op)

    if isinstance(x, BfvCiphertextNode):
        z = BfvCiphertextNode(
            id=random_id() if output_id is None else output_id, level=x.metadata.level, degree=x.metadata.degree
        )
    elif isinstance(x, CkksCiphertextNode):
        z = CkksCiphertextNode(
            id=random_id() if output_id is None else output_id, level=x.metadata.level, degree=x.metadata.degree
        )
    else:
        raise ValueError()
    z.metadata = x.metadata.copy()
    if isinstance(y, DataNode):
        z.metadata.log_slots = max(x.metadata.log_slots, y.metadata.log_slots)
    g_dag.add_edge(op, z)
    return z


def mult(
    x: BfvCiphertextNode | BfvPlaintextNode | CkksCiphertextNode | CkksPlaintextNode | int | float | complex,
    y: BfvCiphertextNode | BfvPlaintextNode | CkksCiphertextNode | CkksPlaintextNode | int | float | complex,
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Multiplication

    Define a multiplication computation step. Supported types: ct*ct, ct*pt, pt*ct, ct*scalar, scalar*ct.
    @param x Input data node or scalar.
    @param y Input data node or scalar.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag, g_param
    if isinstance(x, CiphertextNode):
        op0 = x
        op1 = y
    elif isinstance(y, CiphertextNode):
        op0 = y
        op1 = x
    else:
        raise ValueError('Multiplication expects one ciphertext input.')

    assert op0.metadata.degree == 1
    op = FheComputeNode(OperationType.Mult)
    if isinstance(op1, DataNode):
        if op1.type == DataType.Ciphertext:
            assert (
                op0.metadata.level == op1.metadata.level
                and op1.metadata.degree == 1
                and op0.metadata.is_ntt == op1.metadata.is_ntt
                and op0.metadata.mform_bits == op1.metadata.mform_bits
            )
            z_degree = 2
            if op0.id == op1.id:
                g_dag.add_edge(op0, op)
            else:
                g_dag.add_edges_from([(op0, op), (op1, op)])
        elif op1.type == DataType.Plaintext:
            if not op1.metadata.is_ringt:
                assert (
                    op0.metadata.level == op1.metadata.level
                    and op0.metadata.is_ntt == op1.metadata.is_ntt
                    and op0.metadata.mform_bits == op1.metadata.mform_bits
                )
            z_degree = 1
            g_dag.add_edges_from([(op0, op), (op1, op)])
        else:
            raise ValueError(f'Unsupported input type "{op1.type.value}" for multiplication.')
    else:
        op.scalar = op1
        z_degree = 1
        g_dag.add_edge(op0, op)

    output_node_id = random_id() if output_id is None else output_id
    if isinstance(op0, BfvCiphertextNode):
        z = BfvCiphertextNode(level=op0.metadata.level, id=output_node_id, degree=z_degree)
    elif isinstance(op0, CkksCiphertextNode):
        z = CkksCiphertextNode(level=op0.metadata.level, id=output_node_id, degree=z_degree)
    else:
        raise ValueError('Unsupported ciphertext scheme for multiplication.')
    z.metadata = op0.metadata.copy()
    z.metadata.degree = z_degree
    if isinstance(op1, DataNode):
        z.metadata.log_slots = max(op0.metadata.log_slots, op1.metadata.log_slots)
        if isinstance(z, CkksCiphertextNode):
            z.metadata.scale = op0.metadata.scale * op1.metadata.scale
        elif isinstance(z, BfvCiphertextNode) and op1.type == DataType.Ciphertext:
            if not isinstance(g_param, BfvParam):
                raise ValueError('BFV ciphertext multiplication requires BFV parameters.')
            q_mod_t = 1
            for q in g_param.q[: op0.metadata.level + 1]:
                q_mod_t = (q_mod_t * (q % g_param.t)) % g_param.t
            q_mod_t_neg = (g_param.t - q_mod_t) % g_param.t
            z.metadata.scale = float(
                (int(round(op0.metadata.scale)) * int(round(op1.metadata.scale)) * pow(q_mod_t_neg, -1, g_param.t))
                % g_param.t
            )
    elif isinstance(z, CkksCiphertextNode):
        z.metadata.scale = op0.metadata.scale * _ckks_scalar_mul_scale_factor(op1, op0.metadata.level)
    g_dag.add_edge(op, z)

    return z


def relin(
    x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Relinearization

    Define a relinearization computation step.
    @param x Input data node.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    if x.type != DataType.Ciphertext or x.metadata.degree != 2:
        raise ValueError(f'Unsupported input type "{x.type.value}" with degree {x.metadata.degree} for relinerization.')

    rlk = 'rlk_ntt'
    global g_evk_node_dict
    if rlk not in g_evk_node_dict:
        g_evk_node_dict[rlk] = RelinKeyNode(level=x.metadata.level)
    elif x.metadata.level > g_evk_node_dict[rlk].metadata.level:
        g_evk_node_dict[rlk].metadata.level = x.metadata.level
    op = FheComputeNode(OperationType.Relin)
    g_dag.add_edges_from([(x, op), (g_evk_node_dict[rlk], op)])

    if isinstance(x, BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=x.metadata.level)
    elif isinstance(x, CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=x.metadata.level)
    else:
        raise ValueError()
    z.metadata = x.metadata.copy()
    z.metadata.degree = 1
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
    assert ct3.metadata.degree == 2
    return relin(ct3, output_id)


def rescale(
    x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Rescale

    Define a BFV or CKKS rescale computation step.
    @param x Input data node.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag, g_param
    if not isinstance(x, (BfvCiphertextNode, CkksCiphertextNode)):
        raise ValueError(f'Unsupported input type "{x.type.value}" for rescale.')
    if x.metadata.level < 1:
        raise ValueError('Cannot rescale a ciphertext at level 0.')
    if isinstance(x, CkksCiphertextNode) and not isinstance(g_param, CkksParam):
        raise ValueError('CKKS rescale requires CKKS parameters.')
    op = FheComputeNode(OperationType.Rescale)
    g_dag.add_edge(x, op)
    output_node_id = random_id() if output_id is None else output_id
    if isinstance(x, BfvCiphertextNode):
        z = BfvCiphertextNode(id=output_node_id, level=x.metadata.level - 1, degree=x.metadata.degree)
    else:
        z = CkksCiphertextNode(id=output_node_id, level=x.metadata.level - 1, degree=x.metadata.degree)
    z.metadata = x.metadata.copy()
    if isinstance(x, CkksCiphertextNode):
        z.metadata.scale = x.metadata.scale / g_param.q[x.metadata.level]
    else:
        if not isinstance(g_param, BfvParam):
            raise ValueError('BFV rescale requires BFV parameters.')
        z.metadata.scale = float(
            (int(round(x.metadata.scale)) * pow(g_param.q[x.metadata.level] % g_param.t, -1, g_param.t)) % g_param.t
        )
    z.metadata.level -= 1
    g_dag.add_edge(op, z)
    return z


def drop_level(
    x: BfvCiphertextNode | CkksCiphertextNode, drop_level: int = 1, output_id: Optional[str] = None
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Drop level

    Define a drop-level computation step without rescaling.
    @param x Input data node.
    @param drop_level Number of levels to drop.
    @param output_id Output node ID.
    @return Result data node.
    """
    global g_dag
    if not isinstance(x, (BfvCiphertextNode, CkksCiphertextNode)):
        raise ValueError(f'Unsupported input type "{x.type.value}" for drop level.')
    if x.metadata.level < drop_level:
        raise ValueError('Dropped levels must not be larger than input level.')

    op = DropLevelNode(drop_level)
    g_dag.add_edge(x, op)
    output_node_id = random_id() if output_id is None else output_id
    if isinstance(x, BfvCiphertextNode):
        z = BfvCiphertextNode(id=output_node_id, level=x.metadata.level - drop_level, degree=x.metadata.degree)
    else:
        z = CkksCiphertextNode(id=output_node_id, level=x.metadata.level - drop_level, degree=x.metadata.degree)
    z.metadata = x.metadata.copy()
    z.metadata.level -= drop_level
    g_dag.add_edge(op, z)
    return z


def rotate_cols(
    x: BfvCiphertextNode | CkksCiphertextNode,
    steps: list[int] | int,
    output_id: Optional[str] = None,
    use_default_rotation_keys: bool = True,
) -> list[BfvCiphertextNode | CkksCiphertextNode]:
    """!Ciphertext rotation

    Define ciphertext column rotations. A single rotate_col compute node may consume one ciphertext and multiple
    Galois keys, and may produce multiple ciphertext outputs.
    @param x Input data node.
    @param steps Rotation steps (positive = left rotation, negative = right rotation).
    @param output_id Output node ID prefix.
    @param use_default_rotation_keys Whether to use the fixed default rotation key set.
    @return Result data nodes.
    """

    global g_dag, g_param, g_evk_node_dict
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using rotation operations.')
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate.')

    if isinstance(steps, int):
        steps = [steps]

    op = RotateColNode(steps, use_default_rotation_keys=use_default_rotation_keys)
    g_dag.add_edge(x, op)

    if use_default_rotation_keys:
        key_steps = []
        seen_key_steps = set()
        for step in steps:
            for substep in get_default_column_rotation_substeps(step):
                if substep not in seen_key_steps:
                    key_steps.append(substep)
                    seen_key_steps.add(substep)
    else:
        key_steps = steps

    for step in key_steps:
        gal_elem = get_galois_element_for_column_rotation_by(step, g_param.n)
        glk = f'glk_ntt_col_{gal_elem}'
        if glk not in g_evk_node_dict:
            g_evk_node_dict[glk] = GaloisKeyNode(id=glk, level=x.metadata.level)
        elif x.metadata.level > g_evk_node_dict[glk].metadata.level:
            g_evk_node_dict[glk].metadata.level = x.metadata.level
        g_dag.add_edge(g_evk_node_dict[glk], op)

    output = []
    for step in steps:
        output_node_id = (
            random_id() if output_id is None else (output_id if len(steps) == 1 else f'{output_id}_step{step}')
        )
        if isinstance(x, BfvCiphertextNode):
            z = BfvCiphertextNode(id=output_node_id, level=x.metadata.level, degree=x.metadata.degree)
        elif isinstance(x, CkksCiphertextNode):
            z = CkksCiphertextNode(id=output_node_id, level=x.metadata.level, degree=x.metadata.degree)
        else:
            raise ValueError()
        z.metadata = x.metadata.copy()
        g_dag.add_edge(op, z)
        output.append(z)

    return output


def rotate_rows(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode:
    global g_dag
    if not isinstance(x, BfvCiphertextNode):
        raise ValueError(f'Unsupported input type "{x.type.value}" for rotate rows.')
    glk = 'glk_ntt_row'

    global g_evk_node_dict
    if glk not in g_evk_node_dict:
        g_evk_node_dict[glk] = GaloisKeyNode(id=glk, level=x.metadata.level)
    elif x.metadata.level > g_evk_node_dict[glk].metadata.level:
        g_evk_node_dict[glk].metadata.level = x.metadata.level

    op = RotateRowNode()
    g_dag.add_edges_from([(x, op), (g_evk_node_dict[glk], op)])

    z = BfvCiphertextNode(
        id=random_id() if output_id is None else output_id, level=x.metadata.level, degree=x.metadata.degree
    )
    z.metadata = x.metadata.copy()
    g_dag.add_edge(op, z)

    return z


def conjugate(x: CkksCiphertextNode, output_id: Optional[str] = None) -> CkksCiphertextNode:
    global g_dag
    if not isinstance(x, CkksCiphertextNode):
        raise ValueError(f'Unsupported input type "{x.type.value}" for conjugate.')
    glk = 'glk_ntt_row'

    global g_evk_node_dict
    if glk not in g_evk_node_dict:
        g_evk_node_dict[glk] = GaloisKeyNode(id=glk, level=x.metadata.level)
    elif x.metadata.level > g_evk_node_dict[glk].metadata.level:
        g_evk_node_dict[glk].metadata.level = x.metadata.level

    op = ConjugateNode()
    g_dag.add_edges_from([(x, op), (g_evk_node_dict[glk], op)])

    z = CkksCiphertextNode(
        id=random_id() if output_id is None else output_id, level=x.metadata.level, degree=x.metadata.degree
    )
    z.metadata = x.metadata.copy()
    g_dag.add_edge(op, z)

    return z


def ct_pt_mult_accumulate_add_ct_slice(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextNode | CkksPlaintextNode],
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    global g_dag
    assert len(x) == len(y) + 1

    level = x[0].metadata.level
    degree = x[0].metadata.degree
    is_ntt = x[0].metadata.is_ntt
    mform_bits = x[0].metadata.mform_bits

    sum_cnt = len(x) - 1
    assert sum_cnt in [1, 2, 4, 8, 16]

    op = CmpacSumComputeNode(sum_cnt)

    for xi in x:
        assert (
            xi.type == DataType.Ciphertext
            and xi.metadata.level == level
            and xi.metadata.degree == degree
            and xi.metadata.is_ntt == is_ntt
            and xi.metadata.mform_bits == mform_bits
        )
    for yi in y:
        assert yi.type == DataType.Plaintext and yi.metadata.is_ringt

    for xi in x:
        g_dag.add_edge(xi, op)
    for yi in y:
        g_dag.add_edge(yi, op)

    if isinstance(x[0], BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=level, degree=degree)
    elif isinstance(x[0], CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=level, degree=degree)
    else:
        raise ValueError()
    z.metadata = x[0].metadata.copy()
    if isinstance(z, CkksCiphertextNode):
        z.metadata.scale = x[0].metadata.scale * y[0].metadata.scale
    g_dag.add_edge(op, z)
    return z


def ct_pt_mult_accumulate_slice(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextNode | CkksPlaintextNode],
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    global g_dag
    assert len(x) == len(y)

    level = x[0].metadata.level
    degree = x[0].metadata.degree
    is_ntt = x[0].metadata.is_ntt
    mform_bits = x[0].metadata.mform_bits

    sum_cnt = len(x)
    assert sum_cnt in [1, 2, 4, 8, 16]

    op = CmpSumComputeNode(sum_cnt)

    for xi in x:
        assert (
            xi.type == DataType.Ciphertext
            and xi.metadata.level == level
            and xi.metadata.degree == degree
            and xi.metadata.is_ntt == is_ntt
            and xi.metadata.mform_bits == mform_bits
        )
    for yi in y:
        assert yi.type == DataType.Plaintext and yi.metadata.is_ringt

    for xi in x:
        g_dag.add_edge(xi, op)
    for yi in y:
        g_dag.add_edge(yi, op)

    if isinstance(x[0], BfvCiphertextNode):
        z = BfvCiphertextNode(id=random_id() if output_id is None else output_id, level=level, degree=degree)
    elif isinstance(x[0], CkksCiphertextNode):
        z = CkksCiphertextNode(id=random_id() if output_id is None else output_id, level=level, degree=degree)
    else:
        raise ValueError()
    z.metadata = x[0].metadata.copy()
    if isinstance(z, CkksCiphertextNode):
        z.metadata.scale = x[0].metadata.scale * y[0].metadata.scale
    g_dag.add_edge(op, z)

    return z


def ct_pt_mult_accumulate(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextNode | CkksPlaintextNode],
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode:
    """!Ciphertext-plaintext vector dot product

    Define a ciphertext-plaintext vector dot product step. Prefer this when vector length meets requirements for better performance.
    @param x Input ciphertext vector.
    @param y Input ring-t plaintext vector; must have the same length as the ciphertext vector.
    @return Result data node.
    """
    assert len(x) == len(y) and len(x) > 0
    for yi in y:
        assert yi.type == DataType.Plaintext and yi.metadata.is_ringt

    n_processed_mult: int
    if len(x) >= 16 and isinstance(x[0], (BfvCiphertextNode, CkksCiphertextNode)):
        x_ct_slice = []
        w_pt_slice = []
        for i in range(16):
            x_ct_slice.append(x[i])
            w_pt_slice.append(y[i])

        partial_sum = ct_pt_mult_accumulate_slice(x_ct_slice, w_pt_slice)
        n_processed_mult = 16

    elif len(x) >= 8 and isinstance(x[0], (BfvCiphertextNode, CkksCiphertextNode)):
        x_ct_slice = []
        w_pt_slice = []
        for i in range(8):
            x_ct_slice.append(x[i])
            w_pt_slice.append(y[i])

        partial_sum = ct_pt_mult_accumulate_slice(x_ct_slice, w_pt_slice)
        n_processed_mult = 8
    else:
        partial_sum = mult(x[0], y[0], output_id=output_id)
        n_processed_mult = 1

    n_input: int = len(x)
    while n_processed_mult < n_input:
        slice_size = next(x for x in [16, 8, 4, 2, 1] if n_input - n_processed_mult >= x)
        x_ct_slice = []
        w_pt_slice = []
        for i in range(slice_size):
            x_ct_slice.append(x[n_processed_mult + i])
            w_pt_slice.append(y[n_processed_mult + i])
        x_ct_slice.append(partial_sum)
        slice_output_id = output_id if n_processed_mult + slice_size == n_input else None
        partial_sum = ct_pt_mult_accumulate_add_ct_slice(x_ct_slice, w_pt_slice, output_id=slice_output_id)
        n_processed_mult += slice_size

    assert isinstance(partial_sum, (BfvCiphertextNode, CkksCiphertextNode))
    return partial_sum


def _default_ckks_bootstrap_extra_levels() -> int:
    return 3 + 8 + 4


def bootstrap(x: CkksCiphertextNode, output_id: Optional[str] = None) -> CkksCiphertextNode:
    global g_dag, g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before using bootstrap operation.')
    if not isinstance(g_param, CkksParam):
        raise ValueError('CKKS bootstrap requires CKKS parameters.')
    if x.type != DataType.Ciphertext:
        raise ValueError(f'Unsupported input type "{x.type.value}" for bootstrap.')
    if x.metadata.level != 0:
        raise ValueError(f'Unsupported input level "{x.metadata.level}" for bootstrap.')

    op = FheComputeNode(OperationType.Bootstrap)
    g_dag.add_edge(x, op)

    # Lattigo v6 GenEvaluationKeys creates a bootstrap-specific key set.
    # These keys are generated under the bootstrapping parameters/skN2 and
    # must not be confused with the normal task rlk_ntt/glk_ntt keys.
    global g_evk_node_dict
    btp_key_level = g_param.max_level + _default_ckks_bootstrap_extra_levels()

    evk_rlk = 'evk_rlk'
    if evk_rlk not in g_evk_node_dict:
        g_evk_node_dict[evk_rlk] = RelinKeyNode(id=evk_rlk, level=btp_key_level, key_role='bootstrap')
    else:
        g_evk_node_dict[evk_rlk].metadata.level = btp_key_level
        g_evk_node_dict[evk_rlk].key_role = 'bootstrap'
    g_dag.add_edge(g_evk_node_dict[evk_rlk], op)

    for evk_id in ('evk_n1_to_n2', 'evk_n2_to_n1'):
        if evk_id not in g_evk_node_dict:
            g_evk_node_dict[evk_id] = EvaluationKeyNode(id=evk_id, level=btp_key_level, key_role='bootstrap')
        else:
            g_evk_node_dict[evk_id].metadata.level = btp_key_level
            g_evk_node_dict[evk_id].key_role = 'bootstrap'
        g_dag.add_edge(g_evk_node_dict[evk_id], op)

    evk_dense_to_sparse = 'evk_dense_to_sparse'
    if evk_dense_to_sparse not in g_evk_node_dict:
        g_evk_node_dict[evk_dense_to_sparse] = EvaluationKeyNode(id=evk_dense_to_sparse, level=0, key_role='bootstrap')
    else:
        g_evk_node_dict[evk_dense_to_sparse].metadata.level = 0
        g_evk_node_dict[evk_dense_to_sparse].key_role = 'bootstrap'
    g_dag.add_edge(g_evk_node_dict[evk_dense_to_sparse], op)

    evk_sparse_to_dense = 'evk_sparse_to_dense'
    if evk_sparse_to_dense not in g_evk_node_dict:
        g_evk_node_dict[evk_sparse_to_dense] = EvaluationKeyNode(
            id=evk_sparse_to_dense, level=btp_key_level, key_role='bootstrap'
        )
    else:
        g_evk_node_dict[evk_sparse_to_dense].metadata.level = btp_key_level
        g_evk_node_dict[evk_sparse_to_dense].key_role = 'bootstrap'
    g_dag.add_edge(g_evk_node_dict[evk_sparse_to_dense], op)

    for gal_elem in bootstrapping_galois_elements(g_param.log_n):
        evk_glk = f'evk_glk_{gal_elem}'
        if evk_glk not in g_evk_node_dict:
            g_evk_node_dict[evk_glk] = GaloisKeyNode(id=evk_glk, level=btp_key_level, key_role='bootstrap')
        else:
            g_evk_node_dict[evk_glk].metadata.level = btp_key_level
            g_evk_node_dict[evk_glk].key_role = 'bootstrap'
        g_evk_node_dict[evk_glk].galois_element = gal_elem
        g_dag.add_edge(g_evk_node_dict[evk_glk], op)

    z = CkksCiphertextNode(
        id=random_id() if output_id is None else output_id,
        level=g_param.max_level,
        degree=x.metadata.degree,
        log_slots=x.metadata.log_slots,
        scale=x.metadata.scale,
    )
    z.metadata = x.metadata.copy()
    z.metadata.level = g_param.max_level
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


def process_custom_task(
    input_args: list[Argument] | None = None,
    output_args: list[Argument] | None = None,
    output_instruction_path: str | None = None,
    processor: Processor = Processor.CPU,
) -> dict:
    """!Process custom task

    Convert a custom task into the required output files based on its input and output data arguments.

    Note: set_fhe_param() must be called before invoking this function.

    @param input_args List of all input arguments for the custom task.
    @param output_args List of all output arguments for the custom task.
    @param output_instruction_path Directory to store the task output files.
    @param processor Target processor backend (Processor.CPU or Processor.GPU).
    @return The task abstract computation graph.
    """
    global g_evk_node_dict, g_dag, g_param
    if g_param is None:
        raise RuntimeError('Please call set_fhe_param() before calling process_custom_task().')

    try:
        from .linker.task_context import _TaskContext
    except ImportError:
        from linker.task_context import _TaskContext
    ctx = _TaskContext.build(input_args, output_args, g_evk_node_dict, name='Acc task', algorithm=g_param.algo)

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
                    f'Data node "{node.id}" is not used for any computation, nor is it an output data node.'
                )

    try:
        from .linker import serialize_dag, serialize_signature
    except ImportError:
        from linker import serialize_dag, serialize_signature

    _meta = {'name': ctx.name, 'algorithm': ctx.algorithm.value}
    mag = serialize_dag(
        g_dag,
        inputs=ctx.inputs,
        outputs=ctx.outputs,
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

    if processor in (Processor.GPU, Processor.CPU):
        try:
            from .linker import compile_mega_ag
        except ImportError:
            from linker import compile_mega_ag
        compiled_dag = compile_mega_ag(g_dag, processor, ctx)
        compiled = serialize_dag(
            compiled_dag,
            inputs=ctx.inputs,
            outputs=ctx.outputs,
            meta=_meta,
            use_ops=True,
        )
        with open(os.path.join(output_instruction_path, 'compiled_mega_ag.json'), 'w', encoding='utf-8') as f:
            json.dump(compiled, f, indent=2)

    g_evk_node_dict.clear()
    g_dag.clear()
    reset_node_state()

    return mag

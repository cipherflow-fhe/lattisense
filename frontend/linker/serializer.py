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


"""
serializer.py — Serialization of g_dag and task signature to JSON-ready dicts.

Two entry points:

    serialize_dag(dag, inputs, outputs, meta) -> dict
        Converts a networkx DiGraph of Python node objects to the
        mega_ag.json / compiled_mega_ag.json dict format.
        Works on both the original g_dag and the linker-processed DAG;
        on_cpu / priority fields are included only when present on a node.

    serialize_signature(ctx: _TaskContext) -> dict
        Builds the task_signature.json dict from a resolved _TaskContext.
        ckks_btp_evk field is only written when non-empty.
"""

import networkx as nx

from frontend.types import _CompoundComputeNode, is_compute_node, is_data_node
from .task_context import _TaskContext


# ---------------------------------------------------------------------------
# DAG serialization
# ---------------------------------------------------------------------------


def serialize_dag(
    dag: nx.DiGraph,
    inputs: list,
    outputs: list,
    meta: dict,
    data_serializer=None,
    use_ops: bool = False,
) -> dict:
    """Serialize a DiGraph of FHE node objects to the mega_ag dict format.

    Args:
        dag:            DiGraph whose nodes are DataNode / ComputeNode objects
                        (or their bridge/compound variants from the linker).
        inputs:         DataNode objects listed as graph inputs
                        (online inputs + keys).
        outputs:        DataNode objects listed as graph outputs.
        meta:           Dict with keys 'name', 'algorithm'.
        data_serializer: Optional callable used to serialize each data node.
                         Defaults to node.to_json_dict().
        use_ops:         When true, serialize each top-level compute as a task
                         with an ops list instead of a top-level operation type.

    Returns:
        Dict suitable for json.dump — matches the mega_ag.json schema.
        on_cpu and priority fields are included only when set on a node.
        parameter is NOT included; it is written to fhe_parameter.json separately.
    """
    result: dict = {
        'name': meta['name'],
        'algorithm': meta['algorithm'],
        'inputs': [n.id for n in inputs],
        'outputs': [n.id for n in outputs],
        'data': {},
        'compute': {},
    }
    data_serializer = data_serializer or (lambda node: node.to_json_dict())

    for node in dag.nodes():
        if is_data_node(node):
            result['data'][node.id] = data_serializer(node)
        elif is_compute_node(node):
            d = _serialize_ops_task(dag, node) if use_ops else node.to_json_dict(dag)
            on_cpu = getattr(node, 'on_cpu', None)
            if on_cpu is not None:
                d['on_cpu'] = on_cpu
            if hasattr(node, 'priority'):
                d['priority'] = node.priority
            result['compute'][node.id] = d

    return result


def _serialize_ops_task(dag: nx.DiGraph, node) -> dict:
    if isinstance(node, _CompoundComputeNode):
        return node.to_json_dict(dag)

    op_json = node.to_json_dict(dag)
    return {
        'ops': [op_json],
        'inputs': op_json['inputs'],
        'outputs': op_json['outputs'],
    }


# ---------------------------------------------------------------------------
# Task signature serialization
# ---------------------------------------------------------------------------


def serialize_signature(ctx: _TaskContext) -> dict:
    """Build task_signature.json dict from a resolved _TaskContext.

    Args:
        ctx: Resolved task context produced by _TaskContext.build().

    Returns:
        Dict suitable for json.dump as task_signature.json.
        The ckks_btp_evk field is only written when ctx.ckks_btp_evk_sig
        is non-empty.
    """
    signature: dict = {
        'algorithm': ctx.algorithm.value,
        'key': {
            'rlk': ctx.rlk_sig,
            'glk': ctx.glk_sig,
            'glk_order': ctx.glk_order,
        },
        'online': ctx.input_sigdata + ctx.output_sigdata,
    }
    if ctx.ckks_btp_evk_sig or ctx.ckks_btp_glk_order:
        if ctx.ckks_btp_evk_sig:
            signature['key']['ckks_btp_evk'] = ctx.ckks_btp_evk_sig
        if ctx.ckks_btp_glk_order:
            signature['key']['ckks_btp_glk_order'] = ctx.ckks_btp_glk_order
    return signature

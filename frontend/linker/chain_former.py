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
chain_former.py — Chain formation, priority computation, and serialization.

Steps:
    1. apply_processor_layout  — insert ABI bridge nodes (processor_layout.py)
    2. form_chains()           — merge eligible serial FHE ops into COMPOUND nodes
    3. compute_properties()    — compute bottom_level priority per compute node
    4. _serialize_dag()        — emit compiled_mega_ag.json dict

Entry point: compile_mega_ag(dag, processor, *, inputs, outputs, ...)
"""

import networkx as nx

from frontend.types import (
    ComputeNode,
    OperationType,
    Processor,
    is_key_data_node,
    is_custom_compute,
    is_bridge_compute,
    is_compute_node,
    is_data_node,
)
from .processor_layout import apply_processor_layout
from .task_context import _TaskContext


def compile_mega_ag(
    dag: nx.DiGraph,
    processor: Processor,
    ctx: _TaskContext,
) -> nx.DiGraph:
    """Apply processor layout and compute priorities.

    Args:
        dag:       g_dag from process_custom_task (not modified in place).
        processor: Target processor.
        ctx:       Resolved task context from _TaskContext.build().

    Returns:
        New DiGraph with bridge nodes inserted and priority set on each
        compute node.  Caller is responsible for serialization and I/O.
    """
    dag = apply_processor_layout(dag, processor, ctx.inputs, ctx.outputs)
    dag = form_chains(dag, processor, ctx.outputs)
    dag = compute_properties(dag)
    return dag


# ---------------------------------------------------------------------------
# Chain formation
# ---------------------------------------------------------------------------


_MERGEABLE_OP_TYPES: frozenset[OperationType] = frozenset(
    {
        OperationType.Add,
        OperationType.Sub,
        OperationType.Neg,
        OperationType.Mult,
        OperationType.Relin,
        OperationType.Rescale,
        OperationType.DropLevel,
        OperationType.RotateCol,
        OperationType.RotateRow,
        OperationType.CmpSum,
        OperationType.CmpacSum,
    }
)


class _CompoundComputeNode(ComputeNode):
    is_custom = False
    is_bridge = False
    is_compound = True

    def __init__(self, processor: Processor, internal_ops: list[dict], ext_inputs: list, ext_outputs: list) -> None:
        super().__init__(OperationType.Compound)
        self.id = f'chain_{self.index}'
        self.internal_ops = internal_ops
        self._ext_inputs = ext_inputs
        self._ext_outputs = ext_outputs
        self.on_cpu = processor == Processor.CPU
        self.priority = 0

    def to_json_dict(self, dag: nx.DiGraph) -> dict:
        return {
            'id': self.id,
            'type': OperationType.Compound.value,
            'internal_ops': self.internal_ops,
            'inputs': [d.index for d in self._ext_inputs],
            'outputs': [d.index for d in self._ext_outputs],
        }


def form_chains(dag: nx.DiGraph, processor: Processor, graph_outputs: list) -> nx.DiGraph:
    """Replace safe serial FHE op chains with COMPOUND compute nodes."""
    compute_topo = [n for n in nx.topological_sort(dag) if is_compute_node(n)]
    graph_output_set = set(graph_outputs)

    visited: set = set()
    chains: list[list] = []

    for node in compute_topo:
        if node in visited:
            continue
        if not _is_mergeable_op(node):
            visited.add(node)
            chains.append([node])
            continue

        chain = _candidate_chain(dag, node, visited)
        if _is_valid_chain(dag, chain, graph_output_set):
            visited.update(chain)
            chains.append(chain)
        else:
            visited.add(node)
            chains.append([node])

    return _build_compound_dag(dag, chains, processor, graph_output_set)


def _candidate_chain(dag: nx.DiGraph, start, visited: set) -> list:
    chain = [start]
    current = start

    while True:
        succ = _single_serial_successor(dag, current, visited)
        if succ is None or succ in visited or not _is_mergeable_op(succ):
            break
        if len(_fhe_compute_predecessors(dag, succ)) != 1:
            break
        chain.append(succ)
        current = succ

    return chain


def _single_serial_successor(dag: nx.DiGraph, compute_node, visited: set):
    outputs = _data_successors(dag, compute_node)
    if len(outputs) != 1:
        return None

    out_data = outputs[0]
    if is_key_data_node(out_data):
        return None

    candidates = []
    for consumer in (c for c in dag.successors(out_data) if is_compute_node(c)):
        if consumer in visited or not _is_mergeable_op(consumer):
            continue
        if len(_fhe_compute_predecessors(dag, consumer)) == 1:
            candidates.append(consumer)

    if len(candidates) == 1:
        return candidates[0]

    unary_candidates = [c for c in candidates if len(_non_key_data_predecessors(dag, c)) == 1]
    if len(unary_candidates) == 1:
        return unary_candidates[0]
    return None


def _is_valid_chain(dag: nx.DiGraph, chain: list, graph_outputs: set) -> bool:
    if len(chain) <= 1:
        return False
    if any(not _is_mergeable_op(op) for op in chain):
        return False
    if any(len(_data_successors(dag, op)) != 1 for op in chain):
        return False

    ext_outputs = _chain_external_outputs(dag, chain, graph_outputs)
    if len(ext_outputs) < 1:
        return False

    chain_set = set(chain)
    for data in _chain_internal_data(dag, chain, graph_outputs):
        consumers = [c for c in dag.successors(data) if is_compute_node(c)]
        if not consumers or any(c not in chain_set for c in consumers):
            return False

    return True


def _build_compound_dag(dag: nx.DiGraph, chains: list[list], processor: Processor, graph_outputs: set) -> nx.DiGraph:
    """Construct a new DiGraph replacing each multi-op chain with one COMPOUND node."""
    new_dag = nx.DiGraph()

    for node in dag.nodes():
        if is_data_node(node):
            new_dag.add_node(node)

    for chain in chains:
        if len(chain) == 1:
            op = chain[0]
            new_dag.add_node(op)
            for pred in dag.predecessors(op):
                if pred in new_dag:
                    new_dag.add_edge(pred, op)
            for succ in dag.successors(op):
                if succ in new_dag:
                    new_dag.add_edge(op, succ)
        else:
            compound = _make_compound_node(dag, chain, processor, graph_outputs)
            new_dag.add_node(compound)
            for data in compound._ext_inputs:
                new_dag.add_edge(data, compound)
            for data in compound._ext_outputs:
                new_dag.add_edge(compound, data)

    return new_dag


def _make_compound_node(dag: nx.DiGraph, chain: list, processor: Processor, graph_outputs: set) -> _CompoundComputeNode:
    """Build a COMPOUND compute node for a validated chain."""
    internal_ops = []
    for op in chain:
        op_json = op.to_json_dict(dag)
        internal_ops.append({'index': op.index, **op_json})

    return _CompoundComputeNode(
        processor=processor,
        internal_ops=internal_ops,
        ext_inputs=_chain_external_inputs(dag, chain),
        ext_outputs=_chain_external_outputs(dag, chain, graph_outputs),
    )


def _chain_external_inputs(dag: nx.DiGraph, chain: list) -> list:
    chain_set = set(chain)
    seen: set = set()
    result = []
    for op in chain:
        for data in _data_predecessors(dag, op):
            producers = [p for p in dag.predecessors(data) if is_compute_node(p)]
            if (not producers or any(p not in chain_set for p in producers)) and data not in seen:
                result.append(data)
                seen.add(data)
    return result


def _chain_external_outputs(dag: nx.DiGraph, chain: list, graph_outputs: set) -> list:
    chain_set = set(chain)
    seen: set = set()
    result = []
    for op in chain:
        for data in _data_successors(dag, op):
            consumers = [c for c in dag.successors(data) if is_compute_node(c)]
            if (
                data in graph_outputs or not consumers or any(c not in chain_set for c in consumers)
            ) and data not in seen:
                result.append(data)
                seen.add(data)
    return result


def _chain_internal_data(dag: nx.DiGraph, chain: list, graph_outputs: set) -> list:
    chain_set = set(chain)
    result = []
    for op in chain:
        for data in _data_successors(dag, op):
            consumers = [c for c in dag.successors(data) if is_compute_node(c)]
            if data not in graph_outputs and consumers and all(c in chain_set for c in consumers):
                result.append(data)
    return result


def _data_predecessors(dag: nx.DiGraph, compute_node) -> list:
    return [n for n in dag.predecessors(compute_node) if is_data_node(n)]


def _data_successors(dag: nx.DiGraph, compute_node) -> list:
    return [n for n in dag.successors(compute_node) if is_data_node(n)]


def _non_key_data_predecessors(dag: nx.DiGraph, compute_node) -> list:
    return [n for n in _data_predecessors(dag, compute_node) if not is_key_data_node(n)]


def _is_mergeable_op(node) -> bool:
    return (
        is_compute_node(node)
        and not is_custom_compute(node)
        and not _is_bridge(node)
        and getattr(node, 'type', None) in _MERGEABLE_OP_TYPES
    )


# ---------------------------------------------------------------------------
# Priority computation  (bottom_level = MAKESPAN_FIRST)
# ---------------------------------------------------------------------------


def compute_properties(dag: nx.DiGraph) -> nx.DiGraph:
    """Compute bottom_level for each compute node and store as .priority.

    bottom_level(v) = length of the longest path from v to any sink
    in the compute-to-compute dependency graph.
    """
    # Build compute-to-compute dependency graph
    cg = nx.DiGraph()
    cg.add_nodes_from(n for n in dag if is_compute_node(n))
    for data in (n for n in dag if is_data_node(n)):
        producers = [p for p in dag.predecessors(data) if is_compute_node(p)]
        consumers = [c for c in dag.successors(data) if is_compute_node(c)]
        for p in producers:
            for c in consumers:
                if not cg.has_edge(p, c):
                    cg.add_edge(p, c)

    # Propagate bottom_level from sinks to sources (reverse topological order)
    bottom_level: dict = {n: 0 for n in cg}
    for node in reversed(list(nx.topological_sort(cg))):
        for succ in cg.successors(node):
            candidate = bottom_level[succ] + 1
            if bottom_level[node] < candidate:
                bottom_level[node] = candidate

    for node in cg:
        node.priority = bottom_level[node]

    return dag


# ---------------------------------------------------------------------------
# Graph traversal helpers
# ---------------------------------------------------------------------------


def _is_bridge(node) -> bool:
    return is_bridge_compute(node)


def _fhe_compute_successors(dag: nx.DiGraph, compute_node) -> list:
    """Compute nodes reachable from compute_node via a single non-key data output."""
    result = []
    for out_data in dag.successors(compute_node):
        if not is_data_node(out_data) or is_key_data_node(out_data):
            continue
        for c in dag.successors(out_data):
            if is_compute_node(c):
                result.append(c)
    return result


def _fhe_compute_predecessors(dag: nx.DiGraph, compute_node) -> list:
    """Compute nodes that feed compute_node via a non-key data input."""
    result = []
    for in_data in dag.predecessors(compute_node):
        if not is_data_node(in_data) or is_key_data_node(in_data):
            continue
        for p in dag.predecessors(in_data):
            if is_compute_node(p):
                result.append(p)
    return result

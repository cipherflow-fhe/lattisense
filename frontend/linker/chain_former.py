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
    2. form_chains()           — merge serial FHE ops into COMPOUND nodes
                                 (currently commented out — pending C++ Phase 3)
    3. compute_properties()    — compute bottom_level priority per compute node
    4. _serialize_dag()        — emit compiled_mega_ag.json dict

Entry point: compile_mega_ag(dag, processor, *, inputs, outputs, ...)
"""

import networkx as nx

from frontend.types import (
    Processor,
    gen_compute_node_index,
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
    # dag = form_chains(dag)   # TODO: enable once C++ COMPOUND executor is ready
    dag = compute_properties(dag)
    return dag


# ---------------------------------------------------------------------------
# Chain formation  (pending C++ Phase 3)
# ---------------------------------------------------------------------------


def form_chains(dag: nx.DiGraph) -> nx.DiGraph:
    """Replace serial FHE op chains with COMPOUND compute nodes.

    A chain is a maximal sequence of FHE ops where:
    - Each op has exactly one non-key FHE data output consumed by exactly
      one successor.
    - That successor has exactly one non-key FHE data input.
    - Neither end is a bridge op or custom op.

    Returns a new DiGraph where each chain (or single op) becomes one
    COMPOUND compute node.
    """
    # Collect compute nodes in topological order
    compute_topo = [n for n in nx.topological_sort(dag) if is_compute_node(n)]

    visited: set = set()
    chains: list[list] = []

    for node in compute_topo:
        if node in visited:
            continue
        if _is_bridge(node) or is_custom_compute(node):
            visited.add(node)
            chains.append([node])
            continue

        chain = [node]
        visited.add(node)
        current = node

        while True:
            fhe_succs = _fhe_compute_successors(dag, current)
            if len(fhe_succs) != 1:
                break
            succ = fhe_succs[0]
            if succ in visited or _is_bridge(succ) or is_custom_compute(succ):
                break
            if len(_fhe_compute_predecessors(dag, succ)) != 1:
                break
            chain.append(succ)
            visited.add(succ)
            current = succ

        chains.append(chain)

    return _build_compound_dag(dag, chains)


def _build_compound_dag(dag: nx.DiGraph, chains: list[list]) -> nx.DiGraph:
    """Construct a new DiGraph replacing each multi-op chain with a COMPOUND node."""
    new_dag = nx.DiGraph()

    # Determine which data nodes are internal to a chain
    internal_data: set = set()
    for chain in chains:
        if len(chain) <= 1:
            continue
        chain_set = set(chain)
        for op in chain[:-1]:
            for out_data in dag.successors(op):
                if is_data_node(out_data):
                    consumers = [c for c in dag.successors(out_data) if is_compute_node(c)]
                    if consumers and all(c in chain_set for c in consumers):
                        internal_data.add(out_data)

    # Add all non-internal data nodes to new graph
    for node in dag.nodes():
        if is_data_node(node) and node not in internal_data:
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
            compound = _make_compound_node(dag, chain, internal_data, gen_compute_node_index())
            new_dag.add_node(compound)
            # Wire external inputs and outputs
            ext_inputs = _chain_external_inputs(dag, chain, internal_data)
            ext_outputs = _chain_external_outputs(dag, chain, internal_data)
            for data in ext_inputs:
                if data in new_dag:
                    new_dag.add_edge(data, compound)
            for data in ext_outputs:
                if data in new_dag:
                    new_dag.add_edge(compound, data)

    return new_dag


def _make_compound_node(dag, chain, internal_data, new_index):
    """Build a CompoundComputeNode for a chain of ops."""
    ext_inputs = _chain_external_inputs(dag, chain, internal_data)
    local_idx: dict = {d: i for i, d in enumerate(ext_inputs)}
    next_local = len(ext_inputs)

    internal_ops = []
    for op in chain:
        local_inputs = [local_idx.get(d, -1) for d in dag.predecessors(op) if is_data_node(d)]
        outputs_list = [d for d in dag.successors(op) if is_data_node(d)]
        assert len(outputs_list) == 1, 'Chain op must have exactly one output'
        out_data = outputs_list[0]
        local_idx[out_data] = next_local
        local_output = next_local
        next_local += 1

        op_type = op.type if isinstance(op.type, str) else op.type.value
        op_entry = {
            'type': op_type,
            'output_level': getattr(out_data, 'level', -1),
            'inputs': local_inputs,
            'output': local_output,
        }
        for extra in ('step', 'sum_cnt'):
            if hasattr(op, extra):
                op_entry[extra] = getattr(op, extra)
        internal_ops.append(op_entry)

    ext_outputs = _chain_external_outputs(dag, chain, internal_data)

    # Lightweight compound node object
    class _CompoundNode:
        is_custom = False
        is_bridge = False
        is_compound = True

        def __init__(self, idx, ops, ins, outs):
            self.index = idx
            self.id = f'chain_{idx}'
            self.type = 'compound'
            self.internal_ops = ops
            self._ext_inputs = ins
            self._ext_outputs = outs
            self.on_cpu = None
            self.priority = 0

        def to_json_dict(self, dag):
            return {
                'id': self.id,
                'type': 'compound',
                'internal_ops': self.internal_ops,
                'inputs': [d.index for d in self._ext_inputs],
                'outputs': [d.index for d in self._ext_outputs],
            }

    return _CompoundNode(new_index, internal_ops, ext_inputs, ext_outputs)


def _chain_external_inputs(dag, chain, internal_data):
    seen: set = set()
    result = []
    for op in chain:
        for d in dag.predecessors(op):
            if is_data_node(d) and d not in internal_data and d not in seen:
                result.append(d)
                seen.add(d)
    return result


def _chain_external_outputs(dag, chain, internal_data):
    last_op = chain[-1]
    return [d for d in dag.successors(last_op) if is_data_node(d) and d not in internal_data]


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

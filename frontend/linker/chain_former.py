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
    3. compute_properties()    — compute bottom_level priority per top-level task node
    4. _serialize_dag()        — emit compiled_mega_ag.json dict

Entry point: compile_mega_ag(dag, processor, *, inputs, outputs, ...)
"""

from collections import defaultdict
import os

import networkx as nx

from frontend.types import (
    OperationType,
    Processor,
    _CompoundComputeNode,
    is_key_data_node,
    is_custom_compute,
    is_bridge_compute,
    is_compute_node,
    is_data_node,
)
from .processor_layout import compute_runs_on_cpu


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


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _load_batch_max_size() -> int:
    return _env_int('LATTISENSE_GPU_LOAD_BATCH_MAX_SIZE', 64)


def _load_batch_min_size() -> int:
    return _env_int('LATTISENSE_GPU_LOAD_BATCH_MIN_SIZE', 2)


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
    """Build a multi-op task node for a validated FHE chain."""
    task = _CompoundComputeNode(
        on_cpu=compute_runs_on_cpu(chain[0], processor),
        ops=[_internal_op_json(dag, op) for op in chain],
        ext_inputs=_chain_external_inputs(dag, chain),
        ext_outputs=_chain_external_outputs(dag, chain, graph_outputs),
    )
    task.id = f'chain_{task.index}'
    return task


# ---------------------------------------------------------------------------
# GPU load_to_backend batching
# ---------------------------------------------------------------------------


def form_gpu_load_batches(dag: nx.DiGraph, processor: Processor) -> nx.DiGraph:
    """Batch independent GPU load_to_backend nodes with matching bottom-level priority."""
    if processor != Processor.GPU:
        return dag

    bottom_levels = compute_bottom_levels(dag)
    compute_topo = [n for n in nx.topological_sort(dag) if is_compute_node(n)]
    loads_by_priority: dict[int, list] = defaultdict(list)
    for node in compute_topo:
        if _is_load_batch_eligible(dag, node):
            loads_by_priority[bottom_levels[node]].append(node)

    first_load_to_batch: dict[object, list] = {}
    batched_loads: set = set()
    max_size = _load_batch_max_size()
    min_size = _load_batch_min_size()
    for loads in loads_by_priority.values():
        for start in range(0, len(loads), max_size):
            chunk = loads[start : start + max_size]
            if len(chunk) >= min_size:
                first_load_to_batch[chunk[0]] = chunk
                batched_loads.update(chunk)

    if not batched_loads:
        return dag

    new_dag = nx.DiGraph()
    for node in dag.nodes():
        if is_data_node(node):
            new_dag.add_node(node)

    for node in compute_topo:
        if node in batched_loads:
            if node not in first_load_to_batch:
                continue
            compound = _make_load_batch_compound_node(dag, first_load_to_batch[node], processor)
            new_dag.add_node(compound)
            for data in compound._ext_inputs:
                new_dag.add_edge(data, compound)
            for data in compound._ext_outputs:
                new_dag.add_edge(compound, data)
            continue

        new_dag.add_node(node)
        for pred in dag.predecessors(node):
            if pred in new_dag:
                new_dag.add_edge(pred, node)
        for succ in dag.successors(node):
            if succ in new_dag:
                new_dag.add_edge(node, succ)

    return new_dag


def form_single_op_tasks(dag: nx.DiGraph, processor: Processor) -> nx.DiGraph:
    """Wrap remaining single ops as one-op top-level compound tasks."""
    compute_topo = [n for n in nx.topological_sort(dag) if is_compute_node(n)]
    new_dag = nx.DiGraph()

    for node in dag.nodes():
        if is_data_node(node):
            new_dag.add_node(node)

    for node in compute_topo:
        task = node if isinstance(node, _CompoundComputeNode) else _make_single_op_task(dag, node, processor)
        new_dag.add_node(task)
        for data in _data_predecessors(dag, node):
            new_dag.add_edge(data, task)
        for data in _data_successors(dag, node):
            new_dag.add_edge(task, data)

    return new_dag


def _make_single_op_task(dag: nx.DiGraph, op, processor: Processor) -> _CompoundComputeNode:
    task = _CompoundComputeNode(
        on_cpu=compute_runs_on_cpu(op, processor),
        ops=[_internal_op_json(dag, op)],
        ext_inputs=_data_predecessors(dag, op),
        ext_outputs=_data_successors(dag, op),
    )
    task.index = op.index
    task.id = op.id
    return task


def _internal_op_json(dag: nx.DiGraph, op) -> dict:
    return {'index': op.index, **op.to_json_dict(dag)}


def _is_load_batch_eligible(dag: nx.DiGraph, node) -> bool:
    if not is_bridge_compute(node) or getattr(node, 'type', None) != OperationType.LoadToBackend:
        return False

    inputs = _data_predecessors(dag, node)
    outputs = _data_successors(dag, node)
    return len(inputs) == 1 and len(outputs) == 1 and not is_key_data_node(outputs[0])


def _make_load_batch_compound_node(dag: nx.DiGraph, loads: list, processor: Processor) -> _CompoundComputeNode:
    ops = []
    ext_inputs = []
    ext_outputs = []
    seen_inputs: set = set()
    seen_outputs: set = set()

    for op in loads:
        ops.append(_internal_op_json(dag, op))

        for data in _data_predecessors(dag, op):
            if data not in seen_inputs:
                ext_inputs.append(data)
                seen_inputs.add(data)
        for data in _data_successors(dag, op):
            if data not in seen_outputs:
                ext_outputs.append(data)
                seen_outputs.add(data)

    task = _CompoundComputeNode(
        on_cpu=False,
        ops=ops,
        ext_inputs=ext_inputs,
        ext_outputs=ext_outputs,
    )
    task.id = f'load_batch_{task.index}'
    return task


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


def compute_bottom_levels(dag: nx.DiGraph) -> dict:
    """Compute bottom-level priority values without mutating nodes."""
    cg = _compute_dependency_graph(dag)
    bottom_level: dict = {n: 0 for n in cg}
    for node in reversed(list(nx.topological_sort(cg))):
        for succ in cg.successors(node):
            candidate = bottom_level[succ] + 1
            if bottom_level[node] < candidate:
                bottom_level[node] = candidate
    return bottom_level


def compute_properties(dag: nx.DiGraph) -> nx.DiGraph:
    """Store bottom-level priority only on top-level compound task nodes."""
    for node, priority in compute_bottom_levels(dag).items():
        if isinstance(node, _CompoundComputeNode):
            node.priority = priority
    return dag


def _compute_dependency_graph(dag: nx.DiGraph) -> nx.DiGraph:
    cg = nx.DiGraph()
    cg.add_nodes_from(n for n in dag if is_compute_node(n))
    for data in (n for n in dag if is_data_node(n)):
        producers = [p for p in dag.predecessors(data) if is_compute_node(p)]
        consumers = [c for c in dag.successors(data) if is_compute_node(c)]
        for p in producers:
            for c in consumers:
                if not cg.has_edge(p, c):
                    cg.add_edge(p, c)
    return cg


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

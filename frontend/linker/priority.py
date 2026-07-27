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

import networkx as nx

from frontend.types import DataType, _CompoundComputeNode, is_compute_node


def compute_bottom_levels(dag: nx.DiGraph, compute_topo: list | None = None, op_outputs: dict | None = None) -> dict:
    """Compute bottom-level priority values without building a separate compute graph."""
    if compute_topo is None:
        compute_topo = [n for n in nx.topological_sort(dag) if is_compute_node(n)]
    if op_outputs is None:
        op_outputs = {node: list(dag.successors(node)) for node in compute_topo}

    bottom_level: dict = {node: 0 for node in compute_topo}
    for node in reversed(compute_topo):
        level = 0
        for data in op_outputs[node]:
            for succ in dag.successors(data):
                if succ not in bottom_level:
                    continue
                candidate = bottom_level[succ] + 1
                if level < candidate:
                    level = candidate
        bottom_level[node] = level
    return bottom_level


def _data_size_units(node) -> int:
    """Approximate FHE data size in RNS-polynomial units, independent of ring degree."""
    level = getattr(node, 'level', -1)
    if level < 0:
        return 0

    q_rns_size = level + 1
    if node.type in (DataType.Ciphertext, DataType.Ciphertext3):
        degree = getattr(node, 'degree', -1)
        if degree < 0:
            return 0
        return (degree + 1) * q_rns_size
    if node.type in (DataType.Plaintext, DataType.PlaintextMul, DataType.PlaintextRingt):
        return q_rns_size
    return 0


def _sum_unique_data_size(nodes) -> int:
    total = 0
    seen = set()
    for node in nodes:
        if node in seen:
            continue
        seen.add(node)
        total += _data_size_units(node)
    return total


def _memory_priority_bonus(dag: nx.DiGraph, node, outputs: list | None = None) -> int:
    inputs = list(dag.predecessors(node))
    if outputs is None:
        outputs = list(dag.successors(node))

    input_units = _sum_unique_data_size(inputs)
    output_units = _sum_unique_data_size(outputs)
    return input_units - output_units


def compute_properties(dag: nx.DiGraph) -> nx.DiGraph:
    """Store memory-aware bottom-level priority on top-level compound task nodes."""
    compute_topo = [n for n in nx.topological_sort(dag) if is_compute_node(n)]
    op_outputs = {node: list(dag.successors(node)) for node in compute_topo}
    bottom_levels = compute_bottom_levels(dag, compute_topo, op_outputs)

    bottom_level_weight = 128
    memory_bonus_weight = 2
    raw_priorities = {
        node: bottom_level * bottom_level_weight + memory_bonus_weight * _memory_priority_bonus(dag, node, op_outputs[node])
        for node, bottom_level in bottom_levels.items()
    }
    min_priority = min(raw_priorities.values(), default=0)
    offset = -min_priority if min_priority < 0 else 0

    for node, priority in raw_priorities.items():
        if isinstance(node, _CompoundComputeNode):
            node.priority = priority + offset
    return dag

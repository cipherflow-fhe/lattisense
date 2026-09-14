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

from frontend.types import _CompoundComputeNode, is_compute_node


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


def compute_properties(dag: nx.DiGraph) -> nx.DiGraph:
    """Store bottom-level priority only on top-level compound task nodes."""
    for node, priority in compute_bottom_levels(dag).items():
        if isinstance(node, _CompoundComputeNode):
            node.priority = priority
    return dag

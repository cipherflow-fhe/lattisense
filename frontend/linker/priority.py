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

from frontend.types import _CompoundComputeNode
from .utils import compute_dependency_graph


def compute_bottom_levels(dag: nx.DiGraph) -> dict:
    """Compute bottom-level priority values without mutating nodes."""
    cg = compute_dependency_graph(dag)
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

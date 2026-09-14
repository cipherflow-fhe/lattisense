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

from frontend.types import is_compute_node, is_data_node


def internal_op_json(dag: nx.DiGraph, op) -> dict:
    return op.to_json_dict(dag)


def compound_external_inputs(dag: nx.DiGraph, ops: list) -> list:
    op_set = set(ops)
    seen: set = set()
    result = []
    for op in ops:
        for data in dag.predecessors(op):
            producers = [p for p in dag.predecessors(data) if is_compute_node(p)]
            if (not producers or any(p not in op_set for p in producers)) and data not in seen:
                result.append(data)
                seen.add(data)
    return result


def compound_external_outputs(dag: nx.DiGraph, ops: list, graph_outputs: set) -> list:
    op_set = set(ops)
    seen: set = set()
    result = []
    for op in ops:
        for data in dag.successors(op):
            consumers = [c for c in dag.successors(data) if is_compute_node(c)]
            if (data in graph_outputs or not consumers or any(c not in op_set for c in consumers)) and data not in seen:
                result.append(data)
                seen.add(data)
    return result


def compound_internal_data(dag: nx.DiGraph, ops: list, graph_outputs: set) -> list:
    op_set = set(ops)
    result = []
    for op in ops:
        for data in dag.successors(op):
            consumers = [c for c in dag.successors(data) if is_compute_node(c)]
            if data not in graph_outputs and consumers and all(c in op_set for c in consumers):
                result.append(data)
    return result

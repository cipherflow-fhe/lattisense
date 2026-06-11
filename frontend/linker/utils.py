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


def compute_dependency_graph(dag: nx.DiGraph) -> nx.DiGraph:
    cg = nx.DiGraph()
    cg.add_nodes_from(n for n in dag if is_compute_node(n))
    for data in (n for n in dag if is_data_node(n)):
        producers = [p for p in dag.predecessors(data) if is_compute_node(p)]
        consumers = [c for c in dag.successors(data) if is_compute_node(c)]
        for producer in producers:
            for consumer in consumers:
                if not cg.has_edge(producer, consumer):
                    cg.add_edge(producer, consumer)
    return cg


def internal_op_json(dag: nx.DiGraph, op) -> dict:
    return {'index': op.index, **op.to_json_dict(dag)}


def chain_external_inputs(dag: nx.DiGraph, chain: list) -> list:
    chain_set = set(chain)
    seen: set = set()
    result = []
    for op in chain:
        for data in dag.predecessors(op):
            producers = [p for p in dag.predecessors(data) if is_compute_node(p)]
            if (not producers or any(p not in chain_set for p in producers)) and data not in seen:
                result.append(data)
                seen.add(data)
    return result


def chain_external_outputs(dag: nx.DiGraph, chain: list, graph_outputs: set) -> list:
    chain_set = set(chain)
    seen: set = set()
    result = []
    for op in chain:
        for data in dag.successors(op):
            consumers = [c for c in dag.successors(data) if is_compute_node(c)]
            if (
                data in graph_outputs or not consumers or any(c not in chain_set for c in consumers)
            ) and data not in seen:
                result.append(data)
                seen.add(data)
    return result


def chain_internal_data(dag: nx.DiGraph, chain: list, graph_outputs: set) -> list:
    chain_set = set(chain)
    result = []
    for op in chain:
        for data in dag.successors(op):
            consumers = [c for c in dag.successors(data) if is_compute_node(c)]
            if data not in graph_outputs and consumers and all(c in chain_set for c in consumers):
                result.append(data)
    return result

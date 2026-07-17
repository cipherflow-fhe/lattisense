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

import heapq
from collections import defaultdict

import networkx as nx
from tqdm import tqdm

from frontend.types import (
    BridgeComputeNode,
    ComputeNode,
    CustomComputeNode,
    EncodeRingtComputeNode,
    FheComputeNode,
    OperationType,
    Processor,
    _CompoundComputeNode,
    is_compute_node,
    is_data_node,
    is_key_data_node,
)
from .priority import compute_bottom_levels
from .processor_layout import compute_runs_on_cpu
from .utils import (
    compound_external_inputs,
    compound_external_outputs,
    compound_internal_data,
    internal_op_json,
)


class GreedyCompoundParams:
    mergeable_op_types: frozenset[OperationType] = frozenset(
        {
            OperationType.Add,
            OperationType.Sub,
            OperationType.Neg,
            OperationType.Mult,
            OperationType.Relin,
            OperationType.Rescale,
            OperationType.DropLevel,
            OperationType.MultByi,
            OperationType.DivByi,
            OperationType.RotateCol,
            OperationType.RotateRow,
            OperationType.CmpSum,
            OperationType.CmpacSum,
            # OperationType.Bootstrap,
        }
    )

    launch_overhead_credit = 12
    internal_data_credit = 4
    critical_path_credit = 1
    external_io_penalty = 1
    compute_external_input_penalty = 1
    compute_external_output_penalty = 8
    op_cost_penalty = 1

    max_candidate_cost = 17
    op_costs = {
        OperationType.Add: 1,
        OperationType.Sub: 1,
        OperationType.Neg: 1,
        OperationType.DropLevel: 1,
        OperationType.MultByi: 1,
        OperationType.DivByi: 1,
        OperationType.Rescale: 2,
        OperationType.Relin: 4,
        OperationType.RotateCol: 4,
        OperationType.RotateRow: 4,
        OperationType.CmpSum: 3,
        OperationType.CmpacSum: 3,
        OperationType.Mult: 4,
        OperationType.Bootstrap: 32,
        OperationType.EncodeRingt: 1,
        OperationType.ExportToAbi: 1,
        OperationType.ImportFromAbi: 1,
        OperationType.LoadToBackend: 1,
        OperationType.StoreFromBackend: 1,
    }

    bridge_max_candidate_cost = 16
    bridge_batch_overhead_credit = 10
    bridge_bottom_level_spread_penalty = 2


class GreedyCompoundFormer:
    def __init__(self, dag: nx.DiGraph, processor: Processor, graph_inputs: list, graph_outputs: list):
        self.dag = dag
        self.processor = processor
        self.graph_input_set = set(graph_inputs)
        self.graph_output_set = set(graph_outputs)
        self.params = GreedyCompoundParams
        self.compute_topo = [n for n in nx.topological_sort(dag) if is_compute_node(n)]
        self.topo_index = {node: index for index, node in enumerate(self.compute_topo)}
        self.op_inputs = {node: list(dag.predecessors(node)) for node in self.compute_topo}
        self.op_outputs = {node: list(dag.successors(node)) for node in self.compute_topo}
        self.bottom_levels = compute_bottom_levels(dag, self.compute_topo, self.op_outputs)
        self.runs_on_cpu = {node: compute_runs_on_cpu(node, processor) for node in self.compute_topo}
        self.compute_neighbors = {node: self._collect_compute_neighbors(node) for node in self.compute_topo}
        self.remaining_inputs = {
            node: sum(data not in self.graph_input_set for data in self.op_inputs[node]) for node in self.compute_topo
        }

    def form(self) -> nx.DiGraph:
        processed_ops: set = set()
        compound_groups: list[list] = []
        progress_total = sum(1 for node in self.compute_topo if self._is_mergeable_op(node))
        available_data = set(self.graph_input_set)
        available_computes = self._initial_available_computes()
        available_heap = [(self.topo_index[node], node) for node in available_computes]
        heapq.heapify(available_heap)

        available_bridge_heaps: defaultdict[tuple, list] = defaultdict(list)
        available_encode_ringt_heaps: defaultdict[tuple, list] = defaultdict(list)
        for node in available_computes:
            self._push_available_batch_op(node, available_bridge_heaps, available_encode_ringt_heaps)

        pbar = tqdm(total=progress_total, desc='Greedy compound forming', unit='ops', colour='green')

        try:
            while available_heap:
                node = None
                while available_heap:
                    _, candidate = heapq.heappop(available_heap)
                    if candidate in available_computes and candidate not in processed_ops:
                        node = candidate
                        break
                if node is None:
                    break

                if isinstance(node, BridgeComputeNode):
                    completed, _ = self._best_bridge_batch_candidate(
                        node,
                        available_computes,
                        available_bridge_heaps,
                    )
                    compound_groups.append(completed)
                elif isinstance(node, EncodeRingtComputeNode):
                    completed, _ = self._best_encode_ringt_batch_candidate(
                        node,
                        available_computes,
                        available_encode_ringt_heaps,
                    )
                    compound_groups.append(completed)
                elif not self._is_mergeable_op(node):
                    completed = [node]
                    compound_groups.append(completed)
                else:
                    completed, _ = self._best_compute_candidate(node, processed_ops, available_data)
                    compound_groups.append(completed)

                available_computes.difference_update(completed)
                processed_ops.update(completed)
                new_data = self._mark_outputs_available(completed, available_data)
                for new_compute in self._step_available_computes(new_data, processed_ops):
                    if new_compute in available_computes:
                        continue
                    available_computes.add(new_compute)
                    heapq.heappush(available_heap, (self.topo_index[new_compute], new_compute))
                    self._push_available_batch_op(new_compute, available_bridge_heaps, available_encode_ringt_heaps)
                pbar.update(sum(self._is_mergeable_op(op) for op in completed))
        finally:
            pbar.close()

        return self._build_compound_dag(compound_groups)

    def _collect_compute_neighbors(self, op: ComputeNode) -> list:
        neighbors = []
        for data in self.op_inputs[op]:
            if is_key_data_node(data):
                continue
            neighbors.extend(producer for producer in self.dag.predecessors(data) if isinstance(producer, ComputeNode))

        for data in self.op_outputs[op]:
            if is_key_data_node(data):
                continue
            neighbors.extend(consumer for consumer in self.dag.successors(data) if isinstance(consumer, ComputeNode))

        return neighbors

    def _initial_available_computes(self) -> set:
        return {node for node, remaining in self.remaining_inputs.items() if remaining == 0}

    def _step_available_computes(self, new_data: list, processed_ops: set) -> set:
        newly_available = set()
        for data in new_data:
            for consumer in self.dag.successors(data):
                if consumer in processed_ops:
                    continue
                self.remaining_inputs[consumer] -= 1
                if self.remaining_inputs[consumer] == 0:
                    newly_available.add(consumer)
        return newly_available

    def _mark_outputs_available(self, completed_ops: list, available_data: set) -> list:
        new_data = []
        for op in completed_ops:
            for data in self.op_outputs[op]:
                if data not in available_data:
                    available_data.add(data)
                    new_data.append(data)
        return new_data

    def _candidate_inputs_available(self, ops: list, available_data: set) -> bool:
        produced_by_candidate = {data for op in ops for data in self.op_outputs[op]}
        return all(data in available_data or data in produced_by_candidate for op in ops for data in self.op_inputs[op])

    def _push_available_batch_op(
        self,
        node: ComputeNode,
        available_bridge_heaps: defaultdict[tuple, list],
        available_encode_ringt_heaps: defaultdict[tuple, list],
    ) -> None:
        if isinstance(node, BridgeComputeNode):
            heapq.heappush(available_bridge_heaps[self._bridge_key(node)], (self.topo_index[node], node))
        elif isinstance(node, EncodeRingtComputeNode):
            heapq.heappush(available_encode_ringt_heaps[self._encode_ringt_key(node)], (self.topo_index[node], node))

    def _bridge_topology_key(self, node: BridgeComputeNode) -> tuple:
        consumers = []
        for data in self.op_outputs[node]:
            consumers.extend(succ.index for succ in self.dag.successors(data) if isinstance(succ, ComputeNode))
        if consumers:
            return ('consumers', tuple(sorted(consumers)))

        producers = []
        for data in self.op_inputs[node]:
            producers.extend(pred.index for pred in self.dag.predecessors(data) if isinstance(pred, ComputeNode))
        if producers:
            return ('producers', tuple(sorted(producers)))

        return ('self', node.index)

    def _bridge_key(self, node: BridgeComputeNode) -> tuple:
        return (node.type, self.runs_on_cpu[node], self._bridge_topology_key(node))

    def _encode_ringt_key(self, node: ComputeNode) -> tuple:
        return (node.type, self.runs_on_cpu[node])

    def _best_compute_candidate(
        self,
        start,
        processed_ops: set,
        available_data: set,
    ) -> tuple[list, int]:
        candidate = [start]
        best_score = self._compute_score(candidate)

        while True:
            additions = []
            for op in self._compute_frontier_ops(candidate, processed_ops):
                ops = self._ordered_ops([*candidate, op])
                if self._candidate_cost(ops) > self.params.max_candidate_cost:
                    continue
                if not self._candidate_inputs_available(ops, available_data):
                    continue
                if not compound_external_outputs(self.dag, ops, self.graph_output_set):
                    continue

                score = self._compute_score(ops)
                if score > best_score:
                    additions.append((ops, score))

            if not additions:
                break

            candidate, best_score = max(
                additions,
                key=lambda item: (item[1], len(item[0]), -self.topo_index[item[0][0]]),
            )

        return candidate, best_score

    def _best_bridge_batch_candidate(
        self,
        start: BridgeComputeNode,
        available_computes: set,
        available_bridge_heaps: defaultdict[tuple, list],
    ) -> tuple[list, int]:
        return self._best_batch_candidate(start, available_computes, available_bridge_heaps, self._bridge_key)

    def _best_encode_ringt_batch_candidate(
        self,
        start: ComputeNode,
        available_computes: set,
        available_encode_ringt_heaps: defaultdict[tuple, list],
    ) -> tuple[list, int]:
        return self._best_batch_candidate(
            start, available_computes, available_encode_ringt_heaps, self._encode_ringt_key
        )

    def _best_batch_candidate(
        self,
        start: ComputeNode,
        available_computes: set,
        available_heaps: defaultdict[tuple, list],
        key_fn,
    ) -> tuple[list, int]:
        candidate = [start]
        best_score = self._bridge_batch_score(candidate)

        while True:
            additions = []
            for op in self._batch_frontier_ops(candidate, available_computes, available_heaps, key_fn):
                ops = self._ordered_ops([*candidate, op])
                if self._candidate_cost(ops) > self.params.bridge_max_candidate_cost:
                    continue
                score = self._bridge_batch_score(ops)
                if score > best_score:
                    additions.append((ops, score))

            if not additions:
                break

            candidate, best_score = max(
                additions,
                key=lambda item: (item[1], len(item[0]), -self.topo_index[item[0][0]]),
            )

        return candidate, best_score

    def _batch_frontier_ops(
        self,
        candidate: list,
        available_computes: set,
        available_heaps: defaultdict[tuple, list],
        key_fn,
    ) -> list:
        candidate_set = set(candidate)
        heap = available_heaps[key_fn(candidate[0])]
        buffered = []
        while heap:
            item = heapq.heappop(heap)
            op = item[1]
            if op not in available_computes:
                continue
            if op in candidate_set:
                continue
            if self._candidate_cost([*candidate, op]) > self.params.bridge_max_candidate_cost:
                heapq.heappush(heap, item)
                break
            buffered.append(item)

        for item in buffered:
            heapq.heappush(heap, item)

        return [op for _, op in buffered]

    def _compute_frontier_ops(self, candidate: list, processed_ops: set) -> list:
        candidate_set = set(candidate)
        on_cpu = self.runs_on_cpu[candidate[0]]
        frontier = set()

        for op in candidate:
            for neighbor in self.compute_neighbors[op]:
                if neighbor in candidate_set or neighbor in processed_ops:
                    continue
                if self._is_batch_op(neighbor) or not self._is_mergeable_op(neighbor):
                    continue
                if self.runs_on_cpu[neighbor] != on_cpu:
                    continue
                frontier.add(neighbor)

        return sorted(frontier, key=lambda node: self.topo_index[node])

    def _ordered_ops(self, ops: list) -> list:
        return sorted(ops, key=lambda op: self.topo_index[op])

    def _compute_score(self, ops: list) -> int:
        num_internal_data = len(compound_internal_data(self.dag, ops, self.graph_output_set))
        num_external_inputs = len(compound_external_inputs(self.dag, ops))
        num_external_outputs = len(compound_external_outputs(self.dag, ops, self.graph_output_set))
        return (
            self.params.launch_overhead_credit * (len(ops) - 1)
            + self.params.internal_data_credit * num_internal_data
            + self.params.critical_path_credit * max(self.bottom_levels.get(op, 0) for op in ops)
            - self.params.compute_external_input_penalty * num_external_inputs
            - self.params.compute_external_output_penalty * num_external_outputs
            - self.params.op_cost_penalty * self._candidate_cost(ops)
        )

    def _bridge_batch_score(self, ops: list) -> int:
        bottom_levels = [self.bottom_levels[op] for op in ops]
        bottom_level_spread = max(bottom_levels) - min(bottom_levels)
        ext_inputs = {data for op in ops for data in self.op_inputs[op]}
        ext_outputs = {data for op in ops for data in self.op_outputs[op]}
        return (
            self.params.bridge_batch_overhead_credit * (len(ops) - 1)
            + self.params.critical_path_credit * max(bottom_levels)
            - self.params.bridge_bottom_level_spread_penalty * bottom_level_spread
            - self.params.external_io_penalty * (len(ext_inputs) + len(ext_outputs))
            - self.params.op_cost_penalty * self._candidate_cost(ops)
        )

    def _candidate_cost(self, ops: list) -> int:
        return sum(1 if isinstance(op, CustomComputeNode) else self.params.op_costs[op.type] for op in ops)

    def _build_compound_dag(self, candidates: list[list]) -> nx.DiGraph:
        """Construct a new DiGraph replacing selected candidates with COMPOUND nodes."""
        new_dag = nx.DiGraph()
        first_to_candidate = {ops[0]: ops for ops in candidates}
        replaced_ops = {op for ops in candidates for op in ops}

        for node in self.dag.nodes():
            if is_data_node(node):
                new_dag.add_node(node)

        for node in self.compute_topo:
            if node in first_to_candidate:
                compound = self._make_compound_node(first_to_candidate[node])
                new_dag.add_node(compound)
                for data in compound._ext_inputs:
                    new_dag.add_edge(data, compound)
                for data in compound._ext_outputs:
                    new_dag.add_edge(compound, data)
                continue

            if node in replaced_ops:
                continue

            node.on_cpu = self.runs_on_cpu[node]
            new_dag.add_node(node)
            for pred in self.dag.predecessors(node):
                if pred in new_dag:
                    new_dag.add_edge(pred, node)
            for succ in self.dag.successors(node):
                if succ in new_dag:
                    new_dag.add_edge(node, succ)

        return new_dag

    def _make_compound_node(self, ops: list) -> _CompoundComputeNode:
        task = _CompoundComputeNode(
            on_cpu=self.runs_on_cpu[ops[0]],
            ops=[internal_op_json(self.dag, op) for op in ops],
            ext_inputs=compound_external_inputs(self.dag, ops),
            ext_outputs=compound_external_outputs(self.dag, ops, self.graph_output_set),
        )
        if len(ops) == 1:
            task.index = ops[0].index
            task.id = ops[0].id
        else:
            task.id = f'compound_{task.index}'
        return task

    def _is_batch_op(self, node: ComputeNode) -> bool:
        return isinstance(node, (BridgeComputeNode, EncodeRingtComputeNode))

    def _is_mergeable_op(self, node: ComputeNode) -> bool:
        if isinstance(node, FheComputeNode):
            return node.type in self.params.mergeable_op_types
        return True

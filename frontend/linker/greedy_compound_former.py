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

from collections import defaultdict

import networkx as nx
from tqdm import tqdm

from frontend.types import (
    BridgeComputeNode,
    ComputeNode,
    CustomComputeNode,
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
    chain_external_inputs as compound_external_inputs,
    chain_external_outputs as compound_external_outputs,
    chain_internal_data as compound_internal_data,
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
            OperationType.RotateCol,
            OperationType.RotateRow,
            OperationType.CmpSum,
            OperationType.CmpacSum,
            OperationType.Bootstrap,
        }
    )

    launch_overhead_credit = 12
    internal_data_credit = 4
    critical_path_credit = 1
    external_io_penalty = 1
    op_cost_penalty = 1

    max_candidate_cost = 40
    op_costs = {
        OperationType.Add: 1,
        OperationType.Sub: 1,
        OperationType.Neg: 1,
        OperationType.DropLevel: 1,
        OperationType.Rescale: 2,
        OperationType.Relin: 4,
        OperationType.RotateCol: 4,
        OperationType.RotateRow: 4,
        OperationType.CmpSum: 3,
        OperationType.CmpacSum: 3,
        OperationType.Mult: 4,
        OperationType.Bootstrap: 32,
        OperationType.ExportToAbi: 1,
        OperationType.ImportFromAbi: 1,
        OperationType.LoadToBackend: 1,
        OperationType.StoreFromBackend: 1,
    }

    bridge_max_candidate_cost = 16
    bridge_batch_overhead_credit = 10
    bridge_bottom_level_spread_penalty = 2
    bridge_bottom_level_window = 1


class GreedyCompoundFormer:
    def __init__(self, dag: nx.DiGraph, processor: Processor, graph_inputs: list, graph_outputs: list):
        self.dag = dag
        self.processor = processor
        self.graph_input_set = set(graph_inputs)
        self.graph_output_set = set(graph_outputs)
        self.params = GreedyCompoundParams
        self.compute_topo = [n for n in nx.topological_sort(dag) if is_compute_node(n)]
        self.topo_index = {node: index for index, node in enumerate(self.compute_topo)}
        self.bottom_levels = compute_bottom_levels(dag)
        self.op_inputs = {node: list(dag.predecessors(node)) for node in self.compute_topo}
        self.op_outputs = {node: list(dag.successors(node)) for node in self.compute_topo}
        self.runs_on_cpu = {node: compute_runs_on_cpu(node, processor) for node in self.compute_topo}
        self.compute_neighbors = {node: self._collect_compute_neighbors(node) for node in self.compute_topo}
        self.ops_by_bottom_level: defaultdict[int, list] = defaultdict(list)
        for node in self.compute_topo:
            self.ops_by_bottom_level[self.bottom_levels[node]].append(node)

    def form(self) -> nx.DiGraph:
        processed_ops: set = set()
        compound_groups: list[list] = []
        progress_ops = self._progress_ops()
        available_data = set(self.graph_input_set)
        available_computes = self._initial_available_computes(available_data)
        pbar = tqdm(total=len(progress_ops), desc='Greedy compound forming', unit='ops', colour='green')

        try:
            while available_computes:
                available_computes.difference_update(processed_ops)
                if not available_computes:
                    break

                node = min(available_computes, key=lambda item: self.topo_index[item])
                if not self._is_mergeable_op(node):
                    completed = [node]
                elif isinstance(node, BridgeComputeNode):
                    completed, _ = self._best_bridge_batch_candidate(
                        node,
                        available_computes,
                    )
                    compound_groups.append(completed)
                else:
                    completed, _ = self._best_compute_candidate(node, processed_ops, available_data)
                    compound_groups.append(completed)

                available_computes.difference_update(completed)
                processed_ops.update(completed)
                new_data = self._mark_outputs_available(completed, available_data)
                available_computes.update(self._step_available_computes(new_data, available_data, processed_ops))
                pbar.update(sum(op in progress_ops for op in completed))
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

    def _initial_available_computes(self, available_data: set) -> set:
        return {node for node in self.compute_topo if self._compute_inputs_available(node, available_data)}

    def _step_available_computes(self, new_data: list, available_data: set, processed_ops: set) -> set:
        newly_available = set()
        for data in new_data:
            for consumer in self.dag.successors(data):
                if consumer in processed_ops:
                    continue
                if self._compute_inputs_available(consumer, available_data):
                    newly_available.add(consumer)
        return newly_available

    def _mark_outputs_available(self, completed_ops: list, available_data: set) -> list:
        new_data = []
        seen = set()
        for op in completed_ops:
            for data in self.op_outputs[op]:
                if data in seen:
                    continue
                seen.add(data)
                if data not in available_data:
                    available_data.add(data)
                    new_data.append(data)
        return new_data

    def _compute_inputs_available(self, op, available_data: set) -> bool:
        return all(data in available_data for data in self.op_inputs[op])

    def _candidate_inputs_available(self, ops: list, available_data: set) -> bool:
        produced_by_candidate = {data for op in ops for data in self.op_outputs[op]}
        return all(data in available_data or data in produced_by_candidate for op in ops for data in self.op_inputs[op])

    def _progress_ops(self) -> set:
        return {node for node in self.compute_topo if self._is_mergeable_op(node)}

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
    ) -> tuple[list, int]:
        candidate = [start]
        best_score = self._bridge_batch_score(candidate)

        while True:
            additions = []
            for op in self._bridge_batch_frontier_ops(
                start,
                candidate,
                available_computes,
            ):
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

    def _bridge_batch_frontier_ops(
        self,
        start,
        candidate: list,
        available_computes: set,
    ) -> list:
        candidate_set = set(candidate)
        start_bottom_level = self.bottom_levels[start]
        start_on_cpu = self.runs_on_cpu[start]
        frontier = set()

        for bottom_level in range(
            start_bottom_level - self.params.bridge_bottom_level_window,
            start_bottom_level + self.params.bridge_bottom_level_window + 1,
        ):
            for op in self.ops_by_bottom_level[bottom_level]:
                if op not in available_computes:
                    continue
                if op in candidate_set:
                    continue
                if not isinstance(op, BridgeComputeNode) or not self._is_mergeable_op(op):
                    continue
                if op.type != start.type:
                    continue
                if self.runs_on_cpu[op] != start_on_cpu:
                    continue
                frontier.add(op)

        return sorted(frontier, key=lambda node: self.topo_index[node])

    def _compute_frontier_ops(self, candidate: list, processed_ops: set) -> list:
        candidate_set = set(candidate)
        on_cpu = self.runs_on_cpu[candidate[0]]
        frontier = set()

        for op in candidate:
            for neighbor in self.compute_neighbors[op]:
                if neighbor in candidate_set or neighbor in processed_ops:
                    continue
                if isinstance(neighbor, BridgeComputeNode) or not self._is_mergeable_op(neighbor):
                    continue
                if self.runs_on_cpu[neighbor] != on_cpu:
                    continue
                frontier.add(neighbor)

        return sorted(frontier, key=lambda node: self.topo_index[node])

    def _ordered_ops(self, ops: list) -> list:
        return sorted(ops, key=lambda op: self.topo_index[op])

    def _compute_score(self, ops: list) -> int:
        num_internal_data = len(compound_internal_data(self.dag, ops, self.graph_output_set))
        num_external_io = len(compound_external_inputs(self.dag, ops)) + len(
            compound_external_outputs(self.dag, ops, self.graph_output_set)
        )
        return (
            self.params.launch_overhead_credit * (len(ops) - 1)
            + self.params.internal_data_credit * num_internal_data
            + self.params.critical_path_credit * max(self.bottom_levels.get(op, 0) for op in ops)
            - self.params.external_io_penalty * num_external_io
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

    def _is_mergeable_op(self, node: ComputeNode) -> bool:
        if isinstance(node, FheComputeNode):
            return node.type in self.params.mergeable_op_types
        return True

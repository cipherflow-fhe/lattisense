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

import os
import sys

import networkx as nx

from .linker import apply_processor_layout, compute_properties, compute_runs_on_cpu, serialize_dag
from .linker.utils import internal_op_json
from .types import (
    BridgeComputeNode,
    BridgeDataNode,
    CustomComputeNode,
    DataType,
    FheComputeNode,
    FheDataNode,
    FpgaKernelNode,
    Processor,
    _CompoundComputeNode,
    is_compute_node,
    is_data_node,
)


def _build_fpga_kernels(
    dag: nx.DiGraph,
    param,
    all_output_list: list,
    all_offline_list: list,
) -> list[tuple[FpgaKernelNode, dict, dict]]:
    """Partition bridge-inserted dag into FPGA kernel groups and rewire.

    dag must have already had apply_processor_layout(..., Processor.FPGA, ...) applied so that
    ABI bridge nodes are present.

    FheComputeNodes in the same on_cpu-bounded stage belong to the same
    partition. This mirrors the old FPGA embedding logic and lets one FPGA
    kernel contain all FHE work that can be scheduled together, such as the
    parallel cmc-relin-rescale lanes in one task.

    Returns a list of (FpgaKernelNode, sub_mag, sub_sig) for each partition.
    Mutates dag in place: interior FheComputeNodes and interior FheDataNodes
    are removed and replaced with FpgaKernelNodes.
    """
    result: list[tuple[FpgaKernelNode, dict, dict]] = []
    all_output_set = set(all_output_list)
    all_offline_set = set(all_offline_list)

    # ------------------------------------------------------------------
    # 1. Partition FheComputeNodes by on_cpu compute boundaries
    # ------------------------------------------------------------------
    node_partition: dict = {}

    for node in nx.topological_sort(dag):
        if isinstance(node, (FheDataNode, BridgeDataNode)):
            compute_preds = [
                p
                for p in dag.predecessors(node)
                if isinstance(p, (FheComputeNode, CustomComputeNode, BridgeComputeNode))
            ]
            if not compute_preds:
                node_partition[node] = -1
            else:
                pred = compute_preds[0]
                pred_partition = node_partition.get(pred, -1)
                node_partition[node] = (
                    pred_partition + 1 if compute_runs_on_cpu(pred, Processor.FPGA) else pred_partition
                )
        elif isinstance(node, FheComputeNode):
            preds = [
                node_partition[p]
                for p in dag.predecessors(node)
                if isinstance(p, (FheDataNode, BridgeDataNode)) and node_partition.get(p, -1) >= 0
            ]
            node_partition[node] = max(preds) if preds else 0
        elif isinstance(node, CustomComputeNode):
            preds = [
                node_partition[p]
                for p in dag.predecessors(node)
                if isinstance(p, (FheDataNode, BridgeDataNode)) and node_partition.get(p, -1) >= 0
            ]
            node_partition[node] = max(preds) if preds else 0
        elif isinstance(node, BridgeComputeNode):
            preds = [node_partition[p] for p in dag.predecessors(node) if isinstance(p, (FheDataNode, BridgeDataNode))]
            node_partition[node] = max(preds) if preds else -1

    partitions_by_id: dict[int, list] = {}
    for node, pid in node_partition.items():
        if isinstance(node, FheComputeNode):
            partitions_by_id.setdefault(pid, []).append(node)

    partitions = [partitions_by_id[pid] for pid in sorted(partitions_by_id)]

    # ------------------------------------------------------------------
    # 2. Build sub-mag and rewire dag for each partition
    # ------------------------------------------------------------------
    def _input_sort_key(dn):
        if dn.type == DataType.RelinKey:
            return (1, '')
        if dn.type == DataType.GaloisKey:
            return (2, str(getattr(dn, 'galois_element', '')))
        if dn.type == DataType.SwitchKey:
            return (3, '')
        return (0, '')

    def _canonical_key_id(dn):
        if dn.type == DataType.RelinKey:
            return 'rlk_ntt'
        if dn.type == DataType.GaloisKey:
            galois_element = getattr(dn, 'galois_element', None)
            if galois_element == (param.n << 1) - 1:
                return 'glk_ntt_row'
            return f'glk_ntt_col_{galois_element}'
        return dn.id

    def _sub_data_json(dn):
        d = dn.to_json_dict()
        if dn.type in (DataType.RelinKey, DataType.GaloisKey):
            d['id'] = _canonical_key_id(dn)
        return d

    for compute_list in partitions:
        compute_set = set(compute_list)

        # Collect all data nodes referenced by this partition
        partition_data: set = set()
        for cn in compute_set:
            for n in dag.predecessors(cn):
                if isinstance(n, (FheDataNode, BridgeDataNode)):
                    partition_data.add(n)
            for n in dag.successors(cn):
                if isinstance(n, (FheDataNode, BridgeDataNode)):
                    partition_data.add(n)

        inputs: list = []
        offline_inputs: list = []
        outputs: list = []
        interior: set = set()

        for dn in partition_data:
            fhe_preds = [p for p in dag.predecessors(dn) if isinstance(p, FheComputeNode)]
            produced_here = any(p in compute_set for p in fhe_preds)
            if not produced_here:
                inputs.append(dn)
                if dn in all_offline_set:
                    offline_inputs.append(dn)
            else:
                # Produced here: check if any successor is outside this partition
                consumed_outside = any(
                    not (isinstance(s, FheComputeNode) and s in compute_set) for s in dag.successors(dn)
                )
                if dn in all_output_set or consumed_outside:
                    outputs.append(dn)
                else:
                    interior.add(dn)

        inputs.sort(key=_input_sort_key)

        # Key signature for this partition
        rlk_level = -1
        glk_level: dict[str, int] = {}
        for dn in inputs:
            if dn.type == DataType.RelinKey:
                rlk_level = dn.level
            elif dn.type == DataType.GaloisKey:
                glk_level[str(getattr(dn, 'galois_element', ''))] = dn.level

        kernel = FpgaKernelNode()

        sub_dag = dag.subgraph(partition_data | compute_set)
        sub_mag = serialize_dag(
            sub_dag,
            inputs=inputs,
            outputs=outputs,
            offline_inputs=offline_inputs,
            meta={'name': f'Kernel {kernel.index}', 'algorithm': param.algo.value},
            data_serializer=_sub_data_json,
        )
        sub_sig = {
            'algorithm': param.algo.value,
            'key': {'rlk': rlk_level, 'glk': glk_level},
            'online': [],
            'offline': [],
        }

        # Rewire dag: replace partition with FpgaKernelNode
        for dn in inputs:
            dag.add_edge(dn, kernel)
        for dn in outputs:
            dag.add_edge(kernel, dn)
        for cn in compute_set:
            dag.remove_node(cn)
        for dn in interior:
            dag.remove_node(dn)

        result.append((kernel, sub_mag, sub_sig))

    return result


def form_single_op_tasks(dag: nx.DiGraph, processor: Processor) -> nx.DiGraph:
    """Wrap remaining single ops as one-op top-level compound tasks for FPGA output."""
    compute_topo = [n for n in nx.topological_sort(dag) if is_compute_node(n)]
    new_dag = nx.DiGraph()

    for node in dag.nodes():
        if is_data_node(node):
            new_dag.add_node(node)

    for node in compute_topo:
        task = node if isinstance(node, _CompoundComputeNode) else _make_single_op_task(dag, node, processor)
        new_dag.add_node(task)
        for data in dag.predecessors(node):
            new_dag.add_edge(data, task)
        for data in dag.successors(node):
            new_dag.add_edge(task, data)

    return new_dag


def _make_single_op_task(dag: nx.DiGraph, op, processor: Processor) -> _CompoundComputeNode:
    task = _CompoundComputeNode(
        on_cpu=compute_runs_on_cpu(op, processor),
        ops=[internal_op_json(dag, op)],
        ext_inputs=dag.predecessors(op),
        ext_outputs=dag.successors(op),
    )
    task.index = op.index
    task.id = op.id
    return task


def compile_fpga_mega_ag(dag: nx.DiGraph, param, ctx) -> tuple[nx.DiGraph, list[tuple[FpgaKernelNode, dict, dict]]]:
    """Apply FPGA processor layout, build FPGA kernel MAGs, and compute priorities."""
    compiled_dag = apply_processor_layout(dag, Processor.FPGA, ctx.inputs, ctx.outputs)
    kernel_mags = _build_fpga_kernels(compiled_dag, param, ctx.outputs, ctx.offline)
    compiled_dag = form_single_op_tasks(compiled_dag, Processor.FPGA)
    compiled_dag = compute_properties(compiled_dag)
    return compiled_dag, kernel_mags


def run_fpga_linker(output_instruction_path: str) -> None:
    """Invokes the FPGA linker to compile the computation graph into FPGA instruction files.

    @param output_instruction_path Directory where task files are stored (containing mega_ag.json)
    """
    _linker_root = os.path.normpath(
        os.path.join(os.path.dirname(__file__), '..', 'backends', 'lattisense-fpga', 'lattisense-fpga-linker')
    )
    _compiler_root = os.path.join(_linker_root, 'lattisense-fpga-compiler')
    _linker_pkg = os.path.join(_linker_root, 'linker')

    for _p in (_linker_root, _linker_pkg, _compiler_root):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    from linker.linker_main import run_linker_dev

    _cwd = os.getcwd()
    os.chdir(_linker_root)
    try:
        run_linker_dev(output_instruction_path)
    finally:
        os.chdir(_cwd)

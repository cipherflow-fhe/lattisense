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
processor_layout.py — ABI bridge node insertion for CPU/GPU/FPGA backends.

Mirrors the logic previously in mega_ag_runners/mega_ag.cpp:
  - insert_backend_abi_bridge_nodes()  for GPU
  - insert_cpu_abi_bridge_nodes()      for CPU

Operates in place on a networkx DiGraph of Python node objects.
Must run BEFORE chain formation so that chain boundaries correctly
respect the bridge nodes.
"""

import networkx as nx

from frontend.types import (
    ABIDataNode,
    BackendDataNode,
    OperationType,
    Processor,
    is_bridge_compute,
    is_custom_compute,
    is_custom_data_node,
    is_compute_node,
    is_data_node,
    is_key_data_node,
)
from .bridge_ops import (
    export_to_abi,
    import_from_abi,
    load_to_backend,
    store_from_backend,
)


def apply_processor_layout(
    dag: nx.DiGraph,
    processor: Processor,
    input_nodes: list,
    output_nodes: list,
) -> nx.DiGraph:
    """Insert ABI bridge nodes for the target processor.

    Args:
        dag:          g_dag (modified in place).
        processor:    Target processor.
        input_nodes:  List of DataNode objects that are graph inputs.
        output_nodes: List of DataNode objects that are graph outputs.

    Returns:
        The input DiGraph with bridge compute/data nodes inserted.
    """
    input_set = set(input_nodes)
    output_set = set(output_nodes)

    if processor in (Processor.GPU, Processor.FPGA):
        _insert_backend_bridges(dag, input_set, output_set, processor)
    elif processor == Processor.CPU:
        _insert_cpu_bridges(dag, input_set, output_set)
    else:
        raise ValueError(f'Unsupported processor for layout: {processor!r}')

    return dag


# ---------------------------------------------------------------------------
# GPU / FPGA bridge insertion
# ---------------------------------------------------------------------------


def _insert_backend_bridges(
    dag: nx.DiGraph,
    input_set: set,
    output_set: set,
    processor: Processor,
) -> None:
    """Mutate dag in place — add bridge nodes for GPU or FPGA.

    Cases (mirror mega_ag.cpp::insert_backend_abi_bridge_nodes):

    Case 0: Custom DATA input
        input → EXPORT_TO_ABI → c_struct → custom/backend consumers

    Case 1: Handle data with backend consumers
        handle → EXPORT_TO_ABI → c_struct → LOAD_TO_BACKEND → backend_data
        → backend consumers

    Case 2: Backend-produced data with custom consumers or is output
        backend_data → STORE_FROM_BACKEND → c_struct
                     → IMPORT_FROM_ABI → handle / output

    Case 3: Custom-produced Handle that is graph output
        concrete → IMPORT_FROM_ABI → output_node
    """
    original_data_nodes = [n for n in dag.nodes() if is_data_node(n)]
    for data_node in original_data_nodes:
        is_input = data_node in input_set
        is_output = data_node in output_set
        is_custom_data = is_custom_data_node(data_node)
        is_frontend_handle = _is_frontend_handle(dag, data_node)
        is_backend_data = _is_backend_data(dag, data_node)

        consumers = list(dag.successors(data_node))
        backend_consumers = [c for c in consumers if not is_custom_compute(c)]
        custom_consumers = [c for c in consumers if is_custom_compute(c)]

        # Case 0: Custom DATA input node
        if is_input and is_custom_data:
            c_struct = export_to_abi(dag, data_node)
            _redirect_consumers(dag, data_node, c_struct, custom_consumers + backend_consumers)
            continue

        # Case 1: Handle with backend consumers
        if is_frontend_handle and backend_consumers:
            c_struct = export_to_abi(dag, data_node)
            backend_data = load_to_backend(dag, c_struct, processor)

            _redirect_consumers(dag, data_node, backend_data, backend_consumers)

        # Case 2: Backend-produced data with custom consumers or is output
        if is_backend_data and (custom_consumers or is_output):
            original_producers = list(dag.predecessors(data_node))

            if isinstance(data_node, BackendDataNode):
                backend_data = data_node
            else:
                backend_data = BackendDataNode.create_from(data_node, processor)
                _redirect_producers(dag, data_node, backend_data, original_producers)

            c_struct = store_from_backend(dag, backend_data, processor)

            if is_output:
                import_from_abi(dag, c_struct, data_node)
            else:
                handle = import_from_abi(dag, c_struct)
                _redirect_consumers(dag, data_node, handle, custom_consumers)

            _redirect_consumers(dag, data_node, backend_data, backend_consumers)

        # Case 3: Custom-produced Handle that is graph output (not an input)
        if is_frontend_handle and is_output and not is_input:
            original_producers = list(dag.predecessors(data_node))

            concrete = ABIDataNode.create_from(data_node)
            import_from_abi(dag, concrete, data_node)
            _redirect_producers(dag, data_node, concrete, original_producers)


# ---------------------------------------------------------------------------
# CPU bridge insertion
# ---------------------------------------------------------------------------


def _insert_cpu_bridges(
    dag: nx.DiGraph,
    input_set: set,
    output_set: set,
) -> None:
    """Mutate dag in place — add bridge nodes for CPU.

    CPU operates entirely on Handle objects; only input/output boundaries
    require bridging:

    Each input:  input → EXPORT_TO_ABI → concrete → original consumers
    Each output: original producers → concrete → IMPORT_FROM_ABI → output
    """
    for data_node in list(input_set):
        if is_key_data_node(data_node):
            continue
        original_consumers = list(dag.successors(data_node))
        concrete = export_to_abi(dag, data_node)
        _redirect_consumers(dag, data_node, concrete, original_consumers)

    for data_node in list(output_set):
        original_producers = list(dag.predecessors(data_node))
        original_consumers = list(dag.successors(data_node))
        concrete = ABIDataNode.create_from(data_node)
        import_from_abi(dag, concrete, data_node)
        _redirect_producers(dag, data_node, concrete, original_producers)
        _redirect_consumers(dag, data_node, concrete, original_consumers)


# ---------------------------------------------------------------------------
# Graph mutation helpers
# ---------------------------------------------------------------------------


def _redirect_consumers(
    dag: nx.DiGraph,
    old_node,
    new_node,
    consumers: list,
) -> None:
    """Re-point the given consumers from old_node to new_node.

    Match the old C++ behavior of replacing input pointers in-place, so
    compute-node input order is preserved for serialization.
    """
    for c in consumers:
        inputs = [new_node if p is old_node else p for p in dag.predecessors(c)]
        for p in list(dag.predecessors(c)):
            dag.remove_edge(p, c)
        for p in inputs:
            dag.add_edge(p, c)


def _redirect_producers(dag: nx.DiGraph, old_node, new_node, producers: list | None = None) -> None:
    """Re-point producers of old_node to new_node instead.

    Match the old C++ behavior of replacing output pointers in-place, so
    compute-node output order is preserved for serialization.

    Args:
        producers: Explicit list of producers to redirect. When None, all
                   current predecessors of old_node are used. Pass a
                   pre-computed snapshot to avoid including bridge nodes
                   added between snapshot time and call time.
    """
    producer_set = set(producers if producers is not None else list(dag.predecessors(old_node)))
    for p in producer_set:
        outputs = [new_node if s is old_node else s for s in dag.successors(p)]
        for s in list(dag.successors(p)):
            dag.remove_edge(p, s)
        for s in outputs:
            dag.add_edge(p, s)


def _is_frontend_handle(dag: nx.DiGraph, data_node) -> bool:
    """True if data_node is a frontend Handle.

    A data node is a frontend Handle if:
    - it has no producer compute node (external input), OR
    - its producer is a custom compute node.
    """
    preds = list(dag.predecessors(data_node))
    return not preds or is_custom_compute(preds[0])


def _is_backend_data(dag: nx.DiGraph, data_node) -> bool:
    """True if data_node represents backend device data or backend-produced data."""
    if isinstance(data_node, BackendDataNode):
        return True

    preds = list(dag.predecessors(data_node))
    if not preds:
        return False

    producer = preds[0]
    return is_compute_node(producer) and not is_custom_compute(producer) and not is_bridge_compute(producer)


# ---------------------------------------------------------------------------
# Task placement
# ---------------------------------------------------------------------------


def compute_runs_on_cpu(node, processor: Processor) -> bool:
    """Return whether a single op should execute on CPU for this processor layout."""
    custom = is_custom_compute(node)
    if processor == Processor.CPU:
        return True
    if processor == Processor.GPU:
        return True if custom else node.type in (OperationType.ExportToAbi, OperationType.ImportFromAbi)
    if processor == Processor.FPGA:
        return custom or is_bridge_compute(node)
    raise ValueError(f'Unsupported processor for task placement: {processor!r}')

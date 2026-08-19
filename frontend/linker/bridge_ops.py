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

"""Bridge operator helpers used by processor layout."""

import networkx as nx

from frontend.types import (
    ABIDataNode,
    BackendDataNode,
    ExportToAbiNode,
    ImportFromAbiNode,
    LoadToBackendNode,
    Processor,
    StoreFromBackendNode,
)


def export_to_abi(dag: nx.DiGraph, src, metadata=None) -> ABIDataNode:
    op = ExportToAbiNode()
    dst = ABIDataNode.create_from(src, metadata)
    dag.add_edge(src, op)
    dag.add_edge(op, dst)
    return dst


def import_from_abi(dag: nx.DiGraph, src, dst=None):
    op = ImportFromAbiNode()
    if dst is None:
        dst = ABIDataNode.create_from(src)
    dag.add_edge(src, op)
    dag.add_edge(op, dst)
    return dst


def load_to_backend(dag: nx.DiGraph, src, processor: Processor) -> BackendDataNode:
    op = LoadToBackendNode(processor)
    dst = BackendDataNode.create_from(src, processor)
    dag.add_edge(src, op)
    dag.add_edge(op, dst)
    return dst


def store_from_backend(dag: nx.DiGraph, src, processor: Processor) -> ABIDataNode:
    op = StoreFromBackendNode(processor)
    dst = ABIDataNode.create_from(src)
    dag.add_edge(src, op)
    dag.add_edge(op, dst)
    return dst

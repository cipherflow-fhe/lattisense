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

from frontend.types import Processor
from .chain_former import compute_properties, form_chains, form_gpu_load_batches, form_single_op_tasks
from .processor_layout import apply_processor_layout
from .task_context import _TaskContext


def compile_mega_ag(
    dag: nx.DiGraph,
    processor: Processor,
    ctx: _TaskContext,
) -> nx.DiGraph:
    """Apply processor layout, form top-level tasks, and compute priorities."""
    dag = apply_processor_layout(dag, processor, ctx.inputs, ctx.outputs)
    dag = form_chains(dag, processor, ctx.outputs)
    if processor == Processor.GPU:
        dag = form_gpu_load_batches(dag, processor)
    dag = form_single_op_tasks(dag, processor)
    dag = compute_properties(dag)
    return dag

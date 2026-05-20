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
linker — Compile-time graph transformation for GPU/CPU backends.

Pipeline (run once at compile time, result cached as compiled_mega_ag.json):
    1. apply_processor_layout  — insert ABI bridge nodes
    2. form_chains             — merge serial FHE ops into COMPOUND nodes
    3. compute_properties      — assign scheduling priority per node

Usage:
    from frontend.linker import compile_mega_ag, _TaskContext
    from frontend.types import Processor
    ctx = _build_task_context(...)
    compiled = compile_mega_ag(dag, processor=Processor.GPU, ctx=ctx)
"""

from .chain_former import compile_mega_ag, compute_properties
from .processor_layout import apply_processor_layout
from .serializer import serialize_dag, serialize_signature
from .task_context import _TaskContext

__all__ = [
    'compile_mega_ag',
    'compute_properties',
    'apply_processor_layout',
    'serialize_dag',
    'serialize_signature',
    '_TaskContext',
]

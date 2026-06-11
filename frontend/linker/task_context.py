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
task_context.py — _TaskContext dataclass shared between custom_task.py and the linker.

Type-only references are guarded by TYPE_CHECKING to avoid circular imports.
Custom-task types (Argument, FheDataNode, etc.) are imported lazily inside
_TaskContext.build() which is the sole constructor entry point.

Consumed by:
  - serialize_signature()  in serializer.py
  - compile_mega_ag()      in linker.py
  - run_gpu_linker()       in gpu_backend.py
  - run_cpu_linker()       in cpu_backend.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from frontend.types import Algo


@dataclass
class _TaskContext:
    """Resolved task data built from Argument lists and FHE parameters.

    Carries both node lists (for graph operations) and signature components
    (for serialize_signature). Contains no pre-serialized JSON.

    Use _TaskContext.build() to construct from raw Argument objects.
    """

    name: str
    algorithm: 'Algo'

    # Graph operation data — DataNode objects
    inputs: list  # online inputs + offline inputs + key nodes
    outputs: list
    offline: list

    # Signature components (raw data, not JSON)
    rlk_sig: int  # -1 if no relinearization key
    glk_sig: dict  # galois_element -> level
    ckks_btp_swk_sig: dict  # key_id -> (level, sp_level); empty if not BTP
    input_sigdata: list  # list of sigdata dicts for online inputs
    output_sigdata: list  # list of sigdata dicts for outputs
    offline_sigdata: list  # list of sigdata dicts for offline inputs

    @classmethod
    def build(
        cls,
        input_args,
        output_args,
        offline_input_args,
        swk_node_dict: dict,
        name: str,
        algorithm: 'Algo',
    ) -> _TaskContext:
        """Resolve Argument objects into a _TaskContext.

        Args:
            input_args:          Online input Argument list (or None).
            output_args:         Output Argument list (or None).
            offline_input_args:  Offline input Argument list (or None).
            swk_node_dict:       Global switch-key node dict (g_swk_node_dict).
            name:                Task name string.
            algorithm:           FHE algorithm enum.
        """
        from frontend.types import (  # noqa: PLC0415
            FheDataNode,
            DataType,
        )

        used_ids: list[str] = []

        def _flatten(x):
            if isinstance(x, list):
                result = []
                for item in x:
                    result += _flatten(item)
                return result
            return [x]

        def _shape(x):
            if not isinstance(x, list):
                return []
            sub = _shape(x[0]) if x else []
            return [len(x)] if isinstance(sub, int) else [len(x)] + sub

        def _process_args(args, phase: str):
            if args is None:
                return [], []
            node_list, sigdata_list = [], []
            for arg in args:
                nodes = _flatten(arg.data)
                if not nodes:
                    raise ValueError(f'No data for arg id "{arg.id}".')
                if arg.id in used_ids:
                    raise ValueError(f'Same id "{arg.id}" for different Arguments.')
                used_ids.append(arg.id)
                entry = {
                    'id': arg.id,
                    'type': nodes[0].type.value if isinstance(nodes[0].type, DataType) else nodes[0].type,
                    'size': _shape(arg.data),
                    'phase': phase,
                }
                if isinstance(nodes[0], FheDataNode):
                    entry['level'] = nodes[0].level
                node_list += nodes
                sigdata_list.append(entry)
            return node_list, sigdata_list

        input_nodes, input_sigdata = _process_args(input_args, 'in')
        output_nodes, output_sigdata = _process_args(output_args, 'out')
        offline_nodes, offline_sigdata = _process_args(offline_input_args, 'offline')
        all_inputs = input_nodes + offline_nodes

        # Collect key nodes and build key signatures
        rlk_sig = -1
        if 'rlk_ntt' in swk_node_dict:
            rlk_sig = swk_node_dict['rlk_ntt'].level
            all_inputs.append(swk_node_dict['rlk_ntt'])

        glk_sig: dict = {}
        for k, v in swk_node_dict.items():
            if 'col' in k:
                glk_sig[int(k.split('_')[-1])] = v.level
                all_inputs.append(v)
            elif 'row' in k:
                glk_sig[v.galois_element] = v.level
                all_inputs.append(v)

        ckks_btp_swk_sig: dict = {}
        for k, v in swk_node_dict.items():
            if 'swk' in k:
                ckks_btp_swk_sig[k] = (v.level, v.sp_level)
                all_inputs.append(v)

        return cls(
            name=name,
            algorithm=algorithm,
            inputs=all_inputs,
            outputs=output_nodes,
            offline=offline_nodes,
            rlk_sig=rlk_sig,
            glk_sig=glk_sig,
            ckks_btp_swk_sig=ckks_btp_swk_sig,
            input_sigdata=input_sigdata,
            output_sigdata=output_sigdata,
            offline_sigdata=offline_sigdata,
        )

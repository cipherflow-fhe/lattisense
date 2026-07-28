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

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

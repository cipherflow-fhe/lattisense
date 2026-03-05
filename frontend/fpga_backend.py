import os
import sys


def run_fpga_linker(output_instruction_path: str, translator_dev: bool = True) -> None:
    """调用 FPGA linker，将计算图编译为 FPGA 指令文件。

    @param output_instruction_path 任务文件存储目录（包含 mega_ag.json）
    @param translator_dev 是否为开发模式（True 时直接调用 Python linker，False 时调用编译好的二进制）
    """
    _linker_root = os.path.normpath(
        os.path.join(os.path.dirname(__file__), '..', 'backends', 'lattisense-fpga', 'lattisense-fpga-linker')
    )
    _compiler_root = os.path.join(_linker_root, 'compiler')
    _linker_pkg = os.path.join(_linker_root, 'linker')

    if translator_dev:
        for _p in (_linker_root, _linker_pkg, _compiler_root):
            if _p not in sys.path:
                sys.path.insert(0, _p)
        from linker.linker_main import linker_main_func_for_dev

        _cwd = os.getcwd()
        os.chdir(_linker_root)
        try:
            linker_main_func_for_dev(output_instruction_path)
        finally:
            os.chdir(_cwd)
    else:
        cwd = os.getcwd()
        output_instruction_path = os.path.abspath(output_instruction_path)
        if hasattr(sys, 'frozen'):
            os.chdir(os.path.dirname(sys.executable))
        else:
            os.chdir(_linker_root)
        os.system('dist/compiler -t %s' % output_instruction_path)
        os.chdir(cwd)

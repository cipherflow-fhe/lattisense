# LattiSense

[![CI](https://github.com/cipherflow-fhe/lattisense/actions/workflows/ci.yml/badge.svg)](https://github.com/cipherflow-fhe/lattisense/actions/workflows/ci.yml)
[![Static Analysis](https://github.com/cipherflow-fhe/lattisense/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/cipherflow-fhe/lattisense/actions/workflows/static-analysis.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0-green.svg)](CMakeLists.txt)

**LattiSense** 是由 [CipherFlow](https://cipherflow.ai/) 构建的全同态加密（FHE）开发框架。它帮助开发者构建隐私保护应用，在加密数据上执行复杂计算，全程无需解密。

通过提供统一的抽象接口，LattiSense 屏蔽了 FHE 的密码学复杂性，让您专注于业务逻辑，而编译器和调度器会自动处理异构硬件上的繁重工作。

## 为什么选择 LattiSense？

FHE 生态系统正在蓬勃发展，但往往分散在底层密码学库和特定硬件实现之间。开发者通常需要了解四类不同的工具：

| **类别**              | **关注点**                                                    | **示例**                             |
| --------------------- | ------------------------------------------------------------ | ---------------------------------------- |
| **FHE 算法库**          | 单线程（CPU）或单流（GPU）的算法实现 | SEAL, OpenFHE, TFHE-rs, Lattigo, HEonGPU |
| **FHE 编译器**        | 将高级逻辑翻译为底层指令     | HEIR, Concrete                           |
| **FHE 调度器**        | 运行时并行化和编排                    | TFHE-rs, HLG                             |
| **硬件加速器**        | FPGA 或 ASIC 上的 FHE 算法定制实现  | Zama HPU, HERACLES                       |

**LattiSense 是一个全栈框架**，涵盖上述所有类别的功能。它提供统一的编译器和调度器，集成了一流的外部密码学库和专有硬件加速能力，为开发者提供端到端、高性能、可扩展的 FHE 解决方案。

## 快速入门

LattiSense 的工作流程将 FHE 计算任务的定义与实际运行时执行解耦，允许编译器进行优化并在异构硬件上执行。以下示例展示如何执行两个整数的乘法。

### 步骤 1：定义计算任务（Python）

以下 Python 代码定义了密文 `[[x]]` 和 `[[y]]` 之间乘法的抽象任务：

```python
from frontend.custom_task import *

# 设置全局 FHE 参数
param = Param.create_bfv_default_param(n=16384)
set_fhe_param(param)

# 定义计算任务 z = x * y
level = 2
x = BfvCiphertextNode('x', level)
y = BfvCiphertextNode('y', level)
z = mult_relin(x, y, 'z')

# 将 FHE 计算任务编译为算子指令
process_custom_task(
    input_args=[Argument('x', x), Argument('y', y)],
    output_args=[Argument('z', z)],
    output_instruction_path='examples/quick_start',
)
```

### 步骤 2：执行任务（C++）

以下 C++ 代码执行完整的 FHE 计算流程：生成密钥、编码、加密、计算、解密和解码：

```cpp
#include <fhe_ops_lib/fhe_lib_v2.h>
#include <cxx_sdk_v2/cxx_fhe_task.h>

using namespace std;
using namespace fhe_ops_lib;
using namespace cxx_sdk_v2;

int main() {
    // 初始化 BFV 参数
    uint64_t n = 16384, t = 65537;
    BfvParameter param = BfvParameter::create_parameter(n, t);
    BfvContext context = BfvContext::create_random_context(param);
    int level = 2;

    // 初始化输入消息
    vector<uint64_t> x_mg({3}), y_mg({5});

    // 编码并加密输入数据
    BfvCiphertext x_ct = context.encrypt_asymmetric(context.encode(x_mg, level));
    BfvCiphertext y_ct = context.encrypt_asymmetric(context.encode(y_mg, level));

    // 为输出密文分配空间
    BfvCiphertext z_ct = context.new_ciphertext(level);

    // 加载任务并调用 LattiSense 调度器
    FheTaskCpu mult_task("examples/quick_start");
    vector<CxxVectorArgument> cxx_args = {
        {"x", &x_ct},
        {"y", &y_ct},
        {"z", &z_ct},
    };
    mult_task.run(&context, cxx_args);

    // 解密并解码输出数据
    vector<uint64_t> z_mg = context.decode(context.decrypt(z_ct));
    cout << "Result: " << z_mg[0] << endl; // Result: 15

    return 0;
}
```

---

## 构建与安装

### 环境要求

| 依赖 | 版本要求 | 说明 |
|------|----------|------|
| CMake | >= 3.13 | 构建系统 |
| C++ 编译器 | GCC 10+ / Clang 11+ | 需支持 C++20 |
| Go | >= 1.18 | 用于编译底层全同态密码算法库 |
| Python | >= 3.10 | 用于计算图编译器 |
| networkx | （Python 包） | 计算图编译器依赖 |

**GPU 加速（可选）**：

| 依赖 | 版本要求 | 说明 |
|------|----------|------|
| CUDA Toolkit | >= 12.0 | GPU 计算支持 |
| HEonGPU | 1.1 | GPU 加速库（需预先编译安装） |

### 构建步骤

#### 1. 克隆项目

```bash
git clone --recursive https://github.com/cipherflow-fhe/lattisense.git
cd lattisense
```

#### 2. 安装依赖

```bash
pip install -r requirements.txt
```

#### 3. 编译 SDK

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

#### 4. 安装

```bash
# 安装到自定义目录
cmake .. -DCMAKE_INSTALL_PREFIX=$(pwd)/../install
make install

# 或安装到系统（需要 sudo）
cmake ..
make
sudo make install
```

### 编译选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `CMAKE_INSTALL_PREFIX` | /usr/local | 安装目录 |
| `LATTISENSE_ENABLE_GPU` | OFF | 启用 GPU 加速支持 |
| `LATTISENSE_CUDA_ARCH` | （无） | CUDA 架构（启用 GPU 时必须指定，如 86、89、90） |
| `LATTISENSE_BUILD_TESTS` | OFF | 编译单元测试 |
| `LATTISENSE_BUILD_EXAMPLES` | OFF | 编译示例程序 |
| `LATTISENSE_DEV` | OFF | 开发模式（详细日志输出） |
| `LATTISENSE_BUILD_SEAL_PLUG_IN` | OFF | 编译 SEAL 库插件（需启用 GPU） |

示例：
```bash
cmake .. -DCMAKE_INSTALL_PREFIX=$(pwd)/../install -DLATTISENSE_BUILD_EXAMPLES=ON
cmake .. -DLATTISENSE_ENABLE_GPU=ON -DLATTISENSE_CUDA_ARCH=89
```

启用 GPU 加速需要先编译安装 HEonGPU：

```bash
# 1. 编译 HEonGPU
cd HEonGPU
mkdir build && cd build
cmake .. \
  -DCMAKE_CUDA_ARCHITECTURES=<arch> \
  -DCMAKE_CUDA_COMPILER=<path/to/cuda>/bin/nvcc \
  -DCMAKE_INSTALL_PREFIX=<path/to/install>
make -j$(nproc)
make install

# 2. 返回 SDK 目录，启用 GPU 编译
cd ../..
mkdir build && cd build
cmake .. -DLATTISENSE_ENABLE_GPU=ON -DLATTISENSE_CUDA_ARCH=<arch>
make -j$(nproc)
```

> **注意**：`LATTISENSE_CUDA_ARCH`（以及 HEonGPU 对应的 `CMAKE_CUDA_ARCHITECTURES`）需要根据您的 GPU 型号设置（参考 [CUDA GPUs](https://developer.nvidia.com/cuda-gpus)）：
> - RTX 30xx 系列: 86
> - RTX 40xx 系列: 89
> - H100: 90
> - A100: 80

### 安装目录结构

```
<install_prefix>/
├── lib/
│   ├── liblattisense.so
│   └── cmake/LattiSense/
├── include/lattisense/
│   ├── cxx_sdk_v2/
│   ├── fhe_ops_lib/
│   ├── mega_ag_runners/
│   └── common/
└── share/lattisense/
    ├── doc/
    ├── mega_ag_generator/
    ├── project_template/
```

---

## 在你的项目中使用 SDK

```cmake
cmake_minimum_required(VERSION 3.13)
project(my_fhe_app)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

find_package(LattiSense REQUIRED)

add_executable(my_fhe_app main.cpp)
target_link_libraries(my_fhe_app PRIVATE LattiSense::lattisense)
```

具体细节参考 `examples/project_template/` 目录，了解如何在独立项目中使用 SDK。


## 运行示例

示例程序通过 `LATTISENSE_BUILD_EXAMPLES=ON` 选项与 SDK 一起构建：

```bash
mkdir build && cd build
cmake .. -DLATTISENSE_BUILD_EXAMPLES=ON
make -j$(nproc)

# 生成计算图
cd build/examples/bfv_mult_cpu
python3 bfv_mult_cpu.py

# 运行示例
./bfv_mult_cpu
```

## 运行测试

```bash
# 启用测试编译
mkdir build && cd build
cmake .. -DLATTISENSE_BUILD_TESTS=ON
make -j$(nproc)

# 生成测试数据
cd ../unittests
python3 test_cpu_bfv.py
python3 test_cpu_ckks.py

# 运行测试
cd ../build/unittests
./test_lattigo       # 底层算子测试
./test_cpu_bfv       # BFV CPU 测试
./test_cpu_ckks      # CKKS CPU 测试
```

---

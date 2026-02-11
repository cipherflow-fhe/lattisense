# LattiSense

[![CI](https://github.com/cipherflow-fhe/lattisense/actions/workflows/ci.yml/badge.svg)](https://github.com/cipherflow-fhe/lattisense/actions/workflows/ci.yml)
[![Static Analysis](https://github.com/cipherflow-fhe/lattisense/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/cipherflow-fhe/lattisense/actions/workflows/static-analysis.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0-green.svg)](CMakeLists.txt)

**LattiSense** is a development framework for Fully Homomorphic Encryption (FHE), built by [CipherFlow](https://cipherflow.ai/). It empowers developers to build privacy-preserving applications that perform complex computations on encrypted data without ever needing to decrypt it.

By providing a unified, abstract interface, LattiSense removes the cryptographic complexity of FHE, allowing you to focus on logic while our compiler and scheduler handle the heavy lifting across heterogeneous hardware.

## Why LattiSense?

While the FHE ecosystem is growing, it is often fragmented between low-level cryptographic libraries and specific hardware implementations. Developers typically have to navigate four distinct categories of tools:

| **Category**              | **Focus**                                                    | **Examples**                             |
| ------------------------- | ------------------------------------------------------------ | ---------------------------------------- |
| **Crypto Libraries**      | Single-threaded (CPU) or single-stream (GPU) algorithm implementations | SEAL, OpenFHE, TFHE-rs, Lattigo, HEonGPU |
| **FHE Compilers**         | Translating high-level logic into low-level instructions     | HEIR, Concrete                           |
| **FHE Schedulers**        | Runtime parallelization and orchestration                    | TFHE-rs, HLG                             |
| **Hardware Accelerators** | Customized implementation of FHE algorithms on FPGA or ASIC  | Zama HPU, HERACLES                       |

**LattiSense is a full-stack framework** that covers the functionalities of all these categories. It provides a unified compiler and scheduler that incorporates best-in-class external cryptographic libraries alongside proprietary hardware acceleration. This offers developers a comprehensive system for end-to-end, high-performance, and scalable FHE solutions.

## Quick Start

The workflow of LattiSense decouples the definition of FHE computation tasks from the actual runtime execution, allowing for optimization by the compiler and execution by heterogeneous hardware. This example shows how to perform multiplication of two integers.

### Step 1: Define Computation Task (Python)

The following Python code defines the abstract task of multiplication between ciphertexts `[[x]]` and `[[y]]`:

```python
from frontend.custom_task import *

# Set global FHE parameters
param = Param.create_bfv_default_param(n=16384)
set_fhe_param(param)

# Define computation task z = x * y
level = 2
x = BfvCiphertextNode('x', level)
y = BfvCiphertextNode('y', level)
z = mult_relin(x, y, 'z')

# Compile the task into optimized instructions, in this case targeted for CPU backend.
process_custom_task(
    input_args=[Argument('x', x), Argument('y', y)],
    output_args=[Argument('z', z)],
    output_instruction_path='examples/quick_start',
)
```

### Step 2: Execute Task (C++)

The following C++ code performs the full FHE computation cycle: generate keys, encode, encrypt, compute, decrypt, and decode, where the computation part invokes the multiplication task defined above, and uses CPU to execute the task:

```cpp
#include <fhe_ops_lib/fhe_lib_v2.h>
#include <cxx_sdk_v2/cxx_fhe_task.h>

using namespace std;
using namespace fhe_ops_lib;
using namespace cxx_sdk_v2;

int main() {
    // Initialize BFV parameters
    uint64_t n = 16384, t = 65537;
    BfvParameter param = BfvParameter::create_parameter(n, t);
    BfvContext context = BfvContext::create_random_context(param);
    int level = 2;

    // Initialize input messages
    vector<uint64_t> x_mg({3}), y_mg({5});

    // Encode and encrypt input data
    BfvCiphertext x_ct = context.encrypt_asymmetric(context.encode(x_mg, level));
    BfvCiphertext y_ct = context.encrypt_asymmetric(context.encode(y_mg, level));

    // Allocate space for output ciphertext
    BfvCiphertext z_ct = context.new_ciphertext(level);

    // Load task and invoke the LattiSense scheduler
    FheTaskCpu mult_task("examples/quick_start");
    vector<CxxVectorArgument> cxx_args = {
        {"x", &x_ct},
        {"y", &y_ct},
        {"z", &z_ct},
    };
    mult_task.run(&context, cxx_args);

    // Decrypt and decode output data
    vector<uint64_t> z_mg = context.decode(context.decrypt(z_ct));
    cout << "Result: " << z_mg[0] << endl; // Result: 15

    return 0;
}
```

---

## Build & Installation

The easiest way to install LattiSense is to use the official LattiSense Docker image. For developers, you can build LattiSense from source. For Windows users, you can install LattiSense through WSL2. After installation, please run the example programs to verify the installation.

### Docker

Get started instantly with the official Docker image, no manual dependency installation required:

```bash
docker run -it ghcr.io/cipherflow-fhe/lattisense:latest
```

The container includes the pre-built SDK, compilation toolchain, and project template, ready for development.

### Build from Source

#### Requirements

| Dependency | Version | Description |
|------------|---------|-------------|
| CPU / Memory | 8 cores / 16 GB | Recommended minimum configuration |
| OS | Linux / WSL2 | Operating system requirement |
| CMake | >= 3.13 | Build system |
| C++ Compiler | GCC 10+ / Clang 11+ | C++20 support required |
| Go | >= 1.18 | For building Lattigo crypto library |
| Python | >= 3.10 | For computation graph compiler |
| networkx | (Python package) | Computation graph compiler dependency |

**GPU Acceleration (Optional)**:

| Dependency | Version | Description |
|------------|---------|-------------|
| CUDA Toolkit | >= 12.0 | GPU compute support |
| HEonGPU | 1.1 | GPU acceleration library (requires pre-build) |

#### 1. Clone Repository

```bash
git clone --recursive https://github.com/cipherflow-fhe/lattisense.git
cd lattisense
```

#### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

#### 3. Build SDK (CPU Version)

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

#### 4. Install

```bash
# Install to custom directory
cmake .. -DCMAKE_INSTALL_PREFIX=$(pwd)/../install
make install

# Or install to system (requires sudo)
cmake ..
make
sudo make install
```

#### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `CMAKE_INSTALL_PREFIX` | /usr/local | Installation directory |
| `LATTISENSE_ENABLE_GPU` | OFF | Enable GPU acceleration |
| `LATTISENSE_CUDA_ARCH` | (none) | CUDA architecture (required when GPU enabled, e.g., 86, 89, 90) |
| `LATTISENSE_BUILD_TESTS` | OFF | Build unit tests |
| `LATTISENSE_BUILD_EXAMPLES` | OFF | Build example programs |
| `LATTISENSE_DEV` | OFF | Development mode (verbose logging) |
| `LATTISENSE_BUILD_SEAL_PLUG_IN` | OFF | Build SEAL library plug-in (requires GPU) |

Example:
```bash
cmake .. -DCMAKE_INSTALL_PREFIX=$(pwd)/../install -DLATTISENSE_BUILD_EXAMPLES=ON
cmake .. -DLATTISENSE_ENABLE_GPU=ON -DLATTISENSE_CUDA_ARCH=89
```

To enable GPU acceleration, first build and install HEonGPU:

```bash
# 1. Build HEonGPU
cd HEonGPU
mkdir build && cd build
cmake .. \
  -DCMAKE_CUDA_ARCHITECTURES=<arch> \
  -DCMAKE_CUDA_COMPILER=<path/to/cuda>/bin/nvcc \
  -DCMAKE_INSTALL_PREFIX=<path/to/HEonGPU>/install
make -j$(nproc)
make install

# 2. Return to SDK directory and build with GPU support
cd ../..
mkdir build && cd build
cmake .. -DLATTISENSE_ENABLE_GPU=ON -DLATTISENSE_CUDA_ARCH=<arch>
make -j$(nproc)
```

> **Note**: Set `LATTISENSE_CUDA_ARCH` (and the matching `CMAKE_CUDA_ARCHITECTURES` for HEonGPU) according to your GPU (see [CUDA GPUs](https://developer.nvidia.com/cuda-gpus) for reference):
> - RTX 30xx series: 86
> - RTX 40xx series: 89
> - H100: 90
> - A100: 80

#### Installation Directory Structure

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

## Using the SDK in Your Project

```cmake
cmake_minimum_required(VERSION 3.13)
project(my_fhe_app)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

find_package(LattiSense REQUIRED)

add_executable(my_fhe_app main.cpp)
target_link_libraries(my_fhe_app PRIVATE LattiSense::lattisense)
```

For more see `examples/project_template/` for a complete standalone project example.

---

## Running Examples

When building from source, you can build and run the internal examples:

```bash
mkdir build && cd build
cmake .. -DLATTISENSE_BUILD_EXAMPLES=ON
make -j$(nproc)

# Generate computation graph
cd build/examples/bfv_mult_cpu
python3 bfv_mult_cpu.py

# Run example
./bfv_mult_cpu
```

## Running Tests

```bash
# Build with tests enabled
mkdir build && cd build
cmake .. -DLATTISENSE_BUILD_TESTS=ON
make -j$(nproc)

# Generate test data
cd ../unittests
python3 test_cpu_bfv.py
python3 test_cpu_ckks.py

# Run tests
cd ../build/unittests
./test_lattigo       # underlying operators tests
./test_cpu_bfv       # BFV CPU tests
./test_cpu_ckks      # CKKS CPU tests
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Third-party dependencies and their licenses are listed in the [NOTICE](NOTICE) file.


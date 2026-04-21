# Windows Build (MinGW-w64, CPU-only)

## Prerequisites

- **MSYS2** with MinGW-w64 toolchain:
  ```bash
  pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-make git
  ```
- **Go >= 1.18**: Install from https://golang.org/dl/ and add to PATH
- All commands below should be run from the **MinGW64 shell** (not MSYS2 shell)

## Build fhe_ops_lib (Client Crypto Library)

```bash
git submodule update --init --recursive

cmake -B build -G "MinGW Makefiles" -DLATTISENSE_CLIENT_ONLY=ON
cmake --build build -j$(nproc)
```

`LATTISENSE_CLIENT_ONLY=ON` skips server-side components (cxx_sdk_v2, mega_ag_runners,
lattisense shared library, tests, examples) and only builds `fhe_ops_lib` + Go backend.

Output: `build/fhe_ops_lib/libfhe_ops_lib.dll` and Go backend `liblattigo.dll`

## Verify Build

After building, confirm the DLLs were produced:

```bash
ls build/fhe_ops_lib/libfhe_ops_lib.dll
ls build/fhe_ops_lib/lattigo/go_sdk/liblattigo.dll
```

To write a minimal test, create `test_client.cpp`:

```cpp
#include "fhe_ops_lib/fhe_lib_v2.h"
#include <cstdio>

int main() {
    auto param = fhe_ops_lib::CkksParameter::create_parameter(16384);
    auto ctx = fhe_ops_lib::CkksContext::create_random_context(param);
    double scale = param.get_default_scale();

    std::vector<double> data({3.14, 2.71});
    auto pt = ctx.encode(data, 3, scale);
    auto ct = ctx.encrypt_asymmetric(pt);
    auto pt2 = ctx.decrypt(ct);
    auto result = ctx.decode(pt2);

    printf("input:  [%.2f, %.2f]\n", data[0], data[1]);
    printf("output: [%.2f, %.2f]\n", result[0], result[1]);
    return 0;
}
```

Compile and run:

```bash
g++ -std=c++17 -I<lattisense_root> -I<lattisense_root>/lib \
    test_client.cpp -L build/fhe_ops_lib -lfhe_ops_lib -o test_client
./test_client
```

## Known Limitations

- **`LATTISENSE_CLIENT_ONLY=ON` is required on Windows.** The full `lattisense` shared
  library and server-side components (`cxx_sdk_v2`, `mega_ag_runners`) are not ported.
- **MinGW-w64 only.** MSVC is not supported (Go CGo requires GCC-compatible compiler).
- **`unsigned __int128`** is used in `fhe_ops_lib/utils.cpp`. Supported by MinGW GCC
  but not MSVC — noted for future MSVC porting.
- **GPU and FPGA backends** are not available on Windows.

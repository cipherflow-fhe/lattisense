# BFV/CKKS Key Operator Benchmark

本目录提供 BFV/CKKS 关键算子的 CPU/GPU benchmark 示例，用于统计不同多项式阶数 `N` 下，1024 个独立算子任务的总耗时和吞吐。

## 覆盖范围

默认参数：

- `N`: `4096, 8192, 16384, 32768, 65536`
- 独立算子数量：`1024`
- 默认 level：`all`，自动最多生成和执行到 level 9；如需测试更高 level，可用 `--levels` 显式指定
- CPU 单线程/多线程：通过外部环境变量控制，优先使用 `LATTI_CPU_THREADS`，也兼容 `OMP_NUM_THREADS`
- GPU：使用 `FheTaskGpu`；重型全量 benchmark 建议使用 `--isolate-gpu-case` 让每个 case 独立进程执行，避免同进程显存累计

默认算子：

| Scheme | Operator | 说明 |
| --- | --- | --- |
| BFV | `mult_relin` | 密文乘法 + 重线性化 |
| BFV | `rotate_col` | 列旋转，step=1 |
| BFV | `rotate_rows` | 行旋转 |
| CKKS | `mult_relin` | 密文乘法 + 重线性化 |
| CKKS | `mult_relin_rescale` | 密文乘法 + 重线性化 + rescale |
| CKKS | `rotate_step1` | slot rotation，step=1 |

注意：当前 `frontend/parameter.json` 中 BFV 默认参数只覆盖到 `N=32768`。因此默认生成时 BFV `N=65536` 会被跳过；运行器会优先根据已生成 task 目录推导可执行 level，遇到不存在的 task 目录会在 CSV 中记录 `skipped`，不会中断其他 case。

## 文件说明

```text
benchmark_key_ops.py            # 生成 benchmark task graph
benchmark_key_ops.cpp           # 执行 CPU/GPU benchmark 并输出 text + CSV
sort_benchmark_key_ops_csv.py   # 按 scheme/op/N/level/thread_label 重排 CSV
CMakeLists.txt                  # 注册 benchmark_key_ops 可执行目标，并复制 Python 辅助脚本到 build 目录
README.md                       # 本说明
```

## 推荐运行位置和顺序

推荐顺序是：

1. 在 lattisense 源码目录配置 CMake，并显式启用 examples；
2. 编译 `benchmark_key_ops` target；
3. 进入 build 目录下的 `examples/benchmark_key_ops`；
4. 在该 build 子目录中运行 `benchmark_key_ops.py` 生成 task graph；
5. 在同一个目录中运行 `./benchmark_key_ops`。

这样可以确保生成的 task 目录和 `benchmark_key_ops` 可执行文件位于同一个工作目录。`benchmark_key_ops` 通过相对路径查找 task 目录，如果在源码目录生成 task、却在 build 目录运行可执行文件，会出现 `task directory not found`。

## 1. 配置 CMake

在 lattisense 源码目录执行，例如：

```bash
cd <lattisense-source-dir>

cmake -S . -B build-bench-ops \
  -DLATTISENSE_BUILD_EXAMPLES=ON \
  -DLATTISENSE_ENABLE_GPU=ON \
  -DLATTISENSE_CUDA_ARCH=<your_cuda_arch>
```

如果只跑 CPU，也仍然需要启用 examples：

```bash
cd <lattisense-source-dir>

cmake -S . -B build-bench-ops \
  -DLATTISENSE_BUILD_EXAMPLES=ON
```

`<your_cuda_arch>` 示例：A100 可用 `80`，RTX 30 系可用 `86`，RTX 40 系可用 `89`，H100 可用 `90`。

## 2. 编译 benchmark 可执行文件

继续在 lattisense 源码目录执行：

```bash
cmake --build build-bench-ops --target benchmark_key_ops
```

如果使用了其他 build 目录名，把 `build-bench-ops` 替换成对应目录。

## 3. 进入 build 目录下的 benchmark 目录

```bash
cd build-bench-ops/examples/benchmark_key_ops
```

确认当前目录下应能看到：

```text
benchmark_key_ops
benchmark_key_ops.py
sort_benchmark_key_ops_csv.py
```

## 4. 生成 benchmark task graph

生成默认全部参数和算子：

```bash
python benchmark_key_ops.py
```

如果测试机默认命令是 Python 3，也可以使用：

```bash
python3 benchmark_key_ops.py
```

生成后会在当前 build 子目录下创建带 level 后缀的 task 目录，例如：

```text
bfv_mult_relin_N4096_L0/
bfv_mult_relin_N4096_L1/
bfv_rotate_col_N4096_L0/
bfv_rotate_rows_N4096_L0/
ckks_mult_relin_N4096_L0/
ckks_mult_relin_rescale_N4096_L1/
ckks_rotate_step1_N4096_L0/
...
```

每个 task 目录会包含 `mega_ag.json`、`task_signature.json` 和 `fhe_parameter.json`。其中 `fhe_parameter.json` 记录 task 生成时使用的 FHE 参数；如果运行 benchmark 时提示缺少该文件，请重新运行 `benchmark_key_ops.py` 生成 task。

只生成部分 `N`：

```bash
python benchmark_key_ops.py --n 4096,8192,16384
```

只生成部分 level：

```bash
python benchmark_key_ops.py --n 16384 --levels 0,1,2,3
python benchmark_key_ops.py --n 32768 --levels 1-5
```

降低独立算子数量，用于冒烟验证：

```bash
python benchmark_key_ops.py --n 4096 --levels 0 --ops 8
```

## 5. 运行 CPU 单线程 benchmark

CPU runner 的线程数由环境变量控制，优先读取 `LATTI_CPU_THREADS`，未设置时再读取 `OMP_NUM_THREADS`，两者都未设置时使用默认线程数 `min(32, hardware_concurrency)`。

```bash
LATTI_CPU_THREADS=1 OMP_NUM_THREADS=1 ./benchmark_key_ops \
  --device cpu \
  --thread-label cpu_1t \
  --csv benchmark_key_ops.csv \
  --overwrite-csv
```

## 6. 运行 CPU 多线程 benchmark

将线程数改成测试机期望的 CPU 线程数：

```bash
LATTI_CPU_THREADS=32 OMP_NUM_THREADS=32 ./benchmark_key_ops \
  --device cpu \
  --thread-label cpu_mt \
  --csv benchmark_key_ops.csv
```

如果测试机还依赖其他数学库线程环境变量，可以一起设置，例如：

```bash
LATTI_CPU_THREADS=32 OMP_NUM_THREADS=32 OPENBLAS_NUM_THREADS=32 MKL_NUM_THREADS=32 ./benchmark_key_ops \
  --device cpu \
  --thread-label cpu_mt \
  --csv benchmark_key_ops.csv
```

## 7. 运行 GPU benchmark

```bash
./benchmark_key_ops \
  --device gpu \
  --thread-label gpu \
  --csv benchmark_key_ops.csv \
  --isolate-gpu-case
```

`--isolate-gpu-case` 会让每个选中的 `(scheme, op, N, level)` case 在独立子进程中执行，并追加写入同一个 CSV。该模式适合 `CKKS N=65536 --ops 1024` 这类重型 GPU 全量 benchmark，可避免同一进程内连续 case 导致显存累计或释放不及时。小规模调试时可以不加该参数。

## 8. 常用过滤参数

只跑某些 `N`：

```bash
./benchmark_key_ops --device cpu --thread-label cpu_1t --n 4096,8192 --csv result.csv
```

只跑 BFV：

```bash
./benchmark_key_ops --device cpu --thread-label cpu_1t --scheme bfv --csv result.csv
```

只跑 CKKS：

```bash
./benchmark_key_ops --device gpu --thread-label gpu --scheme ckks --csv result.csv
```

只跑某个算子：

```bash
./benchmark_key_ops --device cpu --thread-label cpu_1t --op mult_relin --csv result.csv
```

只跑部分 level：

```bash
./benchmark_key_ops --device cpu --thread-label cpu_1t --levels 0,1,2,3 --csv result.csv
./benchmark_key_ops --device cpu --thread-label cpu_1t --levels 1-5 --csv result.csv
```

`--levels` 默认值是 `all`，自动最多生成和执行到 level 9。显式指定 `--levels` 时不做 level 9 上限截断，例如 `--levels 10,11` 或 `--levels 0-20` 会按实际生成的 task 和参数支持范围执行。`ckks_mult_relin_rescale` 会自动跳过 level 0，因为该算子包含 rescale，输出 level 为输入 level - 1。

支持的 `--op` 值：

```text
all
mult_relin
rotate_col
rotate_rows
mult_relin_rescale
rotate_step1
```

## 9. CSV 输出

CSV 默认追加写入 `benchmark_key_ops.csv`，也可以通过 `--csv` 指定路径。

如果要避免旧数据混入，在第一轮运行时加 `--overwrite-csv`，程序会先清空指定 CSV，再写入本次结果。后续 CPU 多线程和 GPU 运行不加 `--overwrite-csv`，继续追加到同一个 CSV。

程序启动时也会在终端打印本次运行的线程元数据，例如：

```text
Run metadata: hardware_threads=64 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=<unset> MKL_NUM_THREADS=<unset> levels=all csv=benchmark_key_ops.csv overwrite_csv=true
```

随后程序会按 `scheme/op/N` 分组打印终端结果，每个分组下包含该 case 的每个 level 性能。例如：

```text
Case: BFV op=mult_relin N=4096 device=cpu label=cpu_smoke ops=8
  level=0   time_ms=12.345 ops_per_sec=648.036
  level=1   time_ms=13.456 ops_per_sec=594.530
Case: CKKS op=rotate_step1 N=4096 device=cpu label=cpu_smoke ops=8
  level=0   time_ms=9.876 ops_per_sec=810.045
  level=1   time_ms=10.234 ops_per_sec=781.708
```

CSV 输出仍然是一行记录一个 `(scheme, op, N, level, thread_label)` 结果，便于后续汇总分析。

字段：

```csv
scheme,op,N,level,thread_label,omp_num_threads,ops,time_ms,ops_per_sec,status,error
```

字段含义：

- `scheme`：加密方案，目前为 `BFV` 或 `CKKS`。
- `op`：benchmark 算子类型，例如 `mult_relin`、`rotate_col`、`rotate_rows`、`mult_relin_rescale`、`rotate_step1`。
- `N`：多项式阶数，即 poly modulus degree，例如 `4096`、`8192`、`16384`、`32768`、`65536`。
- `level`：当前 case 使用的密文 level。默认会对每个 `N` 的所有可用 level 分别生成和执行 benchmark。
- `thread_label`：运行标签，用于区分 CPU 单线程、多线程或 GPU。CSV 写出时会将 `cpu_1t`、`cpu_mt`、`gpu` 分别显示为 `CPU_单线程`、`CPU_多线程`、`GPU`；其他自定义标签原样保留。该字段只记录标签，不会自动设置线程数。
- `omp_num_threads`：运行时环境变量 `OMP_NUM_THREADS` 的值；未设置时为 `<unset>`。
- `ops`：当前 case 中独立算子的数量，默认是 `1024`。
- `time_ms`：当前 case 的总执行时间，单位毫秒。该值由 `FheTaskCpu::run()` 或 `FheTaskGpu::run()` 返回时间换算得到。
- `ops_per_sec`：吞吐量，单位是次/秒，计算公式为 `ops / (time_ms / 1000)`。
- `status`：当前 case 的执行状态，取值为 `ok`、`skipped` 或 `failed`。
- `error`：错误信息。成功时为空；跳过或失败时记录原因。

示例：

```csv
BFV,mult_relin,16384,3,CPU_单线程,1,1024,1234.560000,829.374000,ok,
CKKS,rotate_step1,32768,5,GPU,<unset>,1024,345.670000,2962.940000,ok,
BFV,mult_relin,65536,3,CPU_单线程,1,1024,0.000000,0.000000,skipped,"task directory not found: bfv_mult_relin_N65536_L3; run benchmark_key_ops.py first or skip unsupported level/N"
```

`status` 含义：

- `ok`：当前 case 执行成功。
- `skipped`：task 目录不存在，通常是未生成或该参数不支持。
- `failed`：执行过程中抛出异常，例如参数不匹配、显存不足、GPU 未启用等。

## 10. CSV 排序

完整执行 CPU 单线程、CPU 多线程和 GPU 后，可以使用 `sort_benchmark_key_ops_csv.py` 对 CSV 重新排序。排序规则为：CKKS 在前、BFV 在后；同一 scheme 内按 op、N、level 分组；同一 `(scheme, op, N, level)` 下按 `CPU_单线程`、`CPU_多线程`、`GPU` 排列，同时兼容旧标签 `cpu_1t`、`cpu_mt`、`gpu`。

生成新文件：

```bash
python3 sort_benchmark_key_ops_csv.py benchmark_key_ops.csv \
  -o benchmark_key_ops.sorted.csv
```

原地覆盖：

```bash
python3 sort_benchmark_key_ops_csv.py benchmark_key_ops.csv --in-place
```

## 11. 推荐完整流程

```bash
cd <lattisense-source-dir>

cmake -S . -B build-bench-ops \
  -DLATTISENSE_BUILD_EXAMPLES=ON \
  -DLATTISENSE_ENABLE_GPU=ON \
  -DLATTISENSE_CUDA_ARCH=<your_cuda_arch>

cmake --build build-bench-ops --target benchmark_key_ops

cd build-bench-ops/examples/benchmark_key_ops

python benchmark_key_ops.py

LATTI_CPU_THREADS=1 OMP_NUM_THREADS=1 ./benchmark_key_ops \
  --device cpu \
  --thread-label cpu_1t \
  --csv benchmark_key_ops.csv \
  --overwrite-csv

LATTI_CPU_THREADS=32 OMP_NUM_THREADS=32 OPENBLAS_NUM_THREADS=32 MKL_NUM_THREADS=32 ./benchmark_key_ops \
  --device cpu \
  --thread-label cpu_mt \
  --csv benchmark_key_ops.csv

./benchmark_key_ops \
  --device gpu \
  --thread-label gpu \
  --csv benchmark_key_ops.csv \
  --isolate-gpu-case

python3 sort_benchmark_key_ops_csv.py benchmark_key_ops.csv \
  -o benchmark_key_ops.sorted.csv
```

## 12. 冒烟验证流程

用于先确认环境、task 生成和可执行文件调用链路是否正常：

```bash
cd <lattisense-source-dir>

cmake -S . -B build-bench-ops \
  -DLATTISENSE_BUILD_EXAMPLES=ON \
  -DLATTISENSE_ENABLE_GPU=ON \
  -DLATTISENSE_CUDA_ARCH=<your_cuda_arch>

cmake --build build-bench-ops --target benchmark_key_ops

cd build-bench-ops/examples/benchmark_key_ops

python benchmark_key_ops.py --n 4096 --ops 8

LATTI_CPU_THREADS=1 OMP_NUM_THREADS=1 ./benchmark_key_ops \
  --device cpu \
  --thread-label cpu_smoke \
  --n 4096 \
  --ops 8 \
  --csv smoke.csv \
  --overwrite-csv
```

GPU 冒烟：

```bash
./benchmark_key_ops \
  --device gpu \
  --thread-label gpu_smoke \
  --n 4096 \
  --ops 8 \
  --csv smoke.csv
```

## 13. 注意事项

- benchmark 统计的是 `FheTaskCpu::run()` 或 `FheTaskGpu::run()` 返回的任务执行耗时，不包含 task graph 生成时间。
- 输入密文、输出密文、context 和 key 的准备发生在 benchmark case 执行前，不计入 task run 返回的耗时。
- CPU 单线程/多线程的实际差异取决于底层 CPU runner 是否响应 `OMP_NUM_THREADS` 或其他线程环境变量。
- GPU 大参数，特别是 `N=65536` 和 1024 个独立任务，可能需要较大显存；如果失败，会在 CSV 中记录 `failed` 和错误信息。
- 多次运行默认会追加到同一个 CSV；如果需要干净结果，请在第一轮运行时使用 `--overwrite-csv`，或先删除旧 CSV，或使用新的 `--csv` 文件名。

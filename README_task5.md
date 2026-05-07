# 任务五：基于稀疏打包的 Bootstrapping 算子优化

## 一、任务理解

Bootstrapping 是 CKKS 全同态加密中最昂贵的操作，通常占密文推理时间的 50% 以上。
Lattigo 底层已支持 Sparse Secret Encapsulation (SSE)（Boura et al., 2022），但 LattiSense 框架存在以下可优化空间：

1. **C++ SDK 层参数写死**：`CreateCkksBtpParameter()` 固定返回 `N16QP1546H192H32`，无法切换 Dense/Sparse 或其他参数变体。
2. **缺少系统性的性能基准**：框架内没有 Sparse vs Dense 的端到端量化对比。
3. **上层缺少 preset API**：编译器和用户无法按需选择 bootstrapping 参数。

## 二、优化方案

### 2.1 参数可配置化（Go SDK + C++ SDK）

- 在 Go SDK 中定义 8 种预设参数枚举：`BtpPresetSparse0~3`（H=192/768 + H=32）和 `BtpPresetDense0~3`（H=N/2 + H=32）。
- 新增导出函数 `CreateCkksBtpParameterByPreset(preset C.int)`。
- C++ 层 `CkksBtpParameter` 新增 `create_parameter_by_preset(int preset_id)` 静态方法。

### 2.2 系统性 Benchmark

新增 6 组 Go benchmark/test，覆盖：

| 文件 | 用途 |
|------|------|
| `ckks/bootstrapping/sparse_bench_test.go` | Sparse bootstrap 分阶段计时 |
| `ckks/bootstrapping/sparse_vs_dense_bsgs_test.go` | Sparse vs Dense 短参数对比（LogN=13） |
| `ckks/bootstrapping/sparse_vs_dense_full_test.go` | Sparse vs Dense 完整参数对比（LogN=16） |
| `ckks/bootstrapping/bsgs_bench_test.go` | BSGS ratio 调优（Dense 基准） |
| `ckks/bootstrapping/bsgs_opt_test.go` | BSGS ratio 调优（Sparse 1.0/2.0/4.0） |
| `ckks/bootstrapping/preset_test.go` | 8 种 preset 参数合法性验证 |

## 三、实验结果

### 3.1 环境

- CPU: AMD Ryzen 9 7945HX
- Go: 1.22+
- Lattisense: current main + 本 PR

### 3.2 Sparse vs Dense Bootstrapping（LogN=16，完整参数）

| 阶段 | Dense (H=N/2) | Sparse (H=192/H=32) | 加速比 |
|------|---------------|----------------------|--------|
| ModUp | 1.45 s | 0.30 s | **4.8×** |
| CtS | 37.66 s | 11.93 s | **3.2×** |
| EvalMod (Sine) | 9.47 s | 5.84 s | **1.6×** |
| StC | 12.43 s | 3.37 s | **3.7×** |
| **总时间** | **~61.0 s** | **~21.4 s** | **2.85×** |
| 模数层级 | 29 | 25 | **节省 4 层** |
| logQP | 1767 | 1546 | **降低 121 bit** |

### 3.3 BSGS 调优（LogN=16，Ratio=2.0）

| 参数 | CtS | StC | **合计** | 旋转密钥 |
|------|-----|-----|---------|---------|
| **Sparse** | **6.51 s** | **2.71 s** | **9.22 s** | 70 |
| **Dense** | 15.05 s | 3.76 s | **18.81 s** | 70 |
| **加速比** | **2.31×** | **1.39×** | **2.04×** | 相同 |

## 四、如何复现

### 4.1 编译项目

```bash
cd /path/to/lattisense
cmake -B build
cmake --build build -j$(nproc)
```

### 4.2 编译 Go SDK（如需要重新生成 C header / 静态库）

```bash
cd fhe_ops_lib/lattigo/go_sdk
bash build.sh
```

### 4.3 运行 Go 层基准测试

```bash
cd fhe_ops_lib/lattigo/ckks/bootstrapping

# 验证 8 种 preset 参数
go test -v -run TestPresetParameters -count=1

# Sparse vs Dense 短参数对比（约 30s）
go test -v -run TestSparseVsDenseBSGS -count=1

# Sparse vs Dense 完整参数对比（约 3-4min）
go test -v -run TestSparseVsDenseFullParams -count=1

# BSGS ratio 调优
go test -v -run TestBSGSOptShort -count=1
```

### 4.4 C++ 层使用新接口

```cpp
// 旧接口：固定返回 Sparse0
auto param = fhe_ops_lib::CkksBtpParameter::create_parameter();

// 新接口：可选预设
auto param_sparse = fhe_ops_lib::CkksBtpParameter::create_parameter_by_preset(0); // Sparse0
auto param_dense  = fhe_ops_lib::CkksBtpParameter::create_parameter_by_preset(4); // Dense0
```

## 五、改动清单

### C++ Wrapper（lattisense 主仓库）

| 文件 | 改动 |
|------|------|
| `fhe_ops_lib/fhe_lib_v2.h` | 新增 `CkksBtpParameter::create_parameter_by_preset` |
| `fhe_ops_lib/fhe_lib_v2.cpp` | 实现上述方法 |

### Go 实现与测试（lattigo 子模块）

| 文件 | 改动 |
|------|------|
| `go_sdk/bootstrap.go` | 新增 `BtpParameterPreset` 枚举 + `CreateCkksBtpParameterByPreset` |
| `go_sdk/liblattigo.h` | 自动生成，新增导出声明 |
| `go_sdk/liblattigo_sanitized.h` | 同步新增导出声明（供 C++ 编译使用） |
| `ckks/bootstrapping/sparse_bench_test.go` | 新增 Sparse 分阶段 benchmark |
| `ckks/bootstrapping/sparse_vs_dense_bsgs_test.go` | 新增短参数 Sparse vs Dense 对比 |
| `ckks/bootstrapping/sparse_vs_dense_full_test.go` | 新增完整参数 Sparse vs Dense 对比 |
| `ckks/bootstrapping/bsgs_bench_test.go` | 新增 BSGS ratio 调优（Dense 基准） |
| `ckks/bootstrapping/bsgs_opt_test.go` | 新增 BSGS ratio 调优（Sparse） |
| `ckks/bootstrapping/preset_test.go` | 新增 8 种 preset 合法性验证 |

## 六、已知限制与未来工作

1. **lattigo 子模块**：本 PR 更新了 `fhe_ops_lib/lattigo` 子模块指向。由于子模块修改位于独立仓库，需同步提交到 `cipherflow-fhe/lattigo` 或先由维护者合并子模块后再更新引用。
2. **BSGS ratio 自适应**：当前测试固定了几组 ratio，未来可根据模型深度和 slot 数实现自适应选择。
3. **GPU 后端稀疏优化**：HEonGPU 后端尚未针对稀疏密钥封装做特殊 kernel 调度，可进一步挖掘加速空间。

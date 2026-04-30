## FHE Softmax Layer 实现说明

### 概述

本文档描述了在全同态加密（FHE）推理框架下 Softmax 层的完整实现，包括底层算子扩展、计算图层封装、部署集成以及多层级测试。实现基于 CKKS 方案，采用 Chebyshev 多项式近似 exp 和倒数函数，结合 Goldschmidt 迭代提升精度。

### 环境配置

#### 硬件要求

- 内存：建议 16GB 及以上（N=65536 参数集下密文及生成全部旋转密钥较大，当前测试中手动生成特定的旋转密钥以支持在8GB的WSL上进行测试）
- CPU：支持多核并行编译

#### 软件依赖

| 组件 | 说明 |
|---|---|
| CMake | 构建系统，版本 >= 3.13 |
| C++17 或更高 | GCC 或 Clang |
| Go | Lattigo 后端依赖 |
| Python 3.12 | 计算图前端 |
| pytest | Python 测试框架 |

#### Python 依赖

```bash
pip install pytest numpy
```

- 依赖库均继承原仓库已有，无新增

#### 构建项目

```bash
cd ~/latti-ai-main
mkdir -p build && cd build
cmake ..
cmake --build . -j$(nproc)
```

---

### 项目结构与新增/修改文件说明

#### 1. lattisense 层（算子层）

##### 新增算子（C++）

**`inference/lattisense/fhe_ops_lib/fhe_lib_v2.h / fhe_lib_v2.cpp`**

1. 新增 CKKS Chebyshev 多项式求值接口：

```cpp
CkksCiphertext CkksContext::poly_eval_chebyshev(
    const CkksCiphertext& x_ct,
    const std::vector<double>& coeffs,
    double a, double b,
    uint64_t slots,
    double base_scale
)
```

- 实现的是Clenshaw 递推算法，计算阶数较低时就能够达到较好的精度

**`inference/lattisense/mega_ag_runners/cpu/mega_ag_executors_cpu.cpp`**

1. 新增三个计算图算子的 CPU 执行器绑定：

```cpp
template <HEScheme SchemeType> void bind_cpu_poly_eval(ComputeNode& node)
template <HEScheme SchemeType> void bind_cpu_newton_reciprocal(ComputeNode& node)
template <HEScheme SchemeType> void bind_cpu_goldschmidt_reciprocal(ComputeNode& node)
```

- bind_cpu_poly_eval通过传入目标函数指针进行复用的方式，支持多种非线性函数的计算

2. 新增算子类型映射（`mega_ag.cpp`）：

```cpp
{"poly_eval",               OperationType::POLY_EVAL},
{"newton_reciprocal",       OperationType::NEWTON_RECIPROCAL},
{"goldschmidt_reciprocal",  OperationType::GOLDSCHMIDT_RECIPROCAL}
```

##### 新增算子（Python 前端）

**`inference/lattisense/frontend/custom_task.py`**

新增三个计算图节点构造函数：

```python
def poly_eval(x, func, degree, left, right, output_id) -> CkksCiphertextNode
def newton_reciprocal(x, iterations, init_guess, output_id) -> CkksCiphertextNode
def goldschmidt_reciprocal(x, init_guess, iterations, output_id) -> CkksCiphertextNode
```

辅助函数：

```python
def get_chebyshev_coeffs_optimized(func_type, degree, domain)
```

- 每个计算图节点的输出密文level都要进行动态的计算，以适应不同场景下的复用：
  - `poly_eval` 的输出 level 公式为`output_level = x.level - degree - 1 ` 
  - `newton_reciprocal` 的输出 level 公式为`output_level = x.level - 2 * iterations` 
  - `goldschmidt_reciprocal` 的输出 level 公式为`output_level = min(x.level, init_guess.level) - iterations - 1` 

#### 2. lattisense 单元测试

##### Python 测试（`inference/lattisense/unittests/test_cpu_ckks.py`）

新增以下测试方法，单独验证各算子在不同 level 和参数下的计算图构建与指令生成：

```python
def test_exp(self, n_op=4, levels=[7, 8])
def test_reciprocal(self, n_op=4, levels=[8, 9])
def test_newton_reciprocal(self, n_op=4, iterations=4, init_guess=1.0, input_range=(0.5, 1.5), levels=[8, 9])
def test_goldschmidt_reciprocal(self, n_op=4, iterations=3, levels=[8, 9])
def test_poly_chebyshev_bootstrap_toy_goldschmidt(self, n_op=4, iterations=2, levels=[9])
```

##### C++ 测试（`inference/lattisense/unittests/test_cpu_ckks.cpp`）

新增以下测试用例，验证各算子计算逻辑和数值精度：

```cpp
TEST_CASE_METHOD(CkksCpuFixture, "CKKS exp", "")
TEST_CASE_METHOD(CkksCpuFixture, "CKKS reciprocal", "")
TEST_CASE_METHOD(CkksCpuFixture, "CKKS newton reciprocal", "")
TEST_CASE_METHOD(CkksCpuFixture, "CKKS goldschmidt reciprocal", "")
TEST_CASE_METHOD(CkksCpuFixture, "CKKS poly_chebyshev_bootstrap_toy_goldschmidt", "")
```

#### 3. model_generator 层（计算图层）

##### 新增文件

**`inference/model_generator/layers/Softmax_layer_base.py`**

实现 `SoftmaxLayerBase` 类，将 Softmax 的 FHE 计算分解为以下步骤并构建计算图：

1. `poly_eval(exp)` — 对每个输入密文计算 exp(x)
2. `_sum_slots` + 跨密文累加 — 槽内归约得到全局和
3. `mult(mask) + rescale` — 掩码至 slot 0
4. `poly_eval(reciprocal)` — Chebyshev 近似初始倒数估计
5. `drop_level` 对齐 + `goldschmidt_reciprocal` — 迭代优化倒数
6. `mult(mask2) + rescale` + `_broadcast_slots` — 掩码后广播
7. `drop_level` 对齐 + `mult + relin + rescale` — 逐元素乘归一化

构造参数：

```python
SoftmaxLayerBase(
    n_channel,          # 总通道数
    n_channel_per_ct,   # 每个密文中的通道数，2 的幂次配合旋转
    skip,               # 物理槽步长，槽内数据实际间隔
    exp_order,          # exp 的 Chebyshev 多项式阶数
    inv_order,          # 倒数的 Chebyshev 多项式阶数
    input_min,          # 输入范围下界
    input_max,          # 输入范围上界
    n_goldschmidt_iter  # Goldschmidt 迭代次数，默认 2
)
```

##### 修改文件

**`inference/model_generator/deploy_cmds.py`**

新增 `elif layer_config['type'] == 'softmax':` 分支，从 config 读取参数构造 `SoftmaxLayerBase`，创建两个独立的 slot0 掩码节点（`CkksPlaintextRingtNode`）并注册为 `Argument`：

```python
softmax_mask_pt  = CkksPlaintextRingtNode(f'softmax_mask_pt_{layer_id}_0')
softmax_mask_pt2 = CkksPlaintextRingtNode(f'softmax_mask_pt_{layer_id}_1')
```

#### 4.softmax_layer实现层（c++）

##### 新增文件

| 文件                          | 位置                    | 说明                                                   |
| ----------------------------- | ----------------------- | ------------------------------------------------------ |
| `softmax_layer.h / .cpp`      | `inference/fhe_layers/` | 带自举的 Softmax 层，适用于深度不足时刷新 level        |
| `softmax_layer_base.h / .cpp` | `inference/fhe_layers/` | 无自举的基础 Softmax 层，适用于参数集 level 充足的场景 |
| `test_softmax_layer.cpp`      | `inference/unittests/`  | `SoftmaxLayer`（带自举）的单元测试                     |
| `test_softmax_layer_base.cpp` | `inference/unittests/`  | `SoftmaxLayerbase`（无自举）的单元测试                 |

- **两个版本的区别**

​	**`SoftmaxLayer`（带自举，`softmax_layer.h/cpp`）**

使用 `LattigoCkksBtpToyFixture` 提供自举上下文，在 Goldschmidt 迭代后以及倒数掩码后各插入一次 `refresh_ciphertext()`（自举），以恢复 level 供后续乘法使用，适用于输入 level 受限（如自举参数集 max_level 较低）或使用了自举上下文的模型中。

```cpp
// 自举刷新示例（softmax_layer.cpp）
sum_feat = sum_feat.refresh_ciphertext();      // 第一次自举：全局和归一化后
inv_feat = inv_feat.refresh_ciphertext();      // 第二次自举：Goldschmidt 精化后
```

​	**`	SoftmaxLayerbase`（无自举，`softmax_layer_base.h/cpp`）**

使用 `CkksN65536Fixture`（N=65536，max_level=33），依靠充足的 level 预算完成全部计算，无需自举，计算图层的 `Softmax_layer_base.py` 与这一版本对应。

- 两个版本共享相同的算法结构：

```
exp(x) → sum_slots → 跨密文累加 → mask(slot0) →
poly_eval(1/sum) → align_levels → Goldschmidt迭代 →
mask(slot0) → broadcast_slots → exp * inv
```

##### 构造函数参数说明

```cpp
SoftmaxLayer / SoftmaxLayerbase (
    const ls::CkksParameter& param,    // FHE 参数
    const Array<double,1>& exp_coeffs, // exp 的 Chebyshev 系数
    const Array<double,1>& inv_coeffs, // 倒数的 Chebyshev 系数
    uint32_t n_channel_per_ct,         // 每个密文的逻辑通道数，为 2 的幂
    uint32_t level_in,                 // 输入密文的初始 level
    int exp_order,                     // exp 近似阶数
    int inv_order,                     // 倒数近似阶数
    int ciphertext_skip,               // 数据在槽中的间隔，一般为1
    int total_n_channel,               // 总通道数（用于倒数定义域估算）
    double input_min,                  // 输入范围下界
    double input_max                   // 输入范围上界
)
```

倒数定义域由构造函数自动计算：

```cpp
inv_domain_a_ = total_n_channel * exp(input_min) + 0.1;
inv_domain_b_ = total_n_channel * exp(input_max) + 0.5;
```

##### 单元测试说明

**`test_softmax_layer.cpp`（带自举版）**

使用 `LattigoCkksBtpToyFixture` 作为测试上下文， `SoftmaxTestFixture` 在构造时自动计算 Chebyshev 系数，逻辑上与lattisense层的chebyshev系数辅助函数一致，在这里也是为了测试方便

**TEST CASE 1：基础功能**

```
标签: "Softmax basic functionality", "[softmax]"
测试类: SoftmaxTestFixture（继承 LattigoCkksBtpToyFixture）
输入: 4 个随机值，范围 [-2.0, 0.0]，固定种子 42
参数: n_channel_per_ct=4, level_in=9, exp_order=7, inv_order=4
验证:
  - 每个输出与明文 softmax 误差 < 1e-3
  - 输出之和与 1.0 的误差 < 1e-3 
  - 实际相对误差 < 5e-2
```

**TEST CASE 2：模拟ReLU输出做输入**

```
标签: "Softmax after ReLU simulation", "[softmax]"
测试类: SoftmaxTestFixture（独立构造）
输入: 16 个随机值，范围 [0.0, 4.0]，固定种子 123
参数: n_channel_per_ct=4, level_in=9, exp_order=7, inv_order=4
说明: 模拟某模型的输出分布，验证多场景下的精度
验证: 同上
```

**TEST CASE 3：BTP 参数规格打印**

```
标签: [btp_spec]
功能: 对比 CkksBtpParameter::create_toy_parameter() 和 SoftmaxTestFixture 使用的参数是否一致
验证: N 和 max_level 完全匹配
```

运行命令：

```bash
cd ~/latti-ai-main/build/inference/unittests
./test_softmax_layer "[softmax]"
./test_softmax_layer "[btp_spec]"
```

------

**`test_softmax_layer_base.cpp`（无自举版）**

使用 `CkksN65536Fixture`（N=65536）作为测试上下文， `SoftmaxTestFixturebase` 结构与带自举版相同，但不依赖自举参数。

**TEST CASE 1：基础功能**

```
标签: "Softmax basic functionality", "[softmax]"
夹具: SoftmaxTestFixturebase（继承 CkksN65536Fixture）
输入: 4 个随机值，范围 [-2.0, 0.0]，固定种子 42
参数: n_channel_per_ct=4, level_in=19, exp_order=7, inv_order=4
验证:
  - 每个输出与明文 softmax 误差 < 1e-3
  - 输出之和与 1.0 的误差 < 1e-3
  - 实际相对误差 < 5e-2
```

**TEST CASE 2：模拟模型输出做输入**

```
标签: "Softmax after model", "[softmax]"
夹具: SoftmaxTestFixturebase（独立构造）
输入: 16 个随机值，范围 [-1.0, 3.0]，固定种子 123
参数: n_channel_per_ct=4, level_in=19, exp_order=7, inv_order=4
说明: 模拟 ReLU 后的非负输入，使用更大输入范围验证鲁棒性
验证: 同上
```

运行命令：

```bash
cd ~/latti-ai-main/build/inference/unittests
./test_softmax_layer_base "[softmax]"
```

#### 5. 测试层

##### Python 图构建测试（`inference/unittests/test_gen_layers.py`）

新增 `test_softmax_layer`，使用 `PN16QP1761`（N=65536，max_level=33）参数集，验证两组参数配置下计算图的正确构建和指令生成。

```
标签: test_softmax_layer
框架: TestLayerExport
参数集: PN16QP1761（N=65536，max_level=33）

TEST CASE 1:
  输入通道: n_channel=4，n_channel_per_ct=4，n_ct=1
  参数: input_min=-1.0, input_max=1.0, exp_order=7, inv_order=4, level=20

TEST CASE 2:
  输入通道: n_channel=8，n_channel_per_ct=4，n_ct=2
  参数: input_min=-1.0, input_max=1.0, exp_order=7, inv_order=4, level=20

验证:
  - 计算图节点构建无异常（level 对齐、drop_level、goldschmidt 输入一致性）
  - process_custom_task 成功生成指令文件：
      mega_ag.json         （计算图序列化）
      task_signature.json  （参数与 IO 签名）
  - task_signature.json 包含正确的 4 个 online 参数：
      input_ct          (type: ct,       phase: in,  level: 20)
      softmax_mask_pt_0 (type: pt_ringt, phase: in,  level: 0)
      softmax_mask_pt_1 (type: pt_ringt, phase: in,  level: 0)
      output_ct         (type: ct,       phase: out, level: 1)

输出路径: build/inference/hetero/CKKS_softmax/ch_{n_channel}_per_ct_{n_channel_per_ct}/level_20/server/
```

##### C++ 测试（`inference/unittests/test_fhe_layers_hetero.cpp`）

新增 `TEST_CASE_METHOD(CkksN65536Fixture, "softmax_feature0d", "[softmax]")`，加载 `test_gen_layers.py` 生成的指令，执行完整的加密 → FHE 计算 → 解密 → 精度验证流程。

```
标签: "softmax_feature0d", "[softmax]"
测试名: softmax_feature0d
测试类: CkksN65536Fixture（N=65536，仅生成旋转密钥 {±1,±2,±4,±8}）
依赖: test_gen_layers.py 预先生成的指令文件

TEST CASE 1:
  输入: 4 个随机值，范围 [-1.0, 1.0]，固定种子 42
  参数: n_channel=4, n_channel_per_ct=4, n_ct=1, level=20

TEST CASE 2:
  输入: 8 个随机值，范围 [-1.0, 1.0]，固定种子 42
  参数: n_channel=8, n_channel_per_ct=4, n_ct=2, level=20

执行流程:
  1. 按 Feature0DEncrypted 布局加密输入（skip=1），共 n_ct 个密文
  2. 构造输出密文占位
  3. encode_ringt([1,0,...,0], default_scale) 构造两个独立 slot0 掩码明文
  4. 从 task_signature.json 读取 arg_names，按名称前缀匹配构造 cxx_args：
       "input_ct"         → enc_input.data
       "softmax_mask_pt_0" → softmax_mask_pt_0_vec
       "softmax_mask_pt_1" → softmax_mask_pt_1_vec
       "output_ct"        → enc_output.data
  5. FheTaskCpu::run() 加载并执行完整计算图
  6. 设置 enc_output 元数据（n_channel, n_channel_per_ct, skip, pack_type）
  7. Feature0DEncrypted::unpack() 解密输出，与明文 softmax 对比

验证:
  - max_error < 5% × max_abs（相对误差）
  - max_error < 1e-4（绝对误差上限）
  - 输出之和与 1.0 的误差 < 1e-3
  - 打印 [STATS softmax] max_err、rmse、max_abs 供核查
```

##### 修改文件

**`inference/unittests/fixture.hpp` 中的 `CkksN65536Fixture`和`LattigoCkksBtpToyFixture`**

`CkksN65536Fixture`将参数构造方式统一为 `CkksParameter::create_parameter(1 << 16)`，与 `PN16QP1761` 预置参数对齐，确保指令生成和执行使用完全一致的 FHE 参数（Q count=34）。旋转密钥仅生成 Softmax 所需的 `{±1, ±2, ±4, ±8}`，避免内存爆炸。

`LattigoCkksBtpToyFixture`使用toy_bootstraping的参数，在WSL内存支持的范围内验证应用自举上下文的softmax测试通过、功能正确、精度达标。

---

### 运行步骤

#### Step 1：运行 lattisense 算子单元测试

##### **Python 图构建：**

```bash
cd ~/latti-ai-main/inference/lattisense
cmake --build build -j$(nproc)

rm -rf ~/latti-ai-main/inference/lattisense/unittests/test_data/cpu/CKKS_exp_*
rm -rf ~/latti-ai-main/inference/lattisense/unittests/test_data/cpu/CKKS_reciprocal_*
rm -rf ~/latti-ai-main/inference/lattisense/unittests/test_data/cpu/CKKS_newtonreciprocal_* 
rm -rf ~/latti-ai-main/inference/lattisense/unittests/test_data/cpu/CKKS_goldschmidtreciprocal_*
rm -rf ~/latti-ai-main/inference/lattisense/unittests/test_data/cpu/CKKS_goldschmidt_bts*
rm -rf ~/latti-ai-main/inference/lattisense/unittests/test_data/cpu/CKKS_4_poly_*
rm -rf ~/latti-ai-main/inference/lattisense/unittests/test_data/cpu/CKKS_4_poly_bootstrap_toy_goldschmidt

cd ~/latti-ai-main/inference/lattisense/unittests
python3 -m unittest test_cpu_ckks.TestTask.test_exp -v
python3 -m unittest test_cpu_ckks.TestTask.test_reciprocal -v
python3 -m unittest test_cpu_ckks.TestTask.test_newton_reciprocal -v
python3 -m unittest test_cpu_ckks.TestTask.test_goldschmidt_reciprocal -v
python3 -m unittest test_cpu_ckks.TestTask.test_poly_chebyshev_bootstrap_toy -v
python3 -m unittest test_cpu_ckks.TestTask.test_goldschmidt_bootstrap_toy -v
python3 -m unittest test_cpu_ckks.TestTask.test_poly_chebyshev_bootstrap_toy_goldschmidt -v
```

- 如果计算图有修改要重新生成

##### **C++ 数值验证：**

```bash
cd ~/latti-ai-main/inference/lattisense/build/unittests
./test_cpu_ckks "CKKS exp" 
./test_cpu_ckks "CKKS reciprocal" 
./test_cpu_ckks "CKKS newton reciprocal"
./test_cpu_ckks "CKKS goldschmidt reciprocal"
./test_cpu_ckks "CKKS poly_chebyshev_bootstrap_toy"
./test_cpu_ckks "CKKS goldschmidt bts reciprocal"
./test_cpu_ckks "CKKS poly_chebyshev_bootstrap_toy_goldschmidt"
```

#### Step 2：生成 Softmax 计算图指令

```bash
cd ~/latti-ai-main
PYTHONPATH=~/latti-ai-main python3 -m pytest \
    /home/ignite/latti-ai-main/inference/unittests/test_gen_layers.py \
    -k "softmax" -s
```

成功后会生成指令文件，由实际部署路径决定
#### Step 3：编译layer层测试

```bash
cd ~/latti-ai-main/build
cmake --build . -j$(nproc)
```

#### Step 4：运行layer层测试

```bash
cd ~/latti-ai-main/build/inference/unittests
./test_fhe_layers_hetero "[softmax]"
```

---

### 结果说明

#### 测试用例参数

用同样的框架进行多组测试，包括生成计算图的全流程测试和softmax单元测试等，多维度验证结果

- test_fhe_layers_hetero.cpp 

| n_channel | n_channel_per_ct | input_min | input_max | exp_order | inv_order | level |
| --------- | ---------------- | --------- | --------- | --------- | --------- | ----- |
| 4         | 4                | -2.0      | 0.0       | 7         | 4         | 20    |
| 4         | 4                | 0.0       | 2.0       | 7         | 4         | 20    |
| 4         | 4                | -1.0      | 1.0       | 7         | 4         | 20    |
| 8         | 4                | -1.0      | 1.0       | 7         | 4         | 20    |
| 16        | 4                | -2.0      | 0.0       | 7         | 4         | 20    |
| 16        | 4                | -1.0      | 1.0       | 7         | 4         | 20    |

- test_softmax_layer.cpp、test_softmax_layer_base.cpp 

| n_channel | n_channel_per_ct | input_min | input_max | exp_order | inv_order | level |
| --------- | ---------------- | --------- | --------- | --------- | --------- | ----- |
| 4         | 4                | -2.0      | 0.0       | 7         | 4         | 9     |
| 4         | 4                | -2.0      | 0.0       | 7         | 4         | 19    |
| 16        | 4                | 0.0       | 4.0       | 7         | 4         | 9     |
| 16        | 4                | -1.0      | 3.0       | 7         | 4         | 19    |
| 64        | 4                | 0.0       | 4.0       | 7         | 4         | 9     |
| 128       | 4                | 0.0       | 4.0       | 7         | 4         | 9     |

#### 测试输出

##### 算子输出

1. "CKKS exp"：degree = 6, left = -1.0, right = 1.0,levels=[8]

   ```bash
   x=-1.000000  exp_true=0.367879  exp_fhe=0.367921  abs_error=0.000041    Result level: 1
   x=-0.333333  exp_true=0.716531  exp_fhe=0.716521  abs_error=0.000010    Result level: 1
   x=0.333333   exp_true=1.395612  exp_fhe=1.395545  abs_error=0.000067    Result level: 1
   x=1.000000   exp_true=2.718282  exp_fhe=2.718049  abs_error=0.000232    Result level: 1
   ```

2. "CKKS reciprocal"：degree = 6, left = 1.0, right = 5.0,levels=[8]

   ```bash
   x=1.000000  1/x_true=1.000000  1/x_fhe=1.000012  abs_error=0.000012  relative_error=0.000012
   Result level: 1
   x=2.333333  1/x_true=0.428571  1/x_fhe=0.429782  abs_error=0.001211  relative_error=0.002825
   Result level: 1
   x=3.666667  1/x_true=0.272727  1/x_fhe=0.272783  abs_error=0.000056  relative_error=0.000205
   Result level: 1
   x=5.000000  1/x_true=0.200000  1/x_fhe=0.202838  abs_error=0.002838  relative_error=0.014188
   Result level: 1
   ```

3. "CKKS newton reciprocal"：iterations=4, init_guess=1.0, input_range=(0.5, 1.5), levels=[8, 9]

   ```bash
   Creating output buffer with level: 0
   x=0.500000  1/x_true=2.000000  1/x_fhe=1.999969  abs_error=0.000031  relative_error=0.000015
   x=0.833333  1/x_true=1.200000  1/x_fhe=1.200000  abs_error=0.000000  relative_error=0.000000
   x=1.166667  1/x_true=0.857143  1/x_fhe=0.857143  abs_error=0.000000  relative_error=0.000000
   x=1.500000  1/x_true=0.666667  1/x_fhe=0.666656  abs_error=0.000010  relative_error=0.000015
   Creating output buffer with level: 1
   x=0.500000  1/x_true=2.000000  1/x_fhe=1.999970  abs_error=0.000030  relative_error=0.000015
   x=0.833333  1/x_true=1.200000  1/x_fhe=1.200000  abs_error=0.000000  relative_error=0.000000
   x=1.166667  1/x_true=0.857143  1/x_fhe=0.857143  abs_error=0.000000  relative_error=0.000000
   x=1.500000  1/x_true=0.666667  1/x_fhe=0.666657  abs_error=0.000010  relative_error=0.000015
   ```

4. "CKKS goldschmidt reciprocal"：iterations=4, input_range=(0.5, 1.5), levels=[8, 9]

   ```bash
   Creating output buffer with level: 3
   x=0.500000 y=1.000000  1/x_true=2.000000  1/x_fhe=1.999970  abs_error=0.000030  relative_error=0.000015
   x=0.833333 y=1.000000  1/x_true=1.200000  1/x_fhe=1.200000  abs_error=0.000000  relative_error=0.000000
   x=1.166667 y=1.000000  1/x_true=0.857143  1/x_fhe=0.857143  abs_error=0.000000  relative_error=0.000001
   x=1.500000 y=1.000000  1/x_true=0.666667  1/x_fhe=0.666656  abs_error=0.000010  relative_error=0.000015
   Creating output buffer with level: 4
   x=0.500000 y=1.000000  1/x_true=2.000000  1/x_fhe=1.999970  abs_error=0.000030  relative_error=0.000015
   x=0.833333 y=1.000000  1/x_true=1.200000  1/x_fhe=1.200000  abs_error=0.000000  relative_error=0.000000
   x=1.166667 y=1.000000  1/x_true=0.857143  1/x_fhe=0.857143  abs_error=0.000000  relative_error=0.000000
   x=1.500000 y=1.000000  1/x_true=0.666667  1/x_fhe=0.666656  abs_error=0.000010  relative_error=0.000015
   ```

5. "CKKS poly_chebyshev_bootstrap_toy_goldschmidt"：iterations=3, levels=[9], reciprocal_cheb_degree=4,left=1.0, right=10.0 

   ```bash
   [INFO] Index 0 | X: 1 | Expected: 1 | Actual: 1 | Final Level: 5 | abs_error: 6.88706e-10
   [CHECK] cheb 0 | X: 1 | Expected: 1 | Actual: 0.957978 | Final Level: 4 | abs_error: 0.0420221
   [INFO] Index 1 | X: 4 | Expected: 0.25 | Actual: 0.25 | Final Level: 5 | abs_error: 2.90393e-07
   [CHECK] cheb 1 | X: 4 | Expected: 0.25 | Actual: 0.205133 | Final Level: 4 | abs_error: 0.0448671
   [INFO] Index 2 | X: 7 | Expected: 0.142857 | Actual: 0.142857 | Final Level: 5 | abs_error: 2.98444e-09
   [CHECK] cheb 2 | X: 7 | Expected: 0.142857 | Actual: 0.127436 | Final Level: 4 | abs_error: 0.0154213
   [INFO] Index 3 | X: 10 | Expected: 0.1 | Actual: 0.0999248 | Final Level: 5 | abs_error: 7.51753e-05
   [CHECK] cheb 3 | X: 10 | Expected: 0.1 | Actual: 0.141137 | Final Level: 4 | abs_error: 0.0411373
   ```

- **各个算子计算过程正确，输出误差小，能够达到FHE计算精度要求**

##### softmax层输出

test_fhe_layers_hetero.cpp ：n_channel=8,  n_channel_per_ct=4,  input_min=-1.0, input_max=1.0, exp_order=7, inv_order=4, level=20

```bash
[DEBUG] Received coeffs (8): 1.26607 1.13032 0.271495 0.0443368 0.00547424 0.000542926 4.49768e-05 3.1874e-06 
[DEBUG] Received coeffs (8): 1.26607 1.13032 0.271495 0.0443368 0.00547424 0.000542926 4.49768e-05 3.1874e-06 
[DEBUG] Received coeffs (5): 0.121437 -0.111548 0.0509298 -0.0225934 0.00857805 
func_name = exp, left = -1, right = 1
The calculation this time is exp
successfully complete Chebyshev result for exp
func_name = exp, left = -1, right = 1
The calculation this time is exp
successfully complete Chebyshev result for exp
func_name = reciprocal, left = 3.04304, right = 22.2463
The calculation this time is reciprocal
successfully complete Chebyshev result for reciprocal
before drop_level w level：6 y level：6
after drop_level w level：6 y level：6
Max error position: [0], expected=0.218303, actual=0.218297, error=0.000006
[STATS softmax] max_err=5.58e-06  rmse=3.52e-06 max abs=2.18e-01
===============================================================================
All tests passed (3 assertions in 1 test case)
```

test_softmax_layer_base：total_inputs=16,  n_channel_per_ct=4,  input_min=-1.0, input_max=3.0, exp_order=7, inv_order=4, level_in=19

```bash
[DEBUG] Random input: 1.8518 0.7139 1.7635 1.8766 0.9645 2.1201 0.6437 1.3188 -0.4402 0.6041 1.5093 0.2966 -0.0210 1.7790 1.3756 1.5272
[DEBUG] Input to exp: 1.851821 0.713884 1.763539 1.876601
[LEVEL] after exp: 11 (consumed 8)
[DEBUG] After exp: 6.372525 2.041051 5.834311 6.532323
[DEBUG] After sum_slots[0]: slot0=20.780209, slot1=15.407145
[DEBUG] After all sum[0]: slot0=61.188805, slot1=54.567492
[DEBUG] inv_domain: a=5.9861 b=321.8686
[LEVEL] before inv (sum_feat): 10
[LEVEL] after inv: 5 (consumed 5)
[DEBUG] inv_sum (chebyshev): slot0=0.018444 (expected ~0.016343)  slot1=0.107115
[DEBUG] inv_sum (chebyshev): slot0=0.016338 (expected ~0.016343)  slot1=0.428459
[DEBUG] inv_sum (after mask): slot0=0.016338 (expected ~0.016343)  slot1=0.000000
[DEBUG] after bts_2: slot0=0.016338 (expected ~0.016343)  slot1=0.000000
[DEBUG] inv_sum broadcast_slots: slot0=0.016338, slot1=0.016338
[DEBUG] after last mult: slot0=0.104117, slot1=0.033347
[DEBUG] after last mult: slot0=0.042858, slot1=0.136135
[DEBUG] after last mult: slot0=0.010534, slot1=0.029875
[DEBUG] after last mult: slot0=0.015992, slot1=0.096810
Max error position: [5], expected=0.136181, actual=0.136135, error=0.000046
[STATS softmax] max_err=4.60e-05  rmse=2.09e-05  max_abs=1.36e-01
===============================================================================
All tests passed (18 assertions in 1 test case)
```

test_softmax_layer：total_inputs=16,  n_channel_per_ct=4,  input_min=0.0, input_max=4.0, exp_order=7, inv_order=4, level_in=9

```bash
[DEBUG] Random input: 2.8518 1.7139 2.7635 2.8766 1.9645 3.1201 1.6437 2.3188 0.5598 1.6041 2.5093 1.2966 0.9790 2.7790 2.3756 2.5272
[LEVEL] input_level: 9 
[DEBUG] Input to exp: 2.851821 1.713884 2.763539 2.876601
[LEVEL] after exp: 1 (consumed 8)
[DEBUG] After exp: 17.321600 5.547856 15.858628 17.755960
[DEBUG] After sum_slots[0]: slot0=56.484044, slot1=40.158822
[DEBUG] After all sum[0]: slot0=166.320976, slot1=141.441954
[DEBUG] inv_domain: a=16.1000 b=874.0704
[LEVEL] before inv (sum_feat): 9
[LEVEL] after inv: 4 (consumed 5)
[DEBUG] inv_sum (chebyshev): slot0=0.006773 (expected ~0.006012)  slot1=0.039568
[DEBUG] inv_sum (chebyshev): slot0=0.006011 (expected ~0.006012)  slot1=0.158271
[DEBUG] inv_sum (after mask): slot0=0.006011 (expected ~0.006012)  slot1=-0.000000
[LEVEL] before bts_2: 0
[LEVEL] after bts_2: 9
[DEBUG] after bts_2: slot0=0.006010 (expected ~0.006012)  slot1=-0.000000
[DEBUG] inv_sum broadcast_slots: slot0=0.006010, slot1=0.006010
[DEBUG] after last mult: slot0=0.104104, slot1=0.033343
[DEBUG] after last mult: slot0=0.042853, slot1=0.136119
[DEBUG] after last mult: slot0=0.010532, slot1=0.029871
[DEBUG] after last mult: slot0=0.015989, slot1=0.096798
[TIMER] ReLU softmax – layer.run: 3533.759 ms
Max error position: [5], expected=0.136181, actual=0.136119, error=0.000062
[STATS softmax] max_err=6.20e-05  rmse=2.84e-05  max_abs=1.36e-01
===============================================================================
All tests passed (7 assertions in 1 test case)
```

- **三组测试精度均达到要求，相对误差小于5%**

#### 精度指标

| 项目 | 指标 |
|---|---|
| 输出归一化误差（∑output - 1） | < 1e-3 |
| 相对误差cmp.max_error < kRelTol * cmp.max_abs | kRelTol = 5.0e-2 |

#### Level 消耗分析

以 `n_channel=4, input_min=-2.0, input_max=0.0, level=20` 为例：

| 步骤 | 操作 | 消耗层数 | 剩余 level |
|---|---|---|---|
| 输入 | — | — | 20 |
| Step 1 | poly_eval(exp, degree=7) | 8 | 12 |
| Step 2 | sum_slots + add | 0 | 12 |
| Step 3 | mult(mask) + rescale | 1 | 11 |
| Step 4 | poly_eval(reciprocal, degree=4) | 5 | 6 |
| Step 5 | init guess(w*y + rescale) + goldschmidt(iter=2) | 1 + 2 | 3 |
| Step 6 | mult(mask2) + rescale | 1 | 2 |
| Step 6 | broadcast_slots | 0 | 2 |
| Step 7 | drop_level + mult + relin + rescale | 1 | 1 |

---

### 关键设计说明

#### 掩码节点设计

slot0 掩码 `[1, 0, ..., 0]` 是编译期确定的固定常量，采用与 Upsample/AvgPool 层相同的模式：在 `deploy_cmds.py` 创建 `CkksPlaintextRingtNode`，Softmax_layer_base.py中建立make_pt_nodes，通过 `Argument` 注册，在 C++ 侧用 `context.encode_ringt(mask_vec, default_scale)` 编码后传入，使用两个独立节点（`softmax_mask_pt_0`、`softmax_mask_pt_1`）因为两次掩码发生在不同的计算深度，对应不同的 level。

#### Goldschmidt 迭代说明

`goldschmidt_reciprocal` 在 C++ 执行器中每次迭代消耗 1 层（`w * r + rescale`），初始 `w = w * y + rescale` 额外消耗 1 层，共消耗 `iterations + 1` 层，在倒数计算上两次乘法并行实现，相对于牛顿迭代消耗更低。

#### 参数集选择

Softmax 需要约 20 层乘法深度，`PN14QP438`（N=16384，max_level 不足）无法满足要求，只能引入自举，若选用 `PN16QP1761`（N=65536，max_level=33）在`CkksCpuFixture`类中的`gen_rotation_keys()`运行上开销巨大，导致WSL杀死进程无法计算，为避免内存压力，一方面使用toy级参数构建适配自举上下文的softmax，另一方面构建`CkksN65536Fixture` 继承大参数下的计算深度但仅生成 Softmax 所需的旋转密钥，不生成全量密钥，确保正常运行。

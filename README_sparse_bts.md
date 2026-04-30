# Feature: CKKS multi-slot sparse-packed bootstrapping (CPU)

## 概述

本文档描述 LattiSense SDK 中的 CKKS 多槽稀疏打包自举（Sparse-packed Bootstrapping）功能。该功能支持在同一段程序中，对不同槽数的密文进行稀疏打包自举，从而提高了自举操作的效率和灵活性。通过改进 lattigo 后端的 bootstrapping 实现，LattiSense SDK 支持在 CPU 上进行高效的 CKKS 稀疏打包自举操作。

## 组件修改

### lattigo 后端

- ``ckks/bootstrapping/``：新增对 bootstrap 槽位设置的支持，允许用户指定不同的槽数进行自举操作。
- ``ckks/advanced/homomorphic_encoding.go``：修改S2C和C2S，支持不同槽数的同态编码和解码。
- ``go_sdk/main.go``: 新增指定槽数的 encode/decode 接口，允许用户设置明文所需的槽数。
- ``go_sdk/bootstrapping.go``: 修改 Bootstrapping 接口，支持用户指定自举操作的槽数。

### 前后端接口（``fhe_ops_lib/fhe_lib_v2``）

- 新增指定槽数的 encode/decode 的前端接口。
- 修改 `CkksBtpContext`，使其内部可存储多个不同槽数的 bootstrapper 对应的 CkksBtpContext 实例。
  - 相当于实现二级 `BtpContext` 存储结构，第一层根据槽数区分，并提供bootstrap接口；第二层为私有，存储对应槽数的 bootstrapper 实例。
- 修改 `CkksBtpContext` 的 `Bootstrap` 方法，支持根据输入密文的槽数，选择对应的 bootstrapper 进行自举操作。

### 计算图运行（``mega_ag_runners/``，``cxx_sdk_v2/``）

- 新增不同槽数的 bootstrapper 的初始化逻辑，默认初始化用户在计算图中使用到的所有槽数的 bootstrapper。
- 修改计算图运行时的自举操作逻辑，调用 `CkksBtpContext` 的 `Bootstrap` 方法时，传入输入密文的槽数参数，以便选择正确的 bootstrapper 进行自举。

### 计算图生成（``frontend/custom_task.py``）

- 新增指定槽数的 bootstrap 操作的生成逻辑，允许用户在计算图中指定自举操作所需的槽数。
- 修改计算图生成逻辑，确保在生成自举操作时，正确传递槽数参数，以便后续运行时能够正确选择 bootstrapper 进行自举。

### 测试

- `lattigo/ckks/bootstrapping/bootstrapping_test.go`：新增针对不同槽数的自举操作的单元测试，验证自举结果的正确性和性能。
- `unittests/test_lattigo.cpp`：新增针对不同槽数的自举操作的单元测试，验证前后端接口的正确性和性能。
- `unittests/test_cpu_ckks.py`：新增针对不同槽数的自举操作的单元测试，验证计算图生成和运行时的正确性和性能。

## 使用方法说明

样例（`example/ckks_sparse_bootstrap_cpu`）

```python
def ckks_sparse_bootstrap(sparse_slots=[2, 8, 6, 10]):
    # set global FHE param at the very beginning of the application
    param = CkksBtpParam.create_default_param()
    set_fhe_param(param)

    # describe FHE task MegaAG
    level = 0
    x_list = []
    y_list = []
    for i in range(len(sparse_slots)):
        x_list.append(CkksCiphertextNode(f'x_{i}', level))
        # 此处为改进版 bootstrap 的使用实例，用户可直接指定 log_slots 参数，代表当前节点的密文所需的槽数（的对数）
        y_list.append(bootstrap(x_list[i], log_slots=sparse_slots[i], output_id=f'y_{i}'))
        # 可在同一个程序中支持不同槽数的 bootstrap 操作，LattiSense SDK 会根据每个节点的 log_slots 参数，自动选择对应的 bootstrapper 进行自举操作
    
    arg_x = Argument('in_x_list', x_list)
    arg_y = Argument('out_y_list', y_list)

    # compile FHE task
    process_custom_task(
        input_args=[arg_x],
        output_args=[arg_y],
        output_instruction_path=f'project_{"toy" if is_toy else "default"}_sparse_bootstrap/slots_{sparse_slots}',
    )

```

```cpp
void ckks_sparse_bootstrap(bool is_toy = false, const vector<int>& sparse_slots = {2, 8, 6, 10}) {
    CkksBtpParameter param;
    param = CkksBtpParameter::create_parameter();
    CkksBtpContext btp_context = CkksBtpContext::create_random_context(param);

    // 初始化多个 bootstrapper 的逻辑
    SecretKey sk = btp_context.extract_secret_key();
    for (int slots : sparse_slots) {
        btp_context.generate_sparse_bootstrapper(slots, sk, is_toy);
    }

    int level = 0;
    double default_scale = param.get_ckks_parameter().get_default_scale();

    vector<CkksCiphertext> x_list;
    vector<CkksCiphertext> y_list;
    vector<vector<double>> x_true_list;

    for (int i = 0; i < sparse_slots.size(); i++) {
        // 可支持自定义槽数的 encode
        auto x_pt = btp_context.encode_with_slots(x_mg, level, default_scale, current_slots);
        auto x_ct = btp_context.encrypt_symmetric(x_pt);
        x_list.push_back(std::move(x_ct));
        y_list.push_back(btp_context.new_ciphertext(9, default_scale));
    }

    FheTaskCpu cpu_project(project_path);

    vector<CxxVectorArgument> cxx_args = {
        CxxVectorArgument{"in_x_list", &x_list},
        CxxVectorArgument{"out_y_list", &y_list},
    };
    cpu_project.run(&btp_context, cxx_args);
}
```

## 性能

### 1. Original Environment (无稀疏密钥切换开销)

| 稀疏维度 (Log Slots) | 有效槽数 (Active Slots) | 耗时 (Execution Time) | 相对加速比 (vs. Full-Slot) |
| :---: | :---: | :---: | :---: |
| **2** | 4 | **34.81 s** | **2.35×** |
| **3** | 8 | **36.71 s** | **2.23×** |
| **4** | 16 | **38.80 s** | **2.11×** |
| **5** | 32 | **40.34 s** | **2.03×** |
| **6** | 64 | **45.77 s** | **1.79×** |
| **7** | 128 | **46.37 s** | **1.76×** |
| **8** | 256 | **49.09 s** | **1.67×** |
| **9** | 512 | **51.64 s** | **1.58×** |
| **10** | 1024 | **54.12 s** | **1.51×** |
| **11** | 2048 | **57.43 s** | **1.42×** |
| **12** | 4096 | **61.49 s** | **1.33×** |
| **13** | 8192 | **66.19 s** | **1.24×** |
| **14** | 16384 | **75.79 s** | **1.08×** |
| **15 (Baseline)** | 32768 | **81.80 s** | **1.00×** |

### 2. Encapsulated Environment (包含稀疏密钥切换开销)

| 稀疏维度 (Log Slots) | 有效槽数 (Active Slots) | 耗时 (Execution Time) | 相对加速比 (vs. Full-Slot) |
| :---: | :---: | :---: | :---: |
| **2** | 4 | **39.63 s** | **2.04×** |
| **3** | 8 | **39.43 s** | **2.05×** |
| **4** | 16 | **46.10 s** | **1.75×** |
| **5** | 32 | **44.97 s** | **1.80×** |
| **6** | 64 | **48.11 s** | **1.68×** |
| **7** | 128 | **52.05 s** | **1.55×** |
| **8** | 256 | **60.11 s** | **1.34×** |
| **9** | 512 | **56.55 s** | **1.43×** |
| **10** | 1024 | **56.92 s** | **1.42×** |
| **11** | 2048 | **62.52 s** | **1.29×** |
| **12** | 4096 | **67.32 s** | **1.20×** |
| **13** | 8192 | **68.95 s** | **1.17×** |
| **14** | 16384 | **78.60 s** | **1.03×** |
| **15 (Baseline)** | 32768 | **80.73 s** | **1.00×** |


[TOC]

# API参考

欢迎阅读面向用户的“格物”API文档。“格物”平台的面向用户接口共由两部分组成，分别为自定义 FHE 任务的接口和应用程序接口。

+ 自定义 FHE 任务接口：包含用于描述自定义任务的Python接口 ，通过Python语言接口定义FHE任务，生成前文所提到的有向无环图信息 Mega-operator Abstract Graph (MegaAG)，用于应用程序。
+ 应用程序接口：在用户的应用程序里，通过格物SDK，准备FHE计算的参数、context、输入数据，并编码和加密。应用程序接口提供包括密钥生成、加密、解密以及调用异构硬件（CPU/GPU）执行计算任务的C++接口， 同时提供完整的BFV/CKKS全同态算法的算子接口，支持用户根据实际场景的需求直接调用。
## 自定义 FHE 任务接口

自定义 FHE 任务接口通过 Python 语言实现，以下是接口的集合：

|       自定义 FHE 任务接口        |                |
| :---------------------: | :------------: |
|          `add`          |      加法      |
|          `sub`          |      减法      |
|          `neg`          |      取负      |
|         `mult`          |      乘法      |
|         `relin`         |    重线性化    |
|      `mult_relin`       | 乘法+重线性化  |
|        `rescale`        |    模数切换    |
|      `drop_level`       |   level切换    |
|      `rotate_cols`      |     列旋转     |
|  `advanced_rotate_cols` |   高级列旋转   |
|      `rotate_rows`      |     行旋转     |
| `ct_pt_mult_accumulate` | 明密文内积运算 |
|      `ct_to_mul`        | 密文转乘法形式 |
|      `ct_to_ntt`        |  密文转NTT形式 |
|     `ct_to_mform`       | 密文转Montgomery形式 |
|     `ct_ntt_to_ct`      | NTT密文转普通形式 |
|       `bootstrap`       |    CKKS自举    |



### Param 类

描述全同态加密算法参数的类。

#### 构造函数 Param

```Python
def __init__(self, algo: str, n: int = 8192) -> None
```

+ 参数
  + `algo`：算法名称，支持 'BFV' 和 'CKKS'。
  + `n`：多项式度数，默认为 8192。

+ 返回值：无。

#### 类方法 create_default_param

```Python
@classmethod
def create_default_param(cls, algo: str, n: int) -> Param
```

从预定义的参数配置文件（`parameter.json`）中加载默认参数创建参数对象。

+ 参数
  + `algo`：算法名称，支持 'BFV' 和 'CKKS'。
  + `n`：多项式度数，需要与配置文件中定义的值匹配。

+ 返回值：Param 对象。

+ 注意事项
  + 需要 `parameter.json` 文件存在于项目根目录。
  + 配置文件中必须包含指定算法和多项式度数的参数配置。

#### 类方法 create_bfv_custom_param

```Python
@classmethod
def create_bfv_custom_param(cls, n: int, q: List[int], p: List[int], t: int) -> Param
```

从自定义参数创建 BFV 算法参数对象。

+ 参数
  + `n`：多项式度数。
  + `q`：q模数列表。
  + `p`：p模数列表。
  + `t`：明文模数。

+ 返回值：Param 对象。

#### 类方法 create_ckks_custom_param

```Python
@classmethod
def create_ckks_custom_param(cls, n: int, q: List[int], p: List[int]) -> Param
```

从自定义参数创建 CKKS 算法参数对象。

+ 参数
  + `n`：多项式度数。
  + `q`：q模数列表。
  + `p`：p模数列表。

+ 返回值：Param 对象。

#### 类方法 create_ckks_btp_param

```Python
@classmethod
def create_ckks_btp_param(cls) -> Param
```

创建支持 bootstrapping 的 CKKS 算法参数对象，满足128-bit安全性。配置参数为：多项式度数 N=65536，支持 bootstrapping 操作所需的特定模数配置。

+ 参数：无。

+ 返回值：Param 对象。

#### 类方法 create_ckks_toy_btp_param

```Python
@classmethod
def create_ckks_toy_btp_param(cls) -> Param
```

创建一个较小的支持 bootstrapping 的 CKKS 算法参数对象，不满足128-bit安全性。配置参数为：多项式度数 N=8192 Bootstrap 参数，支持 bootstrapping 操作所需的特定模数配置。该参数仅适用于开发和测试场景。

+ 参数：无。

+ 返回值：Param 对象。

### 函数 set_fhe_param

```Python
def set_fhe_param(param: Param) -> None
```

设置全局FHE参数。

**重要**：此函数必须在调用 `process_custom_task()` 之前调用，用于设置后续所有FHE操作使用的全局参数对象。

+ 参数
  + `param`：FHE参数对象，包含算法类型、多项式度数n、模数等信息。

+ 返回值：无。

+ 示例

```Python
# 创建参数对象
param = Param.create_bfv_custom_param(
    n=8192,
    p=[0x7ffffffffb4001],
    q=[0x3fffffffef8001, 0x4000000011c001, 0x40000000120001],
    t=0x28001
)

# 设置为全局参数
set_fhe_param(param)

# 后续调用 process_custom_task() 时会使用此参数
```

### Argument 类

描述任务输入数据参数、输出数据参数、预加载明文阶段输入数据参数的类。

#### 函数 Argument

```Python
def __init__(self, arg_id: str, data: 'DataNode | list') -> None
```

+ 参数
  + `arg_id`：自定义参数id。
  + `data`：数据。可以是单个数据节点、数据节点list、数据节点tuple、或多级的数据节点list或tuple。

+ 返回值：无。

### DataNode 类

描述数据类型的类, 具体使用时应当使用其子类。

**明文类型：**
+ **BfvPlaintextNode**：BFV算法明文类型。
+ **BfvPlaintextRingtNode**：BFV算法环t上的明文类型，用于密文乘明文。
+ **BfvPlaintextMulNode**：BFV算法明文类型，用于密文乘明文，已预处理为NTT和Montgomery形式。
+ **BfvCompressedPlaintextRingtNode**：BFV算法压缩明文类型，用于批量密文乘明文操作。
+ **CkksPlaintextNode**：CKKS算法明文类型。
+ **CkksPlaintextRingtNode**：CKKS算法环t上的明文类型，用于密文乘明文。
+ **CkksPlaintextMulNode**：CKKS算法明文类型，用于密文乘明文，已预处理为NTT和Montgomery形式。

**密文类型：**
+ **BfvCiphertextNode**：BFV算法密文类型，包含2个多项式。
+ **BfvCiphertext3Node**：BFV算法密文类型，包含3个多项式。
+ **CkksCiphertextNode**：CKKS算法密文类型，包含2个多项式。
+ **CkksCiphertext3Node**：CKKS算法密文类型，包含3个多项式。

**密钥类型：**
+ **RelinKeyNode**：重线性化密钥类型。
+ **GaloisKeyNode**：Galois密钥类型，用于旋转操作。

#### 构造函数 DataNode

```Python
def __init__(self, type, id='', degree=-1, level=DEFAULT_LEVEL) -> None
```

+ 参数
  + `type`：数据类型。
  + `id`：自定义参数id。
  + `degree`：数据的degree（多项式个数-1）。
  + `level`：数据的level。
+ 返回值：无。

### 函数 add

```Python
def add(
    x: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | CkksCiphertextNode | CkksPlaintextNode,
    y: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | CkksCiphertextNode | CkksPlaintextNode,
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode
```

定义一个加法计算步骤。支持类型包括`ct+ct, ct+pt, pt+ct, ct+pt_ringt, pt_ringt+ct`。

+ 参数
  + `x`：输入数据节点。
  + `y`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 sub

```Python
def sub(
    x: BfvCiphertextNode | CkksCiphertextNode,
    y: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | CkksCiphertextNode | CkksPlaintextNode,
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode
```

定义一个减法计算步骤。支持类型包括`ct-ct, ct-pt, ct-pt_ringt`。

+ 参数
  + `x`：输入数据节点。
  + `y`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 neg

```Python
def neg(x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode | CkksCiphertextNode
```

定义一个取负计算步骤。

+ 参数
  + `x`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 mult

```Python
def mult(
    x: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | BfvPlaintextMulNode | CkksCiphertextNode | CkksPlaintextNode | CkksPlaintextRingtNode | CkksPlaintextMulNode,
    y: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | BfvPlaintextMulNode | CkksCiphertextNode | CkksPlaintextNode | CkksPlaintextRingtNode | CkksPlaintextMulNode,
    output_id: Optional[str] = None,
    start_block_idx: int = None,
) -> BfvCiphertextNode | BfvCiphertext3Node | CkksCiphertextNode | CkksCiphertext3Node
```

定义一个乘法计算步骤。支持类型包括`ct * ct, ct * pt_ringt, pt_ringt * ct, ct * pt_mul, pt_mul * ct`。

+ 参数
  + `x`：输入数据节点。
  + `y`：输入数据节点。
  + `output_id`： 结果数据节点的id。
  + `start_block_idx`：压缩明文起始块索引（可选）。

+ 返回值：结果数据节点。

### 函数 relin

```Python
def relin(x: BfvCiphertext3Node | CkksCiphertext3Node, output_id: Optional[str] = None) -> BfvCiphertextNode | CkksCiphertextNode
```

定义一个重线性化计算步骤。支持类型包括`ct3`。

+ 参数
  + `x`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 mult_relin

```Python
def mult_relin(x: BfvCiphertextNode | CkksCiphertextNode, y: BfvCiphertextNode | CkksCiphertextNode, output_id=None) -> BfvCiphertextNode | CkksCiphertextNode
```

定义一个密文乘法并重线性化计算步骤。

+ 参数
  + `x`：输入数据节点。
  + `y`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 rescale

```Python
def rescale(x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode | CkksCiphertextNode
```

定义一个模数切换计算步骤。

+ 参数
  + `x`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 drop_level

```Python
def drop_level(x: CkksCiphertextNode, drop_level: int, output_id: Optional[str] = None) -> CkksCiphertextNode
```

定义一个level切换计算步骤。

+ 参数
  + `x`：输入数据节点。
  + `drop_level`：需要减少的level数量。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 rotate_cols

```Python
def rotate_cols(
    x: BfvCiphertextNode | CkksCiphertextNode,
    steps: list[int] | int,
    output_id: Optional[str] = None,
) -> list[BfvCiphertextNode | CkksCiphertextNode]
```

定义一个密文列旋转计算步骤。

+ 参数
  + `x`：输入数据节点。
  + `steps`：旋转的步数（正数为左旋, 负数为右旋）。
  + `output_id`： 结果数据节点的id。
  
+ 返回值：结果数据节点列表。

### 函数 advanced_rotate_cols

```Python
def advanced_rotate_cols(
    x: BfvCiphertextNode | CkksCiphertextNode,
    steps: list[int] | int,
    output_id: Optional[str] = None,
    out_ct_type: str = 'ct',
) -> list[BfvCiphertextNode | CkksCiphertextNode]
```

在准备好旋转步数所对应的旋转公钥后，定义一个密文旋转计算步骤。

+ 参数
  + `x`：输入数据节点。
  + `steps`：旋转的步数（正数为左旋, 负数为右旋）。
  + `output_id`： 结果数据节点的id。
  + `out_ct_type`：输出密文的类型，支持的类型包括 'ct', 'ct-ntt', 'ct-ntt-mf'。
+ 返回值：结果数据节点列表。

### 函数 rotate_rows

```python
def rotate_rows(x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode | CkksCiphertextNode
```

定义一个密文行旋转计算步骤。

+ 参数
  + `x`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 ct_pt_mult_accumulate

```Python
def ct_pt_mult_accumulate(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextRingtNode | CkksPlaintextRingtNode] | BfvCompressedPlaintextRingtNode,
    output_mform: bool | None = None,
) -> BfvCiphertextNode | CkksCiphertextNode
```

定义一个明密文向量内积计算步骤, 在向量长度满足条件的前提下, 当优先使用以提升性能。

+ 参数
  + `x`：输入密文向量。
  + `y`：输入明文向量, 长度要求与密文向量相同，或压缩明文对象。
  + `output_mform`：输出是否为Montgomery形式（可选）。

+ 返回值：结果数据节点。

### 函数 ct_to_mul

```Python
def ct_to_mul(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode
```

将BFV密文转换为乘法形式（NTT + Montgomery形式）。

+ 参数
  + `x`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 ct_to_ntt

```Python
def ct_to_ntt(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode
```

将BFV密文转换为NTT形式。

+ 参数
  + `x`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 ct_to_mform

```Python
def ct_to_mform(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode
```

将BFV密文转换为Montgomery形式。

+ 参数
  + `x`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 ct_ntt_to_ct

```Python
def ct_ntt_to_ct(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode
```

将BFV NTT密文转换为普通形式。

+ 参数
  + `x`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 bootstrap

```Python
def bootstrap(x: CkksCiphertextNode, output_id: Optional[str] = None) -> CkksCiphertextNode
```

定义一个CKKS自举（bootstrapping）计算步骤。

+ 参数
  + `x`：输入数据节点。
  + `output_id`： 结果数据节点的id。

+ 返回值：结果数据节点。

### 函数 process_custom_task

```python
def process_custom_task(
    input_args: list[Argument] = None,
    output_args: list[Argument] = None,
    offline_input_args: list[Argument] = None,
    output_instruction_path: str = None,
    fpga_acc: bool = False,
) -> dict
```

编译自定义任务。根据自定义任务的输入和输出数据参数，把自定义任务编译转化成一系列任务所需文件。

**重要**：调用此函数之前，必须先调用 `set_fhe_param()` 设置全局FHE参数。

+ 参数
  + `input_args`：自定义任务的全部输入参数列表。
  + `output_args`：自定义任务的全部输出参数列表。
  + `offline_input_args`：自定义任务的全部预加载明文阶段输入参数列表，不包含输入数据节点。
  + `output_instruction_path`：自定义任务的任务文件/硬件指令存储目录。
  + `fpga_acc`：硬件加速任务标识。

+ 返回值：任务抽象计算图。

*示例*

```python
from custom_task import *

# 创建并设置全局参数
param = Param.create_bfv_custom_param(
    n=8192,
    p=[0x7ffffffffb4001],
    q=[0x3fffffffef8001, 0x4000000011c001, 0x40000000120001],
    t=0x28001
)
set_fhe_param(param)

# 定义计算图
level = 3
x = BfvCiphertextNode('x', level)
y = BfvCiphertextNode('y', level)
z = mult_relin(x, y, 'z')

# 编译任务
process_custom_task(
    input_args=[Argument('x', x), Argument('y', y)],
    output_args=[Argument('z', z)],
    output_instruction_path='examples/bfv_mult',
    fpga_acc=False,
)
```

## 应用程序接口-FHE算法库

FHE算法库提供用户在应用程序中使用的同态软件算法库，以及执行全同态密码算法相关操作的接口。

使用FHE算法库需要引入头文件：

```c++
#include "cxx_fhe_lib_v2.h"
```

### Handle 模板类

| Public 成员函数                                 |                  |
| :---------------------------------------------- | :--------------- |
| `Handle();`                                     | 默认构造函数     |
| `Handle(uint64_t&& h, bool k = false);`         | 带参构造函数     |
| `Handle(Handle&& other);`                       | 转移Handle对象   |
| `Handle(const Handle&) = delete;`               | 禁止复制         |
| `void operator=(Handle&& other);`               | 转移Handle对象   |
| `void operator=(const Handle& other) = delete;` | 禁止复制         |
| `virtual ~Handle();`                            | 析构函数         |
| `const uint64_t& get() const;`                  | 获取Handle内部值 |
| `bool is_empty() const;`                        | 判断是否为空     |

一个`Handle`对应了一部分内存资源，资源的分配和释放由SDK管理，所以`Handle`不能直接复制，可以使用`std::move()`转移`Handle`内部资源的所有权，也可以调用相应的API函数复制`Handle`对应的内容。

对于密文计算中的加密参数、context、明文、密文、私钥、公钥等对象，C++ SDK使用Handle模板类来统一管理各种对象的资源。基于Handle模板类，C++ SDK封装的Handle类型包括：

**参数和上下文类**：
 * `BfvParameter`：BFV同态参数，包含同态参数N、q、t。
 * `CkksParameter`：CKKS同态参数，包含同态参数N、q。
 * `CkksBtpParameter`：CKKS Bootstrap参数，继承自CkksParameter。
 * `BfvContext`：BFV同态上下文类，包含BFV公钥、私钥等信息。
 * `CkksContext`：CKKS同态上下文类，包含CKKS公钥、私钥等信息。
 * `CkksBtpContext`：CKKS Bootstrap上下文类，支持Bootstrap操作。

**明文类**：
 * `BfvPlaintext`：BFV明文，用于加密、解密、密文加明文。
 * `BfvPlaintextRingt`：BFV环上明文，用于密文乘明文。
 * `BfvPlaintextMul`：BFV乘法明文，用于密文乘明文。
 * `CkksPlaintext`：CKKS明文，用于加密、解密、密文加明文。
 * `CkksPlaintextRingt`：CKKS环上明文，用于密文乘明文。
 * `CkksPlaintextMul`：CKKS乘法明文，用于密文乘明文。

**密文类**：
 * `BfvCiphertext`：BFV密文，包含两个多项式。
 * `BfvCiphertext3`：BFV密文，包含三个多项式。
 * `BfvCompressedCiphertext`：BFV压缩密文。
 * `CkksCiphertext`：CKKS密文，包含两个多项式。
 * `CkksCiphertext3`：CKKS密文，包含三个多项式。
 * `CkksCompressedCiphertext`：CKKS压缩密文。

**密钥类**：
 * `SecretKey`：私钥。
 * `PublicKey`：公钥。
 * `RelinKey`：重线性化公钥。
 * `GaloisKey`：旋转公钥。
 * `KeySwitchKey`：密钥转换公钥。

**分布式计算相关类**：
 * `DBfvContext`：分布式BFV上下文。
 * 多方计算上下文：`CkgContext`、`RkgContext`、`RtgContext`、`E2sContext`、`S2eContext`、`RefreshContext`、`RefreshAndPermuteContext`
 * 各种Share类：`PublicKeyShare`、`RelinKeyShare`、`GaloisKeyShare`、`AdditiveShare`等。

#### 构造函数 Handle

```c++
Handle();  // (1)
Handle(uint64_t&& h, bool k = false);  // (2)
Handle(Handle&& other);  // (3)
Handle(const Handle& other) = delete;  // (4)
```

(1) 创建一个空的`Handle`对象，不对应任何资源，后续可以把其它`Handle`对象的资源转移到这个`Handle`对象上。

- 参数：无。
- 返回值：创建的Handle。

(2) 根据C语言接口的id创建一个新的`Handle`对象，用于SDK内部。

(3) 移动构造函数，把输入的右值`Handle`对象的资源转移到新建`Handle`对象里。

- 参数
  - `other`：输入右值`Handle`对象。
- 返回值：创建的Handle。

*示例*

```c++
CkksCiphertext x2 = context.add(x0, x1);
CkksCiphertext x3(std::move(x2));
```

(4) 禁止拷贝构造函数。

#### 运算符 operator=

```c++
void operator=(Handle&& other);  // (1)
void operator=(const Handle& other) = delete;  // (2)
```

(1) 移动赋值运算符，把输入的右值Handle对象的资源转移到当前Handle对象里。

- 参数
  - `other`：输入右值`Handle`对象。

- 返回值：无。

*示例*

```c++
CkksCiphertext x2 = context.add(x0, x1);
CkksCiphertext x3 = std::move(x2);
```

（2） 禁止拷贝赋值运算符。

#### 析构函数 ~Handle

```c++
virtual ~Handle();
```

- 参数：无。
- 返回值：无。

#### 函数 is_empty

```c++
bool is_empty() const;
```

判断当前`Handle`对象的内容是否为空。

- 参数：无。
- 返回值：当前`Handle`对象的内容是否为空。

#### 函数 get

```c++
const uint64_t& get() const;
```

获得当前`Handle`对象的C语言接口id，用于SDK内部。

- 参数：无。
- 返回值：当前`Handle`对象的C语言接口id。

### BfvParameter类

BfvParameter为同态参数类，包含同态参数N、q、t。BfvParameter继承自Handle类。

#### 函数 create_parameter

```
static BfvParameter create_parameter(uint64_t N, uint64_t t);
```

指定N和t，创建一组BFV算法的同态参数。

- 参数
  - `N`: 多项式阶数N。
  - `t`: 明文模数t。
- 返回值：创建的同态参数对象。

#### 函数 copy

```c++
BfvParameter copy() const;
```

复制当前`BfvParameter`对象。

+ 参数：无。

+ 返回值：复制出的新`BfvParameter`对象。

#### 函数 print

```c++
void print() const;
```

打印BFV同态参数对象的参数值。

+ 参数：无。

+ 返回值：无。

#### 函数 get_q

```c++
uint64_t get_q(int index) const;
```

获取BFV同态参数的密文模数q的一个分量。

+ 参数
  + `index`: 需要的密文模数q分量的编号。

+ 返回值：密文模数q的分量值。

#### 函数 get_n

```c++
int get_n() const;
```

获取一组同态参数里的多项式阶数N。

+ 参数：无。

+ 返回值：多项式阶数N。

#### 函数 get_t

```c++
uint64_t get_t() const;
```

获取一组同态参数里的明文模T。

+ 参数：无。

+ 返回值：明文模T。

#### 函数 get_max_level

```c++
int get_max_level() const;
```

获取一组BFV同态参数的最高明文、密文level。

+ 参数：无。

+ 返回值：最高明文、密文level。

#### 函数 create_custom_parameter

```c++
static BfvParameter create_custom_parameter(uint64_t N, uint64_t t, 
                                            const std::vector<uint64_t>& Q, 
                                            const std::vector<uint64_t>& P);
```

创建一组完全自定义的BFV算法同态参数。该函数允许用户指定所有参数，包括多项式度数、明文模数以及密文模数数组。

+ 参数
  + `N`：多项式阶数，必须是2的幂次。
  + `t`：明文模数，用于定义明文空间。
  + `Q`：密文模数的各个分量组成的向量。
  + `P`：扩展密文模数的各个分量组成的向量。

+ 返回值：创建的同态参数对象。

+ 注意事项
  + 参数配置需要与自定义计算任务的 mega_ag.json 文件中的参数保持一致。

#### 函数 set_parameter

```c++
static BfvParameter set_parameter(uint64_t N, uint64_t t, const std::vector<uint64_t>& Q, const std::vector<uint64_t>& P);
```

使用指定的N、t、密文模数Q和扩展模数P创建BFV同态参数。

+ 参数
  + `N`: 多项式阶数N。
  + `t`: 明文模数t。
  + `Q`: 密文模数的各个分量。
  + `P`: 扩展密文模数的各个分量。

+ 返回值：创建的同态参数对象。

#### 函数 get_p

```c++
uint64_t get_p(int index) const;
```

获取BFV同态参数的扩展密文模数P的一个分量。

+ 参数
  + `index`: 需要的扩展密文模数P分量的编号。

+ 返回值：扩展密文模数P的分量值。

#### 函数 get_q_count

```c++
int get_q_count() const;
```

获取BFV同态参数的密文模数Q的分量个数。

+ 参数：无。

+ 返回值：密文模数Q的分量个数。

#### 函数 get_p_count

```c++
int get_p_count() const;
```

获取BFV同态参数的扩展密文模数P的分量个数。

+ 参数：无。

+ 返回值：扩展密文模数P的分量个数。

### CkksParameter类

用于管理CKKS算法同态参数对象，内部存储同态参数N和密文模数的各个分量。CkksParameter继承自Handle类。

#### 函数 create_parameter

```
static CkksParameter create_parameter(uint64_t N);
```

指定N，创建一组CKKS算法的同态参数。

- 参数
  - `N`: 多项式阶数N。
- 返回值：创建的同态参数对象。

#### 函数 print

```c++
void print() const;
```

打印CKKS同态参数`Handle`对象的参数值。

+ 返回值：无。

#### 函数 get_q

```c++
uint64_t get_q(int index) const;
```

获取CKKS同态参数的密文模数q的一个分量。

+ 参数
  + `index`: 需要的密文模数q分量的编号。

+ 返回值：密文模数q的分量值。

#### 函数 get_n

```c++
int get_n() const;
```

获取一组同态参数里的多项式阶数N。

+ 返回值：多项式阶数N。

#### 函数 get_max_level

```c++
int get_max_level() const;
```

获取一组CKKS同态参数的最高明文、密文level。

+ 参数：无。

+ 返回值：最高明文、密文level。

#### 函数 create_custom_parameter

```c++
static CkksParameter create_custom_parameter(uint64_t N, 
                                             const std::vector<uint64_t>& Q, 
                                             const std::vector<uint64_t>& P);
```

创建一组完全自定义的CKKS算法同态参数。该函数允许用户指定所有参数细节，包括多项式度数以及密文模数数组。

+ 参数
  + `N`：多项式阶数，必须是2的幂次。
  + `Q`：密文模数的各个分量组成的向量。
  + `P`：扩展密文模数的各个分量组成的向量。

+ 返回值：创建的同态参数对象。

#### 函数 copy

```c++
CkksParameter copy() const;
```

复制当前`CkksParameter`对象。

+ 参数：无。

+ 返回值：复制出的新`CkksParameter`对象。

#### 函数 get_p_count

```c++
int get_p_count() const;
```

获取CKKS同态参数的扩展密文模数P的分量个数。

+ 参数：无。

+ 返回值：扩展密文模数P的分量个数。

#### 函数 get_p

```c++
uint64_t get_p(int index) const;
```

获取CKKS同态参数的扩展密文模数P的一个分量。

+ 参数
  + `index`: 需要的扩展密文模数P分量的编号。

+ 返回值：扩展密文模数P的分量值。

#### 函数 get_default_scale

```c++
double get_default_scale() const;
```

获取CKKS同态参数对应的默认scale。默认scale取值为最接近$q_1$的2的整数幂次值。

- 参数：无。
- 返回值：默认scale。


### CkksBtpParameter类

用于管理CKKS Bootstrap算法同态参数对象，包含CKKS基本参数和Bootstrap相关参数。CkksBtpParameter继承自CkksParameter类。

#### 函数 create_parameter

```c++
static CkksBtpParameter create_parameter();
```

创建CKKS Bootstrap同态参数。该参数包含Bootstrap算法所需的所有配置信息。

+ 参数：无。

+ 返回值：创建的CKKS Bootstrap参数对象。

#### 函数 create_toy_parameter

```c++
static CkksBtpParameter create_toy_parameter();
```

创建用于测试的CKKS Bootstrap同态参数。该函数创建一组较小规模的Bootstrap参数，适用于开发测试场景。

+ 参数：无。

+ 返回值：创建的CKKS Bootstrap测试参数对象。

+ 注意事项
  + 该参数配置对应于 Python 端的 `create_ckks_toy_btp_param` 方法。
  + 多项式度数 N=8192，相比标准 Bootstrap 参数（N=65536）更小，适合快速测试。
  + 包含预定义的 Q 和 P 模数数组配置。

#### 函数 get_ckks_parameter

```c++
CkksParameter& get_ckks_parameter();
```

获取CkksBtpParameter中包含的基础CkksParameter对象的引用。

+ 参数：无。

+ 返回值：CkksParameter对象的引用。


### BfvPlaintext类

 BFV明文类，用于加密、解密、密文加明文。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个BFV密文的level。

+ 返回值：密文level值。

#### 函数 print

```c++
void print() const;
```

打印一个BFV明文对象的值。

### BfvPlaintextRingt类

 BFV明文类，用于密文乘明文。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个BFV密文的level。

+ 返回值：密文level值。

### BfvPlaintextMul类

 BFV明文类，用于密文乘明文。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个BFV密文的level。

+ 返回值：密文level值。

### BfvCiphertext类

BFV密文类，包含2个多项式。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个BFV密文的level。

+ 参数：无。
+ 返回值：密文level值。

#### 函数 get_coeff

```c++
uint64_t get_coeff(int poly_idx, int rns_idx, int coeff_idx) const;
```

获取当前BFV密文的一个系数的值。

- 参数
  - `poly_idx`：系数在BFV密文中的多项式编号。
  - `rns_idx`：系数在多项式中的RNS分量编号。
  - `coeff_idx`：系数在RNS分量中的系数编号。
- 返回值：BFV密文里指定系数的值。

#### 函数 serialize

```c++
std::vector<uint8_t> serialize(const BfvParameter& param) const;
```

序列化一个BFV密文。
+ 参数
  + `param`：BFV同态参数。
+ 返回值：序列化后的字节数组。

#### 函数 deserialize

```
static BfvCiphertext deserialize(const std::vector<uint8_t>& data);
```

反序列化一个BFV密文。

+ 参数
  + `data`：二进制字节数组。

- 返回值：反序列化后的`BfvCiphertext`对象。

#### 函数 copy

```c++
BfvCiphertext copy() const;
```

复制一个BFV密文。

+ 返回值：创建的密文对象。

#### 函数 print

```c++
void print() const;
```

打印一个BFV密文对象的值。

+ 返回值：无。

### BfvCiphertext3类

BFV密文类，包含3个多项式。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个BFV密文的level。

+ 返回值：密文level值。

### BfvCompressedCiphertext类

BFV压缩密文类，通过对称加密获得，密文大小为BfvCiphertext的一半。

#### 函数 serialize

```c++
std::vector<uint8_t> serialize(const BfvParameter& param) const;
```

序列化一个BFV压缩密文。

+ 参数
  + `param`: BFV同态参数。

+ 返回值：序列化后的字节数组。
  
#### 函数 deserialize

```c++
static BfvCompressedCiphertext deserialize(const std::vector<uint8_t>& data);
```

反序列化一个BFV压缩密文。

+ 参数
  + `data`: `BfvCompressedCiphertext`对象序列化后的字节数组。

+ 返回值：反序列化后的`BfvCompressedCiphertext`对象。

### CkksPlaintext类

 CKKS明文类，用于加密、解密、密文加明文。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个CKKS密文的level。

+ 返回值：密文level值。

### CkksPlaintextMul类

 CKKS明文类，用于密文乘明文。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个CKKS密文的level。

+ 返回值：密文level值。

### CkksPlaintextRingt类

 CKKS明文类，用于密文乘明文。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个CKKS密文的level。

+ 返回值：密文level值。

### CkksCiphertext类

CKKS密文类，包含2个多项式。

#### 函数 serialize

```c++
std::vector<uint8_t> serialize(const CkksParameter& param) const;
```

序列化一个CKKS密文。

+ 参数：
  + param：CKKS参数对象。

+ 返回值：序列化后的字节数组。

#### 函数 deserialize

```
static CkksCiphertext deserialize(const std::vector<uint8_t>& data);
```

反序列化一个CKKS密文。

+ 参数：
  + `data`：二进制字节数组。

- 返回值：反序列化后的`CkksCiphertext`对象。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个CKKS密文的level。

+ 返回值：密文level。

#### 函数 get_scale

```c++
double get_scale() const;
```

获取一个CKKS密文的scale。

+ 返回值：密文的scale。

#### 函数 copy

```c++
CkksCiphertext copy() const;
```

复制一个CKKS密文。

+ 返回值：创建的密文对象。

#### 函数 print

```c++
void print() const;
```

打印一个CKKS密文对象的值。

+ 返回值：无。

### CkksCiphertext3类

CKKS密文类，包含3个多项式。

#### 函数 get_level

```c++
int get_level() const;
```

获取一个CKKS密文的level。

+ 返回值：密文level值。

#### 函数 copy_to

```c++
void copy_to(const CkksCiphertext3& y_ct) const;
```

把当前对象复制到指定`CkksCiphertext3`对象。

- 参数：
  - `y_ct`: 复制的目的对象。
- 返回值：无。

### CkksCompressedCiphertext类

CKKS压缩密文类，通过对称加密获得，密文大小为CkksCiphertext的一半。

#### 函数 serialize

```c++
std::vector<uint8_t> serialize(const CkksParameter& param) const;
```

序列化当前CKKS压缩密文。

+ 参数：
  + `param`: CKKS同态参数。

+ 返回值：序列化后的字节数组。
  
#### 函数 deserialize

```c++
static CkksCompressedCiphertext deserialize(const std::vector<uint8_t>& data);
```

反序列化一个CKKS压缩密文。

+ 参数：
  + `data`: 一个`CkksCompressedCiphertext`对象序列化后的字节数组。

+ 返回值：反序列化后的`CkksCompressedCiphertext`对象。

### SecretKey类

`SecretKey`包含一个同态的私钥，用于在不同的`FheContext`对象之间传递私钥信息。

### PublicKey

`PublicKey`包含一个同态的加密公钥，用于在不同的`FheContext`对象之间传递加密公钥信息。

### RelinKey

`RelinKey`包含一个同态的重线性化公钥，用于在不同的`FheContext`对象之间传递重线性化公钥信息。

### GaloisKey

`GaloisKey`包含一组同态的旋转公钥，用于在不同的`FheContext`对象之间传递旋转公钥信息。

### FheContext类

`FheContext`是同态上下文类。包含公钥、私钥等信息。具体使用时，应当使用其子类`BfvContext`和`CkksContext`。

#### 函数 extract_secret_key

```c++
virtual SecretKey extract_secret_key() const = 0;
```

从输入context里提取私钥，形成一个独立的私钥变量。

+ 参数：无。

- 返回值：私钥对象。

#### 函数 extract_public_key

```c++
virtual PublicKey extract_public_key() const = 0;
```

从输入context里提取公钥，形成一个独立的公钥变量。

+ 参数：无。

- 返回值：公钥对象。

#### 函数 extract_relin_key

```c++
virtual RelinKey extract_relin_key() const = 0;
```

从输入context里提取BFV重线性化公钥，形成一个独立的重线性化公钥变量。

- 参数：无。
- 返回值：重线性化公钥对象。

#### 函数 extract_galois_key

```c++
virtual GaloisKey extract_galois_key() const = 0;
```

从输入context里提取BFV旋转公钥，形成一个独立的旋转公钥变量。

- 参数：无。
- 返回值：旋转公钥对象。

#### 函数 resize_copies

在多线程计算里，每个线程需要使用一个context的拷贝，`FheContext`可以存储这些context的拷贝，在多次多线程计算之间复用。函数`resize_copies`用于指定在当前`FheContext`对象里，context拷贝的最大份数。

```c++
void resize_copies(int n);
```

- 参数
  - `n`：当前`FheContext`对象里context拷贝的最大份数。
- 返回值：无。

#### 函数 get_copy

```c++
virtual FheContext& get_copy(int index) = 0;
```

在多线程计算里，每个线程需要使用一个context的拷贝，`FheContext`可以存储这些context的拷贝，在多次多线程计算之间复用。函数`get_copy`用于获得一个当前`FheContext`对象的拷贝。

- 参数
  - `index`：需要的context拷贝的编号。
- 返回值：当前`FheContext`对象的一个拷贝。

### BfvContext类

`BfvContext`类继承`FheContext`类，拥有`FheContext`类的全部方法，此处不再赘述。

#### 函数 create_random_context

```c++
static BfvContext create_random_context(const BfvParameter& param, int level = MAX_LEVEL);
```

创建一个新的BfvContext，随机生成里面的私钥、加密公钥、重线性化公钥。

- 参数：
  - `param`：同态参数。
  - `level`：能够处理的最大密文level，默认值是输入同态参数对应的最大密文level。
- 返回值：创建的context。

#### 函数 create_empty_context

```c++
static BfvContext create_empty_context(const BfvParameter& param);
```

创建一个空的BfvContext，里面的私钥、加密公钥、重线性化公钥、旋转公钥都是空值。

+ 参数：
  + `param`： 同态参数。

+ 返回值：创建的context。

#### 函数 gen_rotation_keys

```c++
void gen_rotation_keys(int level = MAX_LEVEL);
```

在 context 中生成标准的旋转公钥集，包括行旋转对应的旋转公钥，和列旋转步数形式为$\pm 2^i$的旋转公钥。

- 参数：
  - `level`：能够处理的最大密文level，默认值是输入同态参数对应的最大密文level。
- 返回值：无。

#### 函数 gen_rotation_keys_for_rotations

```c++
void gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows = false, int level = MAX_LEVEL);
```

在 context 中生成指定的旋转公钥。

+ 参数：
  + `rots`：列旋转的步数。
  + `include_swap_rows`：是否需要行旋转。
  + `level`：能够处理的最大密文level，默认值是输入同态参数对应的最大密文level。

+ 返回值：无。

#### 函数 make_public_context

```c++
BfvContext make_public_context(bool include_pk = true, bool include_rlk = true, bool include_gk = true) const;
```

在请求方一侧，源context包含公钥和私钥，由于私钥不能发送给计算方，请求方需要通过源context对象调用此方法生成子context，生成的子context不包含源context中的私钥信息，可选择性地包含与源context相同的加密公钥、重线性化公钥、旋转公钥。

- 参数：
  - `include_pk`：是否包含加密公钥，默认为true。
  - `include_rlk`：是否包含重线性化公钥，默认为true。
  - `include_gk`：是否包含旋转公钥，默认为true。
- 返回值：子context。

#### 函数 shallow_copy_context

```c++
BfvContext shallow_copy_context() const;
```

浅复制一个BfvContext。在多线程需要并行使用同一个context时，需要把context浅复制，分别传给不同的线程使用。

+ 参数：无。

+ 返回值：复制结果context。

#### 函数 get_parameter

```c++
const BfvParameter& get_parameter();
```

获取context对应的同态参数。

+ 参数：无。

- 返回值：同态参数。

#### 函数 serialize

```c++
std::vector<uint8_t> serialize() const;
```

把BfvContext序列化成字节数组。

+ 参数：无。

+ 返回值：序列化后的字节数组。

#### 函数 deserialize

```c++
static BfvContext deserialize(const std::vector<uint8_t>& data);
```

把字节数组反序列化成BfvContext。

+ 参数：
  + `data`：字节数组的首地址指针。

+ 返回值：反序列化后的BfvContext。

#### 函数 serialize_advanced

```c++
std::vector<uint8_t> serialize_advanced() const;
```

把BfvContext使用高级压缩方式序列化成字节数组，序列化密文应当优先使用此方法。

+ 参数：无。

+ 返回值：序列化后的字节数组。

#### 函数 deserialize_advanced

```c++
static BfvContext deserialize_advanced(const std::vector<uint8_t>& data);
```

把高级压缩格式的字节数组反序列化成BfvContext，反序列化密文应当优先使用此方法。。

+ 参数：
  + `data`：字节数组。

+ 返回值：反序列化后的BfvContext。

#### 函数 generate_public_keys

```c++
void generate_public_keys(int level = MAX_LEVEL);
```

在context中生成公钥相关信息。

+ 参数：
  + `level`：生成的公钥能够处理的最大密文level，默认值是输入同态参数对应的最大密文level。

+ 返回值：无。

#### 函数 set_context_secret_key

```c++
void set_context_secret_key(const SecretKey& sk);
```

把一个私钥配置给一个context。

+ 参数：
  + `sk`：源加密私钥。

+ 返回值：无。

#### 函数 set_context_public_key

```c++
void set_context_public_key(const PublicKey& pk);
```

把一个公钥配置给一个context。

+ 参数：
  + `pk`：源加密公钥。

+ 返回值：无。

#### 函数 set_context_relin_key

```c++
void set_context_relin_key(const RelinKey& rlk);
```

把一个重线性化公钥配置给一个context。

+ 参数：
  + `rlk`：源重线性化公钥。

+ 返回值：无。

#### 函数 set_context_galois_key

```c++
void set_context_galois_key(const GaloisKey& gk);
```

把一个旋转公钥配置给一个context。

+ 参数：
  + `gk`：源旋转公钥。

+ 返回值：无。

#### 函数 encode

```c++
BfvPlaintext encode(const std::vector<uint64_t>& x_mg, int level);
```

把一个消息数据编码成BFV明文，消息数据是一个数组，每个元素表示一个原始消息。

+ 参数：
  + `x_mg`：输入消息数据。

  + `level`：输出明文的level。

+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_ringt

```c++
BfvPlaintextRingt encode_ringt(const std::vector<uint64_t>& x_mg);
```

把一个消息数据编码成用于乘法的环t上的BFV明文。

+ 参数：
  + `x_mg`：输入消息数据。
+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_mul

```c++
BfvPlaintextMul encode_mul(const std::vector<uint64_t>& x_mg, int level);
```

把一个消息数据编码成用于乘法的BFV明文。

+ 参数：
  + `x_mg`：输入消息数据。

  + `level`：输出明文的level。

+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_coeffs

```c++
BfvPlaintext encode_coeffs(const std::vector<uint64_t>& x_mg, int level);
```

把一个整数数组编码成BFV明文，数组元素直接嵌入到明文多项式系数中，不支持点对点乘法。

+ 参数：
  + `x_mg`：输入整数数组。

  + `level`：输出明文的level。

+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_coeffs_ringt

```c++
BfvPlaintextRingt encode_coeffs_ringt(const std::vector<uint64_t>& x_mg);
```

把一个整数数组编码成用于乘法的环t上的BFV明文，数组元素直接嵌入到明文多项式系数中，不支持点对点乘法。

+ 参数：
  + `x_mg`：输入整数数组。
+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_coeffs_mul

```c++
BfvPlaintextMul encode_coeffs_mul(const std::vector<uint64_t>& x_mg, int level);
```

把一个整数数组编码成用于乘法的BFV明文，数组分量直接嵌入到明文多项式系数中，不支持点对点乘法。

+ 参数：
  + `x_mg`：输入整数数组。

  + `level`：输出明文的level。

+ 返回值：编码后的用于乘法的明文。

#### 函数 decode

```c++
std::vector<uint64_t> decode(const BfvPlaintext& x_pt);
```

把一个BFV明文解码成消息数据。

+ 参数：
  + `x_pt`：输入明文。
+ 返回值：解码后的消息数据。

#### 函数 decode_coeffs

```c++
std::vector<uint64_t> decode_coeffs(const BfvPlaintext& x_pt);
```

把一个BFV明文解码成整数数组。

+ 参数：
  + `x_pt`：输入明文。
+ 返回值：解码后的整数数组。

#### 函数 new_ciphertext

```c++
BfvCiphertext new_ciphertext(int level);
```

新建一个密文，根据输入参数为新建密文分配空间。

+ 参数：
  + `level`：新建密文的level。

+ 返回值：创建的密文。

#### 函数 encrypt_asymmetric

```c++
BfvCiphertext encrypt_asymmetric(const BfvPlaintext& x_pt);
```

使用加密公钥加密一个BFV明文。

+ 参数：
  + `x_pt`：输入明文。
+ 返回值：加密后的密文。

#### 函数 encrypt_symmetric

```c++
BfvCiphertext encrypt_symmetric(const BfvPlaintext& x_pt);
```

使用私钥加密一个BFV明文。

+ 参数：
  + `x_pt`：输入明文。

+ 返回值：加密后的密文。

#### 函数 encrypt_symmetric_compressed

```c++
BfvCompressedCiphertext encrypt_symmetric_compressed(const BfvPlaintext& x_pt);
```

使用私钥加密一个BFV明文并压缩。

+ 参数：
  + `x_pt`：输入明文。

+ 返回值：加密后的压缩密文，是BfvCiphertext的一半大小。

#### 函数 decrypt

```c++
BfvPlaintext decrypt(const BfvCiphertext& x_ct);
```
使用解密私钥解密一个BFV密文。

+ 参数：
  + `x_ct`：输入密文。

+ 返回值：解密后的明文。

#### 函数 decrypt

```c++
BfvPlaintext decrypt(const BfvCiphertext3& x_ct);
```

使用解密私钥解密一个多项式个数为3的BFV密文。

+ 参数：
  + `x_ct`：输入密文。

+ 返回值：解密后的明文。

#### 函数 add

```c++
BfvCiphertext add(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);  // (1)
BfvCiphertext3 add(const BfvCiphertext3& x0_ct, const BfvCiphertext3& x1_ct);  // (2)
```

(1) 计算`BfvCiphertext`密文加`BfvCiphertext`密文。

+ 参数：
  + `x0_ct`：输入密文。
  + `x1_ct`：输入密文。
+ 返回值：加法结果密文。

(2) 计算`BfvCiphertext3`密文加`BfvCiphertext3`密文。

+ 参数：
  + `x0_ct`：输入密文。
  + `x1_ct`：输入密文。
+ 返回值：加法结果密文。

#### 函数 add_inplace

```c++
void add_inplace(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);
```

计算密文加密文，结果存在一个输入密文的空间上。

+ 参数：
  + `x0_ct`：输入密文，也是输出结果密文。  
  + `x1_ct`：输入密文。
+ 返回值：无。

#### 函数 add_plain

```c++
BfvCiphertext add_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);
```

计算密文加明文。

+ 参数：
  + `x0_ct`：输入密文。
  + `x1_ct`：输入密文。
+ 返回值：加法结果的密文。

#### 函数 add_plain_inplace

```c++
void add_plain_inplace(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);
```

计算密文加明文，结果覆盖输入密文 x0。

+ 参数：
  + `x0_ct`：输入密文。
  + `x1_ct`：输入密文。
+ 返回值：无。

#### 函数 sub

```c++
BfvCiphertext sub(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);
```

计算密文减密文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_ct`：输入密文。

+ 返回值：减法结果密文。

#### 函数 mult

```c++
BfvCiphertext3 mult(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);
```

计算密文乘密文，得到一个3个多项式的密文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_ct`：输入密文。

+ 返回值：乘法结果的密文。

#### 函数 mult_plain

```c++
BfvCiphertext mult_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);
```

计算密文乘明文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_pt`：输入明文。
+ 返回值：乘法结果的密文。

#### 函数 mult_plain_ringt

```c++
BfvCiphertext mult_plain_ringt(const BfvCiphertext& x0_ct, const BfvPlaintextRingt& x1_pt);
```

计算密文乘明文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_pt`：输入明文。

+ 返回值：乘法结果的密文。

#### 函数 mult_scalar

```c++
BfvCiphertext mult_scalar(const BfvCiphertext& x0_ct, const int64_t x1_value);
```

计算密文乘常数。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_value`：输入常数值。

+ 返回值：乘法结果的密文。

#### 函数 mult_plain_mul

```c++
BfvCiphertext mult_plain_mul(const BfvCiphertext& x0_ct, const BfvPlaintextMul& x1_pt);
```

计算密文乘明文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_pt`：输入明文。

+ 返回值：乘法结果的密文。

#### 函数 ringt_to_mul

```c++
BfvPlaintextMul ringt_to_mul(const BfvPlaintextRingt& x_pt, int level);
```

环t上的乘法明文转换成普通乘法明文。

+ 参数：
  + `x_pt`：输入环t上的明文。
  + `level`：明文的level。
+ 返回值：普通乘法明文。

#### 函数 compressed_ciphertext_to_ciphertext

```c++
BfvCiphertext compressed_ciphertext_to_ciphertext(const BfvCompressedCiphertext& x_ct);
```

压缩的BFV密文转换成普通密文。

+ 参数：
  + `x_ct`：压缩的BFV密文。

+ 返回值：普通BFV密文。

#### 函数 relinearize

```c++
BfvCiphertext relinearize(const BfvCiphertext3& x_ct);
```

计算密文重线性化。

+ 参数：
  + `x_ct`：输入密文。

+ 返回值：重线性化结果的密文。

#### 函数 rescale

```c++
BfvCiphertext rescale(const BfvCiphertext& x_ct);
```

对BFV密文做rescale，把密文模数减少一个分量。

+ 参数：
  + `x_ct`：输入密文。

+ 返回值：rescale结果的密文。


#### 函数 rotate_rows

```c++
BfvCiphertext rotate_rows(const BfvCiphertext& x_ct);
```

对输入密文做行旋转操作。

+ 参数：
  + `x_ct`：输入密文。

+ 返回值：旋转结果的密文。


#### 函数 rotate_cols

```c++
BfvCiphertext rotate_cols(const BfvCiphertext& x_ct, int32_t step);  // (1)
std::map<int32_t, BfvCiphertext> rotate_cols(const BfvCiphertext& x_ct, const std::vector<int32_t>& steps);  // (2)
```

对输入密文做密文列旋转操作。

(1) 输入一个旋转步数，输出一个结果密文。

+ 参数：
  - `x_ct`：输入密文。

  - `step`：旋转步数。

+ 返回值：单步旋转结果的密文。

(2) 输入多个旋转步数，输出多个结果密文。

+ 参数：
  - `x_ct`：输入密文。

  - `steps`：各个旋转步数构成的`vector`。

+ 返回值：输出多个结果密文构成的`map`，旋转步数为map的key，对应的结果密文为map的value。

本函数所使用的旋转公钥需要提前用BfvContext::gen_rotation_keys()函数生成。对于每一个指定的旋转步数，本函数内部会将这个旋转步数写成NAF形式，拆分成一个或多个基本的旋转操作。所以，本函数实际执行的基本旋转操作个数依赖于输入的旋转步数个数和它们的值。


#### 函数 advanced_rotate_cols

```c++
BfvCiphertext advanced_rotate_cols(const BfvCiphertext& x_ct, int32_t step);  // (1)
std::map<int32_t, BfvCiphertext> advanced_rotate_cols(const BfvCiphertext& x_ct, const std::vector<int32_t>& steps);  // (2)
```

对输入密文做密文旋转操作。

(1) 输入一个旋转步数，输出一个结果密文。

+ 参数：
  - `x_ct`：输入密文。
  - `step`：旋转步数。
+ 返回值：单步旋转结果的密文。

(2) 输入多个旋转步数，输出多个结果密文。

- 参数：
  - `x_ct`：输入密文。
  - `steps`：各个旋转步数构成的`vector`。
- 返回值：输出多个结果密文构成的`map`，旋转步数为map的key，对应的结果密文为map的value。

本函数所使用的旋转公钥需要提前用BfvContext::gen_rotation_keys_for_rotations()函数生成。对于每一个指定的旋转步数，本函数会使用准备好的对应的旋转公钥，如果这个旋转公钥不存在，本函数会报错。如果各个旋转公钥都存在，本函数执行hoisted rotation，输出一个或多个结果密文。


#### 函数 plaintext_to_plaintext_ringt

```c++
BfvPlaintextRingt plaintext_to_plaintext_ringt(const BfvPlaintext& x_pt);
```

将一个BFV明文转换成环t上的BFV明文。

+ 参数：
  + `x_pt`：输入明文。

+ 返回值：环t上的明文。

### CkksContext类

`CkksContext`类继承`FheContext`类，拥有`FheContext`类的全部方法，此处不再赘述。

#### 函数 create_empty_context

```c++
static CkksContext create_empty_context(const CkksParameter& param);
```

创建一个空的CkksContext，里面的私钥、加密公钥、重线性化公钥、旋转公钥都是空值。

- 参数：
  - `param`： 同态参数。
- 返回值：创建的context。

#### 函数 create_random_context

```c++
static CkksContext create_random_context(const CkksParameter& param);
```

创建一个新的CkksContext，随机生成里面的私钥、加密公钥、重线性化公钥。

+ 参数：
  + `param`： 同态参数对象。

+ 返回值：创建的CkksContext。

#### 函数 gen_rotation_keys

```c++
void gen_rotation_keys();
```

在 context 中生成标准的旋转公钥集，包括共轭操作对应的旋转公钥，和旋转步数形式为$\pm 2^i$的旋转公钥。


#### 函数 gen_rotation_keys_for_rotations

```c++
void gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows = false, int level = MAX_LEVEL);
```

在 context 中生成指定的旋转公钥。

+ 参数：
  + `rots`：旋转的步数。
  + `include_swap_rows`：是否需要行交换对应的旋转公钥。
  + `level`：生成的旋转公钥的level，默认值为当前同态参数对应的最大level。


#### 函数 make_public_context

```c++
CkksContext make_public_context();
```

在多线程场景下，每个线程需要自己的context，通过源context对象调用此方法生成，生成的新context不包含源context中的私钥信息，与源context有相同的加密公钥、重线性化公钥、旋转公钥。

+ 参数：无。

+ 返回值：不包含私钥信息的context。

#### 函数 get_parameter

```c++
virtual const CkksParameter& get_parameter();
```

获取context对应的同态参数。

+ 参数：无。

- 返回值：同态参数。

#### 函数 serialize

```c++
std::vector<uint8_t> serialize() const;
```

把CkksContext序列化成字节数组。

+ 参数：无。

+ 返回值：序列化后的字节数组。

#### 函数 deserialize

```c++
static CkksContext deserialize(const std::vector<uint8_t>& data);
```

把字节数组反序列化成CkksContext。

+ 参数：
  + `data`：字节数组的首地址指针。

+ 返回值：反序列化后的CkksContext。

#### 函数 encode

```c++
CkksPlaintext encode(const std::vector<double>& x_mg, int level, double scale);
```

把一个消息数据编码成CKKS明文，消息数据是一个数组，每个元素表示一个原始消息。

+ 参数：
  + `x_mg`：输入消息数据。

  + `level`：输出明文的level。

  + `scale`：编码的scale。
+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_ringt

```c++
CkksPlaintextRingt encode_ringt(const std::vector<double>& x_mg, double scale);
```

把一个消息数据编码成用于乘法的环t上的CKKS明文。

+ 参数：
  + `x_mg`：输入消息数据。
  + `scale`：编码的scale。
+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_mul

```c++
CkksPlaintextMul encode_mul(const std::vector<double>& x_mg, int level, double scale);
```

把一个消息数据编码成用于乘法的CKKS明文。

+ 参数：
  + `x_mg`：输入消息数据。

  + `level`：输出明文的level。

  + `scale`：编码的scale。

+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_coeffs

```c++
CkksPlaintext encode_coeffs(const std::vector<double>& x_mg, int level, double scale);
```

把一个浮点数数组编码成CKKS明文，数组元素直接嵌入到明文多项式系数中，不支持点对点乘法。

+ 参数：
  + `x_mg`：输入浮点数数组。

  + `level`：输出明文的level。

  + `scale`：编码的scale。
+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_coeffs_ringt

```c++
CkksPlaintextRingt encode_coeffs_ringt(const std::vector<double>& x_mg, double scale);
```

把一个浮点数数组编码成用于乘法的环t上的CKKS明文，数组元素直接嵌入到明文多项式系数中，不支持点对点乘法。

+ 参数：
  + `x_mg`：输入浮点数数组。
  + `scale`：编码的scale。
+ 返回值：编码后的用于乘法的明文。

#### 函数 encode_coeffs_mul

```c++
CkksPlaintextMul encode_coeffs_mul(const std::vector<double>& x_mg, int level, double scale);
```

把一个浮点数数组编码成用于乘法的CKKS明文，数组分量直接嵌入到明文多项式系数中，不支持点对点乘法。

+ 参数：
  + `x_mg`：输入浮点数数组。

  + `level`：输出明文的level。

  + `scale`：编码的scale。

+ 返回值：编码后的用于乘法的明文。

#### 函数 decode

```c++
std::vector<double> decode(const CkksPlaintext& x_pt);
```

把一个CKKS明文解码成消息数据。

+ 参数：
  + `x_pt`：输入明文。
+ 返回值：解码后的消息数据。

#### 函数 decode_coeffs

```c++
std::vector<double> decode_coeffs(const CkksPlaintext& x_pt);
```

把一个CKKS明文解码成浮点数数组。

+ 参数：
  + `x_pt`：输入明文。
+ 返回值：解码后的浮点数数组。

#### 函数 new_ciphertext

```c++
CkksCiphertext new_ciphertext(int level, double scale);
```

新建一个密文，根据输入参数为新建密文分配空间。

+ 参数：
  + `level`：新建密文的level。

  + `scale`：编码的scale。

+ 返回值：创建的密文。

#### 函数 encrypt_asymmetric

```c++
CkksCiphertext encrypt_asymmetric(const CkksPlaintext& x_pt);
```

使用加密公钥加密一个CKKS明文。

+ 参数：
  + `x_pt`：输入明文。
+ 返回值：加密后的密文。

#### 函数 encrypt_symmetric

```c++
CkksCiphertext encrypt_symmetric(const CkksPlaintext& x_pt);
```

使用私钥加密一个CKKS明文。

+ 参数：
  + `x_pt`：输入明文。

+ 返回值：加密后的密文。

#### 函数 encrypt_symmetric_compressed

```c++
CkksCompressedCiphertext encrypt_symmetric_compressed(const CkksPlaintext& x_pt);
```

使用私钥加密一个CKKS明文并压缩。

+ 参数：
  + `x_pt`：输入明文。

+ 返回值：加密后的压缩密文，是CkksCiphertext的一半大小。


#### 函数 decrypt

```c++
CkksPlaintext decrypt(const CkksCiphertext& x_ct);
```

使用解密私钥解密一个CKKS密文。
```c++
CkksPlaintext decrypt(const CkksCiphertext3& x_ct);
```

使用解密私钥解密一个多项式个数为3的CKKS密文。

+ 参数：
  + `x_ct`：输入密文，其中密文的degree为1或2。

+ 返回值：解密后的明文。

#### 函数 add

```c++
CkksCiphertext add(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct);
```

计算密文加密文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_ct`：输入密文。

+ 返回值：加法结果的密文。

#### 函数 add_plain

```c++
CkksCiphertext add_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt);
```

计算密文加明文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_ct`：输入密文。

+ 返回值：加法结果的密文。

#### 函数 sub

```c++
CkksCiphertext sub(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct);
```

计算密文减密文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_ct`：输入密文。

+ 返回值：减法结果密文。

#### 函数 mult

```c++
CkksCiphertext3 mult(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct);
```

计算密文乘密文，得到一个3个多项式的密文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_ct`：输入密文。

+ 返回值：乘法结果的密文。

#### 函数 mult_plain

```c++
CkksCiphertext mult_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt);
```

计算密文乘明文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_pt`：输入明文。

+ 返回值：乘法结果的密文。

#### 函数 mult_plain_mul

```c++
CkksCiphertext mult_plain_mul(const CkksCiphertext& x0_ct, const CkksPlaintextMul& x1_pt);
```

计算密文乘明文。

+ 参数：
  + `x0_ct`：输入密文。

  + `x1_pt`：输入明文。

+ 返回值：乘法结果的密文。

#### 函数 ringt_to_mul

```c++
CkksPlaintextMul ringt_to_mul(const CkksPlaintextRingt& x_pt, int level);
```

环t上的乘法明文转换成普通乘法明文。

+ 参数：
  + `x_pt`：输入环t上的明文。
  + `level`：输出明文的level。
+ 返回值：`CkksPlaintextMul`格式的明文。

#### 函数 compressed_ciphertext_to_ciphertext

```c++
CkksCiphertext compressed_ciphertext_to_ciphertext(const CkksCompressedCiphertext& x_ct);
```

压缩的CKKS密文转换成普通密文。

+ 参数：
  + `x_ct`：压缩的CKKS密文。

+ 返回值：普通密文。

#### 函数 relinearize

```c++
CkksCiphertext relinearize(const CkksCiphertext3& x_ct);
```

计算密文重线性化。

+ 参数：
  + `x_ct`：输入密文。

+ 返回值：重线性化结果的密文。

#### 函数 drop_level

```c++
CkksCiphertext drop_level(const CkksCiphertext& x_ct);
```

把当前CKKS密文的level减1。

+ 参数：
  + `x_ct`：输入密文。

+ 返回值：level减1后的密文。

#### 函数 rescale

```c++
CkksCiphertext rescale(const CkksCiphertext& x_ct, double min_scale);
```

对CKKS密文做rescale，把密文模数减少一个分量。

+ 参数：
  + `x_ct`：输入密文。
  + `min_scale`：指定密文rescale后的最小scale值。

+ 返回值：rescale结果的密文。

#### 函数 conjugate

```c++
CkksCiphertext conjugate(const CkksCiphertext& x_ct);
```

对密文做共轭操作。

+ 参数：
  + `x_ct`：输入密文。

+ 返回值：输入的共轭密文。


#### 函数 rotate

```c++
CkksCiphertext rotate(const CkksCiphertext& x_ct, int32_t step);  // (1)
std::map<int32_t, CkksCiphertext> rotate(const CkksCiphertext& x_ct, const std::vector<int32_t>& steps);  // (2)
```

对输入密文做密文旋转操作。

(1) 输入一个旋转步数，输出一个结果密文。

+ 参数：
  - `x_ct`：输入密文。

  - `step`：旋转步数。

+ 返回值：单步旋转结果的密文。

(2) 输入多个旋转步数，输出多个结果密文。

+ 参数：
  - `x_ct`：输入密文。

  - `steps`：各个旋转步数构成的`vector`。

+ 返回值：输出多个结果密文构成的`map`，旋转步数为map的key，对应的结果密文为map的value。

本函数所使用的旋转公钥需要提前用CkksContext::gen_rotation_keys()函数生成。对于每一个指定的旋转步数，本函数内部会将这个旋转步数写成NAF形式，拆分成一个或多个基本的旋转操作。所以，本函数实际执行的基本旋转操作个数依赖于输入的旋转步数个数和它们的值。


#### 函数 advanced_rotate

```c++
CkksCiphertext advanced_rotate(const CkksCiphertext& x_ct, int32_t step);  // (1)
std::map<int32_t, CkksCiphertext> advanced_rotate(const CkksCiphertext& x_ct, const std::vector<int32_t>& steps);  // (2)
```

对输入密文做密文旋转操作。

(1) 输入一个旋转步数，输出一个结果密文。

+ 参数：
  - `x_ct`：输入密文。

  - `step`：旋转步数。

+ 返回值：单步旋转结果的密文。

(2) 输入多个旋转步数，输出多个结果密文。

+ 参数：
  - `x_ct`：输入密文。

  - `steps`：各个旋转步数构成的`vector`。

+ 返回值：输出多个结果密文构成的`map`，旋转步数为map的key，对应的结果密文为map的value。

本函数所使用的旋转公钥需要提前用CkksContext::gen_rotation_keys_for_rotations()函数生成。对于每一个指定的旋转步数，本函数会使用准备好的对应的旋转公钥，如果这个旋转公钥不存在，本函数会报错。如果各个旋转公钥都存在，本函数执行hoisted rotation，输出一个或多个结果密文。

### CkksBtpContext类

`CkksBtpContext`类继承`FheContext`类和`CkksContext`类，拥有`FheContext`类和`CkksContext`类的全部方法，此处不再赘述。

#### 函数 create_random_context

```c++
static CkksBtpContext create_random_context(const CkksBtpParameter& param);
```

创建一个新的CkksBtpContext，随机生成里面的私钥、加密公钥、重线性化公钥、旋转公钥。

+ 参数：
  + `param`： 同态参数。

+ 返回值：创建的context。


#### 函数 gen_rotation_keys

```c++
void gen_rotation_keys();
```

在 context 中生成旋转公钥。


#### 函数 gen_rotation_keys_for_rotations

```c++
void gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows = false);
```

在 context 中生成指定的旋转公钥。

+ 参数：
  + `rots`：列旋转的步数。
  + `include_swap_rows`：是否需要行旋转。


#### 函数 make_public_context

```c++
CkksBtpContext make_public_context();
```

在多线程场景下，每个线程需要自己的context，通过源context对象调用此方法生成，生成的子context不包含源context中的私钥信息，与源context有相同的加密公钥、重线性化公钥、旋转公钥。

+ 参数：无。

+ 返回值：子context。

#### 函数 shallow_copy_context

```c++
CkksBtpContext shallow_copy_context();
```

浅复制一个CkksBtpContext。在多线程需要并行使用同一个context时，需要把context浅复制，分别传给不同的线程使用。

+ 参数：无。

+ 返回值：复制结果context。

#### 函数 get_parameter

```c++
CkksParameter& get_parameter() override;
```

从输入context里提取同态参数。

+ 参数：无。

+ 返回值：同态参数。

#### 函数 bootstrap

```c++
CkksCiphertext bootstrap(const CkksCiphertext& x_ct);
```

对输入密文进行密文自举操作。

+ 参数：
    + `x_ct`：输入密文。

+ 返回值：自举后的密文。

### 分布式多方同态计算类

格物SDK还提供了分布式计算和多方安全计算的功能，支持在多个参与方之间安全地执行FHE计算。

#### DBfvContext类

分布式BFV上下文类，继承自BfvContext，支持多方安全计算协议。

```c++
static DBfvContext create_random_context(const BfvParameter& param, const std::vector<uint8_t>& seed, double sigma_smudging);
```

#### 多方计算上下文类

- **CkgContext**：密钥生成上下文，用于多方生成公钥。
- **RkgContext**：重线性化密钥生成上下文，用于多方生成重线性化密钥。
- **RtgContext**：旋转密钥生成上下文，用于多方生成旋转密钥。
- **E2sContext**：密文到秘密分享值转换的上下文。
- **S2eContext**：秘密分享值到密文转换的上下文。
- **RefreshContext**：密文刷新上下文。
- **RefreshAndPermuteContext**：密文刷新和置换上下文。

#### 秘密分享类

多方计算中使用的各种秘密分享：

- **PublicKeyShare**：公钥分享
- **RelinKeyShare**：重线性化密钥分享
- **GaloisKeyShare**：旋转密钥分享
- **AdditiveShare**：加法秘密分享
- **E2sPublicShare**：密文到秘密分享的公开分享
- **S2ePublicShare**：秘密分享到密文的公开分享
- **RefreshShare**：刷新分享
- **RefreshAndPermuteShare**：刷新和置换分享

这些类都提供了`serialize()`和`deserialize()`方法用于网络传输。详细的多方计算协议使用方法请参考相关示例代码。

## 应用程序接口-异构计算API

异构计算API 是格物平台支持CPU、GPU多种计算后端的统一接口。该API提供了灵活的异构计算能力，用户可以根据计算需求和硬件资源选择最适合的计算后端来执行全同态加密任务。使用异构计算API依赖于前文提到的有向无环图信息（MegaAG）。

### 异构计算架构

格物平台的异构计算架构基于统一的`FheTask`抽象类设计，支持两种计算后端：

- **FheTaskCpu**：基于CPU的同态加密计算，适用于通用环境。
- **FheTaskGpu**：基于GPU的同态加密计算，适用于配备通用GPU的环境。

使用C++ 异构计算API需要引入头文件：

```c++
#include "cxx_fhe_task.h"
```

### FheTask基类

`FheTask`是异构计算架构的抽象基类，定义了统一的任务执行接口。所有具体的计算后端（CPU、GPU）都继承自此基类并实现核心的`run()`方法。

#### 构造函数 FheTask

```c++
FheTask() = default;  // (1)
FheTask(const std::string& project_path);  // (2)
FheTask(const FheTask& other) = delete;  // (3)
FheTask(FheTask&& other);  // (4)
```

(1) 默认构造函数，创建一个空的任务对象。

(2) 通过项目路径创建任务对象。

+ 参数
  - `project_path`：任务项目路径，包含任务配置和资源信息。

(3) 禁止复制构造函数。

(4) 移动构造函数，转移资源所有权。

#### 析构函数 ~FheTask

```c++
virtual ~FheTask();
```

释放`FheTask`对象对应的资源。

#### 运算符 operator=

```c++
void operator=(const FheTask& other) = delete;  // (1)
void operator=(FheTask&& other);  // (2)
```

(1) 禁止复制赋值函数。

(2) 移动赋值运算符，转移资源所有权。

#### 函数 run

```c++
virtual uint64_t run(FheContext* context, 
                     const std::vector<CxxVectorArgument>& cxx_args) = 0;
```

执行全同态加密任务的核心虚函数。其派生类实现了此函数以定义具体的计算逻辑。

- 参数
  - `context`：指向FHE上下文对象的指针，包含执行任务所需的加密参数和密钥。
  - `cxx_args`：包含任务输入输出参数信息的数组，每个参数由`CxxVectorArgument`结构体描述。

- 返回值：任务执行时间（以微秒为单位）。


### FheTaskCpu类

`FheTaskCpu`类继承自`FheTask`基类，实现基于CPU的全同态加密计算。

#### 构造函数 FheTaskCpu

```c++
FheTaskCpu() = default;  // (1)
FheTaskCpu(const std::string& project_path);  // (2)
```

(1) 默认构造函数，创建一个空的CPU任务对象。

(2) 通过项目路径创建CPU任务对象。

+ 参数
  - `project_path`：任务项目路径，包含CPU计算任务的配置信息。

#### 函数 run

```c++
uint64_t run(FheContext* context, 
             const std::vector<CxxVectorArgument>& cxx_args) override;
```

基于CPU执行全同态加密计算任务。

- 参数
  - `context`：指向FHE上下文对象的指针，包含加密参数和密钥信息。
  - `cxx_args`：输入输出参数数组，每个参数由`CxxVectorArgument`结构体描述。

- 返回值：任务执行时间（以微秒为单位）。

*示例*

```c++
// 创建CPU计算任务
FheTaskCpu cpu_task("./cpu_project");

// 准备输入输出参数
vector<CxxVectorArgument> cxx_args = {
    {"input_x", &x_ciphertext},
    {"input_y", &y_ciphertext},
    {"output_z", &z_ciphertext},
};

// 执行CPU计算
uint64_t cpu_time = cpu_task.run(&context, cxx_args);
```

### FheTaskGpu类

`FheTaskGpu`类继承自`FheTask`基类，实现基于GPU的全同态加密计算。

#### 构造函数 FheTaskGpu

```c++
FheTaskGpu() = default;  // (1)
FheTaskGpu(const std::string& project_path);  // (2)
```

(1) 默认构造函数，创建一个空的GPU任务对象。

(2) 通过项目路径创建GPU任务对象。

+ 参数
  - `project_path`：任务项目路径，包含GPU计算任务的配置信息。

#### 析构函数 ~FheTaskGpu

```c++
~FheTaskGpu();
```

释放GPU任务对象对应的GPU资源。

#### 函数 run

```c++
uint64_t run(FheContext* context,
             const std::vector<CxxVectorArgument>& cxx_args,
             bool print_time = true);
```

基于GPU执行全同态加密计算任务。

- 参数
  - `context`：指向FHE上下文对象的指针，包含加密参数和密钥信息。
  - `cxx_args`：输入输出参数数组，每个参数由`CxxVectorArgument`结构体描述。
  - `print_time`：是否打印执行时间，默认为 `true`。

- 返回值：任务执行时间（以微秒为单位）。

*示例*

```c++
// 创建GPU计算任务
FheTaskGpu gpu_task("./gpu_project");

// 准备输入输出参数
vector<CxxVectorArgument> cxx_args = {
    {"input_x", &x_ciphertext},
    {"input_y", &y_ciphertext},
    {"output_z", &z_ciphertext},
};

// 执行GPU计算
uint64_t gpu_time = gpu_task.run(&context, cxx_args);
```

### CxxArgumentType枚举

`CxxArgumentType`枚举定义了异构计算任务中支持的参数类型，用于描述输入输出参数的数据类型。


### CxxVectorArgument结构体

`CxxVectorArgument`结构体用于描述异构计算任务中每一个输入输出参数的信息，包含参数标识、类型、level和数据handle指针等关键信息。

#### 成员变量

```c++
struct CxxVectorArgument {
    std::string arg_id;                  // 参数id
    CxxArgumentType type;                // 参数类型
    int level;                          // 参数level
    std::vector<Handle*> flat_handles;  // 参数所包含的数据handle的指针
};
```

- **arg_id**：参数的唯一标识符，用于在任务配置中匹配对应的参数
- **type**：参数的数据类型，必须是`CxxArgumentType`枚举中的一种
- **level**：参数的加密level，用于密文运算的兼容性检查
- **flat_handles**：包含实际数据的Handle指针数组，支持多维向量数据

#### 构造函数 CxxVectorArgument 

```c++
template <typename T> CxxVectorArgument(std::string id, T* hdl);
```

模板构造函数，可以接受各种类型的Handle对象或向量。

- 参数
  - `id`：参数标识符。
  - `hdl`：参数对应的数据，可以是单个Handle对象或`std::vector`构成的任意维度的张量。支持的对象类型包括`BfvCiphertext`、`BfvCiphertext3`、`BfvPlaintext`、`BfvPlaintextRingt`、`BfvPlaintextMul`、`CkksCiphertext`、`CkksCiphertext3`、`CkksPlaintext`、`CkksPlaintextRingt`、`CkksPlaintextMul`。需要说明的是，`CxxVectorArgument`是用来存放用户的输入输出明文/密文的，即`BfvRelinKey`、`BfvGaloisKey`、`CkksRelinKey`、`CkksGaloisKey`等密钥由内部自动处理，不应当被用来构建`CxxVectorArgument`。


*示例*

```c++
// 准备输入数据
vector<uint64_t> x_data({5, 10});
vector<uint64_t> y_data({2, 3});
BfvPlaintext x_pt = context.encode(x_data, level);
BfvPlaintext y_pt = context.encode(y_data, level);   
BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);    // 输入密文
BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);    // 输入密文
BfvCiphertext z_ct = context.new_ciphertext(level);       // 输出密文

// 构造参数向量
vector<CxxVectorArgument> cxx_args = {
    {"input_x", &x_ct},
    {"input_y", &y_ct}, 
    {"output_z", &z_ct},
};

// 支持向量形式参数
vector<BfvCiphertext> ct_vector = {x_ct, y_ct};
CxxVectorArgument vector_arg("ct_vector", &ct_vector);
```


[TOC]

# API Reference

Welcome to the user-facing LattiSense API documentation. The user-facing interface of the LattiSense Platform consists of two parts: the custom FHE task interface and the application program interface.

+ **Custom FHE Task Interface**: Contains Python interfaces for describing custom tasks. Define FHE tasks through the Python language interface and generate the directed acyclic graph information Mega-operator Abstract Graph (MegaAG) mentioned earlier for use in application programs.
+ **Application Program Interface**: In the user's application program, through the LattiSense SDK, prepare FHE computation parameters, context, input data, and perform encoding and encryption. The application program interface provides C++ interfaces including key generation, encryption, decryption, and calling heterogeneous hardware (CPU/FPGA) to execute computation tasks, while also providing complete BFV/CKKS fully homomorphic algorithm operator interfaces to support users in directly calling according to actual scenario requirements.

## Custom FHE Task Interface

The custom FHE task interface is implemented through the Python language. The following are the interface collections:

|       Custom FHE Task Interface        |                |
| :---------------------: | :------------: |
|          `add`          |      Addition      |
|          `sub`          |      Subtraction      |
|          `neg`          |      Negation      |
|         `mult`          |      Multiplication      |
|         `relin`         |    Relinearization    |
|      `mult_relin`       | Multiplication + Relinearization  |
|        `rescale`        |    Modulus Switching    |
|      `drop_level`       |   Level Switching    |
|      `rotate_cols`      |     Column Rotation     |
|  `advanced_rotate_cols` |   Advanced Column Rotation   |
|      `rotate_rows`      |     Row Rotation     |
| `ct_pt_mult_accumulate` | Ciphertext-Plaintext Dot Product |
|      `ct_to_mul`        | Convert Ciphertext to Multiplication Form |
|      `ct_to_ntt`        |  Convert Ciphertext to NTT Form |
|     `ct_to_mform`       | Convert Ciphertext to Montgomery Form |
|     `ct_ntt_to_ct`      | Convert NTT Ciphertext to Normal Form |
|       `bootstrap`       |    CKKS Bootstrap    |

### Param Class

A class describing fully homomorphic encryption algorithm parameters.

#### Constructor Param

```Python
def __init__(self, algo: str, n: int = 8192) -> None
```

+ Parameters
  + `algo`: Algorithm name, supports 'BFV' and 'CKKS'.
  + `n`: Polynomial degree, default is 8192.

+ Return value: None.

#### Class Method create_default_param

```Python
@classmethod
def create_default_param(cls, algo: str, n: int) -> Param
```

Load default parameters from a predefined parameter configuration file (`parameter.json`) to create a parameter object.

+ Parameters
  + `algo`: Algorithm name, supports 'BFV' and 'CKKS'.
  + `n`: Polynomial degree, needs to match the value defined in the configuration file.

+ Return value: Param object.

+ Notes
  + The `parameter.json` file must exist in the project root directory.
  + The configuration file must contain parameter configuration for the specified algorithm and polynomial degree.

#### Class Method create_bfv_custom_param

```Python
@classmethod
def create_bfv_custom_param(cls, n: int, q: List[int], p: List[int], t: int) -> Param
```

Create a BFV algorithm parameter object from custom parameters.

+ Parameters
  + `n`: Polynomial degree.
  + `q`: q modulus list.
  + `p`: p modulus list.
  + `t`: Plaintext modulus.

+ Return value: Param object.

#### Class Method create_ckks_custom_param

```Python
@classmethod
def create_ckks_custom_param(cls, n: int, q: List[int], p: List[int]) -> Param
```

Create a CKKS algorithm parameter object from custom parameters.

+ Parameters
  + `n`: Polynomial degree.
  + `q`: q modulus list.
  + `p`: p modulus list.

+ Return value: Param object.

#### Class Method create_ckks_btp_param

```Python
@classmethod
def create_ckks_btp_param(cls) -> Param
```

Create a CKKS algorithm parameter object that supports bootstrapping, meeting 128-bit security. Configuration parameters: polynomial degree N=65536, specific modulus configuration required for bootstrapping operations.

+ Parameters: None.

+ Return value: Param object.

#### Class Method create_ckks_toy_btp_param

```Python
@classmethod
def create_ckks_toy_btp_param(cls) -> Param
```

Create a smaller CKKS algorithm parameter object that supports bootstrapping, which does not meet 128-bit security. Configuration parameters: polynomial degree N=8192 Bootstrap parameters, specific modulus configuration required for bootstrapping operations. This parameter is only suitable for development and testing scenarios.

+ Parameters: None.

+ Return value: Param object.

### Function set_fhe_param

```Python
def set_fhe_param(param: Param) -> None
```

Set global FHE parameters.

**Important**: This function must be called before calling `process_custom_task()` to set the global parameter object used for all subsequent FHE operations.

+ Parameters
  + `param`: FHE parameter object containing algorithm type, polynomial degree n, modulus, and other information.

+ Return value: None.

+ Example

```Python
# Create parameter object
param = Param.create_bfv_custom_param(
    n=8192,
    p=[0x7ffffffffb4001],
    q=[0x3fffffffef8001, 0x4000000011c001, 0x40000000120001],
    t=0x28001
)

# Set as global parameter
set_fhe_param(param)

# Subsequent calls to process_custom_task() will use this parameter
```

### Argument Class

A class describing task input data parameters, output data parameters, and preload plaintext phase input data parameters.

#### Function Argument

```Python
def __init__(self, arg_id: str, data: 'DataNode | list') -> None
```

+ Parameters
  + `arg_id`: Custom parameter id.
  + `data`: Data. Can be a single data node, data node list, data node tuple, or multi-level data node list or tuple.

+ Return value: None.

### DataNode Class

A class describing data types. Specific subclasses should be used in practice. 

**Plaintext types:**
+ **BfvPlaintextNode**: BFV algorithm plaintext type.
+ **BfvPlaintextRingtNode**: BFV algorithm plaintext type on ring t, used for ciphertext-plaintext multiplication.
+ **BfvPlaintextMulNode**: BFV algorithm plaintext type used for ciphertext-plaintext multiplication, preprocessed in NTT and Montgomery form.
+ **BfvCompressedPlaintextRingtNode**: BFV algorithm compressed plaintext type, used for batch ciphertext-plaintext multiplication operations.
+ **CkksPlaintextNode**: CKKS algorithm plaintext type.
+ **CkksPlaintextRingtNode**: CKKS algorithm plaintext type on ring t, used for ciphertext-plaintext multiplication.
+ **CkksPlaintextMulNode**: CKKS algorithm plaintext type used for ciphertext-plaintext multiplication, preprocessed in NTT and Montgomery form.

**Ciphertext types:**
+ **BfvCiphertextNode**: BFV algorithm ciphertext type containing 2 polynomials.
+ **BfvCiphertext3Node**: BFV algorithm ciphertext type containing 3 polynomials.
+ **CkksCiphertextNode**: CKKS algorithm ciphertext type containing 2 polynomials.
+ **CkksCiphertext3Node**: CKKS algorithm ciphertext type containing 3 polynomials.

**Key types:**
+ **RelinKeyNode**: Relinearization key type.
+ **GaloisKeyNode**: Galois key type used for rotation operations.

#### Constructor DataNode

```Python
def __init__(self, type, id='', degree=-1, level=DEFAULT_LEVEL) -> None
```

+ Parameters
  + `type`: Data type.
  + `id`: Custom parameter id.
  + `degree`: Data degree (number of polynomials - 1).
  + `level`: Data level.
+ Return value: None.

### Function add

```Python
def add(
    x: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | CkksCiphertextNode | CkksPlaintextNode,
    y: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | CkksCiphertextNode | CkksPlaintextNode,
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode
```

Define an addition computation step. Supported types include `ct+ct, ct+pt, pt+ct, ct+pt_ringt, pt_ringt+ct`.

+ Parameters
  + `x`: Input data node.
  + `y`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function sub

```Python
def sub(
    x: BfvCiphertextNode | CkksCiphertextNode,
    y: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | CkksCiphertextNode | CkksPlaintextNode,
    output_id: Optional[str] = None,
) -> BfvCiphertextNode | CkksCiphertextNode
```

Define a subtraction computation step. Supported types include `ct-ct, ct-pt, ct-pt_ringt`.

+ Parameters
  + `x`: Input data node.
  + `y`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function neg

```Python
def neg(x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode | CkksCiphertextNode
```

Define a negation computation step.

+ Parameters
  + `x`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function mult

```Python
def mult(
    x: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | BfvPlaintextMulNode | CkksCiphertextNode | CkksPlaintextNode | CkksPlaintextRingtNode | CkksPlaintextMulNode,
    y: BfvCiphertextNode | BfvPlaintextNode | BfvPlaintextRingtNode | BfvPlaintextMulNode | CkksCiphertextNode | CkksPlaintextNode | CkksPlaintextRingtNode | CkksPlaintextMulNode,
    output_id: Optional[str] = None,
    start_block_idx: int = None,
) -> BfvCiphertextNode | BfvCiphertext3Node | CkksCiphertextNode | CkksCiphertext3Node
```

Define a multiplication computation step. Supported types include `ct * ct, ct * pt_ringt, pt_ringt * ct, ct * pt_mul, pt_mul * ct`.

+ Parameters
  + `x`: Input data node.
  + `y`: Input data node.
  + `output_id`: ID of the result data node.
  + `start_block_idx`: Compressed plaintext start block index (optional).

+ Return value: Result data node.

### Function relin

```Python
def relin(x: BfvCiphertext3Node | CkksCiphertext3Node, output_id: Optional[str] = None) -> BfvCiphertextNode | CkksCiphertextNode
```

Define a relinearization computation step. Supported types include `ct3`.

+ Parameters
  + `x`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function mult_relin

```Python
def mult_relin(x: BfvCiphertextNode | CkksCiphertextNode, y: BfvCiphertextNode | CkksCiphertextNode, output_id=None) -> BfvCiphertextNode | CkksCiphertextNode
```

Define a ciphertext multiplication and relinearization computation step.

+ Parameters
  + `x`: Input data node.
  + `y`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function rescale

```Python
def rescale(x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode | CkksCiphertextNode
```

Define a modulus switching computation step.

+ Parameters
  + `x`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function drop_level

```Python
def drop_level(x: CkksCiphertextNode, drop_level: int, output_id: Optional[str] = None) -> CkksCiphertextNode
```

Define a level switching computation step.

+ Parameters
  + `x`: Input data node.
  + `drop_level`: Number of levels to decrease.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function rotate_cols

```Python
def rotate_cols(
    x: BfvCiphertextNode | CkksCiphertextNode,
    steps: list[int] | int,
    output_id: Optional[str] = None,
) -> list[BfvCiphertextNode | CkksCiphertextNode]
```

Define a ciphertext column rotation computation step.

+ Parameters
  + `x`: Input data node.
  + `steps`: Rotation steps (positive for left rotation, negative for right rotation).
  + `output_id`: ID of the result data node.

+ Return value: List of result data nodes.

### Function advanced_rotate_cols

```Python
def advanced_rotate_cols(
    x: BfvCiphertextNode | CkksCiphertextNode,
    steps: list[int] | int,
    output_id: Optional[str] = None,
    out_ct_type: str = 'ct',
) -> list[BfvCiphertextNode | CkksCiphertextNode]
```

After preparing rotation public keys corresponding to rotation steps, define a ciphertext rotation computation step.

+ Parameters
  + `x`: Input data node.
  + `steps`: Rotation steps (positive for left rotation, negative for right rotation).
  + `output_id`: ID of the result data node.
  + `out_ct_type`: Output ciphertext type. Supported types include 'ct', 'ct-ntt', 'ct-ntt-mf'.
+ Return value: List of result data nodes.

### Function rotate_rows

```python
def rotate_rows(x: BfvCiphertextNode | CkksCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode | CkksCiphertextNode
```

Define a ciphertext row rotation computation step.

+ Parameters
  + `x`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function ct_pt_mult_accumulate

```Python
def ct_pt_mult_accumulate(
    x: list[BfvCiphertextNode | CkksCiphertextNode],
    y: list[BfvPlaintextRingtNode | CkksPlaintextRingtNode] | BfvCompressedPlaintextRingtNode,
    output_mform: bool | None = None,
) -> BfvCiphertextNode | CkksCiphertextNode
```

Define a ciphertext-plaintext vector dot product computation step. When the vector length meets the conditions, this should be prioritized for performance improvement.

+ Parameters
  + `x`: Input ciphertext vector.
  + `y`: Input plaintext vector, required to have the same length as the ciphertext vector, or compressed plaintext object.
  + `output_mform`: Whether output is in Montgomery form (optional).

+ Return value: Result data node.

### Function ct_to_mul

```Python
def ct_to_mul(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode
```

Convert BFV ciphertext to multiplication form (NTT + Montgomery form).

+ Parameters
  + `x`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function ct_to_ntt

```Python
def ct_to_ntt(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode
```

Convert BFV ciphertext to NTT form.

+ Parameters
  + `x`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function ct_to_mform

```Python
def ct_to_mform(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode
```

Convert BFV ciphertext to Montgomery form.

+ Parameters
  + `x`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function ct_ntt_to_ct

```Python
def ct_ntt_to_ct(x: BfvCiphertextNode, output_id: Optional[str] = None) -> BfvCiphertextNode
```

Convert BFV NTT ciphertext to normal form.

+ Parameters
  + `x`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function bootstrap

```Python
def bootstrap(x: CkksCiphertextNode, output_id: Optional[str] = None) -> CkksCiphertextNode
```

Define a CKKS bootstrapping computation step.

+ Parameters
  + `x`: Input data node.
  + `output_id`: ID of the result data node.

+ Return value: Result data node.

### Function process_custom_task

```python
def process_custom_task(
    input_args: list[Argument] = None,
    output_args: list[Argument] = None,
    offline_input_args: list[Argument] = None,
    output_instruction_path: str = None,
    fpga_acc: bool = False,
) -> dict
```

Compile custom task. Based on the input and output data parameters of the custom task, compile and transform the custom task into a series of required files.

**Important**: Before calling this function, you must first call `set_fhe_param()` to set the global FHE parameters.

+ Parameters
  + `input_args`: List of all input parameters for the custom task.
  + `output_args`: List of all output parameters for the custom task.
  + `offline_input_args`: List of all preload plaintext phase input parameters for the custom task, excluding input data nodes.
  + `output_instruction_path`: Storage directory for task files/hardware instructions of the custom task.
  + `fpga_acc`: Hardware accelerator task identifier.

+ Return value: Task abstract computation graph.

*Example*

```python
from custom_task import *

# Create and set global parameters
param = Param.create_bfv_custom_param(
    n=8192,
    p=[0x7ffffffffb4001],
    q=[0x3fffffffef8001, 0x4000000011c001, 0x40000000120001],
    t=0x28001
)
set_fhe_param(param)

# Define computation graph
level = 3
x = BfvCiphertextNode('x', level)
y = BfvCiphertextNode('y', level)
z = mult_relin(x, y, 'z')

# Compile task
process_custom_task(
    input_args=[Argument('x', x), Argument('y', y)],
    output_args=[Argument('z', z)],
    output_instruction_path='examples/bfv_mult',
    fpga_acc=False,
)
```

## Application Program Interface - FHE Algorithm Library

The FHE algorithm library provides the homomorphic software algorithm library used by users in applications, as well as interfaces for performing operations related to fully homomorphic encryption algorithms.

To use the FHE algorithm library, include the header file:

```c++
#include "cxx_fhe_lib_v2.h"
```

### Handle Template Class

| Public Member Functions                         |                  |
| :---------------------------------------------- | :--------------- |
| `Handle();`                                     | Default constructor     |
| `Handle(uint64_t&& h, bool k = false);`         | Parameterized constructor     |
| `Handle(Handle&& other);`                       | Move Handle object   |
| `Handle(const Handle&) = delete;`               | Disable copying         |
| `void operator=(Handle&& other);`               | Move Handle object   |
| `void operator=(const Handle& other) = delete;` | Disable copying         |
| `virtual ~Handle();`                            | Destructor         |
| `const uint64_t& get() const;`                  | Get Handle internal value |
| `bool is_empty() const;`                        | Check if empty     |

A `Handle` corresponds to a portion of memory resources. The allocation and deallocation of resources are managed by the SDK, so `Handle` cannot be directly copied. You can use `std::move()` to transfer ownership of the internal resources of the `Handle`, or call the corresponding API function to copy the content corresponding to the `Handle`.

For objects such as encryption parameters, context, plaintext, ciphertext, private keys, public keys, etc. in ciphertext computation, the C++ SDK uses the Handle template class to uniformly manage the resources of various objects. Based on the Handle template class, the Handle types encapsulated by the C++ SDK include:

**Parameter and context classes**:
 * `BfvParameter`: BFV homomorphic parameters containing homomorphic parameters N, q, t.
 * `CkksParameter`: CKKS homomorphic parameters containing homomorphic parameters N, q.
 * `CkksBtpParameter`: CKKS Bootstrap parameters, inherited from CkksParameter.
 * `BfvContext`: BFV homomorphic context class containing BFV public keys, private keys, and other information.
 * `CkksContext`: CKKS homomorphic context class containing CKKS public keys, private keys, and other information.
 * `CkksBtpContext`: CKKS Bootstrap context class supporting Bootstrap operations.

**Plaintext classes**:
 * `BfvPlaintext`: BFV plaintext for encryption, decryption, ciphertext-plaintext addition.
 * `BfvPlaintextRingt`: BFV ring plaintext for ciphertext-plaintext multiplication.
 * `BfvPlaintextMul`: BFV multiplication plaintext for ciphertext-plaintext multiplication.
 * `CkksPlaintext`: CKKS plaintext for encryption, decryption, ciphertext-plaintext addition.
 * `CkksPlaintextRingt`: CKKS ring plaintext for ciphertext-plaintext multiplication.
 * `CkksPlaintextMul`: CKKS multiplication plaintext for ciphertext-plaintext multiplication.

**Ciphertext classes**:
 * `BfvCiphertext`: BFV ciphertext containing two polynomials.
 * `BfvCiphertext3`: BFV ciphertext containing three polynomials.
 * `BfvCompressedCiphertext`: BFV compressed ciphertext.
 * `CkksCiphertext`: CKKS ciphertext containing two polynomials.
 * `CkksCiphertext3`: CKKS ciphertext containing three polynomials.
 * `CkksCompressedCiphertext`: CKKS compressed ciphertext.

**Key classes**:
 * `SecretKey`: Private key.
 * `PublicKey`: Public key.
 * `RelinKey`: Relinearization public key.
 * `GaloisKey`: Rotation public key.
 * `KeySwitchKey`: Key switching public key.

**Distributed computing related classes**:
 * `DBfvContext`: Distributed BFV context.
 * Multi-party computation contexts: `CkgContext`, `RkgContext`, `RtgContext`, `E2sContext`, `S2eContext`, `RefreshContext`, `RefreshAndPermuteContext`
 * Various Share classes: `PublicKeyShare`, `RelinKeyShare`, `GaloisKeyShare`, `AdditiveShare`, etc.

#### Constructor Handle

```c++
Handle();  // (1)
Handle(uint64_t&& h, bool k = false);  // (2)
Handle(Handle&& other);  // (3)
Handle(const Handle& other) = delete;  // (4)
```

(1) Create an empty `Handle` object that does not correspond to any resource. Resources from other `Handle` objects can be transferred to this `Handle` object later.

- Parameters: None.
- Return value: Created Handle.

(2) Create a new `Handle` object based on the C language interface id, used internally by the SDK.

(3) Move constructor that transfers resources from the input rvalue `Handle` object to the newly created `Handle` object.

- Parameters
  - `other`: Input rvalue `Handle` object.
- Return value: Created Handle.

*Example*

```c++
CkksCiphertext x2 = context.add(x0, x1);
CkksCiphertext x3(std::move(x2));
```

(4) Copy constructor is disabled.

#### Operator operator=

```c++
void operator=(Handle&& other);  // (1)
void operator=(const Handle& other) = delete;  // (2)
```

(1) Move assignment operator that transfers resources from the input rvalue Handle object to the current Handle object.

- Parameters
  - `other`: Input rvalue `Handle` object.

- Return value: None.

*Example*

```c++
CkksCiphertext x2 = context.add(x0, x1);
CkksCiphertext x3 = std::move(x2);
```

(2) Copy assignment operator is disabled.

#### Destructor ~Handle

```c++
virtual ~Handle();
```

- Parameters: None.
- Return value: None.

#### Function is_empty

```c++
bool is_empty() const;
```

Check if the content of the current `Handle` object is empty.

- Parameters: None.
- Return value: Whether the content of the current `Handle` object is empty.

#### Function get

```c++
const uint64_t& get() const;
```

Get the C language interface id of the current `Handle` object, used internally by the SDK.

- Parameters: None.
- Return value: C language interface id of the current `Handle` object.

### BfvParameter Class

BfvParameter is a homomorphic parameter class containing homomorphic parameters N, q, t. BfvParameter inherits from the Handle class.

#### Function create_parameter

```
static BfvParameter create_parameter(uint64_t N, uint64_t t);
```

Create a set of homomorphic parameters for the BFV algorithm by specifying N and t.

- Parameters
  - `N`: Polynomial degree N.
  - `t`: Plaintext modulus t.
- Return value: Created homomorphic parameter object.

#### Function copy

```c++
BfvParameter copy() const;
```

Copy the current `BfvParameter` object.

+ Parameters: None.

+ Return value: New copied `BfvParameter` object.

#### Function print

```c++
void print() const;
```

Print the parameter values of the BFV homomorphic parameter object.

+ Parameters: None.

+ Return value: None.

#### Function get_q

```c++
uint64_t get_q(int index) const;
```

Get a component of the ciphertext modulus q of the BFV homomorphic parameters.

+ Parameters
  + `index`: Index of the required ciphertext modulus q component.

+ Return value: Component value of ciphertext modulus q.

#### Function get_n

```c++
int get_n() const;
```

Get the polynomial degree N in a set of homomorphic parameters.

+ Parameters: None.

+ Return value: Polynomial degree N.

#### Function get_t

```c++
uint64_t get_t() const;
```

Get the plaintext modulus T in a set of homomorphic parameters.

+ Parameters: None.

+ Return value: Plaintext modulus T.

#### Function get_max_level

```c++
int get_max_level() const;
```

Get the maximum plaintext and ciphertext level of a set of BFV homomorphic parameters.

+ Parameters: None.

+ Return value: Maximum plaintext and ciphertext level.

#### Function create_custom_parameter

```c++
static BfvParameter create_custom_parameter(uint64_t N, uint64_t t,
                                            const std::vector<uint64_t>& Q,
                                            const std::vector<uint64_t>& P);
```

Create a fully custom set of BFV algorithm homomorphic parameters. This function allows users to specify all parameters, including polynomial degree, plaintext modulus, and ciphertext modulus array.

+ Parameters
  + `N`: Polynomial degree, must be a power of 2.
  + `t`: Plaintext modulus used to define the plaintext space.
  + `Q`: Vector of components of the ciphertext modulus.
  + `P`: Vector of components of the extended ciphertext modulus.

+ Return value: Created homomorphic parameter object.

+ Notes
  + Parameter configuration needs to be consistent with the parameters in the mega_ag.json file of the custom computation task.

#### Function set_parameter

```c++
static BfvParameter set_parameter(uint64_t N, uint64_t t, const std::vector<uint64_t>& Q, const std::vector<uint64_t>& P);
```

Create BFV homomorphic parameters using the specified N, t, ciphertext modulus Q, and extended modulus P.

+ Parameters
  + `N`: Polynomial degree N.
  + `t`: Plaintext modulus t.
  + `Q`: Components of the ciphertext modulus.
  + `P`: Components of the extended ciphertext modulus.

+ Return value: Created homomorphic parameter object.

#### Function get_p

```c++
uint64_t get_p(int index) const;
```

Get a component of the extended ciphertext modulus P of the BFV homomorphic parameters.

+ Parameters
  + `index`: Index of the required extended ciphertext modulus P component.

+ Return value: Component value of extended ciphertext modulus P.

#### Function get_q_count

```c++
int get_q_count() const;
```

Get the number of components of the ciphertext modulus Q of the BFV homomorphic parameters.

+ Parameters: None.

+ Return value: Number of components of ciphertext modulus Q.

#### Function get_p_count

```c++
int get_p_count() const;
```

Get the number of components of the extended ciphertext modulus P of the BFV homomorphic parameters.

+ Parameters: None.

+ Return value: Number of components of extended ciphertext modulus P.

### CkksParameter Class

Used to manage CKKS algorithm homomorphic parameter objects, internally storing homomorphic parameter N and components of the ciphertext modulus. CkksParameter inherits from the Handle class.

#### Function create_parameter

```
static CkksParameter create_parameter(uint64_t N);
```

Create a set of homomorphic parameters for the CKKS algorithm by specifying N.

- Parameters
  - `N`: Polynomial degree N.
- Return value: Created homomorphic parameter object.

#### Function print

```c++
void print() const;
```

Print the parameter values of the CKKS homomorphic parameter `Handle` object.

+ Return value: None.

#### Function get_q

```c++
uint64_t get_q(int index) const;
```

Get a component of the ciphertext modulus q of the CKKS homomorphic parameters.

+ Parameters
  + `index`: Index of the required ciphertext modulus q component.

+ Return value: Component value of ciphertext modulus q.

#### Function get_n

```c++
int get_n() const;
```

Get the polynomial degree N in a set of homomorphic parameters.

+ Parameters: None.

+ Return value: Polynomial degree N.

#### Function get_max_level

```c++
int get_max_level() const;
```

Get the maximum plaintext and ciphertext level of a set of CKKS homomorphic parameters.

+ Parameters: None.

+ Return value: Maximum plaintext and ciphertext level.

#### Function create_custom_parameter

```c++
static CkksParameter create_custom_parameter(uint64_t N,
                                             const std::vector<uint64_t>& Q,
                                             const std::vector<uint64_t>& P);
```

Create a fully custom set of CKKS algorithm homomorphic parameters. This function allows users to specify all parameter details, including polynomial degree and ciphertext modulus array.

+ Parameters
  + `N`: Polynomial degree, must be a power of 2.
  + `Q`: Vector of components of the ciphertext modulus.
  + `P`: Vector of components of the extended ciphertext modulus.

+ Return value: Created homomorphic parameter object.

#### Function copy

```c++
CkksParameter copy() const;
```

Copy the current `CkksParameter` object.

+ Parameters: None.

+ Return value: New copied `CkksParameter` object.

#### Function get_p_count

```c++
int get_p_count() const;
```

Get the number of components of the extended ciphertext modulus P of the CKKS homomorphic parameters.

+ Parameters: None.

+ Return value: Number of components of extended ciphertext modulus P.

#### Function get_p

```c++
uint64_t get_p(int index) const;
```

Get a component of the extended ciphertext modulus P of the CKKS homomorphic parameters.

+ Parameters
  + `index`: Index of the required extended ciphertext modulus P component.

+ Return value: Component value of extended ciphertext modulus P.

#### Function get_default_scale

```c++
double get_default_scale() const;
```

Get the default scale corresponding to the CKKS homomorphic parameters. The default scale value is the integer power of 2 closest to $q_1$.

- Parameters: None.
- Return value: Default scale.

### CkksBtpParameter Class

Used to manage CKKS Bootstrap algorithm homomorphic parameter objects, containing CKKS basic parameters and Bootstrap-related parameters. CkksBtpParameter inherits from the CkksParameter class.

#### Function create_parameter

```c++
static CkksBtpParameter create_parameter();
```

Create CKKS Bootstrap homomorphic parameters. This parameter contains all configuration information required for the Bootstrap algorithm.

+ Parameters: None.

+ Return value: Created CKKS Bootstrap parameter object.

#### Function create_toy_parameter

```c++
static CkksBtpParameter create_toy_parameter();
```

Create CKKS Bootstrap homomorphic parameters for testing. This function creates a smaller-scale set of Bootstrap parameters suitable for development and testing scenarios.

+ Parameters: None.

+ Return value: Created CKKS Bootstrap test parameter object.

+ Notes
  + This parameter configuration corresponds to the `create_ckks_toy_btp_param` method on the Python side.
  + Polynomial degree N=8192, smaller than standard Bootstrap parameters (N=65536), suitable for quick testing.
  + Contains predefined Q and P modulus array configurations.

#### Function get_ckks_parameter

```c++
CkksParameter& get_ckks_parameter();
```

Get a reference to the base CkksParameter object contained in CkksBtpParameter.

### BfvPlaintext Class

BFV plaintext class for encryption, decryption, and ciphertext-plaintext addition.

#### Function get_level

```c++
int get_level() const;
```

Get the level of a BFV plaintext.

+ Return value: Plaintext level value.

#### Function print

```c++
void print() const;
```

Print the value of a BFV plaintext object.

### BfvPlaintextRingt Class

BFV plaintext class for ciphertext-plaintext multiplication.

#### Function get_level

```c++
int get_level() const;
```

Get the level of a BFV plaintext.

+ Return value: Plaintext level value.

### BfvPlaintextMul Class

BFV plaintext class for ciphertext-plaintext multiplication.

#### Function get_level

```c++
int get_level() const;
```

Get the level of a BFV plaintext.

+ Return value: Plaintext level value.

### BfvCiphertext Class

BFV ciphertext class containing 2 polynomials.

#### Function get_level

```c++
int get_level() const;
```

Get the level of a BFV ciphertext.

+ Parameters: None.
+ Return value: Ciphertext level value.

#### Function get_coeff

```c++
uint64_t get_coeff(int poly_idx, int rns_idx, int coeff_idx) const;
```

Get the value of a coefficient in the current BFV ciphertext.

- Parameters
  - `poly_idx`: Polynomial index of the coefficient in the BFV ciphertext.
  - `rns_idx`: RNS component index of the coefficient in the polynomial.
  - `coeff_idx`: Coefficient index of the coefficient in the RNS component.
- Return value: Value of the specified coefficient in the BFV ciphertext.

#### Function serialize

```c++
std::vector<uint8_t> serialize(const BfvParameter& param) const;
```

Serialize a BFV ciphertext.
+ Parameters
  + `param`: BFV homomorphic parameters.
+ Return value: Serialized byte array.

#### Function deserialize

```
static BfvCiphertext deserialize(const std::vector<uint8_t>& data);
```

Deserialize a BFV ciphertext.

+ Parameters
  + `data`: Binary byte array.

- Return value: Deserialized `BfvCiphertext` object.

#### Function copy

```c++
BfvCiphertext copy() const;
```

Copy a BFV ciphertext.

+ Return value: Created ciphertext object.

#### Function print

```c++
void print() const;
```

Print the value of a BFV ciphertext object.

+ Return value: None.

### BfvCiphertext3 Class

BFV ciphertext class containing 3 polynomials.

#### Function get_level

```c++
int get_level() const;
```

Get the level of a BFV ciphertext.

+ Return value: Ciphertext level value.

### BfvCompressedCiphertext Class

BFV compressed ciphertext class, obtained through symmetric encryption, with ciphertext size half that of BfvCiphertext.

#### Function serialize

```c++
std::vector<uint8_t> serialize(const BfvParameter& param) const;
```

Serialize a BFV compressed ciphertext.

+ Parameters
  + `param`: BFV homomorphic parameters.

+ Return value: Serialized byte array.

#### Function deserialize

```c++
static BfvCompressedCiphertext deserialize(const std::vector<uint8_t>& data);
```

Deserialize a BFV compressed ciphertext.

+ Parameters
  + `data`: Byte array after serializing `BfvCompressedCiphertext` object.

+ Return value: Deserialized `BfvCompressedCiphertext` object.

### CkksPlaintext Class

CKKS plaintext class for encryption, decryption, and ciphertext-plaintext addition.

#### Function get_level

```c++
int get_level() const;
```

Get the level of a CKKS plaintext.

+ Return value: Plaintext level value.

#### Function get_scale

```c++
double get_scale() const;
```

Get the scale of a CKKS plaintext.

+ Return value: Plaintext scale value.

#### Function print

```c++
void print() const;
```

Print the value of a CKKS plaintext object.

### CkksPlaintextRingt Class

CKKS plaintext class for ciphertext-plaintext multiplication.

#### Function get_scale

```c++
double get_scale() const;
```

Get the scale of a CKKS plaintext.

+ Return value: Plaintext scale value.

### CkksPlaintextMul Class

CKKS plaintext class for ciphertext-plaintext multiplication.

#### Function get_level

```c++
int get_level() const;
```

Get the level of a CKKS plaintext.

+ Return value: Plaintext level value.

#### Function get_scale

```c++
double get_scale() const;
```

Get the scale of a CKKS plaintext.

+ Return value: Plaintext scale value.

### CkksCiphertext Class

CKKS ciphertext class containing 2 polynomials.

#### Function get_level

```c++
int get_level() const;
```

Get the level of a CKKS ciphertext.

+ Parameters: None.
+ Return value: Ciphertext level value.

#### Function get_scale

```c++
double get_scale() const;
```

Get the scale of a CKKS ciphertext.

+ Parameters: None.
+ Return value: Ciphertext scale value.

#### Function get_slots

```c++
int get_slots() const;
```

Get the number of slots in a CKKS ciphertext.

+ Parameters: None.
+ Return value: Number of slots.

#### Function serialize

```c++
std::vector<uint8_t> serialize(const CkksParameter& param) const;
```

Serialize a CKKS ciphertext.

+ Parameters
  + `param`: CKKS homomorphic parameters.

+ Return value: Serialized byte array.

#### Function deserialize

```c++
static CkksCiphertext deserialize(const std::vector<uint8_t>& data);
```

Deserialize a CKKS ciphertext.

+ Parameters
  + `data`: Binary byte array.

+ Return value: Deserialized `CkksCiphertext` object.

#### Function copy

```c++
CkksCiphertext copy() const;
```

Copy a CKKS ciphertext.

+ Return value: Created ciphertext object.

#### Function print

```c++
void print() const;
```

Print the value of a CKKS ciphertext object.

+ Return value: None.

### CkksCiphertext3 Class

CKKS ciphertext class containing 3 polynomials.

#### Function get_level

```c++
int get_level() const;
```

Get the level of a CKKS ciphertext.

+ Return value: Ciphertext level value.

#### Function get_scale

```c++
double get_scale() const;
```

Get the scale of a CKKS ciphertext.

+ Return value: Ciphertext scale value.

### CkksCompressedCiphertext Class

CKKS compressed ciphertext class, obtained through symmetric encryption.

#### Function serialize

```c++
std::vector<uint8_t> serialize(const CkksParameter& param) const;
```

Serialize a CKKS compressed ciphertext.

+ Parameters
  + `param`: CKKS homomorphic parameters.

+ Return value: Serialized byte array.

#### Function deserialize

```c++
static CkksCompressedCiphertext deserialize(const std::vector<uint8_t>& data);
```

Deserialize a CKKS compressed ciphertext.

+ Parameters
  + `data`: Byte array after serializing `CkksCompressedCiphertext` object.

+ Return value: Deserialized `CkksCompressedCiphertext` object.

### SecretKey Class

`SecretKey` contains a homomorphic private key, used to pass private key information between different `FheContext` objects.

### PublicKey Class

`PublicKey` contains a homomorphic encryption public key, used to pass encryption public key information between different `FheContext` objects.

### RelinKey Class

`RelinKey` contains a homomorphic relinearization public key, used to pass relinearization public key information between different `FheContext` objects.

### GaloisKey Class

`GaloisKey` contains a set of homomorphic rotation public keys, used to pass rotation public key information between different `FheContext` objects.

### FheContext Class

`FheContext` is the homomorphic context class containing public keys, private keys, and other information. In practice, its subclasses `BfvContext` and `CkksContext` should be used.

#### Function extract_secret_key

```c++
virtual SecretKey extract_secret_key() const = 0;
```

Extract the private key from the input context to form an independent private key variable.

+ Parameters: None.

- Return value: Private key object.

#### Function extract_public_key

```c++
virtual PublicKey extract_public_key() const = 0;
```

Extract the public key from the input context to form an independent public key variable.

+ Parameters: None.

- Return value: Public key object.

#### Function extract_relin_key

```c++
virtual RelinKey extract_relin_key() const = 0;
```

Extract the BFV relinearization public key from the input context to form an independent relinearization public key variable.

- Parameters: None.
- Return value: Relinearization public key object.

#### Function extract_galois_key

```c++
virtual GaloisKey extract_galois_key() const = 0;
```

Extract the BFV rotation public key from the input context to form an independent rotation public key variable.

- Parameters: None.
- Return value: Rotation public key object.

#### Function resize_copies

In multi-threaded computation, each thread needs to use a copy of the context. `FheContext` can store these context copies and reuse them across multiple multi-threaded computations. The function `resize_copies` is used to specify the maximum number of context copies in the current `FheContext` object.

```c++
void resize_copies(int n);
```

- Parameters
  - `n`: Maximum number of context copies in the current `FheContext` object.
- Return value: None.

#### Function get_copy

```c++
virtual FheContext& get_copy(int index) = 0;
```

In multi-threaded computation, each thread needs to use a copy of the context. `FheContext` can store these context copies and reuse them across multiple multi-threaded computations. The function `get_copy` is used to obtain a copy of the current `FheContext` object.

- Parameters
  - `index`: Index of the required context copy.
- Return value: A copy of the current `FheContext` object.

### BfvContext Class

The `BfvContext` class inherits from the `FheContext` class and has all the methods of the `FheContext` class, which will not be repeated here.

#### Function create_random_context

```c++
static BfvContext create_random_context(const BfvParameter& param, int level = MAX_LEVEL);
```

Create a new BfvContext with randomly generated private key, encryption public key, and relinearization public key.

- Parameters:
  - `param`: Homomorphic parameters.
  - `level`: Maximum ciphertext level that can be processed, default is the maximum ciphertext level corresponding to the input homomorphic parameters.
- Return value: Created context.

#### Function create_empty_context

```c++
static BfvContext create_empty_context(const BfvParameter& param);
```

Create an empty BfvContext where the private key, encryption public key, relinearization public key, and rotation public key are all empty values.

+ Parameters:
  + `param`: Homomorphic parameters.

+ Return value: Created context.

#### Function gen_rotation_keys

```c++
void gen_rotation_keys(int level = MAX_LEVEL);
```

Generate a standard set of rotation public keys in the context, including the rotation public key corresponding to row rotation and rotation public keys for column rotation steps in the form $\pm 2^i$.

- Parameters:
  - `level`: Maximum ciphertext level that can be processed, default is the maximum ciphertext level corresponding to the input homomorphic parameters.
- Return value: None.

#### Function gen_rotation_keys_for_rotations

```c++
void gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows = false, int level = MAX_LEVEL);
```

Generate specified rotation public keys in the context.

+ Parameters:
  + `rots`: Column rotation steps.
  + `include_swap_rows`: Whether row rotation is needed.
  + `level`: Maximum ciphertext level that can be processed, default is the maximum ciphertext level corresponding to the input homomorphic parameters.

+ Return value: None.

#### Function make_public_context

```c++
BfvContext make_public_context(bool include_pk = true, bool include_rlk = true, bool include_gk = true) const;
```

On the requester side, the source context contains both public and private keys. Since the private key cannot be sent to the computing party, the requester needs to call this method on the source context object to generate a sub-context. The generated sub-context does not contain the private key information from the source context and can optionally include the same encryption public key, relinearization public key, and rotation public key as the source context.

- Parameters:
  - `include_pk`: Whether to include encryption public key, default is true.
  - `include_rlk`: Whether to include relinearization public key, default is true.
  - `include_gk`: Whether to include rotation public key, default is true.
- Return value: Sub-context.

#### Function shallow_copy_context

```c++
BfvContext shallow_copy_context() const;
```

Shallow copy a BfvContext. When multiple threads need to use the same context in parallel, the context needs to be shallow copied and passed to different threads separately.

+ Parameters: None.

+ Return value: Copied context.

#### Function get_parameter

```c++
const BfvParameter& get_parameter();
```

Get the homomorphic parameters corresponding to the context.

+ Parameters: None.

- Return value: Homomorphic parameters.

#### Function serialize

```c++
std::vector<uint8_t> serialize() const;
```

Serialize BfvContext into a byte array.

+ Parameters: None.

+ Return value: Serialized byte array.

#### Function deserialize

```c++
static BfvContext deserialize(const std::vector<uint8_t>& data);
```

Deserialize a byte array into BfvContext.

+ Parameters:
  + `data`: Byte array pointer.

+ Return value: Deserialized BfvContext.

#### Function serialize_advanced

```c++
std::vector<uint8_t> serialize_advanced() const;
```

Serialize BfvContext into a byte array using advanced compression method. This method should be prioritized for serializing ciphertext.

+ Parameters: None.

+ Return value: Serialized byte array.

#### Function deserialize_advanced

```c++
static BfvContext deserialize_advanced(const std::vector<uint8_t>& data);
```

Deserialize a byte array compressed using advanced method into BfvContext.

+ Parameters:
  + `data`: Byte array pointer.

+ Return value: Deserialized BfvContext.

#### Function set_context_relin_key

```c++
void set_context_relin_key(const RelinKey& rlk);
```

Configure a relinearization key to a context.

+ Parameters:
  + `rlk`: Source relinearization key.

+ Return value: None.

#### Function set_context_galois_key

```c++
void set_context_galois_key(const GaloisKey& gk);
```

Configure a rotation key to a context.

+ Parameters:
  + `gk`: Source rotation key.

+ Return value: None.

#### Function encode

```c++
BfvPlaintext encode(const std::vector<uint64_t>& x_mg, int level);
```

Encode message data into a BFV plaintext. The message data is an array where each element represents an original message.

+ Parameters:
  + `x_mg`: Input message data.
  + `level`: Level of the output plaintext.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_ringt

```c++
BfvPlaintextRingt encode_ringt(const std::vector<uint64_t>& x_mg);
```

Encode message data into a BFV plaintext on ring t for multiplication.

+ Parameters:
  + `x_mg`: Input message data.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_mul

```c++
BfvPlaintextMul encode_mul(const std::vector<uint64_t>& x_mg, int level);
```

Encode message data into a BFV plaintext for multiplication.

+ Parameters:
  + `x_mg`: Input message data.
  + `level`: Level of the output plaintext.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_coeffs

```c++
BfvPlaintext encode_coeffs(const std::vector<uint64_t>& x_mg, int level);
```

Encode an integer array into a BFV plaintext where array elements are directly embedded into plaintext polynomial coefficients. Does not support element-wise multiplication.

+ Parameters:
  + `x_mg`: Input integer array.
  + `level`: Level of the output plaintext.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_coeffs_ringt

```c++
BfvPlaintextRingt encode_coeffs_ringt(const std::vector<uint64_t>& x_mg);
```

Encode an integer array into a BFV plaintext on ring t for multiplication, where array elements are directly embedded into plaintext polynomial coefficients. Does not support element-wise multiplication.

+ Parameters:
  + `x_mg`: Input integer array.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_coeffs_mul

```c++
BfvPlaintextMul encode_coeffs_mul(const std::vector<uint64_t>& x_mg, int level);
```

Encode an integer array into a BFV plaintext for multiplication, where array components are directly embedded into plaintext polynomial coefficients. Does not support element-wise multiplication.

+ Parameters:
  + `x_mg`: Input integer array.
  + `level`: Level of the output plaintext.

+ Return value: Encoded plaintext for multiplication.

#### Function decode

```c++
std::vector<uint64_t> decode(const BfvPlaintext& x_pt);
```

Decode a BFV plaintext into message data.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Decoded message data.

#### Function decode_coeffs

```c++
std::vector<uint64_t> decode_coeffs(const BfvPlaintext& x_pt);
```

Decode a BFV plaintext into an integer array.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Decoded integer array.

#### Function new_ciphertext

```c++
BfvCiphertext new_ciphertext(int level);
```

Create a new ciphertext and allocate space for it based on input parameters.

+ Parameters:
  + `level`: Level of the new ciphertext.

+ Return value: Created ciphertext.

#### Function encrypt_asymmetric

```c++
BfvCiphertext encrypt_asymmetric(const BfvPlaintext& x_pt);
```

Encrypt a BFV plaintext using the encryption public key.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Encrypted ciphertext.

#### Function encrypt_symmetric

```c++
BfvCiphertext encrypt_symmetric(const BfvPlaintext& x_pt);
```

Encrypt a BFV plaintext using the private key.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Encrypted ciphertext.

#### Function encrypt_symmetric_compressed

```c++
BfvCompressedCiphertext encrypt_symmetric_compressed(const BfvPlaintext& x_pt);
```

Encrypt a BFV plaintext using the private key and compress it.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Encrypted compressed ciphertext, half the size of BfvCiphertext.

#### Function decrypt

```c++
BfvPlaintext decrypt(const BfvCiphertext& x_ct);  // (1)
BfvPlaintext decrypt(const BfvCiphertext3& x_ct);  // (2)
```


(1) Decrypt a BFV ciphertext using the decryption private key.

+ Parameters:
  + `x_ct`: Input ciphertext.

+ Return value: Decrypted plaintext.

(2) Decrypt a BFV ciphertext containing 3 polynomials using the decryption private key.

+ Parameters:
  + `x_ct`: Input ciphertext.

+ Return value: Decrypted plaintext.

#### Function add

```c++
BfvCiphertext add(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);  // (1)
BfvCiphertext3 add(const BfvCiphertext3& x0_ct, const BfvCiphertext3& x1_ct);  // (2)
```

(1) Compute `BfvCiphertext` ciphertext plus `BfvCiphertext` ciphertext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_ct`: Input ciphertext.

+ Return value: Addition result ciphertext.

(2) Compute `BfvCiphertext3` ciphertext plus `BfvCiphertext3` ciphertext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_ct`: Input ciphertext.

+ Return value: Addition result ciphertext.

#### Function add_inplace

```c++
void add_inplace(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);
```

Compute ciphertext plus ciphertext, storing the result in the space of one input ciphertext.

+ Parameters:
  + `x0_ct`: Input ciphertext, also the output result ciphertext.
  + `x1_ct`: Input ciphertext.

+ Return value: None.

#### Function add_plain

```c++
BfvCiphertext add_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);
```

Compute ciphertext plus plaintext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_pt`: Input plaintext.

+ Return value: Addition result ciphertext.

#### Function add_plain_inplace

```c++
void add_plain_inplace(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);
```

Compute ciphertext plus plaintext, overwriting input ciphertext x0 with the result.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_pt`: Input plaintext.

+ Return value: None.

#### Function sub

```c++
BfvCiphertext sub(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);
```

Compute ciphertext minus ciphertext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_ct`: Input ciphertext.

+ Return value: Subtraction result ciphertext.

#### Function mult

```c++
BfvCiphertext3 mult(const BfvCiphertext& x0_ct, const BfvCiphertext& x1_ct);
```

Compute ciphertext times ciphertext, obtaining a ciphertext with 3 polynomials.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_ct`: Input ciphertext.

+ Return value: Multiplication result ciphertext.

#### Function mult_plain

```c++
BfvCiphertext mult_plain(const BfvCiphertext& x0_ct, const BfvPlaintext& x1_pt);
```

Compute ciphertext times plaintext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_pt`: Input plaintext.

+ Return value: Multiplication result ciphertext.

#### Function mult_plain_ringt

```c++
BfvCiphertext mult_plain_ringt(const BfvCiphertext& x0_ct, const BfvPlaintextRingt& x1_pt);
```

Compute ciphertext times plaintext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_pt`: Input plaintext.

+ Return value: Multiplication result ciphertext.

#### Function mult_scalar

```c++
BfvCiphertext mult_scalar(const BfvCiphertext& x0_ct, const int64_t x1_value);
```

Compute ciphertext times constant.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_value`: Input constant value.

+ Return value: Multiplication result ciphertext.

#### Function mult_plain_mul

```c++
BfvCiphertext mult_plain_mul(const BfvCiphertext& x0_ct, const BfvPlaintextMul& x1_pt);
```

Compute ciphertext times plaintext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_pt`: Input plaintext.

+ Return value: Multiplication result ciphertext.

#### Function ringt_to_mul

```c++
BfvPlaintextMul ringt_to_mul(const BfvPlaintextRingt& x_pt, int level);
```

Convert multiplication plaintext on ring t to regular multiplication plaintext.

+ Parameters:
  + `x_pt`: Input plaintext on ring t.
  + `level`: Plaintext level.

+ Return value: Regular multiplication plaintext.

#### Function compressed_ciphertext_to_ciphertext

```c++
BfvCiphertext compressed_ciphertext_to_ciphertext(const BfvCompressedCiphertext& x_ct);
```

Convert compressed BFV ciphertext to regular ciphertext.

+ Parameters:
  + `x_ct`: Compressed BFV ciphertext.

+ Return value: Regular BFV ciphertext.

#### Function relinearize

```c++
BfvCiphertext relinearize(const BfvCiphertext3& x_ct);
```

Compute ciphertext relinearization.

+ Parameters:
  + `x_ct`: Input ciphertext.

+ Return value: Relinearization result ciphertext.

#### Function rescale

```c++
BfvCiphertext rescale(const BfvCiphertext& x_ct);
```


Perform rescale on BFV ciphertext, reducing the ciphertext modulus by one component.

+ Parameters:
  + `x_ct`: Input ciphertext.

+ Return value: Rescale result ciphertext.

#### Function rotate_rows

```c++
BfvCiphertext rotate_rows(const BfvCiphertext& x_ct);
```

Perform row rotation operation on input ciphertext.

+ Parameters:
  + `x_ct`: Input ciphertext.

+ Return value: Rotation result ciphertext.

#### Function rotate_cols

```c++
BfvCiphertext rotate_cols(const BfvCiphertext& x_ct, int32_t step);  // (1)
std::map<int32_t, BfvCiphertext> rotate_cols(const BfvCiphertext& x_ct, const std::vector<int32_t>& steps);  // (2)
```

Perform column rotation operation on input ciphertext.

(1) Input one rotation step, output one result ciphertext.

+ Parameters:
  - `x_ct`: Input ciphertext.
  - `step`: Rotation step.

+ Return value: Single-step rotation result ciphertext.

(2) Input multiple rotation steps, output multiple result ciphertexts.

+ Parameters:
  - `x_ct`: Input ciphertext.
  - `steps`: Vector of rotation steps.

+ Return value: Map of multiple result ciphertexts, where rotation steps are the keys and corresponding result ciphertexts are the values.

The rotation keys used by this function need to be generated in advance using the BfvContext::gen_rotation_keys() function. For each specified rotation step, this function internally writes the rotation step in NAF form and splits it into one or more basic rotation operations. Therefore, the actual number of basic rotation operations executed by this function depends on the number of input rotation steps and their values.

#### Function advanced_rotate_cols

```c++
BfvCiphertext advanced_rotate_cols(const BfvCiphertext& x_ct, int32_t step);  // (1)
std::map<int32_t, BfvCiphertext> advanced_rotate_cols(const BfvCiphertext& x_ct, const std::vector<int32_t>& steps);  // (2)
```

Perform rotation operation on input ciphertext.

(1) Input one rotation step, output one result ciphertext.

+ Parameters:
  - `x_ct`: Input ciphertext.
  - `step`: Rotation step.

+ Return value: Single-step rotation result ciphertext.

(2) Input multiple rotation steps, output multiple result ciphertexts.

- Parameters:
  - `x_ct`: Input ciphertext.
  - `steps`: Vector of rotation steps.

- Return value: Map of multiple result ciphertexts, where rotation steps are the keys and corresponding result ciphertexts are the values.

The rotation keys used by this function need to be generated in advance using the BfvContext::gen_rotation_keys_for_rotations() function. For each specified rotation step, this function uses the prepared corresponding rotation key. If this rotation key does not exist, the function will report an error. If all rotation keys exist, this function performs hoisted rotation and outputs one or more result ciphertexts.

#### Function plaintext_to_plaintext_ringt

```c++
BfvPlaintextRingt plaintext_to_plaintext_ringt(const BfvPlaintext& x_pt);
```

Convert a BFV plaintext to a BFV plaintext on ring t.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Plaintext on ring t.

### CkksContext Class

The `CkksContext` class inherits from the `FheContext` class and has all the methods of the `FheContext` class, which will not be repeated here.

#### Function create_empty_context

```c++
static CkksContext create_empty_context(const CkksParameter& param);
```

Create an empty CkksContext where the private key, encryption public key, relinearization public key, and rotation public key are all empty values.

- Parameters:
  - `param`: Homomorphic parameters.

- Return value: Created context.

#### Function create_random_context

```c++
static CkksContext create_random_context(const CkksParameter& param);
```

Create a new CkksContext with randomly generated private key, encryption public key, and relinearization public key.

+ Parameters:
  + `param`: Homomorphic parameter object.

+ Return value: Created CkksContext.

#### Function gen_rotation_keys

```c++
void gen_rotation_keys();
```

Generate a standard set of rotation keys in the context, including rotation keys for conjugation operations and rotation keys with rotation steps in the form $\pm 2^i$.

#### Function gen_rotation_keys_for_rotations

```c++
void gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows = false, int level = MAX_LEVEL);
```

Generate specified rotation keys in the context.

+ Parameters:
  + `rots`: Rotation steps.
  + `include_swap_rows`: Whether to include rotation keys for row swapping.
  + `level`: Level of the generated rotation keys, default is the maximum level corresponding to the current homomorphic parameters.

#### Function make_public_context

```c++
CkksContext make_public_context();
```

In multi-threaded scenarios, each thread needs its own context. The new context generated by calling this method from the source context object does not contain the private key information from the source context, but has the same encryption public key, relinearization public key, and rotation public key as the source context.

+ Parameters: None.

+ Return value: Context without private key information.

#### Function get_parameter

```c++
virtual const CkksParameter& get_parameter();
```

Get the homomorphic parameters corresponding to the context.

+ Parameters: None.

- Return value: Homomorphic parameters.

#### Function serialize

```c++
std::vector<uint8_t> serialize() const;
```

Serialize CkksContext into a byte array.

+ Parameters: None.

+ Return value: Serialized byte array.

#### Function deserialize

```c++
static CkksContext deserialize(const std::vector<uint8_t>& data);
```

Deserialize a byte array into CkksContext.

+ Parameters:
  + `data`: Pointer to the start of the byte array.

+ Return value: Deserialized CkksContext.

#### Function encode

```c++
CkksPlaintext encode(const std::vector<double>& x_mg, int level, double scale);
```


Encode message data into a CKKS plaintext. The message data is an array where each element represents an original message.

+ Parameters:
  + `x_mg`: Input message data.
  + `level`: Level of the output plaintext.
  + `scale`: Encoding scale.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_ringt

```c++
CkksPlaintextRingt encode_ringt(const std::vector<double>& x_mg, double scale);
```

Encode message data into a CKKS plaintext on ring t for multiplication.

+ Parameters:
  + `x_mg`: Input message data.
  + `scale`: Encoding scale.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_mul

```c++
CkksPlaintextMul encode_mul(const std::vector<double>& x_mg, int level, double scale);
```

Encode message data into a CKKS plaintext for multiplication.

+ Parameters:
  + `x_mg`: Input message data.
  + `level`: Level of the output plaintext.
  + `scale`: Encoding scale.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_coeffs

```c++
CkksPlaintext encode_coeffs(const std::vector<double>& x_mg, int level, double scale);
```

Encode a floating-point array into a CKKS plaintext where array elements are directly embedded into plaintext polynomial coefficients. Does not support element-wise multiplication.

+ Parameters:
  + `x_mg`: Input floating-point array.
  + `level`: Level of the output plaintext.
  + `scale`: Encoding scale.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_coeffs_ringt

```c++
CkksPlaintextRingt encode_coeffs_ringt(const std::vector<double>& x_mg, double scale);
```

Encode a floating-point array into a CKKS plaintext on ring t for multiplication, where array elements are directly embedded into plaintext polynomial coefficients. Does not support element-wise multiplication.

+ Parameters:
  + `x_mg`: Input floating-point array.
  + `scale`: Encoding scale.

+ Return value: Encoded plaintext for multiplication.

#### Function encode_coeffs_mul

```c++
CkksPlaintextMul encode_coeffs_mul(const std::vector<double>& x_mg, int level, double scale);
```

Encode a floating-point array into a CKKS plaintext for multiplication, where array components are directly embedded into plaintext polynomial coefficients. Does not support element-wise multiplication.

+ Parameters:
  + `x_mg`: Input floating-point array.
  + `level`: Level of the output plaintext.
  + `scale`: Encoding scale.

+ Return value: Encoded plaintext for multiplication.

#### Function decode

```c++
std::vector<double> decode(const CkksPlaintext& x_pt);
```

Decode a CKKS plaintext into message data.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Decoded message data.

#### Function decode_coeffs

```c++
std::vector<double> decode_coeffs(const CkksPlaintext& x_pt);
```

Decode a CKKS plaintext into a floating-point array.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Decoded floating-point array.

#### Function new_ciphertext

```c++
CkksCiphertext new_ciphertext(int level, double scale);
```

Create a new ciphertext and allocate space for it based on input parameters.

+ Parameters:
  + `level`: Level of the new ciphertext.
  + `scale`: Encoding scale.

+ Return value: Created ciphertext.

#### Function encrypt_asymmetric

```c++
CkksCiphertext encrypt_asymmetric(const CkksPlaintext& x_pt);
```

Encrypt a CKKS plaintext using the encryption public key.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Encrypted ciphertext.

#### Function encrypt_symmetric

```c++
CkksCiphertext encrypt_symmetric(const CkksPlaintext& x_pt);
```

Encrypt a CKKS plaintext using the private key.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Encrypted ciphertext.

#### Function encrypt_symmetric_compressed

```c++
CkksCompressedCiphertext encrypt_symmetric_compressed(const CkksPlaintext& x_pt);
```

Encrypt a CKKS plaintext using the private key and compress it.

+ Parameters:
  + `x_pt`: Input plaintext.

+ Return value: Encrypted compressed ciphertext, half the size of CkksCiphertext.

#### Function decrypt

```c++
CkksPlaintext decrypt(const CkksCiphertext& x_ct);  // (1)
CkksPlaintext decrypt(const CkksCiphertext3& x_ct);  // (2)
```

(1) Decrypt a CKKS ciphertext using the decryption private key.

(2) Decrypt a CKKS ciphertext containing 3 polynomials using the decryption private key.

+ Parameters:
  + `x_ct`: Input ciphertext, where the degree of the ciphertext is 1 or 2.

+ Return value: Decrypted plaintext.

#### Function add

```c++
CkksCiphertext add(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct);
```

Compute ciphertext plus ciphertext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_ct`: Input ciphertext.

+ Return value: Addition result ciphertext.

#### Function add_plain

```c++
CkksCiphertext add_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt);
```

Compute ciphertext plus plaintext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_pt`: Input plaintext.

+ Return value: Addition result ciphertext.

#### Function sub

```c++
CkksCiphertext sub(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct);
```

Compute ciphertext minus ciphertext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_ct`: Input ciphertext.

+ Return value: Subtraction result ciphertext.

#### Function mult

```c++
CkksCiphertext3 mult(const CkksCiphertext& x0_ct, const CkksCiphertext& x1_ct);
```

Compute ciphertext times ciphertext, obtaining a ciphertext with 3 polynomials.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_ct`: Input ciphertext.

+ Return value: Multiplication result ciphertext.

#### Function mult_plain

```c++
CkksCiphertext mult_plain(const CkksCiphertext& x0_ct, const CkksPlaintext& x1_pt);
```

Compute ciphertext times plaintext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_pt`: Input plaintext.

+ Return value: Multiplication result ciphertext.

#### Function mult_plain_mul

```c++
CkksCiphertext mult_plain_mul(const CkksCiphertext& x0_ct, const CkksPlaintextMul& x1_pt);
```

Compute ciphertext times plaintext.

+ Parameters:
  + `x0_ct`: Input ciphertext.
  + `x1_pt`: Input plaintext.

+ Return value: Multiplication result ciphertext.

#### Function ringt_to_mul

```c++
CkksPlaintextMul ringt_to_mul(const CkksPlaintextRingt& x_pt, int level);
```

Convert multiplication plaintext on ring t to regular multiplication plaintext.

+ Parameters:
  + `x_pt`: Input plaintext on ring t.
  + `level`: Level of the output plaintext.

+ Return value: Plaintext in `CkksPlaintextMul` format.

#### Function compressed_ciphertext_to_ciphertext

```c++
CkksCiphertext compressed_ciphertext_to_ciphertext(const CkksCompressedCiphertext& x_ct);
```

Convert compressed CKKS ciphertext to regular ciphertext.

+ Parameters:
  + `x_ct`: Compressed CKKS ciphertext.

+ Return value: Regular ciphertext.

#### Function relinearize

```c++
CkksCiphertext relinearize(const CkksCiphertext3& x_ct);
```

Compute ciphertext relinearization.

+ Parameters:
  + `x_ct`: Input ciphertext.

+ Return value: Relinearization result ciphertext.

#### Function drop_level

```c++
CkksCiphertext drop_level(const CkksCiphertext& x_ct);
```

Reduce the level of the current CKKS ciphertext by 1.

+ Parameters:
  + `x_ct`: Input ciphertext.

+ Return value: Ciphertext after level reduction.

#### Function rescale

```c++
CkksCiphertext rescale(const CkksCiphertext& x_ct, double min_scale);
```

Perform rescale on CKKS ciphertext, reducing the ciphertext modulus by one component.

+ Parameters:
  + `x_ct`: Input ciphertext.
  + `min_scale`: Specified minimum scale value for the ciphertext after rescale.

+ Return value: Rescale result ciphertext.

#### Function conjugate

```c++
CkksCiphertext conjugate(const CkksCiphertext& x_ct);
```

Perform conjugation operation on ciphertext.

+ Parameters:
  + `x_ct`: Input ciphertext.

+ Return value: Conjugated ciphertext of the input.

#### Function rotate

```c++
CkksCiphertext rotate(const CkksCiphertext& x_ct, int32_t step);  // (1)
std::map<int32_t, CkksCiphertext> rotate(const CkksCiphertext& x_ct, const std::vector<int32_t>& steps);  // (2)
```

Perform rotation operation on input ciphertext.

(1) Input one rotation step, output one result ciphertext.

+ Parameters:
  - `x_ct`: Input ciphertext.
  - `step`: Rotation step.

+ Return value: Single-step rotation result ciphertext.

(2) Input multiple rotation steps, output multiple result ciphertexts.

+ Parameters:
  - `x_ct`: Input ciphertext.
  - `steps`: Vector of rotation steps.

+ Return value: Map of multiple result ciphertexts, where rotation steps are the keys and corresponding result ciphertexts are the values.

The rotation keys used by this function need to be generated in advance using the CkksContext::gen_rotation_keys() function. For each specified rotation step, this function internally writes the rotation step in NAF form and splits it into one or more basic rotation operations. Therefore, the actual number of basic rotation operations executed by this function depends on the number of input rotation steps and their values.

#### Function advanced_rotate

```c++
CkksCiphertext advanced_rotate(const CkksCiphertext& x_ct, int32_t step);  // (1)
std::map<int32_t, CkksCiphertext> advanced_rotate(const CkksCiphertext& x_ct, const std::vector<int32_t>& steps);  // (2)
```

Perform rotation operation on input ciphertext.

(1) Input one rotation step, output one result ciphertext.

+ Parameters:
  - `x_ct`: Input ciphertext.
  - `step`: Rotation step.

+ Return value: Single-step rotation result ciphertext.


(2) Input multiple rotation steps, output multiple result ciphertexts.

+ Parameters:
  - `x_ct`: Input ciphertext.
  - `steps`: Vector of rotation steps.

+ Return value: Map of multiple result ciphertexts, where rotation steps are the keys and corresponding result ciphertexts are the values.

The rotation keys used by this function need to be generated in advance using the CkksContext::gen_rotation_keys_for_rotations() function. For each specified rotation step, this function uses the prepared corresponding rotation key. If this rotation key does not exist, the function will report an error. If all rotation keys exist, this function performs hoisted rotation and outputs one or more result ciphertexts.

### CkksBtpContext Class

The `CkksBtpContext` class inherits from the `FheContext` and `CkksContext` classes and has all the methods of these classes, which will not be repeated here.

#### Function create_random_context

```c++
static CkksBtpContext create_random_context(const CkksBtpParameter& param);
```

Create a new CkksBtpContext with randomly generated private key, encryption public key, relinearization public key, and rotation public key.

+ Parameters:
  + `param`: Homomorphic parameters.

+ Return value: Created context.

#### Function gen_rotation_keys

```c++
void gen_rotation_keys();
```

Generate rotation keys in the context.

#### Function gen_rotation_keys_for_rotations

```c++
void gen_rotation_keys_for_rotations(const std::vector<int32_t>& rots, bool include_swap_rows = false);
```

Generate specified rotation keys in the context.

+ Parameters:
  + `rots`: Column rotation steps.
  + `include_swap_rows`: Whether to include row rotation.

#### Function make_public_context

```c++
CkksBtpContext make_public_context();
```

In multi-threaded scenarios, each thread needs its own context. The sub-context generated by calling this method from the source context object does not contain the private key information from the source context, but has the same encryption public key, relinearization public key, and rotation public key as the source context.

+ Parameters: None.

+ Return value: Sub-context.

#### Function shallow_copy_context

```c++
CkksBtpContext shallow_copy_context();
```

Shallow copy a CkksBtpContext. When multiple threads need to use the same context in parallel, the context needs to be shallow copied and passed to different threads separately.

+ Parameters: None.

+ Return value: Copied context.

#### Function get_parameter

```c++
CkksParameter& get_parameter() override;
```

Extract homomorphic parameters from the input context.

+ Parameters: None.

+ Return value: Homomorphic parameters.

#### Function bootstrap

```c++
CkksCiphertext bootstrap(const CkksCiphertext& x_ct);
```

Perform ciphertext bootstrapping operation on the input ciphertext.

+ Parameters:
  + `x_ct`: Input ciphertext.

+ Return value: Bootstrapped ciphertext.

### Distributed Multi-Party Homomorphic Computing Classes

The LattiSense SDK also provides distributed computing and multi-party secure computation capabilities, supporting secure execution of FHE computations among multiple participants.

#### DBfvContext Class

Distributed BFV context class, inheriting from BfvContext, supporting multi-party secure computation protocols.

```c++
static DBfvContext create_random_context(const BfvParameter& param, const std::vector<uint8_t>& seed, double sigma_smudging);
```

#### Multi-Party Computation Context Classes

- **CkgContext**: Key generation context for multi-party public key generation.
- **RkgContext**: Relinearization key generation context for multi-party relinearization key generation.
- **RtgContext**: Rotation key generation context for multi-party rotation key generation.
- **E2sContext**: Ciphertext to secret share conversion context.
- **S2eContext**: Secret share to ciphertext conversion context.
- **RefreshContext**: Ciphertext refresh context.
- **RefreshAndPermuteContext**: Ciphertext refresh and permutation context.

#### Secret Share Classes

Various secret shares used in multi-party computation:

- **PublicKeyShare**: Public key share
- **RelinKeyShare**: Relinearization key share
- **GaloisKeyShare**: Rotation key share
- **AdditiveShare**: Additive secret share
- **E2sPublicShare**: Ciphertext to secret share public share
- **S2ePublicShare**: Secret share to ciphertext public share
- **RefreshShare**: Refresh share
- **RefreshAndPermuteShare**: Refresh and permutation share

All these classes provide `serialize()` and `deserialize()` methods for network transmission. For detailed usage of multi-party computation protocols, please refer to relevant example code.

## Application Program Interface - Heterogeneous Computing API

The Heterogeneous Computing API is the unified interface for the LattiSense Platform to support multiple computing backends including CPU and GPU. This API provides flexible heterogeneous computing capabilities, allowing users to select the most suitable computing backend to execute fully homomorphic encryption tasks based on computational requirements and hardware resources. Using the Heterogeneous Computing API depends on the directed acyclic graph information (MegaAG) mentioned earlier.

### Heterogeneous Computing Architecture

The heterogeneous computing architecture of the LattiSense Platform is designed based on the unified `FheTask` abstract class, supporting two computing backends:

- **FheTaskCpu**: CPU-based homomorphic encryption computation, suitable for general environments.
- **FheTaskGpu**: GPU-based homomorphic encryption computation, suitable for environments equipped with general-purpose GPUs.

To use the C++ Heterogeneous Computing API, include the header file:

```c++
#include "cxx_fhe_task.h"
```

### FheTask Base Class

`FheTask` is the abstract base class of the heterogeneous computing architecture, defining a unified task execution interface. All specific computing backends (CPU, GPU) inherit from this base class and implement the core `run()` method.

#### Constructor FheTask

```c++
FheTask() = default;  // (1)
FheTask(const std::string& project_path);  // (2)
FheTask(const FheTask& other) = delete;  // (3)
FheTask(FheTask&& other);  // (4)
```

(1) Default constructor, creates an empty task object.

(2) Create a task object through project path.

+ Parameters
  - `project_path`: Task project path, containing task configuration and resource information.

(3) Copy constructor is disabled.

(4) Move constructor, transfers resource ownership.

#### Destructor ~FheTask

```c++
virtual ~FheTask();
```

Release resources corresponding to the `FheTask` object.

#### Operator operator=

```c++
void operator=(const FheTask& other) = delete;  // (1)
void operator=(FheTask&& other);  // (2)
```


(1) Copy assignment operator is disabled.

(2) Move assignment operator, transfers resource ownership.

#### Function run

```c++
virtual uint64_t run(FheContext* context, 
                     const std::vector<CxxVectorArgument>& cxx_args) = 0;
```

Core virtual function for executing fully homomorphic encryption tasks. Derived classes implement this function to define specific computation logic.

- Parameters
  - `context`: Pointer to FHE context object, containing encryption parameters and keys required for task execution.
  - `cxx_args`: Array containing task input/output parameter information, with each parameter described by a `CxxVectorArgument` struct.

- Return value: Task execution time (in microseconds).

### FheTaskCpu Class

The `FheTaskCpu` class inherits from the `FheTask` base class, implementing CPU-based fully homomorphic encryption computation.

#### Constructor FheTaskCpu

```c++
FheTaskCpu() = default;  // (1)
FheTaskCpu(const std::string& project_path);  // (2)
```

(1) Default constructor, creates an empty CPU task object.

(2) Create a CPU task object through project path.

+ Parameters
  - `project_path`: Task project path, containing configuration information for CPU computation tasks.

#### Function run

```c++
uint64_t run(FheContext* context, 
             const std::vector<CxxVectorArgument>& cxx_args) override;
```

Execute fully homomorphic encryption computation task on CPU.

- Parameters
  - `context`: Pointer to FHE context object, containing encryption parameters and key information.
  - `cxx_args`: Input/output parameter array, with each parameter described by a `CxxVectorArgument` struct.

- Return value: Task execution time (in microseconds).

*Example*

```c++
// Create CPU computation task
FheTaskCpu cpu_task("./cpu_project");

// Prepare input/output parameters
vector<CxxVectorArgument> cxx_args = {
    {"input_x", &x_ciphertext},
    {"input_y", &y_ciphertext},
    {"output_z", &z_ciphertext},
};

// Execute CPU computation
uint64_t cpu_time = cpu_task.run(&context, cxx_args);
```

### FheTaskGpu Class

The `FheTaskGpu` class inherits from the `FheTask` base class, implementing GPU-based fully homomorphic encryption computation.

#### Constructor FheTaskGpu

```c++
FheTaskGpu() = default;  // (1)
FheTaskGpu(const std::string& project_path);  // (2)
```

(1) Default constructor, creates an empty GPU task object.

(2) Create a GPU task object through project path.

+ Parameters
  - `project_path`: Task project path, containing configuration information for GPU computation tasks.

#### Destructor ~FheTaskGpu

```c++
~FheTaskGpu();
```

Release GPU resources corresponding to the GPU task object.

#### Function run

```c++
uint64_t run(FheContext* context,
             const std::vector<CxxVectorArgument>& cxx_args,
             bool print_time = true);
```

Execute fully homomorphic encryption computation task on GPU.

- Parameters
  - `context`: Pointer to FHE context object, containing encryption parameters and key information.
  - `cxx_args`: Input/output parameter array, with each parameter described by a `CxxVectorArgument` struct.
  - `print_time`: Whether to print execution time, default is `true`.

- Return value: Task execution time (in microseconds).

*Example*

```c++
// Create GPU computation task
FheTaskGpu gpu_task("./gpu_project");

// Prepare input/output parameters
vector<CxxVectorArgument> cxx_args = {
    {"input_x", &x_ciphertext},
    {"input_y", &y_ciphertext},
    {"output_z", &z_ciphertext},
};

// Execute GPU computation
uint64_t gpu_time = gpu_task.run(&context, cxx_args);
```

### CxxArgumentType Enum

The `CxxArgumentType` enum defines the parameter types supported in heterogeneous computing tasks, used to describe the data types of input and output parameters.

### CxxVectorArgument Struct

The `CxxVectorArgument` struct is used to describe information about each input/output parameter in heterogeneous computing tasks, containing key information such as parameter identifier, type, level, and data handle pointers.

#### Member Variables

```c++
struct CxxVectorArgument {
    std::string arg_id;                  // Parameter id
    CxxArgumentType type;                // Parameter type
    int level;                          // Parameter level
    std::vector<Handle*> flat_handles;  // Pointers to data handles contained in the parameter
};
```

- **arg_id**: Unique identifier of the parameter, used to match corresponding parameters in task configuration
- **type**: Data type of the parameter, must be one of the `CxxArgumentType` enum values
- **level**: Encryption level of the parameter, used for ciphertext operation compatibility checks
- **flat_handles**: Array of Handle pointers containing actual data, supporting multi-dimensional vector data

#### Constructor CxxVectorArgument

```c++
template <typename T> CxxVectorArgument(std::string id, T* hdl);
```

Template constructor that can accept various types of Handle objects or vectors.

- Parameters
  - `id`: Parameter identifier.
  - `hdl`: Data corresponding to the parameter, can be a single Handle object or a tensor of arbitrary dimensions composed of `std::vector`. Supported object types include `BfvCiphertext`, `BfvCiphertext3`, `BfvPlaintext`, `BfvPlaintextRingt`, `BfvPlaintextMul`, `CkksCiphertext`, `CkksCiphertext3`, `CkksPlaintext`, `CkksPlaintextRingt`, `CkksPlaintextMul`. It should be noted that `CxxVectorArgument` is used to store user input/output plaintexts/ciphertexts, meaning that keys such as `BfvRelinKey`, `BfvGaloisKey`, `CkksRelinKey`, `CkksGaloisKey` are handled internally automatically and should not be used to construct `CxxVectorArgument`.

*Example*

```c++
// Prepare input data
vector<uint64_t> x_data({5, 10});
vector<uint64_t> y_data({2, 3});
BfvPlaintext x_pt = context.encode(x_data, level);
BfvPlaintext y_pt = context.encode(y_data, level);   
BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);    // Input ciphertext
BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);    // Input ciphertext
BfvCiphertext z_ct = context.new_ciphertext(level);       // Output ciphertext

// Construct parameter vector
vector<CxxVectorArgument> cxx_args = {
    {"input_x", &x_ct},
    {"input_y", &y_ct}, 
    {"output_z", &z_ct},
};

// Support vector form parameters
vector<BfvCiphertext> ct_vector = {x_ct, y_ct};
CxxVectorArgument vector_arg("ct_vector", &ct_vector);
```

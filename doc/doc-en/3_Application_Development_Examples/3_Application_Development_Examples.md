[TOC]

# Application Development Examples

In this chapter, we demonstrate the development process and functional characteristics of the LattiSense Platform through several typical application tasks.

## Computing Multiplication Using the BFV Algorithm

In this section, we demonstrate a simple example to complete a BFV ciphertext multiplication.

For different computing chips, the LattiSense Platform supports the same development process, divided into offline and online phases. In addition, for CPU computing power, the platform also supports a development process without using the FHE instruction compiler. Next, we will demonstrate how to complete a BFV ciphertext multiplication in cases without using the FHE instruction compiler and using the FHE instruction compiler respectively.

### Development Process Without Using FHE Instruction Compiler

Computing BFV ciphertext multiplication can be divided into the following 4 steps:

Step 1: Users first need to select appropriate homomorphic parameters. After selecting the polynomial degree $n$ and plaintext modulus $t$, use `create_parameter(n, t)` to generate homomorphic parameters, then call `create_random_context(param)` to generate the corresponding context. Only after completing these two operations can subsequent basic arithmetic operations be performed. The level in the example represents the number of RNS components of a plaintext or ciphertext in the BFV algorithm minus one. The maximum level can be obtained through the `BfvParameter::get_max_level()` function. In this example, we use `level = 3`. The level of the plaintext needs to be specified when encoding later.

```C++
uint64_t t = 0x1b4001;
uint64_t n = 16384;
BfvParameter param = BfvParameter::create_parameter(n, t);
BfvContext context = BfvContext::create_random_context(param);
int level = 3;
```

Step 2: In this example, we compute two integer multiplications $5 \times 2$ and $10 \times 3$. At this point, we can use the SIMD feature of the BFV algorithm to pack (5,10) into one ciphertext and (2,3) into another ciphertext. When the two ciphertexts perform homomorphic multiplication, the corresponding components also complete the corresponding multiplication operations. Specifically, we first need to encode the message data using `encode()` to obtain the plaintext object, and then encrypt the plaintext object using `encrypt_asymmetric()` to obtain the ciphertext object. The `encrypt_asymmetric()` used here represents asymmetric encryption. There is also a symmetric encryption function `encrypt_symmetric()` in the SDK.

```C++
vector<uint64_t> x_mg({5, 10});
vector<uint64_t> y_mg({2, 3});
BfvPlaintext x_pt = context.encode(x_mg, level);
BfvPlaintext y_pt = context.encode(y_mg, level);
BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);
```

Step 3: Use `mult()` to perform multiplication operations on ciphertext. The result of the BFV algorithm's multiplication operator is a ciphertext with 3 polynomials, and we want the ciphertext to remain as 2 polynomials, so we need to use `relinearize()` to perform relinearization on the result ciphertext.

```C++
BfvCiphertext3 z_ct3 = context.mult(x_ct, y_ct);
BfvCiphertext z_ct = context.relinearize(z_ct3);
```

Step 4: To verify the correctness of the result, we need to restore the ciphertext to plaintext result data. Therefore, we need to first decrypt using `decrypt()` to obtain the plaintext, and then decode the plaintext using `decode()` to obtain the data message.

```C++
BfvPlaintext z_pt = context.decrypt(z_ct);
vector<uint64_t> z_mg = context.decode(z_pt);
print_message(z_mg.data(), "z_mg", 2);  // Print result: x2_mg = [10, 30, ...]
```

This process is similar to most current homomorphic algorithm libraries.

### Development Process Using FHE Instruction Compiler

Here we use the LattiSense Platform to call CPU to complete a BFV ciphertext multiplication.

**Offline Phase: Custom Computation Task**

After selecting the homomorphic parameters, users write a Python program to describe the abstract computation flow. Generally, this abstract computation flow can be seen as a directed acyclic graph composed of abstract data nodes and abstract computation nodes. Then call library functions to translate and compile the custom computation task.

An abstract computation graph for BFV ciphertext multiplication can be represented as the following diagram.

![fhe_pipeline](image-20231205120746833.png)

The 3 ciphertext data nodes in the diagram are assumed to be all at level 3. This computation graph can be represented by the following code:

```python
level = 3
x = BfvCiphertextNode('x', level)
y = BfvCiphertextNode('y', level)
z = mult_relin(x, y, 'z')
```

For the data x and y in this computation graph, two data nodes need to be constructed. The line of code `z = mult_relin(x, y, 'z')` defines a computation node and the output data node of this computation node. Given the type of the computation node and the type and level of the input data nodes, the type and level of the output data node can be inferred, so intermediate data nodes and output data nodes do not need to be defined separately.

For this example, after describing the abstract computation graph, it is necessary to set the global FHE parameters, then call the `process_custom_task()` library function to generate the corresponding FHE operator instructions and output them to the specified directory:

```Python
# Set global parameters (custom parameters, only for CPU execution)
param = Param.create_bfv_custom_param(
    n=8192,
    p=[0x7ffffffffb4001],
    q=[0x3fffffffef8001, 0x4000000011c001, 0x40000000120001],
    t=0x28001
)
set_fhe_param(param)

# Compile task
process_custom_task(
    input_args=[Argument('x', x), Argument('y', y)],
    output_args=[Argument('z', z)],
    output_instruction_path='examples/bfv_mult',
    fpga_acc=False,
)
```
Here `fpga_acc = False` indicates that this is a task executed by CPU or GPU, and `param = Param.create_bfv_custom_param(...)` is the homomorphic parameter completely customized by the user. Of course, the LattiSense Platform also supports users to select default parameters based only on the polynomial degree.

**Online Phase: Call Computing Chips to Execute Custom Tasks**

In the online phase, users load custom tasks in the application program, input specific data, call appropriate computing power to execute custom tasks and obtain output data.

The online phase code of this example is completely the same as Steps 1, 2, and 4 of the previous example [Development Process Without Using FHE Instruction Compiler](#development-process-without-using-fhe-instruction-compiler), only Step 3 ciphertext computation step is different.

Step 3: Load the computation task generated in the offline phase,

```C++
FheTaskCpu project("example/bfv_mult");
```

Before executing computation, input and output data need to correspond to objects in the abstract custom task. For the output data `z_ct` in this example, we need to use `new_ciphertext()` to create a new ciphertext to correspond to it. In the custom task, the input and output data of ciphertext multiplication are named "x", "y", "z" respectively. In the online phase code, they are `x_ct`, `y_ct`, `z_ct` respectively. `vector<CxxVectorArgument> cxx_args` represents this correspondence. Finally, we call the `run()` member function, specify the context and data, and execute ciphertext computation on the corresponding computing chip. (Note: In the algorithm, the relinearization operation requires the use of the relinearization public key. In this example, the SDK will automatically extract the relinearization public key contained in the context and load it together with the input data into the computing chip.)

```C++
BfvCiphertext z_ct = context.new_ciphertext(level);
vector<CxxVectorArgument> cxx_args = {
    {"x", &x_ct},
    {"y", &y_ct},
    {"z", &z_ct},
};
project.run(&context, cxx_args);
```

After that, decryption and decoding of `z_ct` can obtain results consistent with the previous section.

In subsequent examples, we will only focus on the development process using the FHE instruction compiler.

## Computing Polynomial Using the BFV Algorithm

In this example, our custom task is to compute a seventh-degree polynomial $y = \sum_{i=0}^7 a_i \cdot x^{i}$, where the coefficients $a_i$ are in plaintext form and the data $x$ is in ciphertext form. The computation of this seventh-degree polynomial includes computing various powers $x^i, i=2,3,\ldots,7$ from $x$, as well as computing ciphertext-plaintext multiplication and accumulation of each coefficient $a_i$ with $x^i$. Here we demonstrate how to perform computations at the lowest possible level to minimize ciphertext computation.

**Offline Phase**

For the ciphertext-plaintext multiplication and accumulation of $a_i$ with $x^i$, the multiplication depth is 1, which can be executed at level 1. Computing different powers of $x$ requires different multiplication depths. After calculation, we can use the following computation graph to compute each $x^i$, where solid lines represent ciphertext multiplication and dashed lines represent rescale:

![fhe_pipeline](image-20231205143802781.png)

The following code describes the computation flow of the entire seventh-degree polynomial:

```python
x = BfvCiphertextNode('x', 4)
a0 = BfvPlaintextNode('a_0', 1)
a = [BfvPlaintextMulNode(f'a_{i}', 1) for i in range(1, 8)]

x1_lv4 = x
x2_lv3 = rescale(mult_relin(x1_lv4, x1_lv4))
x1_lv3 = rescale(x1_lv4)
x3_lv2 = rescale(mult_relin(x1_lv3, x2_lv3))
x4_lv2 = rescale(mult_relin(x2_lv3, x2_lv3))
x2_lv2 = rescale(x2_lv3)
x5_lv1 = rescale(mult_relin(x2_lv2, x3_lv2))
x6_lv1 = rescale(mult_relin(x3_lv2, x3_lv2))
x7_lv1 = rescale(mult_relin(x3_lv2, x4_lv2))
x2_lv1 = rescale(x2_lv2)
x3_lv1 = rescale(x3_lv2)
x4_lv1 = rescale(x4_lv2)
x1_lv2 = rescale(x1_lv3)
x1_lv1 = rescale(x1_lv2)
x_powers = [x1_lv1, x2_lv1, x3_lv1, x4_lv1, x5_lv1, x6_lv1, x7_lv1]
y = a0
for i in range(7):
    y = add(y, mult(x_powers[i], a[i]))

# Set global parameters (custom parameters, only for CPU execution)
param = Param.create_bfv_custom_param(
    n=8192,
    p=[0x7ffffffffb4001],
    q=[0x3fffffffef8001, 0x4000000011c001, 0x40000000120001, 0x3fffffffd08001, 0x7fffffffe90001],
    t=0x1b4001
)
set_fhe_param(param)

# Compile task
process_custom_task(
    input_args=[Argument('x', x), Argument('a0', a0), Argument('a', a)],
    output_args=[Argument('y', y)],
    output_instruction_path='examples/bfv_poly_7',
    fpga_acc=False,
)
```

Note in this example:

1. $a_0$ participates in ciphertext+plaintext, while other plaintext coefficients $a_i$ participate in ciphertext*plaintext. These two types of plaintexts have different encoding formats and need to be defined as different types of plaintext data nodes here.
2. The list of plaintext coefficients $a_i$ can be input to `process_custom_task()` as a one-dimensional array. Two-dimensional, three-dimensional, and four-dimensional data node arrays are also supported.

**Online Phase**

After the offline phase is completed, the online phase code has the same overall structure as the previous example:

```c++
uint64_t t = 0x1b4001;
uint64_t n = 8192;
BfvParameter param = BfvParameter::create_parameter(n, t);
BfvContext context = BfvContext::create_random_context(param);

vector<uint64_t> x_mg({1, 2, 3, 4});
vector<uint64_t> a0_mg({1, 1, 1, 1});
vector<vector<uint64_t>> a_mg;
for(int i = 0; i < 7; i++) {
  a_mg.push_back({i+2, i+2, i+2, i+2});
}
BfvPlaintext x_pt = context.encode(x_mg, 4);
BfvPlaintext a0_pt = context.encode(a0_mg, 1);
vector<BfvPlaintextMul> a_pt_mul;
for(int i = 0; i < 7; i++) {
  a_pt_mul.push_back(context.encode_mul(a_mg[i], 1));
}
BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
BfvCiphertext y_ct = context.new_ciphertext(1);

FheTaskCpu cpu_project("examples/bfv_poly_7");
vector<CxxVectorArgument> cxx_args = {
    {"x", &x_ct},
    {"a0", &a0_pt},
    {"a", &a_pt_mul},
    {"y", &y_ct},
};
cpu_project.run(&context, cxx_args);

BfvPlaintext y_pt = context.decrypt(y_ct);
vector<uint64_t> y_mg = context.decode(y_pt);
print_message(y_mg.data(), "y_mg", 4);
```

It is worth noting that:

1. $a_0$ participates in ciphertext-plaintext addition, while other plaintext coefficients $a_i$ participate in ciphertext-plaintext multiplication. They need to use `encode()` ($a_0$) and `encode_mul()` ($a_i$) respectively to encode into different plaintext formats.
2. The type of the hardware task input parameter `a_pt_mul` is `vector<BfvPlaintextMul>`, which corresponds to the one-dimensional array parameter `a` in the offline phase.

## Computing Multiplication Using the CKKS Algorithm

In this example, we use the CPU to compute a CKKS ciphertext multiplication and rescale.

In the offline phase, the abstract computation description for this task can be directly written:

```python
# Set global parameters (custom parameters, only for CPU execution)
param = Param.create_ckks_custom_param(
    n=8192,
    p=[0x7ffffffffb4001],
    q=[0x3fffffffef8001, 0x4000000011c001, 0x40000000120001, 0x3fffffffd08001]
)
set_fhe_param(param)

# Define computation graph
level = 3
x = CkksCiphertextNode('x', level)
y = CkksCiphertextNode('y', level)
z = rescale(mult_relin(x, y), 'z')

# Compile task
process_custom_task(
    input_args=[Argument('x', x), Argument('y', y)],
    output_args=[Argument('z', z)],
    output_instruction_path='examples/ckks_mult',
    fpga_acc=False,
)
```

In the online phase, the message data type for CKKS is floating-point numbers. A major difference from the BFV algorithm is that users need to pay attention to the scale of each CKKS ciphertext. The default_scale of the input data is obtained by `param.get_default_scale()`, which is approximately equal to each ciphertext modulus component.

```c++
double default_scale = param.get_default_scale();
...
CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
```

After multiplication of two ciphertexts with scale `default_scale`, the scale of the product is `default_scale*default_scale`. After rescale of the product ciphertext, the level of the ciphertext decreases by 1, while the scale is divided by the last component of the current ciphertext modulus. In this example, the level of the product ciphertext is 3, so the modulus divided by is $q_3$. Thus, the scale of the computation result is $\texttt{default\_scale}^{2}/q_3$. This scale is close to the original scale `default_scale`, but the difference between them generally cannot be ignored. Users need to specify the scale of the computation result ciphertext to ensure the correctness of the decryption result. When declaring the output ciphertext, the code is as follows:

```c++
CkksCiphertext z_ct = context.new_ciphertext(level - 1, default_scale * default_scale / param.get_q(level));
```

The other code in the online part is similar to the previous example. The overall process is as follows:

```c++
uint64_t N = 8192;
CkksParameter param = CkksParameter::create_parameter(N);
CkksContext context = CkksContext::create_random_context(param);
int level = 3;
double default_scale = param.get_default_scale();

vector<double> x_mg({5.0, 10.0});
vector<double> y_mg({2.0, 3.0});
CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

FheTaskCpu cpu_project("examples/ckks_mult");
CkksCiphertext z_ct = context.new_ciphertext(level - 1, default_scale * default_scale / param.get_q(level));
vector<CxxVectorArgument> cxx_args = {
    {"x", &x_ct},
    {"y", &y_ct},
    {"z", &z_ct},
};
cpu_project.run(&context, cxx_args);

CkksPlaintext z_pt = context.decrypt(z_ct);
vector<double> z_mg = context.decode(z_pt);

print_double_message(z_mg.data(), "z_mg", 2); // Print result: z_mg = [10.000001, 30.000002, ...]
```

## Computing Logistic Regression Inference Using the CKKS Algorithm

In this example, we use the CPU to execute logistic regression inference based on the CKKS algorithm. The computation formula for logistic regression inference is:
$$
y = \mathbf{x}\cdot\mathbf{w}+b = \sum_{i=0}^{n_f-1} x_i\cdot w_i + b
$$

In a two-party computation scenario, $\mathbf{x}$ and $y$ are in ciphertext form, while $\mathbf{w}$ and $b$ are in plaintext form. To reduce communication overhead for a single inference, we encode all input feature values $\mathbf{x}$ into the first $n_f$ slots of one ciphertext (assuming the number of input feature values is not greater than the number of encoding slots 4096 in one ciphertext). Correspondingly, the coefficients $\mathbf{w}$ are encoded into the first $n_f$ slots of one plaintext. The computing party first computes the product of the ciphertext of $\mathbf{x}$ and the plaintext of $\mathbf{w}$:
$$
[\![\mathbf{u}_0]\!]=[\![\mathbf{x}]\!]\odot [\mathbf{w}]
$$

where $[\![\cdot]\!]$ denotes the ciphertext obtained after encoding and encrypting the array inside, $[\cdot]$ denotes the plaintext obtained after encoding the array inside, and $\odot$ denotes homomorphic multiplication. At this point, the computing party needs to add up the first $n_f$ values of the product $\mathbf{u}_0$. This step requires multiple rotations and accumulation of $[\![\mathbf{u}_0]\!]$. Specifically, let $n_f'$ be the smallest integer power of 2 not less than $n_f$. In the first round, the computing party computes:
$$
[\![\mathbf{u}_1]\!] = Rotate\left([\![\mathbf{u}_0]\!], \frac{n_f'}{2}\right)\oplus [\![\mathbf{u}_0]\!]
$$

where $\oplus$ denotes homomorphic addition. It can be seen that the first $\frac{n_f'}{2}$ values of $\mathbf{u}_1$ are respectively the sums of 2 numbers in $\mathbf{u}_0$. In the second round, the computing party computes:
$$
[\![\mathbf{u}_2]\!] = Rotate\left([\![\mathbf{u}_1]\!], \frac{n_f'}{4}\right)\oplus [\![\mathbf{u}_1]\!]
$$

The first $\frac{n_f'}{4}$ values of $\mathbf{u}_2$ are respectively the sums of 4 numbers in $\mathbf{u}_0$. And so on. After $\lceil \log_2 n_f \rceil$ rounds, the first value of $\mathbf{u}_{\lceil \log_2 n_f \rceil}$ is the sum of all $n_f$ products. At this point, the addition with $b$ can be computed:
$$
[\![\mathbf{s}]\!] = [\![\mathbf{u}_{\lceil \log n_f \rceil}]\!] \oplus [(b, 0, 0, \ldots)]
$$

The value of $s_0$ is the logistic regression result $y$ we need to obtain.

It is worth noting that at this time, on the result values such as $s_1$, $s_2$, etc., additional information about $\mathbf{w}$ and $b$ is contained. If the requester decrypts to obtain these values, they can obtain more model parameter information beyond $y$, making it easier to infer model parameter values. To avoid this leakage, we need to mask these components. The computing party can multiply by a mask at the end to achieve this purpose:
$$
[\![y]\!] = [\![\mathbf{s}]\!] \odot [(1, 0, 0, \dots)]
$$

The abstract computation description for the above process is:

```python
level = 3
n_input_feature = 30

x = CkksCiphertextNode(level=level)
w = CkksPlaintextRingtNode()
b = CkksPlaintextNode(level=level-1)
mask = CkksPlaintextRingtNode()

u = rescale(mult(x, w))
n_rotate = math.ceil(math.log(n_input_feature, 2))
step = int(math.pow(2, n_rotate) / 2)
for _ in range(n_rotate):
    u_rot = rotate_cols(u, step)
    u = add(u, u_rot[0])
    step = step // 2
s = add(u, b)
y = rescale(mult(s, mask))

# Set global parameters (custom parameters, only for CPU execution)
param = Param.create_ckks_custom_param(
    n=8192,
    p=[0x7ffffffffb4001],
    q=[0x3fffffffef8001, 0x4000000011c001, 0x40000000120001, 0x3fffffffd08001]
)
set_fhe_param(param)

# Compile task
process_custom_task(
    input_args=[Argument('x', x), Argument('w', w), Argument('b', b), Argument('mask', mask)],
    output_args=[Argument('y', y)],
    output_instruction_path='examples/ckks_logistic_regression',
    fpga_acc=False,
)
```

The code structure in the online phase is similar to the previous examples, encoding and encrypting each data accordingly, and configuring the scale of each parameter according to the computation flow. The code is as follows:

```c++
int level = 3;
int n_input_feature = 30;
uint64_t N = 8192;
CkksParameter param = CkksParameter::create_parameter(N);
CkksContext ctx = CkksContext::create_random_context(param);
double default_scale = param.get_default_scale();

vector<double> x_mg{
    0.04207487339675331,  -0.954683801149814,  0.09197705756340246, -0.27253446447507956, 0.18750564232192835,
    0.5840745966505123,   0.4062792877225865,  0.4622266401590458,  0.3727272727272728,   0.21103622577927572,
    -0.2877059569074779,  -0.7590611739745403, -0.2619328087452292, -0.45237748366635655, -0.6814087092497536,
    -0.29720311232613317, -0.7286363636363636, -0.3987497632127297, -0.3767096302133168,  -0.6339151223691666,
    0.24155104944859485,  -0.716950959488273,  0.336620349619005,   -0.09860401101061744, 0.20227167668229562,
    0.23858311261169463,  0.13722044728434502, 0.8240549828178696,  0.19692489651094025,  -0.16227207136298039};
vector<double> w_mg{
    -0.38779230675573784, -0.08020498791940865, -0.42494960644275187, -0.3011337927885834, 0.19736016953065058,
    -0.3452779920215878,  -0.678324870145478,   -0.8177783668067259,  0.15226510934692553, 0.5859673866284915,
    0.01255264233893136,  0.4752989745604508,   0.05023635251466458,  0.11310208234475544, 0.5530291648269257,
    0.12287678195417821,  0.3339257590342935,   0.07939103265266986,  0.5650923127926508,  0.44168413736941736,
    -0.5564150081657178,  -0.2552746866713479,  -0.544768402633023,   -0.3273054244777431, -0.05454841442127498,
    -0.3247696994741705,  -0.498143298043605,   -1.092540674562078,   0.08402652360008195, 0.16040344319412192};
vector<double> b_mg{0.430568328365614};
vector<double> mask{1.0};

auto x_pt = ctx.encode(x_mg, level, default_scale);
auto x_ct = ctx.encrypt_asymmetric(x_pt);
auto w_pt = ctx.encode_ringt(w_mg, default_scale);
auto b_pt = ctx.encode(b_mg, level - 1, default_scale * default_scale / param.get_q(level));
auto mask_pt = ctx.encode_ringt(mask, default_scale);
auto y_ct = ctx.new_ciphertext(
    level - 2, default_scale * default_scale * default_scale / param.get_q(level) / param.get_q(level - 1));

FheTaskCpu cpu_project("examples/ckks_logistic_regression");
vector<CxxVectorArgument> cxx_args = {
    {"x", &x_ct}, {"w", &w_pt}, {"b", &b_pt}, {"mask", &mask_pt}, {"y", &y_ct},
};
cpu_project.run(&ctx, cxx_args);

CkksPlaintext y_pt = ctx.decrypt(y_ct);
vector<double> y_mg = ctx.decode(y_pt);

print_double_message(y_mg.data(), "y_mg", 4);  // Print result: y_mg = [-2.883086, 0.000002, -0.000001, -0.000002, ...]
```

## Data Serialization

In a typical two-party fully homomorphic ciphertext computation mode, the overall computation flow executed by both parties is as follows:

1. The requester executes key generation, data encoding, and data encryption.
2. The requester sends public keys and ciphertext data to the computing party.
3. The computing party encodes its own data into plaintext.
4. The computing party uses the requester's public keys, the requester's ciphertext data, and its own plaintext data to execute fully homomorphic ciphertext computation.
5. The computing party sends the computation result ciphertext to the requester.
6. The requester uses the private key to decrypt the computation result ciphertext and decode it to obtain the result data.

In Steps 2 and 5 of this process, both parties need to transmit public keys and ciphertext data over the network. In this example, we demonstrate methods for serializing and deserializing these data. The computing party's computation task is to execute a CKKS ciphertext multiplication using software.

The overall computation flow above can be divided into three phases, corresponding to three functions in the example:

```c++
int main() {
    auto data_0 = client_phase_0();
    auto data_1 = server_phase_1(&get<1>(data_0), &get<2>(data_0), &get<3>(data_0));
    client_phase_2(&get<0>(data_0), &data_1);
}
```

In the first phase, the requester executes Steps 1-2. The code is as follows:

```c++
tuple<CkksContext, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>> client_phase_0() {
    int N = 16384;
    CkksParameter param = CkksParameter::create_parameter(N);
    CkksContext ctx = CkksContext::create_random_context(param);
    int level = 3;
    double default_scale = pow(2, 32);

    vector<double> x_mg({5.0, 10.0});
    vector<double> y_mg({2.0, 3.0});
    CkksPlaintext x_pt = ctx.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = ctx.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = ctx.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = ctx.encrypt_asymmetric(y_pt);

    CkksContext public_ctx = ctx.make_public_context();
    vector<uint8_t> public_ctx_bin = public_ctx.serialize();
    vector<uint8_t> x_bin = x_ct.serialize();
    vector<uint8_t> y_bin = y_ct.serialize();
    return {move(ctx), public_ctx_bin, x_bin, y_bin};
}
```

In addition to regular key generation, data encoding, and data encryption, the requester needs to call the `make_public_context()` function to generate a context containing only public key information. Next, the requester serializes the context containing only public key information, the ciphertext of x, and the ciphertext of y respectively. The resulting `public_ctx_bin`, `x_bin`, and `y_bin` are of type `vector<uint8_t>`, containing serialized binary data that can be used for network transmission. The original context does not need to be serialized and needs to be retained for subsequent decryption, so it is also part of the return value.

In the second phase, the computing party executes Steps 3-5. The code is as follows:

```c++
vector<uint8_t> server_phase_1(vector<uint8_t>* ctx_bin, vector<uint8_t>* x_bin, vector<uint8_t>* y_bin) {
    CkksContext public_context_de = CkksContext::deserialize(ctx_bin);
    CkksCiphertext x_ct_de = CkksCiphertext::deserialize(x_bin);
    CkksCiphertext y_ct_de = CkksCiphertext::deserialize(y_bin);
    CkksCiphertext3 z_ct3 = public_context_de.mult(x_ct_de, y_ct_de);
    CkksCiphertext z_ct = public_context_de.relinearize(z_ct3);
    vector<uint8_t> z_bin = z_ct.serialize(public_context_de.get_parameter());
    return z_bin;
}
```

In this example, the computing party has no data of its own that needs to be encoded. The computing party needs to deserialize the context containing only public key information, the ciphertext of x, and the ciphertext of y respectively, then can normally execute ciphertext computation, and finally serialize the result ciphertext and return it. `z_bin` can be used for network transmission.

In the third phase, the requester executes Step 6. The code is as follows:

```c++
void client_phase_2(CkksContext* ctx, vector<uint8_t>* z_bin) {
    CkksCiphertext z_ct_de = CkksCiphertext::deserialize(z_bin);
    CkksPlaintext z_pt = ctx->decrypt(z_ct_de);
    vector<double> z_mg = ctx->decode(z_pt);
    print_double_message(z_mg.data(), "z_mg", 2);  // Output: z_mg = [10.000000, 29.999998, ...]
}
```

The requester deserializes the ciphertext of z, then can use the original context for decryption and decoding to obtain the correct computation result.


[TOC]

# Platform Overview

The LattiSense FHE Development Platform is architected as a comprehensive, end-to-end environment for the construction and deployment of FHE-based solutions. A standard 2-party FHE protocol is illustrated below.

![fhe_pipeline](fhe_pipeline.png)

The primary bottleneck in such protocols is the server-side FHE computation, which entails substantial computational overhead and extensive requirements for intermediate data storage. To address these performance challenges, LattiSense integrates a set of compile-time optimizers, and a set of dynamic runtime schedulers. Analogous to the modern MLIR compilation framework, these optimizations are stratified into multiple hierarchical layers, or passes, to systematically enhance execution efficiency.

At the highest level of the representations, an FHE task is expressed as a directed acyclic graph (DAG), which in LattiSense is called the Encrypted pRocess Graph (ERG, or Erg). An Erg is composed of date nodes and compute nodes: a data node encapsulates a single (FHE) ciphertext, a plaintext, or a specific public key, while a compute node represents an operation between data nodes such as ciphertext-plaintext addition, ciphertext-ciphertext multiplication, ciphertext rotation, or the bootstrapping of a ciphertext. The LattiSense frontend provides a Python interface that enables developers to programmatically construct these Ergs.

At the execution level, the platform is designed for heterogeneous acceleration, allowing FHE tasks to be processed by CPUs, GPUs, or specialized hardware accelerators such as FPGAs and ASICs. Because these distinct processor architectures require specialized instruction sets and parallelization strategies, LattiSense performs the critical role of hardware abstraction. It automatically lowers the high-level Erg into optimized and parallelized machine instructions tailored to the specific constraints and capabilities of the user-specified processor.

## Recap: FHE Data Types and Operators (BFV & CKKS)

Fully Homomorphic Encryption (FHE) schemes, specifically the BFV (Brakerski-Fan-Vercauteren) and CKKS (Cheon-Kim-Kim-Song) algorithms, are built upon the Ring Learning With Errors (RLWE) problem over a cyclotomic ring $R = \mathbb{Z}[x]/(x^N + 1)$. All the following FHE objects are constrcuted by polynomials on $R$, or on some residue ring of $R$ modulo an integer. These schemes enable mathematical operations to be performed directly on encrypted data.

### Parameters and Key Management

The security and capacity of an FHE scheme are defined by a set of global parameters. The **Ring Dimension ($N$)** is a power of two that determines the number of coefficients in the polynomials and, consequently, the number of "slots" available for SIMD (Single Instruction, Multiple Data) processing. The **Ciphertext Modulus ($Q$)** defines the range of the coefficients in ciphertext polynomials. In BFV, the **Plaintext Modulus ($t$)** defines the range of the coefficients in plaintext polynomials, whereas CKKS uses a **Scaling Factor ($\Delta$)** for fixed-point precision.

The cryptographic lifecycle begins with **Key Generation**, the process of creating the necessary keys for a session:

- **Secret Key ($sk$):** A private polynomial $s$ with small coefficients used for decryption.
- **Public Key ($pk$):** A pair $(a, b)$ where $b = -(as + e) \pmod Q$, used for encryption.
- **Evaluation Keys ($evk$):** Specialized keys, such as **Relinearization Keys** and **Galois Keys**, which allow the server to perform complex operations like multiplication and rotation without accessing the secret key.

### The Cryptographic Pipeline

Data undergoes several transformations to enable homomorphic processing:

1. **Encode:** The process of converting a raw **Message ($m$)** (a vector of numbers) into a **Plaintext ($pt$)**, which is a polynomial in the ring $R$. This maps the user's data into the algebraic structure required for encryption.
2. **Encrypt:** The process of transforming a plaintext into a **Ciphertext ($ct$)** using the public key. A ciphertext typically consists of a pair of polynomials $(c_0, c_1)$ that hide the underlying message behind a layer of controlled noise.
3. **Decrypt:** The process of using the secret key to extract the plaintext polynomial from a ciphertext.
4. **Decode:** The final step where the plaintext polynomial is converted back into the original message format (the vector of numbers).

In the implementations, plaintexts and ciphertexts are stored in the **Residue Number System (RNS)** format. RNS represents large coefficients as a set of smaller residues modulo a chain of primes $q_1, q_2, \dots, q_k$, allowing high-precision arithmetic to be executed using standard 64-bit machine words. The RNS structure naturally gives rise to the concept of the **multiplicative level**. A ciphertext's level indicates the number of remaining primes in its RNS basis.

### Supported Computation Operations

- **Addition and Subtraction:** Point-wise operations supporting both **ct-ct** and **ct-pt** computation.

- **Multiplication:** Point-wise operation supporting both **ct-ct** and **ct-pt** multiplication. In the ct-ct case, this results in an expanded "size-3" ciphertext $(c_0, c_1, c_2)$.

- **Relinearization:** Transforms a size-3 ciphertext back into the standard size-2 form $(c_0, c_1)$.

- **Rescaling (CKKS):** Divides the message by the scaling factor and drops an RNS prime to manage magnitude.

- **Modulo Switching (BFV):** Scales down ciphertext polynomials to a smaller modulus to reduce noise.

- **Drop Level (CKKS):** Decreases the multiplicative level by removing one or more primes from the RNS basis.

- **Rotation:** Cyclically shifts message values across SIMD slots using Galois Keys.

- **Bootstrapping (CKKS):** Homomorphically evaluates the decryption circuit to refresh a ciphertext, resetting its noise and increasing its multiplicative level.

A plaintext can participate in operations including encode, decode, encrypt, decrypt, multiplication, and addition/subtraction. Regarding the computational costs, these operations have different preferences for the plaintext format. To efficiently perform these operations, 3 variants of plaintext formats are introduced. Their properties are listed below.

| Plaintext Data Format | Supported Operations                         | In NTT Form | In  Montgomery  Form | Number of RNS Components | Ciphertext Multiplication by Plaintext Computational Overhead |
| --------------------- | -------------------------------------------- | ----------- | -------------------- | ------------------------ | ------------------------------------------------------------ |
| `BfvPlaintext`        | encryption, decryption, addition/subtraction, multiplication | No          | No                   | L+1                      | Large                                                         |
| `BfvPlaintextMul`     | multiplication                               | Yes         | Yes                  | L+1                      | Small                                                        |
| `BfvPlaintextRingt`   | multiplication, addition/subtraction         | No          | No                   | 1                        | Medium                                                       |
| `CkksPlaintext`       | encryption, decryption, addition/subtraction, multiplication | Yes         | No                   | L+1                      | Medium                                                     |
| `CkksPlaintextMul`    | multiplication                               | Yes         | Yes                  | L+1                      | Small                                                        |
| `CkksPlaintextRingt`  | multiplication, addition/subtraction         | No          | No                   | 1                        | Large                                                       |

## Defining Encrypted pRocess Graphs

An **Encrypted pRocess Graph (ERG, or Erg)** serves as the structural blueprint for FHE tasks, modeled as a directed acyclic graph (DAG). In LattiSense, an Erg is composed of data nodes and compute nodes. A data node represents a single ciphertext, a plaintext, a relinearization key, a Galois key, etc. A compute node represents an operation between data nodes such as ciphertext-plaintext addition, ciphertext-ciphertext multiplication, ciphertext rotation, or the bootstrapping of a ciphertext. These nodes are "abstract" entities—they define the logic of the computation without being tied to specific physical data or memory until the moment of execution.

The LattiSense Python frontend provides a high-level interface to build these Ergs by specifying FHE parameters, defining input nodes, and chaining compute operations. As a running example, consider an order-7 polynomial evaluation: $y=\sum_{i=0}^7 a_i x^i$, where $x$ is an encrypted variable and $a_i$ are plaintext coefficients.

To initialize a task, you first establish the FHE parameters, either using a hardware-optimized default or a custom configuration:

```python
param = Param.create_bfv_default_param(n=16384)
set_fhe_param(param)
```

Next, you define the input data nodes by specifying their types and initial properties, such as their multiplicative levels:

```python
x = BfvCiphertextNode(level=4)
a0 = BfvPlaintextNode(level=1)
a = [BfvPlaintextMulNode(level=1) for i in range(1, 8)]
```

The computation logic is then constructed by linking nodes. Note that you don't need to manually define evaluation keys; the frontend automatically analyzes the graph and inserts the required key nodes into the final ERG:

```python
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
```

Finally, the ERG is finalized by grouping nodes into `Argument` objects and exporting the graph as a JSON file for the runtime:

```python
process_custom_task(
    input_args=[Argument('x', x), Argument('a0', a0), Argument('a', a)],
    output_args=[Argument('y', y)],
    output_instruction_path='examples/bfv_poly_7',
)
```

------

## Runtime SDK

The Runtime SDK transitions the abstract ERG into a concrete execution environment. While it provides standard FHE utilities—such as key generation, encoding, and encryption—its primary role in LattiSense is managing the high-performance execution of an Erg across various hardware backends.

Using the polynomial evaluation example, the C++ application logic begins with the standard FHE pipeline: establishing context, encoding messages, and encrypting inputs. At this stage, you also create placeholders for the output ciphertexts:

```c++
uint64_t n = 16384;
uint64_t t = 0x1b4001;
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
```

To execute the task, the runtime variables are mapped to the ERG’s named arguments. The scalar arguments `x`, `a0`, `y` are mapped to a single ciphertext or plaintext object, while the 1-dimensional vector argument `a` is mapped to a `vector<BfvPlaintextMul>` object. The SDK then processes the graph, leveraging the specified hardware backend (in this case, CPU) to handle the actual FHE computation:

```c++
FheTaskCpu task("examples/bfv_poly_7");
vector<CxxVectorArgument> cxx_args = {
    {"x", &x_ct},
    {"a0", &a0_pt},
    {"a", &a_pt_mul},
    {"y", &y_ct},
};
task.run(&context, cxx_args);
```

Once `task.run` completes, the output placeholder (`y_ct`) is populated with the result. The process concludes with decryption and decoding to retrieve the final message:

```c++
BfvPlaintext y_pt = context.decrypt(y_ct);
vector<uint64_t> y_mg = context.decode(y_pt);
printf("y_mg = [%lu, %lu, %lu, %lu, ...]\n", y_mg[0], y_mg[1], y_mg[2], y_mg[3]);
```


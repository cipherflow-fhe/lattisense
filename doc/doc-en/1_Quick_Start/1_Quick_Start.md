[TOC]

# Quick Start

This chapter provides a quick introduction to the LattiSense Fully Homomorphic Encryption Development Platform (LattiSense Platform), including background on fully homomorphic encryption technology, an overview of the LattiSense Platform, and a minimal development example. For more detailed information about the LattiSense Platform, please refer to subsequent chapters.

## Fully Homomorphic Encryption Technology

In today's world where data has become the core driving force of modern economy and society, issues of data privacy and security have also become unprecedentedly important. How to fully utilize the value of data while effectively protecting personal privacy and business secrets has become a global challenge. Traditional encryption technologies, such as Transport Layer Security (TLS) and data-at-rest encryption, protect "data in transit" and "statically stored data" respectively, but there has long been a huge security risk gap in the "data in use" stage. To perform computation and analysis on data, we must first decrypt it, which undoubtedly exposes sensitive information to potential attackers and untrusted computing environments. The emergence of Fully Homomorphic Encryption (FHE) technology provides a revolutionary solution to this fundamental contradiction.

Fully homomorphic encryption is a disruptive encryption paradigm that allows arbitrary computations to be performed directly on ciphertext. With FHE, we can perform basic operations such as addition and multiplication on encrypted data without exposing the original data content, and then combine them into arbitrarily complex computational functions. The computation results also exist in encrypted form, and only users with the key can decrypt and obtain the final plaintext results. This means that information can remain encrypted throughout the entire lifecycle, from data generation, transmission, storage to computation, thus theoretically achieving absolute data security in a "zero trust" environment.

The core property of FHE lies in its unique "homomorphic" attribute, which is the structure-preserving property between encryption operations and algebraic operations. Simply put, performing a certain operation on ciphertext is equivalent to performing the same operation on plaintext:
$$
\textrm{Eval}(f, \textrm{Enc}(m_0), ..., \textrm{Enc}(m_{k-1})) = \textrm{Enc}(f(m_0, ..., m_{k-1}))
$$
Where $\textrm{Enc}$ is the encryption function, $\textrm{Eval}$ is the algorithm for executing arbitrary function $f$ on ciphertext, and $m$ is the original plaintext data. This property makes FHE known as the "holy grail" of cryptography, perfectly unifying the usability and confidentiality of data, and laying the theoretical foundation for building next-generation secure computing applications.

The concept of FHE was first proposed by Rivest, Adleman, and Dertouzos in 1978, but for more than thirty years thereafter, constructing a truly feasible scheme proved to be extremely difficult. It wasn't until 2009 that Craig Gentry first proposed a viable FHE scheme based on Ideal Lattices in his doctoral thesis, marking a historic breakthrough in the field. Gentry's scheme creatively introduced the "bootstrapping" technique, which refreshes and controls the continuously accumulated "noise" during computation by performing homomorphic decryption on ciphertext, thus enabling support for computations on circuits of arbitrary depth. This pioneering work also established that almost all modern FHE technologies are based on the mathematical problem of "lattice cryptography".

Since Gentry's breakthrough, FHE technology has undergone several generations of rapid development, with significant improvements in performance and ease of use:

- **First Generation FHE:** Represented by Gentry's original scheme, it proved the feasibility of FHE, but its enormous computational overhead and key size kept it at the theoretical verification stage, far from practical application.
- **Second Generation FHE:** Around 2011-2013, a series of schemes based on Learning With Errors (LWE) and Ring Learning With Errors (RLWE) problems emerged, such as BGV and BFV. These schemes greatly optimized noise management and computational efficiency by introducing key technologies such as Modulus Switching, Key Switching, and Relinearization, making FHE applications possible in specific scenarios. This generation of schemes mainly targets exact integer arithmetic.
- **Third Generation FHE:** Focused on improving the speed and efficiency of the bootstrapping process. Represented by FHEW and TFHE schemes, they reduced bootstrapping time from minutes to sub-second levels, significantly reducing the cost of executing complex logic gate operations, especially suitable for homomorphic evaluation of Boolean circuits and lookup tables.
- **Fourth Generation FHE:** Represented by the CKKS scheme, which opened a new direction for approximate computation. CKKS allows homomorphic encryption and computation on floating-point or real numbers. Although controllable approximation errors are introduced during computation, this has expanded the application potential of FHE in machine learning, scientific computing, and other fields.

Currently, FHE technology is at a critical period of transition from academic research to industrial application. Although its performance still lags behind plaintext computation by orders of magnitude, with continuous algorithm optimization, hardware acceleration development, improvement of FHE application solutions, and advancement of standardization processes, FHE's performance bottlenecks are being continuously overcome. Leading technology companies, academic institutions, and startups around the world are investing in research and development, and the open-source community has also produced a series of mature FHE libraries such as HElib, SEAL, OpenFHE, and TFHE-rs, greatly lowering the barrier for developers to explore and apply FHE.

## LattiSense Fully Homomorphic Encryption Development Platform

The LattiSense Fully Homomorphic Encryption Development Platform (LattiSense Platform) provides comprehensive underlying technical tools for fully homomorphic encryption developers, including software development frameworks for fully homomorphic encryption algorithms, hardware acceleration solutions, and application task compilation and scheduling frameworks.

As a cutting-edge technology with broad prospects, fully homomorphic encryption technology faces two main difficulties in application development:
1. Compared to plaintext computation, fully homomorphic encryption computation increases the computational load by several orders of magnitude. Even after utilizing various optimization methods at the algorithm and software levels, ciphertext computation performance remains a major performance bottleneck.
2. Although fully homomorphic encryption can support general computational tasks, to achieve optimal performance, it is necessary to carefully select cryptographic protocols, homomorphic parameters, encoding methods, etc., for each step of the task. These issues involve considerable FHE expertise and complex global optimization problems.

To address these challenges, the LattiSense Platform, based on comprehensive support for the FHE algorithms BFV and CKKS, provides two main functions:
1. A heterogeneous hardware acceleration platform has been built, which supports multiple computing chips to execute FHE computations through a unified interface. The CPU task scheduling component supports full utilization of CPU multi-core resources to implement parallel processing of FHE tasks; GPU acceleration support can further improve the performance of large-scale computation tasks.
2. Based on the LattiSense Platform, the LattiSense product family provides multiple application development frameworks, including the LattiQuery ciphertext query framework and the LattiIntelligence AI model secure inference framework, which implement optimal FHE ciphertext computation processes for various typical tasks in database and AI model inference domains, allowing developers to focus on higher-level solution design.

## LattiSense Platform Development Example

In this section, we introduce the basic usage of the LattiSense Platform through a simple example. We use the BFV algorithm to perform multiplication on integer data $x$ and $y$ on ciphertext: first encode and encrypt $x$ and $y$ respectively to obtain the corresponding ciphertexts $[\![x]\!]$ and $[\![y]\!]$, then compute the ciphertext multiplication $[\![x]\!] \times [\![y]\!]$, and the computation result can be restored to the plaintext result $x\times y$ after decryption and decoding.

On the LattiSense Platform, we take $x=3, y=5$, and use the CPU to execute this ciphertext computation. We need two parts of code. The first part is the offline phase, which defines the task to be computed on ciphertext through Python code.

```python
# Set global FHE parameters
param = Param.create_bfv_custom_param(
    n=8192,
    p=[0x7ffffffffb4001],
    q=[0x3fffffffef8001, 0x4000000011c001, 0x40000000120001],
    t=0x28001
)
set_fhe_param(param)

# Define computation task z = x * y
level = 2
x = BfvCiphertextNode('x', level)
y = BfvCiphertextNode('y', level)
z = mult_relin(x, y, 'z')

# Compile the above FHE computation task into CPU FHE operator instructions
process_custom_task(
    input_args=[Argument('x', x), Argument('y', y)],
    output_args=[Argument('z', z)],
    output_instruction_path='quick_start',
    fpga_acc=False,
)
```

The second part is the online phase, which calls the computing chip for ciphertext computation through the Runtime component. In this example:

```c++
#include <cxx_sdk_v2/cxx_fhe_task.h>
#include <fhe_ops_lib/fhe_lib_v2.h>

using namespace std;
using namespace cxx_sdk_v2;

// Initialize parameters required for BFV
uint64_t t = 0x28001;
uint64_t n = 8192;
BfvParameter param = BfvParameter::create_parameter(n, t);
BfvContext context = BfvContext::create_random_context(param);
int level = 3;

// Initialize vectors x, y
vector<uint64_t> x_mg({3});  // x_mg = [3, 0, 0, ...]
vector<uint64_t> y_mg({5});  // y_mg = [5, 0, 0, ...]

// Encode and encrypt vector x
BfvPlaintext x_pt = context.encode(x_mg, level);
BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

// Encode and encrypt vector y
BfvPlaintext y_pt = context.encode(y_mg, level);
BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

// Allocate space for ciphertext z
BfvCiphertext z_ct = context.new_ciphertext(level);

// Call CPU to execute computation task
FheTaskCpu cpu_project("quick_start");
vector<CxxVectorArgument> cxx_args = {
    {"x", &x_ct},
    {"y", &y_ct},
    {"z", &z_ct},
};
cpu_project.run(&context, cxx_args);

// Decrypt and decode ciphertext z to finally obtain the product of x and y
BfvPlaintext z_pt = context.decrypt(z_ct);
vector<uint64_t> z_mg = context.decode(z_pt);
print_message(z_mg.data(), "z_mg", 3);  // Print result: z_mg = [15, 0, 0, ...]
```


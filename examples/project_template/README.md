# Project Template

This template demonstrates how to use FHE SDK (LattiSense) in your own project. It includes a complete BFV multiplication example that you can use to verify your SDK installation.

## Prerequisites

FHE SDK must be installed. See the main README for installation instructions.

## Quick Start

### Step 1: Generate Computation Graph

```bash
python3 bfv_mult.py
```

This creates the `bfv_mult/` directory containing the compiled FHE task.

### Step 2: Build and Run

```bash
mkdir build && cd build

# If SDK installed to system (/usr/local)
cmake ..

# If SDK installed to custom directory
cmake .. -DCMAKE_PREFIX_PATH=<install_prefix>/lib/cmake/LattiSense

make
./my_fhe_app
```

## Expected Output

```
=== BFV Multiplication Example ===
x = [5, 10]
y = [2, 3]
z = x * y = [10, 30]
Expected:   [10, 30]

SUCCESS: FHE SDK is working correctly!
```

## Files

- `bfv_mult.py` - Python script to define and compile the FHE computation task
- `main.cpp` - C++ program that executes the FHE task
- `CMakeLists.txt` - CMake build configuration

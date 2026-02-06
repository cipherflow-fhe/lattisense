/*
 * Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cxx_sdk_v2/cxx_fhe_task.h>
#include <fhe_ops_lib/fhe_lib_v2.h>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <vector>
#include <string>

#include "feature.h"
#include "conv2d_packed_layer.h"
#include "array_util.h"

using namespace cxx_sdk_v2;
using namespace fhe_ops_lib;

void benchmark_convolution(uint32_t input_size, uint32_t kernel_size, uint32_t n_in_channel, uint32_t n_out_channel) {
    // Parameters
    const int N = 16384;
    const int n_slot = N / 2;
    const int init_level = 2;
    const Duo input_shape = {input_size, input_size};
    const Duo kernel_shape = {kernel_size, kernel_size};
    const Duo stride = {1, 1};
    const Duo skip = {1, 1};

    printf("\n=== Convolution Benchmark (GPU) ===\n");
    printf("Input shape: %s, Kernel shape: %s\n", str(input_shape).c_str(), str(kernel_shape).c_str());
    printf("Channels: in=%u, out=%u, Stride: %s\n", n_in_channel, n_out_channel, str(stride).c_str());

    // Initialize CKKS context
    printf("Initializing CKKS context (N=%d)...\n", N);
    CkksParameter param = CkksParameter::create_parameter(N);
    CkksContext context = CkksContext::create_random_context(param);
    context.gen_rotation_keys();

    // Generate random data
    printf("Generating random weights and input...\n");
    auto conv_weight = gen_random_array<4>({n_out_channel, n_in_channel, kernel_shape[0], kernel_shape[1]}, 0.1);
    auto conv_bias = gen_random_array<1>({n_out_channel}, 0.1);
    auto input_array = gen_random_array<3>({n_in_channel, input_shape[0], input_shape[1]}, 1.0);

    uint32_t n_channel_per_ct = n_slot / (input_shape[0] * input_shape[1]);

    // Prepare convolution layer weights
    printf("Preparing convolution layer weights...\n");
    Conv2DPackedLayer conv_layer(param, input_shape, conv_weight, conv_bias, stride, skip, n_channel_per_ct,
                                 init_level);
    conv_layer.prepare_weight();

    // Encrypt input
    printf("Encrypting input features...\n");
    Feature2DEncrypted input_feature(&context, init_level);
    input_feature.pack(input_array, false, param.get_default_scale());

    // Prepare output feature
    Feature2DEncrypted output_feature(&context, init_level - 1);
    output_feature.shape[0] = input_shape[0] / stride[0];
    output_feature.shape[1] = input_shape[1] / stride[1];
    output_feature.skip[0] = skip[0] * stride[0];
    output_feature.skip[1] = skip[1] * stride[1];
    output_feature.n_channel = n_out_channel;
    output_feature.n_channel_per_ct = n_channel_per_ct;

    for (uint32_t i = 0; i < div_ceil(n_out_channel, n_channel_per_ct); i++) {
        output_feature.data.push_back(context.new_ciphertext(init_level - 1, param.get_default_scale()));
    }

    // Build project path based on configuration
    std::string project_path = "CKKS_conv2d_" + std::to_string(n_in_channel) + "_in_" + std::to_string(n_out_channel) +
                               "_out_channel_" + std::to_string(stride[0]) + "_stride_" +
                               std::to_string(input_shape[0]) + "_" + std::to_string(input_shape[1]) + "_" +
                               std::to_string(kernel_shape[0]) + "_" + std::to_string(kernel_shape[1]) + "/level_" +
                               std::to_string(init_level) + "/server/";

    printf("Project path: %s\n", project_path.c_str());

    // Prepare arguments for task execution
    std::vector<CxxVectorArgument> cxx_args = {
        CxxVectorArgument{"input_0", &input_feature.data},
        CxxVectorArgument{"convw__conv1_Conv", &conv_layer.weight_pt_},
        CxxVectorArgument{"convb__conv1_Conv", &conv_layer.bias_pt_},
        CxxVectorArgument{"output", &output_feature.data},
    };

    // Execute convolution on GPU
    printf("Executing FHE convolution on GPU...\n");
    FheTaskGpu task(project_path);

    auto start = std::chrono::high_resolution_clock::now();
    task.run(&context, cxx_args);
    auto end = std::chrono::high_resolution_clock::now();

    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    printf("GPU execution time: %.2f ms\n", elapsed_ms);

    // Decrypt and verify result
    printf("Decrypting output...\n");
    auto y_mg = output_feature.unpack();

    // Run plaintext convolution for comparison
    printf("Running plaintext convolution for verification...\n");
    auto y_expected = conv_layer.run_plaintext(input_array);

    // Print first few values
    print_array_values(y_mg.to_array_1d().data(), "FHE output", 10);
    print_array_values(y_expected.to_array_1d().data(), "Plaintext output", 10);

    // Compare results
    auto compare_result = compare(y_expected, y_mg);
    printf("\nVerification Results:\n");
    printf("  Max absolute value: %.6f\n", compare_result.max_abs);
    double error_pct = (compare_result.max_abs > 0) ? 100.0 * compare_result.max_error / compare_result.max_abs : 0.0;
    double rmse_pct = (compare_result.rms > 0) ? 100.0 * compare_result.rmse / compare_result.rms : 0.0;
    printf("  Max error: %.6f (%.4f%% of max)\n", compare_result.max_error, error_pct);
    printf("  RMSE: %.6f (%.4f%% of RMS)\n", compare_result.rmse, rmse_pct);

    // Check if results are within acceptable tolerance
    bool passed = (compare_result.max_error < 5.0e-2 * compare_result.max_abs) &&
                  (compare_result.rmse < 1.0e-2 * compare_result.rms);
    printf("\nTest %s\n", passed ? "PASSED" : "FAILED");
}

void run_all_benchmarks() {
    struct Config {
        uint32_t input_size;
        uint32_t kernel_size;
        uint32_t n_in_channel;
        uint32_t n_out_channel;
    };

    std::vector<Config> configs = {
        // Single channel cases
        {4, 5, 1, 1},
        {8, 5, 1, 1},
        {16, 5, 1, 1},
        {32, 5, 1, 1},
        {64, 5, 1, 1},
        // Multi-channel cases
        {32, 3, 1, 32},
        {32, 3, 4, 4},
        {32, 3, 32, 1},
        // Different kernel sizes
        {16, 1, 1, 1},
        {16, 3, 1, 1},
        {16, 5, 1, 1},
    };

    printf("Running all convolution benchmarks on GPU...\n");
    printf("================================================================\n");

    for (const auto& cfg : configs) {
        try {
            benchmark_convolution(cfg.input_size, cfg.kernel_size, cfg.n_in_channel, cfg.n_out_channel);
        } catch (const std::exception& e) {
            printf("\nError for input=%u, kernel=%u, in_ch=%u, out_ch=%u: %s\n", cfg.input_size, cfg.kernel_size,
                   cfg.n_in_channel, cfg.n_out_channel, e.what());
        }
    }

    printf("\n================================================================\n");
    printf("All benchmarks completed.\n");
}

void print_help(const char* prog_name) {
    printf("Convolution Benchmark (GPU)\n");
    printf("\n");
    printf("Usage: %s [options]\n", prog_name);
    printf("\n");
    printf("Options:\n");
    printf("  (no args)     Run default benchmark (input=4, kernel=5, channels=1)\n");
    printf("  all           Run all default configurations\n");
    printf("  <input> <kernel> [in_ch] [out_ch]  Run specific configuration\n");
    printf("  -h, --help    Print this help message\n");
    printf("\n");
    printf("Arguments:\n");
    printf("  input_size    Input feature map size (power of 2: 4, 8, 16, 32, 64)\n");
    printf("  kernel_size   Convolution kernel size (odd: 1, 3, 5)\n");
    printf("  in_ch         Number of input channels (default: 1)\n");
    printf("  out_ch        Number of output channels (default: 1)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                  Run default benchmark (4x4 input, 5x5 kernel)\n", prog_name);
    printf("  %s all              Run all benchmarks\n", prog_name);
    printf("  %s 32 3             Run 32x32 input with 3x3 kernel, 1 channel\n", prog_name);
    printf("  %s 32 3 4 32        Run 32x32 input, 3x3 kernel, 4 in / 32 out channels\n", prog_name);
}

int main(int argc, char* argv[]) {
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_help(argv[0]);
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "all") == 0) {
        run_all_benchmarks();
        return 0;
    }

    // Parse arguments with defaults: input_size=4, kernel_size=5, n_in_channel=1, n_out_channel=1
    uint32_t input_size = 4;     // default
    uint32_t kernel_size = 5;    // default
    uint32_t n_in_channel = 1;   // default
    uint32_t n_out_channel = 1;  // default

    if (argc >= 2) {
        char* endptr;
        long val = std::strtol(argv[1], &endptr, 10);
        if (*endptr != '\0' || val <= 0) {
            printf("Error: Invalid input size '%s'\n", argv[1]);
            return 1;
        }
        input_size = static_cast<uint32_t>(val);
    }
    if (argc >= 3) {
        char* endptr;
        long val = std::strtol(argv[2], &endptr, 10);
        if (*endptr != '\0' || val <= 0) {
            printf("Error: Invalid kernel size '%s'\n", argv[2]);
            return 1;
        }
        kernel_size = static_cast<uint32_t>(val);
    }
    if (argc >= 4) {
        char* endptr;
        long val = std::strtol(argv[3], &endptr, 10);
        if (*endptr != '\0' || val <= 0) {
            printf("Error: Invalid input channel count '%s'\n", argv[3]);
            return 1;
        }
        n_in_channel = static_cast<uint32_t>(val);
    }
    if (argc >= 5) {
        char* endptr;
        long val = std::strtol(argv[4], &endptr, 10);
        if (*endptr != '\0' || val <= 0) {
            printf("Error: Invalid output channel count '%s'\n", argv[4]);
            return 1;
        }
        n_out_channel = static_cast<uint32_t>(val);
    }

    // Validate input size is power of 2
    if ((input_size & (input_size - 1)) != 0) {
        printf("Error: Input size must be a power of 2 (got %u)\n", input_size);
        return 1;
    }

    // Validate kernel size is odd
    if (kernel_size % 2 == 0) {
        printf("Error: Kernel size must be odd (got %u)\n", kernel_size);
        return 1;
    }

    benchmark_convolution(input_size, kernel_size, n_in_channel, n_out_channel);
    return 0;
}

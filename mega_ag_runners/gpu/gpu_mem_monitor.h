// Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <cuda_runtime.h>
#include <nvml.h>

// ---------------------------------------------------------------------------
// GpuMemoryMonitor: background thread that samples per-process GPU memory
// usage via NVML every `interval_ms` milliseconds.
// Only the calling process's VRAM is counted (other processes are excluded).
// After stop(), dumps a CSV and prints peak/avg/final stats to stderr.
// ---------------------------------------------------------------------------
struct GpuMemoryMonitor {
    struct Sample {
        long elapsed_ms;
        double used_gb;   // this process only
        double total_gb;  // full device VRAM
    };

    std::vector<Sample> samples;
    std::atomic<bool> running{false};
    std::thread thr;
    int interval_ms;
    double used_at_start_gb{0.0};
    double total_gb{0.0};
    std::chrono::steady_clock::time_point t0;

    nvmlDevice_t device{};
    unsigned int pid{0};
    bool nvml_ok{false};

    explicit GpuMemoryMonitor(int interval_ms_ = 100) : interval_ms(interval_ms_) {}

    // Returns "base_NNNN.csv" where NNNN is the first index with no existing file.
    static std::string next_csv_path(const std::string& base = "mem_usage_gpu") {
        char buf[8];
        for (int i = 0; i < 10000; ++i) {
            snprintf(buf, sizeof(buf), "%04d", i);
            std::string path = base + "_" + buf + ".csv";
            if (!std::ifstream(path).good())
                return path;
        }
        return base + "_9999.csv";
    }

    // Query this process's GPU memory usage in GB via NVML.
    // Returns 0.0 if NVML is unavailable or this process has no allocation yet.
    double read_process_used_gb() const {
        if (!nvml_ok)
            return 0.0;

        // Retry with a larger buffer if the initial size is insufficient.
        unsigned int count = 64;
        std::vector<nvmlProcessInfo_t> infos(count);
        nvmlReturn_t ret = nvmlDeviceGetComputeRunningProcesses(device, &count, infos.data());
        if (ret == NVML_ERROR_INSUFFICIENT_SIZE) {
            infos.resize(count);
            ret = nvmlDeviceGetComputeRunningProcesses(device, &count, infos.data());
        }
        if (ret != NVML_SUCCESS)
            return 0.0;

        for (unsigned int i = 0; i < count; ++i) {
            if (infos[i].pid == pid)
                return static_cast<double>(infos[i].usedGpuMemory) / 1024.0 / 1024.0 / 1024.0;
        }
        return 0.0;
    }

    void start() {
        pid = static_cast<unsigned int>(getpid());

        // Initialize NVML and get the handle for the current CUDA device.
        nvml_ok = (nvmlInit() == NVML_SUCCESS);
        if (nvml_ok) {
            int cuda_device = 0;
            cudaGetDevice(&cuda_device);
            nvml_ok = (nvmlDeviceGetHandleByIndex(cuda_device, &device) == NVML_SUCCESS);
        }

        // Total VRAM via CUDA.
        size_t free_bytes = 0, total_bytes = 0;
        cudaMemGetInfo(&free_bytes, &total_bytes);
        total_gb = total_bytes / 1024.0 / 1024.0 / 1024.0;

        used_at_start_gb = read_process_used_gb();
        t0 = std::chrono::steady_clock::now();
        running = true;
        thr = std::thread([this] {
            while (running) {
                auto now = std::chrono::steady_clock::now();
                long ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
                samples.push_back({ms, read_process_used_gb(), total_gb});
                std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            }
        });
    }

    void stop(const std::string& csv_path = "mem_usage_gpu.csv") {
        running = false;
        if (thr.joinable())
            thr.join();

        // Final sample
        auto now = std::chrono::steady_clock::now();
        long ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
        samples.push_back({ms, read_process_used_gb(), total_gb});

        if (nvml_ok)
            nvmlShutdown();

        double peak_used_gb = 0.0, sum_used_gb = 0.0;
        for (auto& s : samples) {
            if (s.used_gb > peak_used_gb)
                peak_used_gb = s.used_gb;
            sum_used_gb += s.used_gb;
        }
        double avg_used_gb = samples.empty() ? 0.0 : sum_used_gb / (double)samples.size();
        double window_delta_gb = peak_used_gb - used_at_start_gb;

        fprintf(stderr, "\n[GPU-MEM] ---- GPU Memory Usage Report (this process) ----\n");
        fprintf(stderr, "[GPU-MEM] Samples        : %zu (interval %d ms)\n", samples.size(), interval_ms);
        fprintf(stderr, "[GPU-MEM] Total VRAM     : %.2f GB\n", total_gb);
        fprintf(stderr, "[GPU-MEM] Used at start  : %.2f GB\n", used_at_start_gb);
        fprintf(stderr, "[GPU-MEM] Peak Used      : %.2f GB  (%.1f%%)\n", peak_used_gb,
                total_gb > 0 ? 100.0 * peak_used_gb / total_gb : 0.0);
        fprintf(stderr, "[GPU-MEM] Window Delta   : %.2f GB  [peak - used_at_start]\n", window_delta_gb);
        fprintf(stderr, "[GPU-MEM] Avg  Used      : %.2f GB\n", avg_used_gb);
        fprintf(stderr, "[GPU-MEM] Final Used     : %.2f GB\n", samples.back().used_gb);
        fprintf(stderr, "[GPU-MEM] Duration       : %ld ms\n", samples.back().elapsed_ms);
        fprintf(stderr, "[GPU-MEM] CSV            : %s\n", csv_path.c_str());
        fprintf(stderr, "[GPU-MEM] -------------------------------------------------\n\n");

        std::ofstream ofs(csv_path);
        ofs << "elapsed_ms,used_gb,total_gb\n";
        for (auto& s : samples)
            ofs << s.elapsed_ms << "," << std::fixed << s.used_gb << "," << std::fixed << s.total_gb << "\n";
    }
};

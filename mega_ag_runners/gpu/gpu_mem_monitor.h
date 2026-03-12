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
#include <vector>

#include <cuda_runtime.h>

// ---------------------------------------------------------------------------
// GpuMemoryMonitor: background thread that samples cudaMemGetInfo every
// `interval_ms` milliseconds and records (elapsed_ms, used_gb, total_gb).
// After stop(), dumps a CSV and prints peak/avg/final stats to stderr.
// ---------------------------------------------------------------------------
struct GpuMemoryMonitor {
    struct Sample {
        long elapsed_ms;
        double used_gb;
        double total_gb;
    };

    std::vector<Sample> samples;
    std::atomic<bool> running{false};
    std::thread thr;
    int interval_ms;
    size_t total_bytes{0};
    size_t used_at_start{0};
    std::chrono::steady_clock::time_point t0;

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

    // Read currently used GPU memory in bytes (total - free).
    static size_t read_used_bytes() {
        size_t free_bytes = 0, total_bytes = 0;
        cudaMemGetInfo(&free_bytes, &total_bytes);
        return total_bytes - free_bytes;
    }

    void start() {
        size_t free_bytes = 0;
        cudaMemGetInfo(&free_bytes, &total_bytes);
        used_at_start = total_bytes - free_bytes;
        t0 = std::chrono::steady_clock::now();
        running = true;
        thr = std::thread([this] {
            while (running) {
                auto now = std::chrono::steady_clock::now();
                long ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
                size_t used = read_used_bytes();
                samples.push_back({ms, used / 1024.0 / 1024.0 / 1024.0, total_bytes / 1024.0 / 1024.0 / 1024.0});
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
        size_t used_final = read_used_bytes();
        samples.push_back({ms, used_final / 1024.0 / 1024.0 / 1024.0, total_bytes / 1024.0 / 1024.0 / 1024.0});

        double peak_used_gb = 0.0, sum_used_gb = 0.0;
        for (auto& s : samples) {
            if (s.used_gb > peak_used_gb)
                peak_used_gb = s.used_gb;
            sum_used_gb += s.used_gb;
        }
        double avg_used_gb = samples.empty() ? 0.0 : sum_used_gb / (double)samples.size();
        double window_delta_gb = peak_used_gb - (used_at_start / 1024.0 / 1024.0 / 1024.0);
        double total_gb = total_bytes / 1024.0 / 1024.0 / 1024.0;

        fprintf(stderr, "\n[GPU-MEM] ---- GPU Memory Usage Report ----\n");
        fprintf(stderr, "[GPU-MEM] Samples        : %zu (interval %d ms)\n", samples.size(), interval_ms);
        fprintf(stderr, "[GPU-MEM] Total VRAM     : %.2f GB\n", total_gb);
        fprintf(stderr, "[GPU-MEM] Peak Used      : %.2f GB  (%.1f%%)\n", peak_used_gb,
                100.0 * peak_used_gb / total_gb);
        fprintf(stderr, "[GPU-MEM] Window Delta   : %.2f GB  [peak - used_at_start]\n", window_delta_gb);
        fprintf(stderr, "[GPU-MEM] Avg  Used      : %.2f GB\n", avg_used_gb);
        fprintf(stderr, "[GPU-MEM] Final Used     : %.2f GB\n", samples.back().used_gb);
        fprintf(stderr, "[GPU-MEM] Duration       : %ld ms\n", samples.back().elapsed_ms);
        fprintf(stderr, "[GPU-MEM] CSV            : %s\n", csv_path.c_str());
        fprintf(stderr, "[GPU-MEM] -------------------------------------------\n\n");

        std::ofstream ofs(csv_path);
        ofs << "elapsed_ms,used_gb,total_gb\n";
        for (auto& s : samples)
            ofs << s.elapsed_ms << "," << std::fixed << s.used_gb << "," << std::fixed << s.total_gb << "\n";
    }
};

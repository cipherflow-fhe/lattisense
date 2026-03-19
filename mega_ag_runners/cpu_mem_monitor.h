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
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// MemoryMonitor: background thread that samples /proc/self/status every
// `interval_ms` milliseconds and records (elapsed_ms, VmRSS_kB) pairs.
//
// Each sample is flushed to the CSV file immediately, so data is preserved
// even if the process is killed abnormally (SIGKILL, crash, OOM, etc.).
// ---------------------------------------------------------------------------
struct MemoryMonitor {
    struct MemInfo {
        long rss_kb;
        long hwm_kb;
    };
    struct Sample {
        long elapsed_ms;
        long rss_kb;
    };

    std::vector<Sample> samples;
    std::atomic<bool> running{false};
    std::thread thr;
    int interval_ms;
    long rss_at_start{0};
    long hwm_at_start{0};
    std::chrono::steady_clock::time_point t0;
    std::ofstream ofs_live;  // written continuously
    std::string csv_path_;

    explicit MemoryMonitor(int interval_ms_ = 100) : interval_ms(interval_ms_) {}

    // Destructor ensures the file is flushed and closed even on abnormal exit
    // (uncaught exception, early return, etc.). SIGKILL cannot be caught, but
    // since each sample is already flushed, the data written so far is safe.
    ~MemoryMonitor() {
        if (running.exchange(false)) {
            if (thr.joinable())
                thr.join();
        }
        if (ofs_live.is_open()) {
            ofs_live.flush();
            ofs_live.close();
        }
    }

    // Read VmRSS + AnonHugePages and VmHWM from /proc/self/status.
    // AnonHugePages are resident but not counted in VmRSS on some kernels;
    // adding them makes our RSS match what htop reports.
    // VmHWM is kernel-maintained and never misses an inter-sample spike.
    static MemInfo read_mem() {
        FILE* f = fopen("/proc/self/status", "r");
        if (!f)
            return {-1, -1};
        char line[256];
        long rss = 0, anon_huge = 0, hwm = 0;
        int found = 0;
        while (found < 3 && fgets(line, sizeof(line), f)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                sscanf(line + 6, " %ld", &rss);
                ++found;
            } else if (strncmp(line, "VmHWM:", 6) == 0) {
                sscanf(line + 6, " %ld", &hwm);
                ++found;
            } else if (strncmp(line, "AnonHugePages:", 14) == 0) {
                sscanf(line + 14, " %ld", &anon_huge);
                ++found;
            }
        }
        fclose(f);
        return {rss + anon_huge, hwm};
    }

    // Returns "base_NNNN.csv" where NNNN is one past the highest existing index.
    static std::string next_csv_path(const std::string& base = "mem_usage_cpu") {
        char buf[16];
        int next = 0;
        for (int i = 0; i < 10000; ++i) {
            snprintf(buf, sizeof(buf), "%04d", i);
            if (std::ifstream(base + "_" + buf + ".csv").good())
                next = i + 1;
        }
        snprintf(buf, sizeof(buf), "%04d", next < 10000 ? next : 9999);
        return base + "_" + buf + ".csv";
    }

    // Open the CSV and start the background sampling thread.
    // The file is written sample-by-sample so it survives abnormal termination.
    void start(const std::string& csv_path = "mem_usage_cpu.csv") {
        csv_path_ = csv_path;

        ofs_live.open(csv_path_, std::ios::out | std::ios::trunc);
        ofs_live << "elapsed_ms,rss_kb,rss_gb\n";
        ofs_live.flush();

        auto m = read_mem();
        rss_at_start = m.rss_kb;
        hwm_at_start = m.hwm_kb;
        t0 = std::chrono::steady_clock::now();
        running = true;
        thr = std::thread([this] {
            while (running) {
                auto now = std::chrono::steady_clock::now();
                long ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
                auto m = read_mem();
                samples.push_back({ms, m.rss_kb});

                // Write and flush immediately so data survives a kill signal.
                ofs_live << ms << "," << m.rss_kb << "," << std::fixed << m.rss_kb / 1024.0 / 1024.0 << "\n";
                ofs_live.flush();

                std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            }
        });
    }

    void stop() {
        running = false;
        if (thr.joinable())
            thr.join();

        // Final sample
        auto now = std::chrono::steady_clock::now();
        long ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
        auto m = read_mem();
        samples.push_back({ms, m.rss_kb});

        ofs_live << ms << "," << m.rss_kb << "," << std::fixed << m.rss_kb / 1024.0 / 1024.0 << "\n";
        ofs_live.flush();
        ofs_live.close();

        long max_rss = 0, sum_rss = 0;
        for (auto& s : samples) {
            if (s.rss_kb > max_rss)
                max_rss = s.rss_kb;
            sum_rss += s.rss_kb;
        }
        long avg_rss = samples.empty() ? 0 : sum_rss / (long)samples.size();
        long peak_delta_kb = max_rss - rss_at_start;
        long hwm_at_end = read_mem().hwm_kb;
        long hwm_delta_kb = hwm_at_end - hwm_at_start;

        fprintf(stderr, "\n[MEM] ---- Memory Usage Report ----\n");
        fprintf(stderr, "[MEM] Samples        : %zu (interval %d ms)\n", samples.size(), interval_ms);
        fprintf(stderr, "[MEM] RSS at start   : %ld kB  (%.1f GB)\n", rss_at_start, rss_at_start / 1024.0 / 1024.0);
        fprintf(stderr, "[MEM] Peak RSS       : %ld kB  (%.1f GB)  [sampled max]\n", max_rss,
                max_rss / 1024.0 / 1024.0);
        fprintf(stderr, "[MEM] Peak Delta     : %ld kB  (%.1f GB)  [peak RSS - rss_at_start]\n", peak_delta_kb,
                peak_delta_kb / 1024.0 / 1024.0);
        fprintf(stderr, "[MEM] HWM Delta      : %ld kB  (%.1f GB)  [VmHWM end - start, catches inter-sample spikes]\n",
                hwm_delta_kb, hwm_delta_kb / 1024.0 / 1024.0);
        fprintf(stderr, "[MEM] Avg RSS        : %ld kB  (%.1f GB)\n", avg_rss, avg_rss / 1024.0 / 1024.0);
        fprintf(stderr, "[MEM] Final RSS      : %ld kB  (%.1f GB)\n", samples.back().rss_kb,
                samples.back().rss_kb / 1024.0 / 1024.0);
        fprintf(stderr, "[MEM] Duration       : %ld ms\n", samples.back().elapsed_ms);
        fprintf(stderr, "[MEM] CSV            : %s\n", csv_path_.c_str());
        fprintf(stderr, "[MEM] -----------------------------------\n\n");
    }
};

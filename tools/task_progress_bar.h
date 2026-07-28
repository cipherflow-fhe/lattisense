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

#ifndef TASK_PROGRESS_BAR_H
#define TASK_PROGRESS_BAR_H

#include <chrono>
#include <cstddef>
#include <string>

#include "indicators/block_progress_bar.hpp"

namespace fhe_ops_lib {

class TaskProgressBar {
public:
    explicit TaskProgressBar(size_t total)
        : total_(total), bar_(indicators::BlockProgressBar{
                             indicators::option::BarWidth{60},
                             indicators::option::MaxProgress{total},
                             indicators::option::ShowElapsedTime{true},
                             indicators::option::ShowRemainingTime{true},
                             indicators::option::Stream{std::cerr},
                         }),
          last_update_(std::chrono::steady_clock::now() - std::chrono::milliseconds(10)) {}

    // Rate-limited update: redraws at most once per 100 ms.
    void update(size_t done) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update_).count() >= 100) {
            bar_.set_option(indicators::option::PostfixText{std::to_string(done) + "/" + std::to_string(total_)});
            bar_.set_progress(done);
            last_update_ = now;
        }
    }

    // Renders the final state and marks the bar as completed.
    void finalize() {
        bar_.set_option(indicators::option::PostfixText{std::to_string(total_) + "/" + std::to_string(total_)});
        bar_.set_progress(total_);
        bar_.mark_as_completed();
    }

private:
    size_t total_;
    indicators::BlockProgressBar bar_;
    std::chrono::steady_clock::time_point last_update_;
};

}  // namespace fhe_ops_lib

#endif  // TASK_PROGRESS_BAR_H

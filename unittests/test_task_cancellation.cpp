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

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "../cxx_sdk_v2/cxx_fhe_task.h"
#include "../mega_ag_runners/cpu_task_utils.h"
#include "../mega_ag_runners/task_cancellation.h"
#include "../mega_ag_runners/wrapper.h"

namespace {

struct DummyContext {
    DummyContext shallow_copy_context() const {
        return {};
    }
};

struct Barrier {
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false;
    bool release = false;

    void enter_and_wait() {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        cv.notify_all();
        cv.wait(lock, [&] { return release; });
    }

    void wait_until_entered() {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&] { return entered; });
    }

    void release_waiter() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            release = true;
        }
        cv.notify_all();
    }
};

MegaAG make_chain_ag(Barrier* first_barrier, std::atomic<int>* executed) {
    MegaAG ag;
    ag.algo = ALGO_BFV;
    ag.processor = Processor::CPU;

    ag.data.emplace(1, DatumNode{1, "input"});
    ag.data.emplace(2, DatumNode{2, "mid"});
    ag.data.emplace(3, DatumNode{3, "output"});
    ag.data.at(1).is_input = true;
    ag.data.at(3).is_output = true;
    ag.inputs = {1};
    ag.outputs = {3};

    ag.computes.emplace(10, ComputeNode{10, "first"});
    ag.computes.emplace(11, ComputeNode{11, "second"});

    auto executor_1 = [first_barrier, executed](ExecutionContext&, const std::unordered_map<NodeIndex, std::any>&,
                                                std::any& output, const ComputeNode&) {
        executed->fetch_add(1);
        first_barrier->enter_and_wait();
        output = std::make_shared<int>(1);
    };
    auto executor_2 = [executed](ExecutionContext&, const std::unordered_map<NodeIndex, std::any>&, std::any& output,
                                 const ComputeNode&) {
        executed->fetch_add(1);
        output = std::make_shared<int>(2);
    };

    ag.computes.at(10).on_cpu = true;
    ag.computes.at(10).priority = 10;
    ag.computes.at(10).executor = executor_1;
    ag.computes.at(11).on_cpu = true;
    ag.computes.at(11).priority = 9;
    ag.computes.at(11).executor = executor_2;

    ag.computes.at(10).input_nodes = {&ag.data.at(1)};
    ag.computes.at(10).output_nodes = {&ag.data.at(2)};
    ag.computes.at(11).input_nodes = {&ag.data.at(2)};
    ag.computes.at(11).output_nodes = {&ag.data.at(3)};
    ag.data.at(1).successors = {&ag.computes.at(10)};
    ag.data.at(2).predecessors = {&ag.computes.at(10)};
    ag.data.at(2).successors = {&ag.computes.at(11)};
    ag.data.at(3).predecessors = {&ag.computes.at(11)};

    return ag;
}

}  // namespace

TEST_CASE("CPU cancellation public API symbols compile", "[cancel][cpu][api]") {
    REQUIRE(FHE_TASK_OK == 0);
    REQUIRE(FHE_TASK_CANCELLED == -1);
    lattisense::TaskCancelledException ex;
    REQUIRE(std::string(ex.what()) == "FHE task was cancelled");
}

TEST_CASE("run_tasks throws cancellation after draining active CPU node", "[cancel][cpu]") {
    Barrier barrier;
    std::atomic<int> executed{0};
    std::atomic<bool> cancel_requested{false};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    BS::priority_thread_pool pool(2);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeIndex, std::any> available_data;
    available_data[1] = std::make_shared<int>(0);

    std::exception_ptr runner_exception;
    std::thread runner([&] {
        try {
            RunTasksOptions options;
            options.cancel_flag = &cancel_requested;
            run_tasks(ag, pool, context, available_data, options);
        } catch (...) { runner_exception = std::current_exception(); }
    });

    barrier.wait_until_entered();
    cancel_requested.store(true);
    barrier.release_waiter();
    runner.join();

    REQUIRE(runner_exception != nullptr);
    REQUIRE_THROWS_AS(std::rethrow_exception(runner_exception), mega_ag_runner::TaskCancelled);
    REQUIRE(executed.load() == 1);
    REQUIRE(available_data.find(3) == available_data.end());
}

TEST_CASE("run_tasks skips completed-total wait after cancellation", "[cancel][cpu]") {
    Barrier barrier;
    std::atomic<int> executed{0};
    std::atomic<bool> cancel_requested{false};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    BS::priority_thread_pool pool(1);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeIndex, std::any> available_data;
    available_data[1] = std::make_shared<int>(0);

    std::exception_ptr runner_exception;
    std::thread runner([&] {
        try {
            RunTasksOptions options;
            options.cancel_flag = &cancel_requested;
            run_tasks(ag, pool, context, available_data, options);
        } catch (...) { runner_exception = std::current_exception(); }
    });

    barrier.wait_until_entered();
    cancel_requested.store(true);
    barrier.release_waiter();
    runner.join();

    REQUIRE(runner_exception != nullptr);
    REQUIRE_THROWS_AS(std::rethrow_exception(runner_exception), mega_ag_runner::TaskCancelled);
    REQUIRE(executed.load() == 1);
}

TEST_CASE("cancelled run does not report completed equals total", "[cancel][cpu]") {
    Barrier barrier;
    std::atomic<int> executed{0};
    std::atomic<bool> cancel_requested{false};
    std::atomic<bool> saw_complete{false};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    BS::priority_thread_pool pool(1);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeIndex, std::any> available_data;
    available_data[1] = std::make_shared<int>(0);

    ProgressCallback progress = [&](int completed, int total) {
        if (completed == total) {
            saw_complete.store(true);
        }
    };

    std::exception_ptr runner_exception;
    std::thread runner([&] {
        try {
            RunTasksOptions options;
            options.progress_callback = progress;
            options.cancel_flag = &cancel_requested;
            run_tasks(ag, pool, context, available_data, options);
        } catch (...) { runner_exception = std::current_exception(); }
    });

    barrier.wait_until_entered();
    cancel_requested.store(true);
    barrier.release_waiter();
    runner.join();

    REQUIRE(runner_exception != nullptr);
    REQUIRE_THROWS_AS(std::rethrow_exception(runner_exception), mega_ag_runner::TaskCancelled);
    REQUIRE_FALSE(saw_complete.load());
}

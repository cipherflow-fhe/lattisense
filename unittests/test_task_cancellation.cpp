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

#include "fixture.hpp"
#include "utils.h"

#include <atomic>
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

struct DummyContext {};

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

    ag.data.emplace("input", DatumNode{"input"});
    ag.data.emplace("mid", DatumNode{"mid"});
    ag.data.emplace("output", DatumNode{"output"});
    ag.data.at("input").is_input = true;
    ag.data.at("output").is_output = true;
    ag.inputs = {"input"};
    ag.outputs = {"output"};

    auto executor_1 = [first_barrier, executed](ExecutionContext&, std::unordered_map<NodeId, std::any>& data_cache,
                                                const ComputeNode& self) {
        executed->fetch_add(1);
        first_barrier->enter_and_wait();
        data_cache[self.output_nodes.at(0)->id] = std::make_shared<int>(1);
    };
    auto executor_2 = [executed](ExecutionContext&, std::unordered_map<NodeId, std::any>& data_cache,
                                 const ComputeNode& self) {
        executed->fetch_add(1);
        data_cache[self.output_nodes.at(0)->id] = std::make_shared<int>(2);
    };

    ComputeNode first_op{"first_op"};
    first_op.input_nodes = {&ag.data.at("input")};
    first_op.output_nodes = {&ag.data.at("mid")};
    first_op.executor = executor_1;

    ComputeNode second_op{"second_op"};
    second_op.input_nodes = {&ag.data.at("mid")};
    second_op.output_nodes = {&ag.data.at("output")};
    second_op.executor = executor_2;

    CompoundComputeNode first{"first"};
    first.input_nodes = {&ag.data.at("input")};
    first.output_nodes = {&ag.data.at("mid")};
    first.ops = {std::move(first_op)};
    first.on_cpu = true;
    first.priority = 10;

    CompoundComputeNode second{"second"};
    second.input_nodes = {&ag.data.at("mid")};
    second.output_nodes = {&ag.data.at("output")};
    second.ops = {std::move(second_op)};
    second.on_cpu = true;
    second.priority = 9;

    ag.computes.emplace("first", std::move(first));
    ag.computes.emplace("second", std::move(second));

    ag.data.at("input").successors = {&ag.computes.at("first")};
    ag.data.at("mid").predecessors = {&ag.computes.at("first")};
    ag.data.at("mid").successors = {&ag.computes.at("second")};
    ag.data.at("output").predecessors = {&ag.computes.at("second")};

    return ag;
}

template <typename Task> void require_real_bfv_poly_cancellation(Task& project, BfvContext& context) {
    auto xv = new_test_cts(4, context, 3);
    auto av = new_test_cts(3, context, 3);

    std::vector<BfvCiphertext> z_list;
    z_list.reserve(4);
    for (int i = 0; i < 4; i++) {
        z_list.push_back(BfvCiphertext(context.parameter(), 3));
    }

    std::vector<CxxVectorArgument> args = {
        {"in_x_list", &xv.ciphertexts()},
        {"in_a_list", &av.ciphertexts()},
        {"out_z_list", &z_list},
    };

    std::atomic<bool> cancellation_requested{false};
    auto progress_callback = [&project, &cancellation_requested](int completed, int) {
        if (completed > 0 && !cancellation_requested.exchange(true)) {
            project.request_cancel();
        }
    };

    REQUIRE_THROWS_AS(project.run(&context, args, progress_callback), lattisense::TaskCancelledException);
    REQUIRE(cancellation_requested.load());
}

}  // namespace

TEST_CASE("CPU cancellation public API symbols compile", "[cancel][cpu][api]") {
    REQUIRE(FHE_TASK_OK == 0);
    REQUIRE(FHE_TASK_CANCELLED == -1);
    lattisense::TaskCancelledException ex;
    REQUIRE(std::string(ex.what()) == "FHE task was cancelled");
}

TEST_CASE("FheTaskCpu cancels real BFV poly task", "[cancel][cpu][real]") {
    BfvParameter parameter = BfvTestDefaultParams::create();
    BfvContext context = BfvContext::create_random_context(parameter);
    lattisense::FheTaskCpu project(cpu_base_path + "/" + BfvTestDefaultParams::get_tag() + "/BFV_n_poly/level_3");

    require_real_bfv_poly_cancellation(project, context);
}

#ifdef LATTISENSE_ENABLE_GPU
TEST_CASE("FheTaskGpu cancels real BFV poly task", "[cancel][gpu][real]") {
    BfvParameter parameter = BfvTestDefaultParams::create();
    BfvContext context = BfvContext::create_random_context(parameter);
    lattisense::FheTaskGpu project(gpu_base_path + "/" + BfvTestDefaultParams::get_tag() + "/BFV_n_poly/level_3");

    require_real_bfv_poly_cancellation(project, context);
}
#endif

TEST_CASE("run_tasks throws cancellation after draining active CPU node", "[cancel][cpu]") {
    Barrier barrier;
    std::atomic<int> executed{0};
    std::atomic<bool> cancel_requested{false};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    BS::priority_thread_pool pool(2);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeId, std::any> available_data;
    available_data["input"] = std::make_shared<int>(0);

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
    REQUIRE(available_data.find("output") == available_data.end());
}

TEST_CASE("run_tasks skips completed-total wait after cancellation", "[cancel][cpu]") {
    Barrier barrier;
    std::atomic<int> executed{0};
    std::atomic<bool> cancel_requested{false};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    BS::priority_thread_pool pool(1);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeId, std::any> available_data;
    available_data["input"] = std::make_shared<int>(0);

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
    std::unordered_map<NodeId, std::any> available_data;
    available_data["input"] = std::make_shared<int>(0);

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

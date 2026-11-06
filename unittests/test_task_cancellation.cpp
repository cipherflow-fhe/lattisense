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
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
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

TEST_CASE("CPU C boundary reports failures and preserves the C++ error", "[failure][cpu][abi]") {
    const auto path = std::filesystem::temp_directory_path() /
                      ("latti-task-abi-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(path);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::filesystem::remove_all(path); }
    } cleanup{path};

    REQUIRE(create_fhe_cpu_task(path.c_str()) == nullptr);
    REQUIRE(std::string(fhe_cpu_task_last_error()).find("Cannot open MegaAG file") != std::string::npos);
    REQUIRE_THROWS_AS(rethrow_fhe_cpu_task_error(), std::runtime_error);

    std::ofstream(path / "compiled_mega_ag.json") << R"({"algorithm":"CKKS","data":{},"compute":{},"inputs":[],"outputs":[]})";
    std::ofstream(path / "fhe_parameter.json") << R"({"log_n":"invalid","q":[],"p":[]})";
    const auto task = create_fhe_cpu_task(path.c_str());
    REQUIRE(task != nullptr);
    REQUIRE(run_fhe_cpu_task(task, nullptr, 0, nullptr, 0, nullptr, nullptr) == FHE_TASK_ERROR);
    REQUIRE(std::string(fhe_cpu_task_last_error()).size() > 0);
    REQUIRE_THROWS(rethrow_fhe_cpu_task_error());
    release_fhe_cpu_task(task);
#ifndef LATTISENSE_ENABLE_GPU
    REQUIRE(begin_fhe_gpu_resource_release(0) == FHE_TASK_OK);
    REQUIRE(finish_fhe_gpu_resource_release(0) == FHE_TASK_OK);
#endif
}

TEST_CASE("FheTaskCpu cancels real BFV poly task", "[cancel][cpu][real]") {
    BfvParameter parameter = BfvTestDefaultParams::create();
    BfvContext context = BfvContext::create_random_context(parameter);
    lattisense::FheTaskCpu project(cpu_base_path + "/" + BfvTestDefaultParams::get_tag() + "/BFV_n_poly/level_3");

    require_real_bfv_poly_cancellation(project, context);
}

#ifdef LATTISENSE_ENABLE_GPU
TEST_CASE("GPU resource gate rejects other owners and recovers after release errors", "[failure][gpu][resources]") {
    const auto path = std::filesystem::temp_directory_path() /
                      ("latti-gpu-gate-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(path);
    struct Cleanup {
        std::filesystem::path path;
        fhe_task_handle first = nullptr, second = nullptr;
        std::vector<std::pair<std::string, std::optional<std::string>>> environment;
        ~Cleanup() {
            release_fhe_gpu_task(first);
            release_fhe_gpu_task(second);
            if (begin_fhe_gpu_resource_release(0) == FHE_TASK_OK) finish_fhe_gpu_resource_release(0);
            for (const auto& [name, value] : environment) {
                if (value) setenv(name.c_str(), value->c_str(), 1);
                else unsetenv(name.c_str());
            }
            std::filesystem::remove_all(path);
        }
    } cleanup{path};
    for (const auto* name : {"HEONGPU_DEVICE_POOL_INITIAL_BYTES", "HEONGPU_DEVICE_POOL_MAX_BYTES",
                             "HEONGPU_HOST_POOL_INITIAL_BYTES", "HEONGPU_HOST_POOL_MAX_BYTES"}) {
        const char* old = std::getenv(name);
        cleanup.environment.emplace_back(name, old ? std::optional<std::string>(old) : std::nullopt);
        setenv(name, std::string(name).find("INITIAL") != std::string::npos ? "1048576" : "268435456", 1);
    }
    REQUIRE(create_fhe_gpu_task(path.c_str()) == nullptr);
    REQUIRE(begin_fhe_gpu_resource_release(0) == FHE_TASK_OK);
    REQUIRE(finish_fhe_gpu_resource_release(0) == FHE_TASK_OK);

    std::ofstream(path / "compiled_mega_ag.json") << R"({"algorithm":"CKKS","data":{},"compute":{},"inputs":[],"outputs":[]})";
    std::ofstream(path / "fhe_parameter.json") << "{}";
    cleanup.first = create_fhe_gpu_task(path.c_str());
    REQUIRE(cleanup.first != nullptr);
    cleanup.second = create_fhe_gpu_task(path.c_str());
    REQUIRE(cleanup.second != nullptr);
    REQUIRE(begin_fhe_gpu_resource_release(1) == FHE_TASK_RESOURCE_BUSY);
    release_fhe_gpu_task(cleanup.second);
    cleanup.second = nullptr;
    REQUIRE(begin_fhe_gpu_resource_release(0) == FHE_TASK_RESOURCE_BUSY);
    REQUIRE(begin_fhe_gpu_resource_release(1) == FHE_TASK_OK);
    REQUIRE(begin_fhe_gpu_resource_release(1) == FHE_TASK_RESOURCE_BUSY);
    REQUIRE(create_fhe_gpu_task(path.c_str()) == nullptr);
    release_fhe_gpu_task(cleanup.first);
    cleanup.first = nullptr;
    REQUIRE(finish_fhe_gpu_resource_release(-1) == FHE_TASK_RESOURCE_ERROR);
    REQUIRE(begin_fhe_gpu_resource_release(0) == FHE_TASK_OK);
    REQUIRE(finish_fhe_gpu_resource_release(0) == FHE_TASK_OK);
    cleanup.first = create_fhe_gpu_task(path.c_str());
    REQUIRE(cleanup.first != nullptr);
}

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

TEST_CASE("run_tasks drains failures and permits pool reuse", "[failure][cpu]") {
    Barrier barrier;
    barrier.release = true;
    std::atomic<int> executed{0};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    BS::priority_thread_pool pool(2);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeId, std::any> available_data;
    available_data["input"] = std::make_shared<int>(0);

    RunTasksOptions options;
    options.progress_callback = [](int, int) { throw std::runtime_error("progress failed"); };
    REQUIRE_THROWS_WITH(run_tasks(ag, pool, context, available_data, options), "progress failed");
    REQUIRE(executed.load() == 1);
    REQUIRE(available_data.find("mid") == available_data.end());
    REQUIRE(available_data.find("output") == available_data.end());

    run_tasks(ag, pool, context, available_data);
    REQUIRE(executed.load() == 3);
    REQUIRE(available_data.find("output") != available_data.end());
}

TEST_CASE("run_tasks drains workers when dispatcher submission fails", "[failure][cpu]") {
    Barrier barrier;
    barrier.release = true;
    std::atomic<int> executed{0};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    BS::priority_thread_pool pool(1);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeId, std::any> available_data;
    available_data["input"] = std::make_shared<int>(0);

    RunTasksOptions options;
    options.get_other_args = [](const CompoundComputeNode&) -> std::vector<std::any> {
        throw std::runtime_error("submission failed");
    };
    options.cleanup = [] { throw std::runtime_error("cleanup failed"); };
    REQUIRE_THROWS_WITH(run_tasks(ag, pool, context, available_data, options), "submission failed");
    REQUIRE(executed.load() == 0);

    run_tasks(ag, pool, context, available_data);
    REQUIRE(executed.load() == 2);
}

TEST_CASE("run_tasks reports missing CPU output", "[failure][cpu]") {
    Barrier barrier;
    std::atomic<int> executed{0};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    ag.computes.at("first").ops.at(0).executor =
        [&executed](ExecutionContext&, std::unordered_map<NodeId, std::any>&, const ComputeNode&) {
            executed.fetch_add(1);
        };
    BS::priority_thread_pool pool(1);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeId, std::any> available_data;
    available_data["input"] = std::make_shared<int>(0);

    REQUIRE_THROWS_AS(run_tasks(ag, pool, context, available_data), std::out_of_range);
    REQUIRE(executed.load() == 1);
    REQUIRE(available_data.find("output") == available_data.end());
}

TEST_CASE("missing multi-output result publishes none", "[failure][cpu]") {
    Barrier barrier;
    barrier.release = true;
    std::atomic<int> executed{0};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    ag.data.emplace("missing", DatumNode{"missing"});
    ag.computes.at("first").output_nodes.push_back(&ag.data.at("missing"));
    BS::priority_thread_pool pool(1);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeId, std::any> available_data;
    available_data["input"] = std::make_shared<int>(0);

    REQUIRE_THROWS_AS(run_tasks(ag, pool, context, available_data), std::out_of_range);
    REQUIRE(executed.load() == 1);
    REQUIRE(available_data.find("mid") == available_data.end());
    REQUIRE(available_data.find("missing") == available_data.end());
    REQUIRE(available_data.find("output") == available_data.end());
}

TEST_CASE("dependency scheduling failure rolls back outputs", "[failure][cpu]") {
    Barrier barrier;
    barrier.release = true;
    std::atomic<int> executed{0};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    CompoundComputeNode invalid_successor{"not_in_graph"};
    invalid_successor.input_nodes = {&ag.data.at("mid")};
    ag.data.at("mid").successors.push_back(&invalid_successor);
    BS::priority_thread_pool pool(1);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeId, std::any> available_data;
    available_data["input"] = std::make_shared<int>(0);

    REQUIRE_THROWS_AS(run_tasks(ag, pool, context, available_data), std::out_of_range);
    REQUIRE(executed.load() == 1);
    REQUIRE(available_data.find("input") != available_data.end());
    REQUIRE(available_data.find("mid") == available_data.end());
    REQUIRE(available_data.find("output") == available_data.end());
}

TEST_CASE("failed output publication restores existing values", "[failure][cpu]") {
    DatumNode first{"first"};
    DatumNode second{"second"};
    CompoundComputeNode node{"node"};
    node.output_nodes = {&first, &second};
    std::unordered_map<NodeId, std::any> source{{"first", 1}, {"second", 2}};
    std::unordered_map<NodeId, std::any> destination{{"first", 9}};

    REQUIRE_THROWS_WITH(publish_task_outputs(node, source, destination, [] { throw std::runtime_error("schedule"); }),
                        "schedule");
    REQUIRE(std::any_cast<int>(destination.at("first")) == 9);
    REQUIRE(destination.find("second") == destination.end());
}

TEST_CASE("run_tasks propagates asynchronous backend failure after drain", "[failure][cpu]") {
    Barrier barrier;
    std::atomic<int> executed{0};
    MegaAG ag = make_chain_ag(&barrier, &executed);
    ag.computes.at("first").on_cpu = false;
    BS::priority_thread_pool pool(1);
    auto context = std::make_unique<DummyContext>();
    std::unordered_map<NodeId, std::any> available_data;
    available_data["input"] = std::make_shared<int>(0);
    std::thread backend;
    bool drained = false;

    RunTasksOptions options;
    options.submit_backend_task = [&](NodeId, std::mutex&, std::priority_queue<TaskInfo>&, std::set<NodeId>&,
                                      std::atomic<size_t>&, std::atomic<size_t>&, std::atomic<size_t>&,
                                      std::condition_variable&,
                                      std::mutex&, std::unordered_map<NodeId, std::atomic<int>>&,
                                      TaskFailureState& failure) {
        backend = std::thread([&failure] {
            failure.report(std::make_exception_ptr(std::runtime_error("backend failed")));
        });
    };
    options.cleanup = [&] { backend.join(); drained = true; };

    REQUIRE_THROWS_WITH(run_tasks(ag, pool, context, available_data, options), "backend failed");
    REQUIRE(drained);
    REQUIRE(executed.load() == 0);
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

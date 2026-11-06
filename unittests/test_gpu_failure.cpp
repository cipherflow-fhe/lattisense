// Copyright (c) 2026 CipherFlow (Shenzhen) Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <cuda_runtime_api.h>
#include "../fhe_ops_lib/schemes/ckks/ckks.h"
#include "../mega_ag_runners/wrapper.h"
#include "../mega_ag_runners/mega_ag.h"
extern "C" {
#include "../abi/c_structs.h"
}

namespace {
std::atomic<const char*> next_failure{nullptr};
std::atomic<int> streams{0}, events{0};
bool fail(const char* name) {
    auto expected = next_failure.load();
    return expected && std::strcmp(expected, name) == 0 && next_failure.compare_exchange_strong(expected, nullptr);
}
template <class Function> Function real(const char* name) {
    auto function = reinterpret_cast<Function>(dlsym(RTLD_NEXT, name));
    if (!function) std::abort();
    return function;
}
}

// Interpose only in this test executable. Production CUDA calls are unchanged.
extern "C" cudaError_t cudaStreamCreate(cudaStream_t* stream) {
    if (fail("stream-create")) return cudaErrorUnknown;
    const auto result = real<decltype(&cudaStreamCreate)>("cudaStreamCreate")(stream);
    if (result == cudaSuccess) ++streams;
    return result;
}
extern "C" cudaError_t cudaStreamDestroy(cudaStream_t stream) {
    const auto result = real<decltype(&cudaStreamDestroy)>("cudaStreamDestroy")(stream);
    if (result == cudaSuccess) --streams;
    return fail("stream-destroy") ? cudaErrorUnknown : result;
}
extern "C" cudaError_t cudaStreamSynchronize(cudaStream_t stream) {
    const auto result = real<decltype(&cudaStreamSynchronize)>("cudaStreamSynchronize")(stream);
    return fail("stream-sync") ? cudaErrorUnknown : result;
}
extern "C" cudaError_t cudaEventCreate(cudaEvent_t* event) {
    if (fail("event-create")) return cudaErrorUnknown;
    const auto result = real<decltype(&cudaEventCreate)>("cudaEventCreate")(event);
    if (result == cudaSuccess) ++events;
    return result;
}
extern "C" cudaError_t cudaEventRecord(cudaEvent_t event, cudaStream_t stream) {
    if (fail("event-record")) return cudaErrorUnknown;
    return real<decltype(&cudaEventRecord)>("cudaEventRecord")(event, stream);
}
extern "C" cudaError_t cudaEventSynchronize(cudaEvent_t event) {
    const auto result = real<decltype(&cudaEventSynchronize)>("cudaEventSynchronize")(event);
    return fail("event-sync") ? cudaErrorUnknown : result;
}
extern "C" cudaError_t cudaEventDestroy(cudaEvent_t event) {
    const auto result = real<decltype(&cudaEventDestroy)>("cudaEventDestroy")(event);
    if (result == cudaSuccess) --events;
    return fail("event-destroy") ? cudaErrorUnknown : result;
}
extern "C" cudaError_t cudaMemcpyAsync(void* destination, const void* source, size_t bytes,
                                      cudaMemcpyKind kind, cudaStream_t stream) {
    if (kind == cudaMemcpyHostToDevice && fail("load")) return cudaErrorUnknown;
    if (kind == cudaMemcpyDeviceToHost && fail("store")) return cudaErrorUnknown;
    return real<decltype(&cudaMemcpyAsync)>("cudaMemcpyAsync")(destination, source, bytes, kind, stream);
}

TEST_CASE("GPU failures drain actual CUDA handles and permit a fresh run", "[failure][gpu]") {
    namespace fs = std::filesystem;
    using namespace fhe_ops_lib;
    const auto root = fs::temp_directory_path() / ("latti-gpu-failure-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(root);
    struct Cleanup {
        fs::path path;
        fhe_task_handle task = nullptr;
        ~Cleanup() {
            next_failure = nullptr;
            release_fhe_gpu_task(task);
            if (begin_fhe_gpu_resource_release(0) == FHE_TASK_OK) finish_fhe_gpu_resource_release(0);
            fs::remove_all(path);
        }
    } cleanup{root};
    const auto params = CkksParameter::create_parameter(12, RingType::Standard);
    std::ofstream(root / "fhe_parameter.json") << nlohmann::json{
        {"log_n", 12}, {"max_level", 1}, {"log_default_scale", 40}, {"ring_type", 0},
        {"q", {params.q()[0], params.q()[1]}}, {"p", {params.p()[0]}}};
    std::ofstream(root / "compiled_mega_ag.json") << R"({"algorithm":"CKKS",
      "data":{"mid":{"type":"test","is_custom":true},"done":{"type":"test","is_custom":true}},
      "compute":{
        "first":{"inputs":[],"outputs":["mid"],"on_cpu":false,"ops":[{"type":"test","is_custom":true,"inputs":[],"outputs":["mid"]}]},
        "second":{"inputs":["mid"],"outputs":["done"],"on_cpu":false,"ops":[{"type":"test","is_custom":true,"inputs":["mid"],"outputs":["done"]}]}
      },"inputs":[],"outputs":[]})";
    cleanup.task = create_fhe_gpu_task(root.c_str());
    REQUIRE(cleanup.task != nullptr);
    std::atomic<int> executed{0};
    bool compute_failure = false;
    ExecutorFunc executor = [&](ExecutionContext&, std::unordered_map<NodeId, std::any>& data, const ComputeNode& node) {
        ++executed;
        if (compute_failure) throw std::runtime_error("injected GPU execute failure");
        data[node.output_nodes.at(0)->id] = std::make_shared<int>(1);
    };
    const char* type = "test";
    void* executor_ptr = &executor;
    REQUIRE(bind_gpu_task_custom_executors(cleanup.task, &type, &executor_ptr, 1) == FHE_TASK_OK);
    const auto initial_streams = streams.load(), initial_events = events.load();
    for (const char* fault : {"stream-create", "event-create", "event-record", "event-sync", "event-destroy", "stream-sync", "stream-destroy", "execute"}) {
        INFO(fault);
        executed = 0;
        compute_failure = std::strcmp(fault, "execute") == 0;
        next_failure = compute_failure ? nullptr : fault;
        REQUIRE(run_fhe_gpu_task(cleanup.task, nullptr, 0, nullptr, 0, nullptr, nullptr, 0) == FHE_TASK_ERROR);
        REQUIRE(next_failure.load() == nullptr);
        REQUIRE_THROWS(rethrow_fhe_gpu_task_error());
        REQUIRE(streams.load() == initial_streams);
        REQUIRE(events.load() == initial_events);
        if (compute_failure || std::strncmp(fault, "event-", 6) == 0 && std::strcmp(fault, "event-destroy") != 0)
            REQUIRE(executed.load() == 1);
        compute_failure = false;
        executed = 0;
        REQUIRE(run_fhe_gpu_task(cleanup.task, nullptr, 0, nullptr, 0, nullptr, nullptr, 0) == FHE_TASK_OK);
        REQUIRE(executed.load() == 2);
        REQUIRE(streams.load() == initial_streams);
        REQUIRE(events.load() == initial_events);
    }

    // Exercise the production LOAD/STORE executors, with faults armed only
    // after context initialization so they reach the graph's transfer calls.
    release_fhe_gpu_task(cleanup.task);
    cleanup.task = nullptr;
    std::ofstream(root / "compiled_mega_ag.json") << R"({"algorithm":"CKKS",
      "data":{
        "abi":{"type":"ct","degree":1,"level":1,"log_slots":11,"scale":1099511627776},
        "device":{"type":"ct","degree":1,"level":1,"log_slots":11,"scale":1099511627776},
        "host":{"type":"ct","degree":1,"level":1,"log_slots":11,"scale":1099511627776},
        "done":{"type":"test","is_custom":true}},
      "compute":{
        "source":{"inputs":[],"outputs":["abi"],"on_cpu":true,"ops":[{"type":"make-abi","is_custom":true,"inputs":[],"outputs":["abi"]}]},
        "load":{"inputs":["abi"],"outputs":["device"],"on_cpu":false,"ops":[{"type":"load_to_backend","inputs":["abi"],"outputs":["device"]}]},
        "store":{"inputs":["device"],"outputs":["host"],"on_cpu":false,"ops":[{"type":"store_from_backend","inputs":["device"],"outputs":["host"]}]},
        "sink":{"inputs":["host"],"outputs":["done"],"on_cpu":true,"ops":[{"type":"check-abi","is_custom":true,"inputs":["host"],"outputs":["done"]}]}
      },"inputs":[],"outputs":[]})";
    cleanup.task = create_fhe_gpu_task(root.c_str());
    REQUIRE(cleanup.task != nullptr);
    const char* transfer_failure = nullptr;
    std::atomic<int> verified{0};
    ExecutorFunc source = [&](ExecutionContext&, std::unordered_map<NodeId, std::any>& data, const ComputeNode& node) {
        auto cipher = std::shared_ptr<CCiphertext>(new CCiphertext{}, [](CCiphertext* pointer) {
            free_ciphertext(pointer);
            delete pointer;
        });
        alloc_ciphertext(cipher.get(), 2, 1, 4096);
        std::fill_n(cipher->data, 2 * 2 * 4096, uint64_t{7});
        data[node.output_nodes.at(0)->id] = cipher;
        next_failure = transfer_failure;
    };
    ExecutorFunc sink = [&](ExecutionContext&, std::unordered_map<NodeId, std::any>& data, const ComputeNode& node) {
        const auto cipher = std::any_cast<std::shared_ptr<CCiphertext>>(data.at(node.input_nodes.at(0)->id));
        for (size_t index = 0; index < 2 * 2 * 4096; ++index)
            if (cipher->data[index] != 7) throw std::runtime_error("GPU transfer changed payload");
        ++verified;
        data[node.output_nodes.at(0)->id] = std::make_shared<int>(1);
    };
    const char* transfer_types[] = {"make-abi", "check-abi"};
    void* transfer_executors[] = {&source, &sink};
    REQUIRE(bind_gpu_task_custom_executors(cleanup.task, transfer_types, transfer_executors, 2) == FHE_TASK_OK);
    REQUIRE(bind_gpu_task_abi_bridge_executors(cleanup.task, &source, &sink) == FHE_TASK_OK);
    const auto transfer_result = run_fhe_gpu_task(cleanup.task, nullptr, 0, nullptr, 0, nullptr, nullptr, 0);
    INFO(fhe_gpu_task_last_error());
    REQUIRE(transfer_result == FHE_TASK_OK);
    REQUIRE(verified.load() == 1);
    const auto transfer_streams = streams.load(), transfer_events = events.load();
    for (const char* fault : {"load", "store"}) {
        INFO(fault);
        transfer_failure = fault;
        verified = 0;
        REQUIRE(run_fhe_gpu_task(cleanup.task, nullptr, 0, nullptr, 0, nullptr, nullptr, 0) == FHE_TASK_ERROR);
        REQUIRE(next_failure.load() == nullptr);
        REQUIRE_THROWS(rethrow_fhe_gpu_task_error());
        REQUIRE(verified.load() == 0);
        REQUIRE(streams.load() == transfer_streams);
        REQUIRE(events.load() == transfer_events);
        transfer_failure = nullptr;
        REQUIRE(run_fhe_gpu_task(cleanup.task, nullptr, 0, nullptr, 0, nullptr, nullptr, 0) == FHE_TASK_OK);
        REQUIRE(verified.load() == 1);
        REQUIRE(streams.load() == transfer_streams);
        REQUIRE(events.load() == transfer_events);
    }
}

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
#include "nlohmann/json.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace cxx_sdk_v2;

namespace {

constexpr int kDefaultOps = 1024;
constexpr int kFallbackMaxLevel = 3;
constexpr int kDefaultMaxAutoLevel = 9;
constexpr uint64_t kBfvPlainModulus = 65537;
const std::vector<uint64_t> kDefaultNValues = {4096, 8192, 16384, 32768, 65536};

struct Options {
    std::string device = "cpu";
    std::string thread_label;
    std::vector<uint64_t> n_values = kDefaultNValues;
    std::string levels = "all";
    int ops = kDefaultOps;
    std::string csv_path = "benchmark_key_ops.csv";
    bool overwrite_csv = false;
    bool isolate_gpu_case = false;
    std::string scheme_filter = "all";
    std::string op_filter = "all";
    unsigned int hardware_threads = 0;
    std::string omp_num_threads;
    std::string openblas_num_threads;
    std::string mkl_num_threads;
};

struct CaseDef {
    std::string scheme;
    std::string op;
    std::string task_prefix;
};

struct Result {
    std::string scheme;
    std::string op;
    uint64_t n;
    int level;
    std::string device;
    std::string thread_label;
    unsigned int hardware_threads = 0;
    std::string omp_num_threads;
    std::string openblas_num_threads;
    std::string mkl_num_threads;
    int ops;
    double time_ms = 0.0;
    double ops_per_sec = 0.0;
    std::string status;
    std::string error;
};

struct CkksTaskParameter {
    uint64_t n = 0;
    int max_level = 0;
    std::vector<uint64_t> q;
    std::vector<uint64_t> p;
    double scale = 0.0;
};

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return std::tolower(c); });
    return value;
}

std::string env_value(const char* name) {
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') {
        return "<unset>";
    }
    return value;
}

bool parse_bool_value(const std::string& value) {
    const std::string lower = to_lower(value);
    return lower != "0" && lower != "false" && lower != "off" && lower != "no";
}

std::vector<std::string> split_csv_string(const std::string& value) {
    std::vector<std::string> items;
    std::stringstream stream(value);
    std::string item;
    while (std::getline(stream, item, ',')) {
        item.erase(item.begin(), std::find_if(item.begin(), item.end(), [](unsigned char c) { return !std::isspace(c); }));
        item.erase(std::find_if(item.rbegin(), item.rend(), [](unsigned char c) { return !std::isspace(c); }).base(), item.end());
        if (!item.empty()) {
            items.push_back(item);
        }
    }
    return items;
}

std::vector<uint64_t> parse_n_values(const std::string& value) {
    std::vector<uint64_t> n_values;
    for (const auto& item : split_csv_string(value)) {
        n_values.push_back(std::stoull(item));
    }
    if (n_values.empty()) {
        throw std::invalid_argument("--n must contain at least one N value");
    }
    return n_values;
}

std::vector<int> parse_level_values(const std::string& value, int max_level, int min_level) {
    std::vector<int> levels;
    const std::string lower = to_lower(value);
    if (lower == "all") {
        for (int level = min_level; level <= max_level; ++level) {
            levels.push_back(level);
        }
        return levels;
    }

    for (const auto& item : split_csv_string(value)) {
        const auto dash = item.find('-');
        if (dash == std::string::npos) {
            levels.push_back(std::stoi(item));
            continue;
        }
        const int start = std::stoi(item.substr(0, dash));
        const int end = std::stoi(item.substr(dash + 1));
        if (end < start) {
            throw std::invalid_argument("Invalid --levels range: " + item);
        }
        for (int level = start; level <= end; ++level) {
            levels.push_back(level);
        }
    }

    std::sort(levels.begin(), levels.end());
    levels.erase(std::unique(levels.begin(), levels.end()), levels.end());
    levels.erase(std::remove_if(levels.begin(), levels.end(), [min_level, max_level](int level) {
                     return level < min_level || level > max_level;
                 }),
                 levels.end());
    return levels;
}

std::string next_arg_value(int& index, int argc, char* argv[], const std::string& name) {
    if (index + 1 >= argc) {
        throw std::invalid_argument("Missing value for " + name);
    }
    ++index;
    return argv[index];
}

bool parse_key_value(const std::string& arg, std::string& key, std::string& value) {
    const auto pos = arg.find('=');
    if (pos == std::string::npos) {
        key = arg;
        value.clear();
        return false;
    }
    key = arg.substr(0, pos);
    value = arg.substr(pos + 1);
    return true;
}

Options parse_options(int argc, char* argv[]) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        std::string key;
        std::string value;
        const bool has_inline_value = parse_key_value(argv[i], key, value);

        if (key == "--help" || key == "-h") {
            std::cout << "Usage: benchmark_key_ops [options]\n"
                      << "  --device <cpu|gpu>             Execution device. Default: cpu\n"
                      << "  --thread-label <label>         Label written to CSV, e.g. cpu_1t, cpu_mt, gpu\n"
                      << "  --n <N1,N2,...>                N values. Default: 4096,8192,16384,32768,65536\n"
                      << "  --levels <all|0,1|1-3>         Levels to run. Default: all, capped at level 9\n"
                      << "  --ops <count>                  Independent operators per task. Default: 1024\n"
                      << "  --csv <path>                   CSV output path. Default: benchmark_key_ops.csv\n"
                      << "  --overwrite-csv                Truncate CSV before writing this run\n"
                      << "  --isolate-gpu-case             Run each selected GPU case in a child process\n"
                      << "  --scheme <all|bfv|ckks>        Scheme filter. Default: all\n"
                      << "  --op <all|mult_relin|rotate_col|rotate_rows|mult_relin_rescale|rotate_step1>\n"
                      << "                                  Operator filter. Default: all\n";
            std::exit(0);
        } else if (key == "--device") {
            options.device = to_lower(has_inline_value ? value : next_arg_value(i, argc, argv, key));
        } else if (key == "--thread-label") {
            options.thread_label = has_inline_value ? value : next_arg_value(i, argc, argv, key);
        } else if (key == "--n") {
            options.n_values = parse_n_values(has_inline_value ? value : next_arg_value(i, argc, argv, key));
        } else if (key == "--levels") {
            options.levels = has_inline_value ? value : next_arg_value(i, argc, argv, key);
        } else if (key == "--ops") {
            options.ops = std::stoi(has_inline_value ? value : next_arg_value(i, argc, argv, key));
        } else if (key == "--csv") {
            options.csv_path = has_inline_value ? value : next_arg_value(i, argc, argv, key);
        } else if (key == "--overwrite-csv") {
            options.overwrite_csv = has_inline_value ? parse_bool_value(value) : true;
        } else if (key == "--isolate-gpu-case") {
            options.isolate_gpu_case = has_inline_value ? parse_bool_value(value) : true;
        } else if (key == "--scheme") {
            options.scheme_filter = to_lower(has_inline_value ? value : next_arg_value(i, argc, argv, key));
        } else if (key == "--op") {
            options.op_filter = to_lower(has_inline_value ? value : next_arg_value(i, argc, argv, key));
        } else {
            throw std::invalid_argument("Unknown option: " + key);
        }
    }

    if (options.device != "cpu" && options.device != "gpu") {
        throw std::invalid_argument("--device must be cpu or gpu");
    }
    if (options.thread_label.empty()) {
        options.thread_label = options.device;
    }
    if (options.ops <= 0) {
        throw std::invalid_argument("--ops must be positive");
    }
    options.hardware_threads = std::thread::hardware_concurrency();
    options.omp_num_threads = env_value("OMP_NUM_THREADS");
    options.openblas_num_threads = env_value("OPENBLAS_NUM_THREADS");
    options.mkl_num_threads = env_value("MKL_NUM_THREADS");
    return options;
}

std::vector<CaseDef> all_cases() {
    return {
        {"BFV", "mult_relin", "bfv_mult_relin"},
        {"BFV", "rotate_col", "bfv_rotate_col"},
        {"BFV", "rotate_rows", "bfv_rotate_rows"},
        {"CKKS", "mult_relin", "ckks_mult_relin"},
        {"CKKS", "mult_relin_rescale", "ckks_mult_relin_rescale"},
        {"CKKS", "rotate_step1", "ckks_rotate_step1"},
    };
}

bool matches_filter(const CaseDef& def, const Options& options) {
    const std::string scheme = to_lower(def.scheme);
    const std::string op = to_lower(def.op);
    const bool scheme_matches = options.scheme_filter == "all" || options.scheme_filter == scheme;
    const bool op_matches = options.op_filter == "all" || options.op_filter == op;
    return scheme_matches && op_matches;
}

std::string task_path(const CaseDef& def, uint64_t n, int level) {
    return def.task_prefix + "_N" + std::to_string(n) + "_L" + std::to_string(level);
}

CkksTaskParameter load_ckks_task_parameter(const std::string& path) {
    const std::string parameter_path = path + "/fhe_parameter.json";
    std::ifstream input(parameter_path);
    if (!input) {
        throw std::runtime_error("Cannot open CKKS parameter file: " + parameter_path +
                                 "; regenerate benchmark tasks with benchmark_key_ops.py");
    }

    const nlohmann::json parameter_json = nlohmann::json::parse(input);
    CkksTaskParameter parameter;
    parameter.n = parameter_json.at("n").get<uint64_t>();
    parameter.max_level = parameter_json.at("max_level").get<int>();
    parameter.q = parameter_json.at("q").get<std::vector<uint64_t>>();
    parameter.p = parameter_json.at("p").get<std::vector<uint64_t>>();
    if (parameter_json.contains("scale")) {
        parameter.scale = parameter_json.at("scale").get<double>();
    }
    return parameter;
}

bool parse_task_level(const CaseDef& def, uint64_t n, const std::filesystem::path& path, int& level) {
    if (!std::filesystem::is_directory(path)) {
        return false;
    }

    const std::string name = path.filename().string();
    const std::string prefix = def.task_prefix + "_N" + std::to_string(n) + "_L";
    if (name.rfind(prefix, 0) != 0) {
        return false;
    }

    const std::string level_text = name.substr(prefix.size());
    if (level_text.empty() ||
        !std::all_of(level_text.begin(), level_text.end(), [](unsigned char c) { return std::isdigit(c); })) {
        return false;
    }

    level = std::stoi(level_text);
    return true;
}

std::vector<int> generated_levels_for_case(const CaseDef& def, uint64_t n) {
    std::vector<int> levels;
    for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::current_path())) {
        int level = 0;
        if (parse_task_level(def, n, entry.path(), level)) {
            levels.push_back(level);
        }
    }
    std::sort(levels.begin(), levels.end());
    levels.erase(std::unique(levels.begin(), levels.end()), levels.end());
    return levels;
}

int max_generated_level_for_case(const CaseDef& def, uint64_t n) {
    const std::vector<int> levels = generated_levels_for_case(def, n);
    if (!levels.empty()) {
        return levels.back();
    }
    return kFallbackMaxLevel;
}

int max_level_for_case(const CaseDef& def, uint64_t n) {
    return max_generated_level_for_case(def, n);
}

std::vector<int> levels_for_case(const CaseDef& def, uint64_t n, const Options& options) {
    const int min_level = def.op == "mult_relin_rescale" ? 1 : 0;
    int max_level = max_level_for_case(def, n);
    if (to_lower(options.levels) == "all") {
        max_level = std::min(max_level, kDefaultMaxAutoLevel);
    }
    return parse_level_values(options.levels, max_level, min_level);
}

std::vector<uint64_t> bfv_message(int index) {
    return {static_cast<uint64_t>(index + 2)};
}

std::vector<double> ckks_message(int index) {
    return {static_cast<double>(index + 2)};
}

std::vector<uint64_t> bfv_rotation_message(uint64_t n, int index) {
    std::vector<uint64_t> message(n / 2);
    for (uint64_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<uint64_t>(index) + i;
    }
    return message;
}

std::vector<double> ckks_rotation_message(uint64_t n, int index) {
    std::vector<double> message(n / 2);
    for (uint64_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<double>(index) + static_cast<double>(i);
    }
    return message;
}

uint64_t run_task(const Options& options, FheContext* context, const std::string& path, const std::vector<CxxVectorArgument>& args) {
    if (options.device == "cpu") {
        FheTaskCpu task(path);
        return task.run(context, args);
    }

#ifdef LATTISENSE_ENABLE_GPU
    FheTaskGpu task(path);
    return task.run(context, args, false);
#else
    throw std::runtime_error("GPU benchmark requested, but lattisense was built without LATTISENSE_ENABLE_GPU");
#endif
}

uint64_t run_bfv_case(const CaseDef& def, uint64_t n, int level, const Options& options, const std::string& path) {
    BfvParameter param = BfvParameter::create_parameter(n, kBfvPlainModulus);
    BfvContext context = BfvContext::create_random_context(param);

    if (def.op == "mult_relin") {
        std::vector<BfvCiphertext> xs;
        std::vector<BfvCiphertext> ys;
        std::vector<BfvCiphertext> zs;
        xs.reserve(options.ops);
        ys.reserve(options.ops);
        zs.reserve(options.ops);
        for (int i = 0; i < options.ops; ++i) {
            xs.push_back(context.encrypt_asymmetric(context.encode(bfv_message(i), level)));
            ys.push_back(context.encrypt_asymmetric(context.encode(bfv_message(i + 1), level)));
            zs.push_back(context.new_ciphertext(level));
        }
        std::vector<CxxVectorArgument> args = {{"xs", &xs}, {"ys", &ys}, {"zs", &zs}};
        return run_task(options, &context, path, args);
    }

    context.gen_rotation_keys(level);
    std::vector<BfvCiphertext> xs;
    std::vector<BfvCiphertext> ys;
    xs.reserve(options.ops);
    ys.reserve(options.ops);
    for (int i = 0; i < options.ops; ++i) {
        xs.push_back(context.encrypt_asymmetric(context.encode(bfv_rotation_message(n, i), level)));
        ys.push_back(context.new_ciphertext(level));
    }
    std::vector<CxxVectorArgument> args = {{"xs", &xs}, {"ys", &ys}};
    return run_task(options, &context, path, args);
}

uint64_t run_ckks_case(const CaseDef& def, uint64_t n, int level, const Options& options, const std::string& path) {
    const CkksTaskParameter task_parameter = load_ckks_task_parameter(path);
    if (task_parameter.n != n) {
        throw std::runtime_error("CKKS task parameter N mismatch: expected " + std::to_string(n) + ", got " +
                                 std::to_string(task_parameter.n));
    }

    CkksParameter param = CkksParameter::create_custom_parameter(n, task_parameter.q, task_parameter.p);
    CkksContext context = CkksContext::create_random_context(param);
    const double scale = task_parameter.scale > 0.0 ? task_parameter.scale : param.get_default_scale();

    if (def.op == "mult_relin" || def.op == "mult_relin_rescale") {
        std::vector<CkksCiphertext> xs;
        std::vector<CkksCiphertext> ys;
        std::vector<CkksCiphertext> zs;
        xs.reserve(options.ops);
        ys.reserve(options.ops);
        zs.reserve(options.ops);
        for (int i = 0; i < options.ops; ++i) {
            xs.push_back(context.encrypt_asymmetric(context.encode(ckks_message(i), level, scale)));
            ys.push_back(context.encrypt_asymmetric(context.encode(ckks_message(i + 1), level, scale)));
            if (def.op == "mult_relin_rescale") {
                zs.push_back(context.new_ciphertext(level - 1, scale * scale / static_cast<double>(param.get_q(level))));
            } else {
                zs.push_back(context.new_ciphertext(level, scale * scale));
            }
        }
        std::vector<CxxVectorArgument> args = {{"xs", &xs}, {"ys", &ys}, {"zs", &zs}};
        return run_task(options, &context, path, args);
    }

    context.gen_rotation_keys(level);
    std::vector<CkksCiphertext> xs;
    std::vector<CkksCiphertext> ys;
    xs.reserve(options.ops);
    ys.reserve(options.ops);
    for (int i = 0; i < options.ops; ++i) {
        xs.push_back(context.encrypt_asymmetric(context.encode(ckks_rotation_message(n, i), level, scale)));
        ys.push_back(context.new_ciphertext(level, scale));
    }
    std::vector<CxxVectorArgument> args = {{"xs", &xs}, {"ys", &ys}};
    return run_task(options, &context, path, args);
}

Result run_case(const CaseDef& def, uint64_t n, int level, const Options& options) {
    Result result;
    result.scheme = def.scheme;
    result.op = def.op;
    result.n = n;
    result.level = level;
    result.device = options.device;
    result.thread_label = options.thread_label;
    result.hardware_threads = options.hardware_threads;
    result.omp_num_threads = options.omp_num_threads;
    result.openblas_num_threads = options.openblas_num_threads;
    result.mkl_num_threads = options.mkl_num_threads;
    result.ops = options.ops;

    const std::string path = task_path(def, n, level);
    if (!std::filesystem::exists(path)) {
        result.status = "skipped";
        result.error = "task directory not found: " + path + "; run benchmark_key_ops.py first or skip unsupported level/N";
        return result;
    }

    try {
        uint64_t time_ns = 0;
        if (def.scheme == "BFV") {
            time_ns = run_bfv_case(def, n, level, options, path);
        } else {
            time_ns = run_ckks_case(def, n, level, options, path);
        }
        result.time_ms = static_cast<double>(time_ns) / 1.0e6;
        result.ops_per_sec = static_cast<double>(options.ops) / (static_cast<double>(time_ns) / 1.0e9);
        result.status = "ok";
    } catch (const std::exception& exc) {
        result.status = "failed";
        result.error = exc.what();
    } catch (...) {
        result.status = "failed";
        result.error = "unknown error";
    }

    return result;
}

std::string csv_escape(const std::string& value) {
    if (value.find_first_of(",\"\n\r") == std::string::npos) {
        return value;
    }
    std::string escaped = "\"";
    for (char c : value) {
        if (c == '\"') {
            escaped += "\"\"";
        } else {
            escaped += c;
        }
    }
    escaped += "\"";
    return escaped;
}

bool file_exists_and_non_empty(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec) && std::filesystem::file_size(path, ec) > 0;
}

std::string csv_thread_label(const std::string& label) {
    if (label == "cpu_1t") {
        return "CPU_单线程";
    }
    if (label == "cpu_mt") {
        return "CPU_多线程";
    }
    if (label == "gpu") {
        return "GPU";
    }
    return label;
}

void prepare_csv(const Options& options) {
    if (!options.overwrite_csv) {
        return;
    }
    std::ofstream out(options.csv_path, std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Failed to truncate CSV output: " + options.csv_path);
    }
}

void append_csv(const std::string& path, const Result& result) {
    const bool needs_header = !file_exists_and_non_empty(path);
    std::ofstream out(path, std::ios::app);
    if (!out) {
        throw std::runtime_error("Failed to open CSV output: " + path);
    }
    if (needs_header) {
        out << "scheme,op,N,level,thread_label,omp_num_threads,ops,time_ms,ops_per_sec,status,error\n";
    }
    out << csv_escape(result.scheme) << ','
        << csv_escape(result.op) << ','
        << result.n << ','
        << result.level << ','
        << csv_escape(csv_thread_label(result.thread_label)) << ','
        << csv_escape(result.omp_num_threads) << ','
        << result.ops << ','
        << std::fixed << std::setprecision(6) << result.time_ms << ','
        << std::fixed << std::setprecision(6) << result.ops_per_sec << ','
        << csv_escape(result.status) << ','
        << csv_escape(result.error) << '\n';
}

void print_run_metadata(const Options& options) {
    std::cout << "Run metadata: hardware_threads=" << options.hardware_threads
              << " OMP_NUM_THREADS=" << options.omp_num_threads
              << " OPENBLAS_NUM_THREADS=" << options.openblas_num_threads
              << " MKL_NUM_THREADS=" << options.mkl_num_threads
              << " levels=" << options.levels
              << " csv=" << options.csv_path
              << " overwrite_csv=" << (options.overwrite_csv ? "true" : "false")
              << std::endl;
}

void print_case_header(const CaseDef& def, uint64_t n, const Options& options) {
    std::cout << "Case: " << def.scheme
              << " op=" << def.op
              << " N=" << n
              << " device=" << options.device
              << " label=" << options.thread_label
              << " ops=" << options.ops
              << std::endl;
}

void print_result(const Result& result) {
    std::cout << "  level=" << std::left << std::setw(3) << result.level;
    if (result.status == "ok") {
        std::cout << " time_ms=" << std::fixed << std::setprecision(3) << result.time_ms
                  << " ops_per_sec=" << std::fixed << std::setprecision(3) << result.ops_per_sec;
    } else {
        std::cout << " status=" << result.status << " error=" << result.error;
    }
    std::cout << std::endl;
}

Result make_control_result(const CaseDef& def, uint64_t n, int level, const Options& options, std::string status, std::string error = "") {
    Result result;
    result.scheme = def.scheme;
    result.op = def.op;
    result.n = n;
    result.level = level;
    result.device = options.device;
    result.thread_label = options.thread_label;
    result.hardware_threads = options.hardware_threads;
    result.omp_num_threads = options.omp_num_threads;
    result.openblas_num_threads = options.openblas_num_threads;
    result.mkl_num_threads = options.mkl_num_threads;
    result.ops = options.ops;
    result.status = std::move(status);
    result.error = std::move(error);
    return result;
}

std::string shell_quote(const std::string& value) {
    std::string quoted = "'";
    for (char c : value) {
        if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted += c;
        }
    }
    quoted += "'";
    return quoted;
}

std::string build_child_case_command(const std::string& executable_path,
                                     const CaseDef& def,
                                     uint64_t n,
                                     int level,
                                     const Options& options) {
    std::ostringstream command;
    command << shell_quote(executable_path)
            << " --device " << shell_quote(options.device)
            << " --thread-label " << shell_quote(options.thread_label)
            << " --scheme " << shell_quote(to_lower(def.scheme))
            << " --op " << shell_quote(def.op)
            << " --n " << shell_quote(std::to_string(n))
            << " --levels " << shell_quote(std::to_string(level))
            << " --ops " << shell_quote(std::to_string(options.ops))
            << " --csv " << shell_quote(options.csv_path);
    return command.str();
}

bool command_succeeded(int system_status) {
    return system_status == 0;
}

Result run_isolated_case(const std::string& executable_path,
                         const CaseDef& def,
                         uint64_t n,
                         int level,
                         const Options& options) {
    const std::string path = task_path(def, n, level);
    if (!std::filesystem::exists(path)) {
        Result result = make_control_result(
            def,
            n,
            level,
            options,
            "skipped",
            "task directory not found: " + path + "; run benchmark_key_ops.py first or skip unsupported level/N");
        print_result(result);
        append_csv(options.csv_path, result);
        return result;
    }

    const std::string command = build_child_case_command(executable_path, def, n, level, options);
    std::cout << "  isolated level=" << level << " command=" << command << std::endl;

    const int status = std::system(command.c_str());
    if (!command_succeeded(status)) {
        Result result = make_control_result(
            def,
            n,
            level,
            options,
            "failed",
            "isolated child process failed with status " + std::to_string(status));
        print_result(result);
        return result;
    }

    return make_control_result(def, n, level, options, "ok");
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        const Options options = parse_options(argc, argv);
        prepare_csv(options);
        print_run_metadata(options);

        int success_count = 0;
        int selected_count = 0;

        for (const auto& def : all_cases()) {
            if (!matches_filter(def, options)) {
                continue;
            }
            for (uint64_t n : options.n_values) {
                const std::vector<int> levels = levels_for_case(def, n, options);
                if (levels.empty()) {
                    continue;
                }
                print_case_header(def, n, options);
                for (int level : levels) {
                    ++selected_count;
                    Result result;
                    if (options.device == "gpu" && options.isolate_gpu_case) {
                        result = run_isolated_case(argv[0], def, n, level, options);
                    } else {
                        result = run_case(def, n, level, options);
                        print_result(result);
                        append_csv(options.csv_path, result);
                    }
                    if (result.status == "ok") {
                        ++success_count;
                    }
                }
            }
        }

        if (selected_count == 0) {
            std::cerr << "No benchmark cases matched --scheme/--op/--levels filters." << std::endl;
            return 1;
        }
        if (success_count == 0) {
            std::cerr << "No benchmark case completed successfully." << std::endl;
            return 1;
        }
        return 0;
    } catch (const std::exception& exc) {
        std::cerr << "benchmark_key_ops error: " << exc.what() << std::endl;
        return 1;
    }
}

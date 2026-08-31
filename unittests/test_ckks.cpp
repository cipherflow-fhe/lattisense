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

#include <algorithm>
#include <cmath>
#include <complex>
#include <random>
#include <utility>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "fixture.hpp"
#include "cxx_fhe_task.h"
#include "schemes/ckks/precision.h"
#include "utils.h"

using namespace fhe_ops_lib;

namespace {

constexpr int kSparseLogSlots = 9;
constexpr int kSparseBinaryRhsLogSlots = 11;

template <typename T> vector<T> expand_sparse_slots(const vector<T>& values, int log_slots) {
    vector<T> result(1 << log_slots);
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = values[i % values.size()];
    }
    return result;
}

template <typename T> vector<T> expand_to_log_slots(const vector<T>& values, int src_log_slots, int dst_log_slots) {
    return src_log_slots == dst_log_slots ? values : expand_sparse_slots(values, dst_log_slots);
}

vector<pair<int, int>> binary_slot_cases(const CkksParameter& param, bool same_input = false) {
    vector<pair<int, int>> cases = {{param.log_max_slots(), param.log_max_slots()}};
    if (param.log_n() == 14) {
        cases.emplace_back(kSparseLogSlots, same_input ? kSparseLogSlots : kSparseBinaryRhsLogSlots);
    }
    return cases;
}

vector<int> unary_slot_cases(const CkksParameter& param) {
    vector<int> cases = {param.log_max_slots()};
    if (param.log_n() == 14) {
        cases.push_back(kSparseLogSlots);
    }
    return cases;
}

string unary_slot_tag(int log_slots) {
    return "lslots" + to_string(log_slots);
}

string binary_slot_tag(int lhs_log_slots, int rhs_log_slots) {
    return unary_slot_tag(lhs_log_slots) + "_rslots" + to_string(rhs_log_slots);
}

template <typename RunFunc>
void run_ckks_backends(const string& section_suffix, const string& relative_path, RunFunc run) {
    const auto section_name = [](const string& backend, const string& suffix) {
        return suffix.empty() ? backend : backend + " " + suffix;
    };

    SECTION(section_name("cpu", section_suffix)) {
        FheTaskCpu project(cpu_base_path + "/" + relative_path);
        run(project);
    }
#ifdef LATTISENSE_ENABLE_GPU
    SECTION(section_name("gpu", section_suffix)) {
        FheTaskGpu project(gpu_base_path + "/" + relative_path);
        run(project);
    }
#endif
}

}  // namespace

// ---------------------------------------------------------------------------
// Multi-param tests (default n=16384 and custom n=8192)
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cap", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (bool is_ringt : {false, true}) {
        string task_name = is_ringt ? "cap_ringt" : "cap";
        string section_prefix = is_ringt ? "pt-ringt" : "pt";
        for (const auto& [lhs_log_slots, rhs_log_slots] : binary_slot_cases(this->param)) {
            string slot_tag = binary_slot_tag(lhs_log_slots, rhs_log_slots);
            for (int level = this->min_level; level <= this->max_level; level++) {
                SECTION(section_prefix + " " + slot_tag + " lv=" + to_string(level)) {
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_" + task_name + "/" +
                                           slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        auto yv =
                            new_test_complex_pts(this->n_op, this->ctx, is_ringt ? 0 : level, is_ringt, rhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level));

                        vector<CxxVectorArgument> args = {
                            {"in_x_list", &xv.ciphertexts()},
                            {"in_y_list", &yv.plaintexts()},
                            {"out_z_list", &z_list},
                        };
                        proj.run(&this->ctx, args);
                        int output_log_slots = std::max(lhs_log_slots, rhs_log_slots);
                        for (int i = 0; i < this->n_op; i++) {
                            vector<complex<double>> lhs =
                                expand_to_log_slots(xv.messages()[i], lhs_log_slots, output_log_slots);
                            vector<complex<double>> rhs =
                                expand_to_log_slots(yv.messages()[i], rhs_log_slots, output_log_slots);
                            verify_ckks_precision(this->ctx, vec_add(lhs, rhs), z_list[i]);
                        }
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cac", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (bool same_input : {false, true}) {
        for (const auto& [lhs_log_slots, rhs_log_slots] : binary_slot_cases(this->param, same_input)) {
            string slot_tag =
                same_input ? unary_slot_tag(lhs_log_slots) : binary_slot_tag(lhs_log_slots, rhs_log_slots);
            for (int level = this->min_level; level <= this->max_level; level++) {
                SECTION(string(same_input ? "same-ct" : "ct") + " " + slot_tag + " lv=" + to_string(level)) {
                    string task_name = same_input ? "casc" : "cac";
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_" + task_name + "/" +
                                           slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        auto yv = new_test_complex_cts(this->n_op, this->ctx, level, rhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level));

                        vector<CxxVectorArgument> args;
                        if (same_input) {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        } else {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"in_y_list", &yv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        }
                        proj.run(&this->ctx, args);
                        int output_log_slots = std::max(lhs_log_slots, rhs_log_slots);
                        for (int i = 0; i < this->n_op; i++) {
                            vector<complex<double>> lhs =
                                expand_to_log_slots(xv.messages()[i], lhs_log_slots, output_log_slots);
                            vector<complex<double>> rhs =
                                same_input ? lhs :
                                             expand_to_log_slots(yv.messages()[i], rhs_log_slots, output_log_slots);
                            verify_ckks_precision(this->ctx, vec_add(lhs, rhs), z_list[i]);
                        }
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS add scalar", "", CkksTestDefaultParams, CkksTestCustomParams) {
    const vector<pair<string, complex<double>>> scalar_cases = {
        {"0_75", {0.75, 0.0}}, {"minus_1", {-1.0, 0.0}}, {"i", {0.0, 1.0}}, {"minus_i", {0.0, -1.0}}};

    for (const auto& [scalar_tag, scalar] : scalar_cases) {
        for (int lhs_log_slots : unary_slot_cases(this->param)) {
            string slot_tag = unary_slot_tag(lhs_log_slots);
            for (int level = this->min_level; level <= this->max_level; level++) {
                SECTION(scalar_tag + " " + slot_tag + " lv=" + to_string(level)) {
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_add_scalar/" + scalar_tag +
                                           "/" + slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level));

                        vector<CxxVectorArgument> args = {
                            {"in_x_list", &xv.ciphertexts()},
                            {"out_z_list", &z_list},
                        };
                        proj.run(&this->ctx, args);
                        for (int i = 0; i < this->n_op; i++)
                            verify_ckks_precision(this->ctx, vec_add(xv.messages()[i], scalar), z_list[i]);
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS csp", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (bool is_ringt : {false, true}) {
        string task_name = is_ringt ? "csp_ringt" : "csp";
        string section_prefix = is_ringt ? "pt-ringt" : "pt";
        for (const auto& [lhs_log_slots, rhs_log_slots] : binary_slot_cases(this->param)) {
            string slot_tag = binary_slot_tag(lhs_log_slots, rhs_log_slots);
            for (int level = this->min_level; level <= this->max_level; level++) {
                SECTION(section_prefix + " " + slot_tag + " lv=" + to_string(level)) {
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_" + task_name + "/" +
                                           slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        auto yv =
                            new_test_complex_pts(this->n_op, this->ctx, is_ringt ? 0 : level, is_ringt, rhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level));

                        vector<CxxVectorArgument> args = {
                            {"in_x_list", &xv.ciphertexts()},
                            {"in_y_list", &yv.plaintexts()},
                            {"out_z_list", &z_list},
                        };
                        proj.run(&this->ctx, args);
                        int output_log_slots = std::max(lhs_log_slots, rhs_log_slots);
                        for (int i = 0; i < this->n_op; i++) {
                            vector<complex<double>> lhs =
                                expand_to_log_slots(xv.messages()[i], lhs_log_slots, output_log_slots);
                            vector<complex<double>> rhs =
                                expand_to_log_slots(yv.messages()[i], rhs_log_slots, output_log_slots);
                            verify_ckks_precision(this->ctx, vec_sub(lhs, rhs), z_list[i]);
                        }
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS csc", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (bool same_input : {false, true}) {
        for (const auto& [lhs_log_slots, rhs_log_slots] : binary_slot_cases(this->param, same_input)) {
            string slot_tag =
                same_input ? unary_slot_tag(lhs_log_slots) : binary_slot_tag(lhs_log_slots, rhs_log_slots);
            for (int level = this->min_level; level <= this->max_level; level++) {
                SECTION(string(same_input ? "same-ct" : "ct") + " " + slot_tag + " lv=" + to_string(level)) {
                    string task_name = same_input ? "cssc" : "csc";
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_" + task_name + "/" +
                                           slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        auto yv = new_test_complex_cts(this->n_op, this->ctx, level, rhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level));

                        vector<CxxVectorArgument> args;
                        if (same_input) {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        } else {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"in_y_list", &yv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        }
                        proj.run(&this->ctx, args);
                        int output_log_slots = std::max(lhs_log_slots, rhs_log_slots);
                        for (int i = 0; i < this->n_op; i++) {
                            vector<complex<double>> lhs =
                                expand_to_log_slots(xv.messages()[i], lhs_log_slots, output_log_slots);
                            vector<complex<double>> rhs =
                                same_input ? lhs :
                                             expand_to_log_slots(yv.messages()[i], rhs_log_slots, output_log_slots);
                            verify_ckks_precision(this->ctx, vec_sub(lhs, rhs), z_list[i]);
                        }
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS sub scalar", "", CkksTestDefaultParams, CkksTestCustomParams) {
    const vector<pair<string, complex<double>>> scalar_cases = {
        {"0_75", {0.75, 0.0}}, {"minus_1", {-1.0, 0.0}}, {"i", {0.0, 1.0}}, {"minus_i", {0.0, -1.0}}};

    for (const auto& [scalar_tag, scalar] : scalar_cases) {
        for (int lhs_log_slots : unary_slot_cases(this->param)) {
            string slot_tag = unary_slot_tag(lhs_log_slots);
            for (int level = this->min_level; level <= this->max_level; level++) {
                SECTION(scalar_tag + " " + slot_tag + " lv=" + to_string(level)) {
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_sub_scalar/" + scalar_tag +
                                           "/" + slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level));

                        vector<CxxVectorArgument> args = {
                            {"in_x_list", &xv.ciphertexts()},
                            {"out_z_list", &z_list},
                        };
                        proj.run(&this->ctx, args);
                        for (int i = 0; i < this->n_op; i++)
                            verify_ckks_precision(this->ctx, vec_sub(xv.messages()[i], scalar), z_list[i]);
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmp", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (bool is_ringt : {false, true}) {
        string task_name = is_ringt ? "cmp_ringt" : "cmp";
        string section_prefix = is_ringt ? "pt-ringt" : "pt";
        for (const auto& [lhs_log_slots, rhs_log_slots] : binary_slot_cases(this->param)) {
            string slot_tag = binary_slot_tag(lhs_log_slots, rhs_log_slots);
            for (int level = 1; level <= this->max_level; level++) {
                SECTION(section_prefix + " " + slot_tag + " lv=" + to_string(level)) {
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_" + task_name + "/" +
                                           slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        auto yv =
                            new_test_complex_pts(this->n_op, this->ctx, is_ringt ? 0 : level, is_ringt, rhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level));

                        vector<CxxVectorArgument> args = {
                            {"in_x_list", &xv.ciphertexts()},
                            {"in_y_list", &yv.plaintexts()},
                            {"out_z_list", &z_list},
                        };
                        proj.run(&this->ctx, args);
                        int output_log_slots = std::max(lhs_log_slots, rhs_log_slots);
                        for (int i = 0; i < this->n_op; i++) {
                            vector<complex<double>> lhs =
                                expand_to_log_slots(xv.messages()[i], lhs_log_slots, output_log_slots);
                            vector<complex<double>> rhs =
                                expand_to_log_slots(yv.messages()[i], rhs_log_slots, output_log_slots);
                            verify_ckks_precision(this->ctx, vec_mul(lhs, rhs), z_list[i]);
                        }
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS mult scalar", "", CkksTestDefaultParams, CkksTestCustomParams) {
    const vector<pair<string, complex<double>>> scalar_cases = {
        {"0_75", {0.75, 0.0}}, {"minus_1", {-1.0, 0.0}}, {"i", {0.0, 1.0}}, {"minus_i", {0.0, -1.0}}};

    for (const auto& [scalar_tag, scalar] : scalar_cases) {
        for (int lhs_log_slots : unary_slot_cases(this->param)) {
            string slot_tag = unary_slot_tag(lhs_log_slots);
            for (int level = 1; level <= this->max_level; level++) {
                SECTION(scalar_tag + " " + slot_tag + " lv=" + to_string(level)) {
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_mult_scalar/" + scalar_tag +
                                           "/" + slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level));

                        vector<CxxVectorArgument> args = {
                            {"in_x_list", &xv.ciphertexts()},
                            {"out_z_list", &z_list},
                        };
                        proj.run(&this->ctx, args);
                        for (int i = 0; i < this->n_op; i++)
                            verify_ckks_precision(this->ctx, vec_mul(xv.messages()[i], scalar), z_list[i]);
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmc", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (bool same_input : {false, true}) {
        for (const auto& [lhs_log_slots, rhs_log_slots] : binary_slot_cases(this->param, same_input)) {
            string slot_tag =
                same_input ? unary_slot_tag(lhs_log_slots) : binary_slot_tag(lhs_log_slots, rhs_log_slots);
            for (int level = 1; level <= this->max_level; level++) {
                SECTION(string(same_input ? "same-ct" : "ct") + " " + slot_tag + " lv=" + to_string(level)) {
                    string task_name = same_input ? "csqr" : "cmc";
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_" + task_name + "/" +
                                           slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        auto yv = new_test_complex_cts(this->n_op, this->ctx, level, rhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level, 2));

                        vector<CxxVectorArgument> args;
                        if (same_input) {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        } else {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"in_y_list", &yv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        }
                        proj.run(&this->ctx, args);
                        int output_log_slots = std::max(lhs_log_slots, rhs_log_slots);
                        for (int i = 0; i < this->n_op; i++) {
                            vector<complex<double>> lhs =
                                expand_to_log_slots(xv.messages()[i], lhs_log_slots, output_log_slots);
                            vector<complex<double>> rhs =
                                same_input ? lhs :
                                             expand_to_log_slots(yv.messages()[i], rhs_log_slots, output_log_slots);
                            verify_ckks_precision(this->ctx, vec_mul(lhs, rhs), this->ctx.relinearize(z_list[i]));
                        }
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmc_relin", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (bool same_input : {false, true}) {
        for (const auto& [lhs_log_slots, rhs_log_slots] : binary_slot_cases(this->param, same_input)) {
            string slot_tag =
                same_input ? unary_slot_tag(lhs_log_slots) : binary_slot_tag(lhs_log_slots, rhs_log_slots);
            for (int level = 1; level <= this->max_level; level++) {
                SECTION(string(same_input ? "same-ct" : "ct") + " " + slot_tag + " lv=" + to_string(level)) {
                    string task_name = same_input ? "csqr_relin" : "cmc_relin";
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_" + task_name + "/" +
                                           slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        auto yv = new_test_complex_cts(this->n_op, this->ctx, level, rhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level));

                        vector<CxxVectorArgument> args;
                        if (same_input) {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        } else {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"in_y_list", &yv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        }
                        proj.run(&this->ctx, args);
                        int output_log_slots = std::max(lhs_log_slots, rhs_log_slots);
                        for (int i = 0; i < this->n_op; i++) {
                            vector<complex<double>> lhs =
                                expand_to_log_slots(xv.messages()[i], lhs_log_slots, output_log_slots);
                            vector<complex<double>> rhs =
                                same_input ? lhs :
                                             expand_to_log_slots(yv.messages()[i], rhs_log_slots, output_log_slots);
                            verify_ckks_precision(this->ctx, vec_mul(lhs, rhs), z_list[i]);
                        }
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmc_relin_rescale", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (bool same_input : {false, true}) {
        for (const auto& [lhs_log_slots, rhs_log_slots] : binary_slot_cases(this->param, same_input)) {
            string slot_tag =
                same_input ? unary_slot_tag(lhs_log_slots) : binary_slot_tag(lhs_log_slots, rhs_log_slots);
            for (int level = 1; level <= this->max_level; level++) {
                SECTION(string(same_input ? "same-ct" : "ct") + " " + slot_tag + " lv=" + to_string(level)) {
                    string task_name = same_input ? "csqr_relin_rescale" : "cmc_relin_rescale";
                    string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_" + task_name + "/" +
                                           slot_tag + "/level_" + to_string(level);
                    run_ckks_backends("", relative_path, [&](auto& proj) {
                        auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                        auto yv = new_test_complex_cts(this->n_op, this->ctx, level, rhs_log_slots);
                        vector<CkksCiphertext> z_list;
                        z_list.reserve(this->n_op);
                        for (int _i = 0; _i < this->n_op; _i++)
                            z_list.push_back(CkksCiphertext(this->param, level - 1));

                        vector<CxxVectorArgument> args;
                        if (same_input) {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        } else {
                            args = {
                                {"in_x_list", &xv.ciphertexts()},
                                {"in_y_list", &yv.ciphertexts()},
                                {"out_z_list", &z_list},
                            };
                        }
                        proj.run(&this->ctx, args);
                        int output_log_slots = std::max(lhs_log_slots, rhs_log_slots);
                        for (int i = 0; i < this->n_op; i++) {
                            vector<complex<double>> lhs =
                                expand_to_log_slots(xv.messages()[i], lhs_log_slots, output_log_slots);
                            vector<complex<double>> rhs =
                                same_input ? lhs :
                                             expand_to_log_slots(yv.messages()[i], rhs_log_slots, output_log_slots);
                            verify_ckks_precision(this->ctx, vec_mul(lhs, rhs), z_list[i]);
                        }
                    });
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS rescale", "", CkksTestDefaultParams, CkksTestCustomParams) {
    for (int lhs_log_slots : unary_slot_cases(this->param)) {
        string slot_tag = unary_slot_tag(lhs_log_slots);
        for (int level = 1; level <= this->max_level; level++) {
            SECTION(slot_tag + " lv=" + to_string(level)) {
                string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_rescale/" + slot_tag +
                                       "/level_" + to_string(level);
                run_ckks_backends("", relative_path, [&](auto& proj) {
                    vector<vector<complex<double>>> x_messages;
                    vector<CkksCiphertext> x_list;
                    x_messages.reserve(this->n_op);
                    x_list.reserve(this->n_op);
                    double input_scale = this->default_scale * static_cast<double>(this->param.q()[level]);
                    for (int _i = 0; _i < this->n_op; _i++) {
                        x_messages.push_back(rand_complex_values(1 << lhs_log_slots));
                        CkksPlaintext plaintext(this->param,
                                                plaintext_metadata(false, true, level, lhs_log_slots, input_scale));
                        this->ctx.encode(x_messages.back(), plaintext);
                        x_list.push_back(this->ctx.encrypt(plaintext));
                    }

                    vector<CkksCiphertext> y_list;
                    y_list.reserve(this->n_op);
                    for (int _i = 0; _i < this->n_op; _i++)
                        y_list.push_back(CkksCiphertext(this->param, level - 1));

                    vector<CxxVectorArgument> args = {
                        {"in_x_list", &x_list},
                        {"out_y_list", &y_list},
                    };
                    proj.run(&this->ctx, args);
                    for (int i = 0; i < this->n_op; i++)
                        verify_ckks_precision(this->ctx, x_messages[i], y_list[i]);
                });
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS drop_level", "", CkksTestDefaultParams, CkksTestCustomParams) {
    int drop_level = 2;
    for (int lhs_log_slots : unary_slot_cases(this->param)) {
        string slot_tag = unary_slot_tag(lhs_log_slots);
        for (int level = 2; level <= this->max_level; level++) {
            SECTION(slot_tag + " lv=" + to_string(level)) {
                string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_drop_level/drop_" +
                                       to_string(drop_level) + "/" + slot_tag + "/level_" + to_string(level);
                run_ckks_backends("", relative_path, [&](auto& proj) {
                    auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                    vector<CkksCiphertext> y_list;
                    y_list.reserve(this->n_op);
                    for (int _i = 0; _i < this->n_op; _i++)
                        y_list.push_back(CkksCiphertext(this->param, level - drop_level));

                    vector<CxxVectorArgument> args = {
                        {"in_x_list", &xv.ciphertexts()},
                        {"out_y_list", &y_list},
                    };
                    proj.run(&this->ctx, args);
                    for (int i = 0; i < this->n_op; i++)
                        verify_ckks_precision(this->ctx, xv.messages()[i], y_list[i]);
                });
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS rotate_col", "", CkksTestDefaultParams, CkksTestCustomParams) {
    vector<int32_t> steps;
    for (int i = 1; i <= 8; i++)
        steps.push_back(i);
    string steps_str = "steps_" + to_string(steps.front()) + "_to_" + to_string(steps.back());

    for (bool use_default_rotation_keys : {true, false}) {
        SECTION(use_default_rotation_keys ? "default rotation" : "non-default rotation") {
            if (use_default_rotation_keys) {
                this->ctx.gen_rotation_keys();
            } else {
                this->ctx.gen_rotation_keys(steps);
            }
            string key_mode_tag = use_default_rotation_keys ? "default" : "non-default";

            for (int lhs_log_slots : unary_slot_cases(this->param)) {
                string slot_tag = unary_slot_tag(lhs_log_slots);
                for (int level = 1; level <= this->max_level; level++) {
                    SECTION(slot_tag + " lv=" + to_string(level)) {
                        string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_rotate_col/" +
                                               steps_str + "/" + key_mode_tag + "/" + slot_tag + "/level_" +
                                               to_string(level);
                        run_ckks_backends("", relative_path, [&](auto& proj) {
                            auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                            vector<vector<CkksCiphertext>> y_list(this->n_op);
                            for (int i = 0; i < this->n_op; i++)
                                for (int j = 0; j < (int)steps.size(); j++)
                                    y_list[i].push_back(CkksCiphertext(this->param, level));
                            vector<CxxVectorArgument> args = {
                                {"arg_x", &xv.ciphertexts()},
                                {"arg_y", &y_list},
                            };
                            proj.run(&this->ctx, args);

                            for (int i = 0; i < this->n_op; i++)
                                for (int j = 0; j < (int)steps.size(); j++)
                                    verify_ckks_precision(this->ctx, vec_rotate(xv.messages()[i], steps[j]),
                                                          y_list[i][j]);
                        });
                    }
                }
            }
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS conjugate", "", CkksTestDefaultParams, CkksTestCustomParams) {
    this->ctx.gen_rotation_keys(vector<int32_t>{}, true);

    for (int lhs_log_slots : unary_slot_cases(this->param)) {
        string slot_tag = unary_slot_tag(lhs_log_slots);
        for (int level = 1; level <= this->max_level; level++) {
            SECTION(slot_tag + " lv=" + to_string(level)) {
                string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_conjugate/" + slot_tag +
                                       "/level_" + to_string(level);
                run_ckks_backends("", relative_path, [&](auto& proj) {
                    auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                    vector<CkksCiphertext> y_list;
                    y_list.reserve(this->n_op);
                    for (int _i = 0; _i < this->n_op; _i++)
                        y_list.push_back(CkksCiphertext(this->param, level));

                    vector<CxxVectorArgument> args = {
                        {"arg_x", &xv.ciphertexts()},
                        {"arg_y", &y_list},
                    };
                    proj.run(&this->ctx, args);

                    for (int i = 0; i < this->n_op; i++)
                        verify_ckks_precision(this->ctx, vec_conj(xv.messages()[i]), y_list[i]);
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MAC tests — default param only
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS ct_pt_ringt_mac", "", CkksTestDefaultParams) {
    int level = 5;
    if (this->max_level < level)
        return;

    for (int m = 2; m <= 20; m++) {
        SECTION("m=" + to_string(m) + "/lv=" + to_string(level)) {
            string relative_path = this->tag + "/CKKS_cmpac_ringt/level_" + to_string(level) + "_m_" + to_string(m);
            run_ckks_backends("", relative_path, [&](auto& proj) {
                auto cv = new_test_complex_cts(m, this->ctx, level);
                auto pv = new_test_complex_pts(m, this->ctx, 0, true);
                vector<CkksCiphertext> z_list;
                z_list.reserve(1);
                z_list.push_back(CkksCiphertext(this->param, level));

                vector<CxxVectorArgument> args = {
                    {"in_c_list", &cv.ciphertexts()},
                    {"in_p_list", &pv.plaintexts()},
                    {"out_z_list", &z_list},
                };
                proj.run(&this->ctx, args);

                vector<complex<double>> expected(this->n_slot, complex<double>{0.0, 0.0});
                for (int i = 0; i < m; i++)
                    expected = vec_add(expected, vec_mul(cv.messages()[i], pv.messages()[i]));
                verify_ckks_precision(this->ctx, expected, z_list[0]);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS n_poly", "[.]", CkksTestDefaultParams) {
    if (this->max_level < 4)
        return;

    SECTION("lv=4") {
        string relative_path = this->tag + "/CKKS_n_poly/level_4";
        run_ckks_backends("", relative_path, [&](auto& proj) {
            auto xv = new_test_complex_cts(1, this->ctx, 4);
            auto coeff0v = new_test_complex_pts(1, this->ctx, 1, false);
            auto coeffsv = new_test_complex_pts(3, this->ctx, 0, true);
            vector<CkksCiphertext> y_list;
            y_list.push_back(CkksCiphertext(this->param, 1));

            vector<CxxVectorArgument> args = {
                {"x", &xv.ciphertexts()},
                {"coeff0", &coeff0v.plaintexts()},
                {"coeffs", &coeffsv.plaintexts()},
                {"y", &y_list},
            };
            proj.run(&this->ctx, args);

            vector<complex<double>> y_true = coeff0v.messages()[0];
            vector<complex<double>> x_power = xv.messages()[0];
            for (int j = 0; j < 3; j++) {
                if (j > 0)
                    x_power = vec_mul(x_power, xv.messages()[0]);
                y_true = vec_add(y_true, vec_mul(x_power, coeffsv.messages()[j]));
            }
            verify_ckks_precision(this->ctx, y_true, y_list[0], 12);
        });
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS custom encode and cap", "", CkksTestDefaultParams) {
    for (int level = 1; level <= this->max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            string relative_path =
                this->tag + "/CKKS_" + to_string(this->n_op) + "_custom_encode_and_cap/level_" + to_string(level);
            run_ckks_backends("", relative_path, [&](auto& proj) {
                auto xv = new_test_complex_cts(this->n_op, this->ctx, level);

                vector<vector<complex<double>>> y_vals;
                vector<CustomData> y_list;
                for (int i = 0; i < this->n_op; i++) {
                    y_vals.push_back(rand_complex_values(this->n_slot));
                    y_list.push_back(CustomData(y_vals[i]));
                }
                vector<CkksCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(CkksCiphertext(this->param, level));

                std::unordered_map<std::string, ExecutorFunc> custom_executors;
                custom_executors["encode"] = [this](ExecutionContext& exec_ctx,
                                                    std::unordered_map<NodeId, std::any>& local_data,
                                                    const ComputeNode& self) -> void {
                    auto* ckks_ctx = exec_ctx.get_arithmetic_context<CkksContext>();
                    if (!self.custom_prop.has_value())
                        throw std::runtime_error("Custom property not found for encode operation");
                    int encode_level = self.custom_prop->attributes["level"].get<int>();
                    double encode_scale = self.custom_prop->attributes["scale"].get<double>();
                    const NodeId& input_node_id = self.input_nodes[0]->id;
                    auto input_handle_ptr = std::any_cast<std::shared_ptr<CustomData>>(local_data.at(input_node_id));
                    auto* msg_vec = input_handle_ptr->get_typed_data<std::vector<std::complex<double>>>();
                    auto plaintext = std::make_shared<CkksPlaintext>(
                        ckks_ctx->parameter(), plaintext_metadata(false, true, encode_level,
                                                                  ckks_ctx->parameter().log_max_slots(), encode_scale));
                    ckks_ctx->encode(*msg_vec, *plaintext);
                    local_data[self.output_nodes[0]->id] = plaintext;
                };
                proj.bind_custom_executors(custom_executors);

                vector<CxxVectorArgument> args = {
                    {"in_x_list", &xv.ciphertexts()},
                    {"in_y_list", &y_list},
                    {"out_z_list", &z_list},
                };
                proj.run(&this->ctx, args);

                for (int i = 0; i < this->n_op; i++) {
                    vector<complex<double>> z_true = vec_add(xv.messages()[i], y_vals[i]);
                    verify_ckks_precision(this->ctx, z_true, z_list[i]);
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap tests — default param only
// ---------------------------------------------------------------------------

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS bootstrap", "[.]", CkksTestDefaultParams) {
    this->ctx.create_bootstrapper();
    for (int log_slots : unary_slot_cases(this->param)) {
        string slot_tag = unary_slot_tag(log_slots);
        SECTION(slot_tag + " lv=0") {
            string relative_path = this->tag + "/CKKS_" + to_string(this->n_op) + "_bootstrap/" + slot_tag + "/level_0";
            run_ckks_backends("", relative_path, [&](auto& proj) {
                auto xv = new_test_complex_cts(this->n_op, this->ctx, 0, log_slots);
                vector<CkksCiphertext> y_list;
                y_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    y_list.push_back(
                        CkksCiphertext(this->param, this->max_level));  // full bootstrap refreshes to max level
                vector<CxxVectorArgument> args = {
                    {"in_x_list", &xv.ciphertexts()},
                    {"out_y_list", &y_list},
                };
                proj.run(&this->ctx, args);

                const int bootstrap_log2_min_prec =
                    std::max(this->param.log_default_scale() - this->param.log_n() - 12, 0);
                for (int i = 0; i < this->n_op; i++)
                    verify_ckks_precision(this->ctx, xv.messages()[i], y_list[i], bootstrap_log2_min_prec,
                                          /*print_precision_stats=*/true);
            });
        }
    }
}

// Multiple ciphertexts bootstrapped together through a single node
// (frontend list form; the backend evaluates them in one bootstrap_many call).
TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS bootstrap_multi", "[.]", CkksTestDefaultParams) {
    this->ctx.create_bootstrapper();
    for (int log_slots : unary_slot_cases(this->param)) {
        string slot_tag = unary_slot_tag(log_slots);
        SECTION(slot_tag + " lv=0") {
            string relative_path =
                this->tag + "/CKKS_" + to_string(this->n_op) + "_bootstrap_multi/" + slot_tag + "/level_0";
            run_ckks_backends("", relative_path, [&](auto& proj) {
                auto xv = new_test_complex_cts(this->n_op, this->ctx, 0, log_slots);
                vector<CkksCiphertext> y_list;
                y_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    y_list.push_back(CkksCiphertext(this->param, this->max_level));
                vector<CxxVectorArgument> args = {
                    {"in_x_list", &xv.ciphertexts()},
                    {"out_y_list", &y_list},
                };
                proj.run(&this->ctx, args);

                const int bootstrap_log2_min_prec =
                    std::max(this->param.log_default_scale() - this->param.log_n() - 12, 0);
                for (int i = 0; i < this->n_op; i++)
                    verify_ckks_precision(this->ctx, xv.messages()[i], y_list[i], bootstrap_log2_min_prec,
                                          /*print_precision_stats=*/true);
            });
        }
    }
}

TEMPLATE_TEST_CASE_METHOD(CkksFixture, "CKKS cmc_relin_rescale_bootstrap", "[.]", CkksTestDefaultParams) {
    this->ctx.create_bootstrapper();
    for (const auto& [lhs_log_slots, rhs_log_slots] : binary_slot_cases(this->param)) {
        string slot_tag = binary_slot_tag(lhs_log_slots, rhs_log_slots);
        SECTION(slot_tag + " lv=3") {
            int level = 3;
            string relative_path =
                this->tag + "/CKKS_" + to_string(this->n_op) + "_cmc_relin_rescale_bootstrap/" + slot_tag + "/level_3";
            run_ckks_backends("", relative_path, [&](auto& proj) {
                auto xv = new_test_complex_cts(this->n_op, this->ctx, level, lhs_log_slots);
                auto yv = new_test_complex_cts(this->n_op, this->ctx, level, rhs_log_slots);
                vector<CkksCiphertext> z_list;
                z_list.reserve(this->n_op);
                for (int _i = 0; _i < this->n_op; _i++)
                    z_list.push_back(CkksCiphertext(this->param, this->max_level));
                vector<CxxVectorArgument> args = {
                    {"in_x_list", &xv.ciphertexts()},
                    {"in_y_list", &yv.ciphertexts()},
                    {"out_z_list", &z_list},
                };
                proj.run(&this->ctx, args);

                int output_log_slots = std::max(lhs_log_slots, rhs_log_slots);
                const int bootstrap_log2_min_prec =
                    std::max(this->param.log_default_scale() - this->param.log_n() - 12, 0);
                for (int i = 0; i < this->n_op; i++) {
                    vector<complex<double>> lhs =
                        expand_to_log_slots(xv.messages()[i], lhs_log_slots, output_log_slots);
                    vector<complex<double>> rhs =
                        expand_to_log_slots(yv.messages()[i], rhs_log_slots, output_log_slots);
                    verify_ckks_precision(this->ctx, vec_mul(lhs, rhs), z_list[i], bootstrap_log2_min_prec);
                }
            });
        }
    }
}

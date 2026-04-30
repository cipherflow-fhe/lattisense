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

/** @file mega_ag_executors_cpu.cpp
 * @brief CPU executor implementations for MegaAG compute nodes
 */

#include <memory>
#include <stdexcept>
#include <any>
#include <iostream>
#include "../mega_ag_executors.h"
#include "fhe_lib_v2.h"

using namespace fhe_ops_lib;

// Helper macro to extract common executor setup with typed data
#define CPU_EXECUTOR_SETUP(SchemeType)                                                                                 \
    using CiphertextType = std::conditional_t<SchemeType == HEScheme::BFV, BfvCiphertext, CkksCiphertext>;             \
    using Ciphertext3Type = std::conditional_t<SchemeType == HEScheme::BFV, BfvCiphertext3, CkksCiphertext3>;          \
    using PlaintextType = std::conditional_t<SchemeType == HEScheme::BFV, BfvPlaintext, CkksPlaintext>;                \
    using PlaintextRingtType = std::conditional_t<SchemeType == HEScheme::BFV, BfvPlaintextRingt, CkksPlaintextRingt>; \
    using PlaintextMulType = std::conditional_t<SchemeType == HEScheme::BFV, BfvPlaintextMul, CkksPlaintextMul>;       \
    using ContextType = std::conditional_t<SchemeType == HEScheme::BFV, BfvContext, CkksContext>;                      \
    ContextType* context = nullptr;                                                                                    \
    if constexpr (SchemeType == HEScheme::BFV) {                                                                       \
        context = std::any_cast<BfvContext*>(ctx.context);                                                             \
    } else {                                                                                                           \
        if (auto* ckks_ctx = std::any_cast<CkksContext*>(&ctx.context)) {                                              \
            context = *ckks_ctx;                                                                                       \
        } else if (auto* ckks_btp_ctx = std::any_cast<CkksBtpContext*>(&ctx.context)) {                                \
            context = *ckks_btp_ctx;                                                                                   \
        } else {                                                                                                       \
            throw std::runtime_error("Unknown CKKS context type");                                                     \
        }                                                                                                              \
    }                                                                                                                  \
    std::vector<CiphertextType*> ciphertexts;                                                                          \
    std::vector<Ciphertext3Type*> ciphertexts3;                                                                        \
    std::vector<PlaintextType*> plaintexts;                                                                            \
    std::vector<PlaintextRingtType*> plaintexts_ringt;                                                                 \
    std::vector<PlaintextMulType*> plaintexts_mul;                                                                     \
    for (auto* input_node : self.input_nodes) {                                                                        \
        auto input_any = inputs.at(input_node->index);                                                                 \
        auto input_handle_ptr = std::any_cast<std::shared_ptr<Handle>>(input_any);                                     \
        Handle* input_handle = input_handle_ptr.get();                                                                 \
        if (input_node->datum_type == TYPE_CIPHERTEXT) {                                                               \
            if (input_node->degree == 2) {                                                                             \
                ciphertexts3.push_back(static_cast<Ciphertext3Type*>(input_handle));                                   \
            } else {                                                                                                   \
                ciphertexts.push_back(static_cast<CiphertextType*>(input_handle));                                     \
            }                                                                                                          \
        } else if (input_node->datum_type == TYPE_PLAINTEXT) {                                                         \
            if (input_node->p && input_node->p->is_ringt) {                                                            \
                plaintexts_ringt.push_back(static_cast<PlaintextRingtType*>(input_handle));                            \
            } else if (input_node->is_ntt && input_node->is_mform) {                                                   \
                plaintexts_mul.push_back(static_cast<PlaintextMulType*>(input_handle));                                \
            } else {                                                                                                   \
                plaintexts.push_back(static_cast<PlaintextType*>(input_handle));                                       \
            }                                                                                                          \
        } else {                                                                                                       \
            throw std::runtime_error("Unknown input datum type");                                                      \
        }                                                                                                              \
    }

// Helper function to find plaintext node in inputs
// Returns the 2nd input node (index 1) as the plaintext node when there are exactly 2 inputs
static DatumNode* find_plaintext_node(const ComputeNode& node) {
    if (node.input_nodes.size() == 2) {
        auto* datum_node = node.input_nodes[1];
        if (datum_node->datum_type == DataType::TYPE_PLAINTEXT) {
            return datum_node;  // 2nd input node is plaintext
        }
    }
    return nullptr;
}

template <HEScheme SchemeType> void bind_cpu_add(ComputeNode& node) {
    if (node.input_nodes.size() == 1) {
        // Single input: ct + ct (same input)
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            CPU_EXECUTOR_SETUP(SchemeType);
            output = std::static_pointer_cast<Handle>(
                std::make_shared<CiphertextType>(context->add(*ciphertexts[0], *ciphertexts[0])));
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if (pt_node->p && pt_node->p->is_ringt) {
                // ct + pt_ringt (BFV and CKKS)
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    CPU_EXECUTOR_SETUP(SchemeType);
                    output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(
                        context->add_plain_ringt(*ciphertexts[0], *plaintexts_ringt[0])));
                };
            } else {
                // ct + pt (normal)
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    CPU_EXECUTOR_SETUP(SchemeType);
                    output = std::static_pointer_cast<Handle>(
                        std::make_shared<CiphertextType>(context->add_plain(*ciphertexts[0], *plaintexts[0])));
                };
            }
        } else {
            // ct + ct
            node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                               std::any& output, const ComputeNode& self) -> void {
                CPU_EXECUTOR_SETUP(SchemeType);
                output = std::static_pointer_cast<Handle>(
                    std::make_shared<CiphertextType>(context->add(*ciphertexts[0], *ciphertexts[1])));
            };
        }
    }
}

template <HEScheme SchemeType> void bind_cpu_sub(ComputeNode& node) {
    if (node.input_nodes.size() == 1) {
        // Single input: ct - ct (same input)
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            CPU_EXECUTOR_SETUP(SchemeType);
            output = std::static_pointer_cast<Handle>(
                std::make_shared<CiphertextType>(context->sub(*ciphertexts[0], *ciphertexts[0])));
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if (pt_node->p && pt_node->p->is_ringt) {
                // ct - pt_ringt (BFV and CKKS)
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    CPU_EXECUTOR_SETUP(SchemeType);
                    output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(
                        context->sub_plain_ringt(*ciphertexts[0], *plaintexts_ringt[0])));
                };
            } else {
                // ct - pt (normal)
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    CPU_EXECUTOR_SETUP(SchemeType);
                    output = std::static_pointer_cast<Handle>(
                        std::make_shared<CiphertextType>(context->sub_plain(*ciphertexts[0], *plaintexts[0])));
                };
            }
        } else {
            // ct - ct
            node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                               std::any& output, const ComputeNode& self) -> void {
                CPU_EXECUTOR_SETUP(SchemeType);
                output = std::static_pointer_cast<Handle>(
                    std::make_shared<CiphertextType>(context->sub(*ciphertexts[0], *ciphertexts[1])));
            };
        }
    }
}

template <HEScheme SchemeType> void bind_cpu_neg(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        CPU_EXECUTOR_SETUP(SchemeType);
        output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(context->negate(*ciphertexts[0])));
    };
}

template <HEScheme SchemeType> void bind_cpu_mult(ComputeNode& node) {
    if (node.input_nodes.size() == 1) {
        // Single input: ct * ct (same input)
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            CPU_EXECUTOR_SETUP(SchemeType);
            output = std::static_pointer_cast<Handle>(
                std::make_shared<Ciphertext3Type>(context->mult(*ciphertexts[0], *ciphertexts[0])));
        };
    } else {
        DatumNode* pt_node = find_plaintext_node(node);
        if (pt_node) {
            if (pt_node->p && pt_node->p->is_ringt) {
                // ct * pt_ringt
                if constexpr (SchemeType == HEScheme::BFV) {
                    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                       std::any& output, const ComputeNode& self) -> void {
                        CPU_EXECUTOR_SETUP(SchemeType);
                        output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(
                            context->mult_plain_ringt(*ciphertexts[0], *plaintexts_ringt[0])));
                    };
                } else {
                    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                       std::any& output, const ComputeNode& self) -> void {
                        CPU_EXECUTOR_SETUP(SchemeType);
                        int level = ciphertexts[0]->get_level();
                        PlaintextMulType pt_mul = context->ringt_to_mul(*plaintexts_ringt[0], level);
                        output = std::static_pointer_cast<Handle>(
                            std::make_shared<CiphertextType>(context->mult_plain_mul(*ciphertexts[0], pt_mul)));
                    };
                }
            } else if (pt_node->is_ntt && pt_node->is_mform) {
                // ct * pt_mul
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    CPU_EXECUTOR_SETUP(SchemeType);
                    output = std::static_pointer_cast<Handle>(
                        std::make_shared<CiphertextType>(context->mult_plain_mul(*ciphertexts[0], *plaintexts_mul[0])));
                };
            } else {
                // ct * pt (normal)
                node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                   std::any& output, const ComputeNode& self) -> void {
                    CPU_EXECUTOR_SETUP(SchemeType);
                    output = std::static_pointer_cast<Handle>(
                        std::make_shared<CiphertextType>(context->mult_plain(*ciphertexts[0], *plaintexts[0])));
                };
            }
        } else {
            // ct * ct
            node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                               std::any& output, const ComputeNode& self) -> void {
                CPU_EXECUTOR_SETUP(SchemeType);
                output = std::static_pointer_cast<Handle>(
                    std::make_shared<Ciphertext3Type>(context->mult(*ciphertexts[0], *ciphertexts[1])));
            };
        }
    }
}

template <HEScheme SchemeType> void bind_cpu_relin(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        CPU_EXECUTOR_SETUP(SchemeType);
        output =
            std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(context->relinearize(*ciphertexts3[0])));
    };
}

template <HEScheme SchemeType> void bind_cpu_rescale(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        CPU_EXECUTOR_SETUP(SchemeType);
        if constexpr (SchemeType == HEScheme::BFV) {
            output =
                std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(context->rescale(*ciphertexts[0])));
        } else {
            output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(
                context->rescale(*ciphertexts[0], context->get_parameter().get_default_scale())));
        }
    };
}

template <HEScheme SchemeType> void bind_cpu_drop_level(ComputeNode& node) {
    if constexpr (SchemeType == HEScheme::CKKS) {
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            CPU_EXECUTOR_SETUP(SchemeType);
            output = std::static_pointer_cast<Handle>(
                std::make_shared<CiphertextType>(context->drop_level(*ciphertexts[0], 1)));
        };
    } else {
        throw std::runtime_error("DROP_LEVEL only supported for CKKS scheme");
    }
}

template <HEScheme SchemeType> void bind_cpu_rotate_col(ComputeNode& node) {
    if (!node.p) {
        throw std::runtime_error("ROTATE_COL requires rotation_step property");
    }
    int step = node.p->rotation_step;
    node.executor = [step](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
        CPU_EXECUTOR_SETUP(SchemeType);
        if constexpr (SchemeType == HEScheme::BFV) {
            output = std::static_pointer_cast<Handle>(
                std::make_shared<CiphertextType>(context->advanced_rotate_cols(*ciphertexts[0], step)));
        } else {
            output = std::static_pointer_cast<Handle>(
                std::make_shared<CiphertextType>(context->advanced_rotate(*ciphertexts[0], step)));
        }
    };
}

template <HEScheme SchemeType> void bind_cpu_rotate_row(ComputeNode& node) {
    node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs, std::any& output,
                       const ComputeNode& self) -> void {
        CPU_EXECUTOR_SETUP(SchemeType);
        if constexpr (SchemeType == HEScheme::BFV) {
            output = std::static_pointer_cast<Handle>(
                std::make_shared<CiphertextType>(context->rotate_rows(*ciphertexts[0])));
        } else {
            output =
                std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(context->conjugate(*ciphertexts[0])));
        }
    };
}

template <HEScheme SchemeType> void bind_cpu_cmpac_sum(ComputeNode& node) {
    if (!node.p) {
        throw std::runtime_error("MAC_W_PARTIAL_SUM requires sum_cnt property");
    }
    int n = node.p->sum_cnt;
    DatumNode* pt_node = node.input_nodes[n + 1];

    if (pt_node->p && pt_node->p->is_ringt) {
        // ct * pt_ringt
        if constexpr (SchemeType == HEScheme::BFV) {
            node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                std::any& output, const ComputeNode& self) -> void {
                CPU_EXECUTOR_SETUP(SchemeType);
                std::vector<CiphertextType> products(n);
                for (int i = 0; i < n; i++) {
                    products[i] = context->mult_plain_ringt(*ciphertexts[i], *plaintexts_ringt[i]);
                }
                CiphertextType sum = std::move(products[0]);
                for (int i = 0; i < n - 1; i++) {
                    sum = context->add(sum, products[i + 1]);
                }
                output = std::static_pointer_cast<Handle>(
                    std::make_shared<CiphertextType>(context->add(sum, *ciphertexts[n])));
            };
        } else {
            // CKKS: convert pt_ringt to pt_mul then multiply
            node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                std::any& output, const ComputeNode& self) -> void {
                CPU_EXECUTOR_SETUP(SchemeType);
                std::vector<CiphertextType> products(n);
                for (int i = 0; i < n; i++) {
                    int level = ciphertexts[i]->get_level();
                    PlaintextMulType pt_mul = context->ringt_to_mul(*plaintexts_ringt[i], level);
                    products[i] = context->mult_plain_mul(*ciphertexts[i], pt_mul);
                }
                CiphertextType sum = std::move(products[0]);
                for (int i = 0; i < n - 1; i++) {
                    sum = context->add(sum, products[i + 1]);
                }
                output = std::static_pointer_cast<Handle>(
                    std::make_shared<CiphertextType>(context->add(sum, *ciphertexts[n])));
            };
        }
    } else if (pt_node->is_ntt && pt_node->is_mform) {
        // ct * pt_mul
        node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                            std::any& output, const ComputeNode& self) -> void {
            CPU_EXECUTOR_SETUP(SchemeType);
            std::vector<CiphertextType> products(n);
            for (int i = 0; i < n; i++) {
                products[i] = context->mult_plain_mul(*ciphertexts[i], *plaintexts_mul[i]);
            }
            CiphertextType sum = std::move(products[0]);
            for (int i = 0; i < n - 1; i++) {
                sum = context->add(sum, products[i + 1]);
            }
            output =
                std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(context->add(sum, *ciphertexts[n])));
        };
    } else {
        // ct * pt (normal)
        node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                            std::any& output, const ComputeNode& self) -> void {
            CPU_EXECUTOR_SETUP(SchemeType);
            std::vector<CiphertextType> products(n);
            for (int i = 0; i < n; i++) {
                products[i] = context->mult_plain(*ciphertexts[i], *plaintexts[i]);
            }
            CiphertextType sum = std::move(products[0]);
            for (int i = 0; i < n - 1; i++) {
                sum = context->add(sum, products[i + 1]);
            }
            output =
                std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(context->add(sum, *ciphertexts[n])));
        };
    }
}

template <HEScheme SchemeType> void bind_cpu_cmp_sum(ComputeNode& node) {
    if (!node.p) {
        throw std::runtime_error("MAC_WO_PARTIAL_SUM requires sum_cnt property");
    }
    int n = node.p->sum_cnt;
    DatumNode* pt_node = node.input_nodes[n];

    if (pt_node->p && pt_node->p->is_ringt) {
        // ct * pt_ringt
        if constexpr (SchemeType == HEScheme::BFV) {
            node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                std::any& output, const ComputeNode& self) -> void {
                CPU_EXECUTOR_SETUP(SchemeType);
                std::vector<CiphertextType> products(n);
                for (int i = 0; i < n; i++) {
                    products[i] = context->mult_plain_ringt(*ciphertexts[i], *plaintexts_ringt[i]);
                }
                CiphertextType sum = std::move(products[0]);
                for (int i = 0; i < n - 1; i++) {
                    sum = context->add(sum, products[i + 1]);
                }
                output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(std::move(sum)));
            };
        } else {
            // CKKS: convert pt_ringt to pt_mul then multiply
            node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                                std::any& output, const ComputeNode& self) -> void {
                CPU_EXECUTOR_SETUP(SchemeType);
                std::vector<CiphertextType> products(n);
                for (int i = 0; i < n; i++) {
                    int level = ciphertexts[i]->get_level();
                    PlaintextMulType pt_mul = context->ringt_to_mul(*plaintexts_ringt[i], level);
                    products[i] = context->mult_plain_mul(*ciphertexts[i], pt_mul);
                }
                CiphertextType sum = std::move(products[0]);
                for (int i = 0; i < n - 1; i++) {
                    sum = context->add(sum, products[i + 1]);
                }
                output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(std::move(sum)));
            };
        }
    } else if (pt_node->is_ntt && pt_node->is_mform) {
        // ct * pt_mul
        node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                            std::any& output, const ComputeNode& self) -> void {
            CPU_EXECUTOR_SETUP(SchemeType);
            std::vector<CiphertextType> products(n);
            for (int i = 0; i < n; i++) {
                products[i] = context->mult_plain_mul(*ciphertexts[i], *plaintexts_mul[i]);
            }
            CiphertextType sum = std::move(products[0]);
            for (int i = 0; i < n - 1; i++) {
                sum = context->add(sum, products[i + 1]);
            }
            output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(std::move(sum)));
        };
    } else {
        // ct * pt (normal)
        node.executor = [n](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                            std::any& output, const ComputeNode& self) -> void {
            CPU_EXECUTOR_SETUP(SchemeType);
            std::vector<CiphertextType> products(n);
            for (int i = 0; i < n; i++) {
                products[i] = context->mult_plain(*ciphertexts[i], *plaintexts[i]);
            }
            CiphertextType sum = std::move(products[0]);
            for (int i = 0; i < n - 1; i++) {
                sum = context->add(sum, products[i + 1]);
            }
            output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(std::move(sum)));
        };
    }
}

template <HEScheme SchemeType> void bind_cpu_bootstrap(ComputeNode& node) {
    if constexpr (SchemeType == HEScheme::CKKS) {
        node.executor = [](ExecutionContext& ctx, const std::unordered_map<NodeIndex, std::any>& inputs,
                           std::any& output, const ComputeNode& self) -> void {
            CPU_EXECUTOR_SETUP(SchemeType);
            auto* btp_context = dynamic_cast<CkksBtpContext*>(context);
            if (!btp_context) {
                throw std::runtime_error("Bootstrap requires CkksBtpContext");
            }
            auto input_scale = ciphertexts[0]->get_scale();
            ciphertexts[0]->set_scale(btp_context->get_parameter().get_default_scale());
            auto result = btp_context->bootstrap(*ciphertexts[0]);
            result.set_scale(input_scale);
            output = std::static_pointer_cast<Handle>(std::make_shared<CiphertextType>(std::move(result)));
        };
    } else {
        throw std::runtime_error("BOOTSTRAP only supported for CKKS scheme");
    }
}

/**
 * 辅助函数：计算目标函数在 [a, b] 区间的切比雪夫系数
 * 用于将连续函数转换为 Clenshaw 算法所需的向量
 */
std::vector<double> compute_chebyshev_coeffs(double (*func)(double), double a, double b, int degree) {
    int n = degree + 1;
    std::vector<double> coeffs(n, 0.0);
    // 使用离散余弦变换 (DCT-II) 采样点
    for (int j = 0; j < n; ++j) {
        double sum = 0.0;
        for (int k = 0; k < n; ++k) {
            // 切比雪夫节点映射到 [a, b]
            double x_k = std::cos(M_PI * (k + 0.5) / n);
            double real_x = 0.5 * (b - a) * x_k + 0.5 * (b + a);
            sum += func(real_x) * std::cos(M_PI * j * (k + 0.5) / n);
        }
        coeffs[j] = (2.0 / n) * sum;
    }
    return coeffs;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////
// 单独添加基于chebyshev基的多项式求值
////////////////////////////////////////////////////////////////////////////////////////////////////////
template <HEScheme SchemeType> void bind_cpu_poly_eval(ComputeNode& node) {
    // 模板函数，限定 CKKS 方案
    if constexpr (SchemeType == HEScheme::CKKS) {
        // 从节点属性中读取参数
        if (!node.p) throw std::runtime_error("POLY_EVAL missing properties");
        int degree = node.p->poly_degree;
        double left = node.p->poly_left;
        double right = node.p->poly_right;
        std::string func_name = node.p->poly_func;
        std::vector<double> coeffs = node.p->poly_coeffs;
        if (coeffs.empty()) {
            throw std::runtime_error("POLY_EVAL: empty coefficients from Python");
        }
        std::cout << "[DEBUG] Received coeffs (" << coeffs.size() << "): ";
        for (double c : coeffs) std::cout << c << " ";
        std::cout << std::endl;

        node.executor = [coeffs, left, right, func_name, degree](
            ExecutionContext& ctx,
            const std::unordered_map<NodeIndex, std::any>& inputs,
            std::any& output,
            const ComputeNode& self) -> void {
            //  宏展开后得到 context 指针和 ciphertexts 向量
            CPU_EXECUTOR_SETUP(SchemeType);
            // 确保 context 有效
            if (!context) {
                throw std::runtime_error("CkksContext is null in poly_eval executor");
            }
            // 互斥锁保护（避免 CGO 并发问题）
            static std::mutex cgo_mutex;
            std::lock_guard<std::mutex> lock(cgo_mutex);

            // 输出记录
            std::cout << "func_name = " << func_name 
                     << ", left = " << left 
                     << ", right = " << right << "\n";
            uint64_t slots = context->get_parameter().get_n() / 2;
            double base_scale = context->get_parameter().get_default_scale();
            // std::cout << "[CHECK] bind_cpu_poly_eval read Scale: " << base_scale << std::endl;

            // 进行选择，确定目标函数指针
            double (*target_op)(double) = nullptr;
            if (func_name == "exp") {
                target_op = static_cast<double(*)(double)>(std::exp);
            } else if (func_name == "reciprocal") {
                target_op = [](double x) -> double { return 1.0 / x; };
            } else if (func_name == "sigmoid") {
                target_op = [](double x) -> double { return 1.0 / (1.0 + std::exp(-x)); };
            } else {
                throw std::runtime_error("Unsupported function: " + func_name);
            }   

            std::cout << "The calculation this time is " << func_name << std::endl;
            // 调用Clenshaw 算法
            auto result = context->poly_eval_chebyshev(*ciphertexts[0], coeffs, left, right, slots, base_scale);
            std::cout << "successfully complete Chebyshev result for " << func_name << std::endl;

            output = std::static_pointer_cast<Handle>(
                std::make_shared<CiphertextType>(std::move(result)));
        };
    } else {
        throw std::runtime_error("POLY_EVAL only supported for CKKS");
    }
}
// 牛顿迭代实际计算
template <HEScheme SchemeType> void bind_cpu_newton_reciprocal(ComputeNode& node) {
    if constexpr (SchemeType == HEScheme::CKKS) {
        if (!node.p) throw std::runtime_error("NEWTON_RECIPROCAL missing properties");

        int iterations = node.p->newton_iterations;
        double init_guess = node.p->newton_init_guess; // 单值初值

        // 将读取的参数传入进行计算，实现真正的计算逻辑
        node.executor = [iterations, init_guess](
            ExecutionContext& ctx,
            const std::unordered_map<NodeIndex, std::any>& inputs,
            std::any& output,
            const ComputeNode& self) -> void {
            
            CPU_EXECUTOR_SETUP(SchemeType);
            static std::mutex cgo_mutex;
            std::lock_guard<std::mutex> lock(cgo_mutex);

            uint64_t slots = context->get_parameter().get_n() / 2;
            double base_scale = context->get_parameter().get_default_scale();
            auto& x_orig = *ciphertexts[0];
            auto init_level = x_orig.get_level();

            // 1. 构造密文 0: y = x - x
            auto y = context->sub(x_orig, x_orig);
            // 2. 将 init_guess 编码为明文，Level 和 Scale 必须与 y 对齐
            std::vector<double> init_vec(slots, init_guess);
            auto init_pt = context->encode(init_vec, y.get_level(), y.get_scale());
            // 3. y = 密文(0) + 明文 -> y 现在是密文常数
            y = context->add_plain(y, init_pt);
            
            // 牛顿迭代，一次迭代消耗两层
            for (int i = 0; i < iterations; ++i) {
                // 每次迭代前，确保 w 和 y 在同一 Level 上
                if (x_orig.get_level() > y.get_level()) {
                    x_orig = context->drop_level(x_orig, x_orig.get_level() - y.get_level());
                } else if (y.get_level() > x_orig.get_level()) {
                    y = context->drop_level(y, y.get_level() - x_orig.get_level());
                }
                CkksCiphertext3 t3 = context->mult(x_orig, y);
                CkksCiphertext t   = context->relinearize(t3);
                t = context->rescale(t, base_scale);   // t.level == y.level - 1

                // 1. 计算 r = 2.0 - t
                std::vector<double> two_vec(slots, 2.0);
                CkksPlaintext two_pt = context->encode(two_vec,t.get_level(), t.get_scale());
                auto t_minus_two = context->sub_plain(t, two_pt);
                auto r = context->negate(t_minus_two);   // r = 2.0 - t，y.level - 1
                // 再次处理层级，此时y.level 与 r.level = y.level - 1
                if (y.get_level() > r.get_level()) {
                    y = context->drop_level(y, y.get_level() - r.get_level());
                } else if (r.get_level() > y.get_level()) {
                    r = context->drop_level(r, r.get_level() - y.get_level());
                }
                // 更新y
                CkksCiphertext3 y3  = context->mult(y, r);
                CkksCiphertext y_new = context->relinearize(y3);
                y_new = context->rescale(y_new, base_scale);
                // y_new.level == y.level - 2（经过对齐后的 y）

                y = std::move(y_new);
            }

            output = std::static_pointer_cast<Handle>(
                std::make_shared<CiphertextType>(std::move(y)));
        };
    } else {
        throw std::runtime_error("NEWTON_RECIPROCAL only supported for CKKS");
    }
}

template <HEScheme SchemeType> void bind_cpu_goldschmidt_reciprocal(ComputeNode& node) {
    if constexpr (SchemeType == HEScheme::CKKS) {
        if (!node.p) throw std::runtime_error("goldschmidt_reciprocal missing properties");

        int iterations = node.p->goldschmidt_iterations;

        // 将读取的参数传入进行计算，实现真正的计算逻辑
        node.executor = [iterations](
            ExecutionContext& ctx,
            const std::unordered_map<NodeIndex, std::any>& inputs,
            std::any& output,
            const ComputeNode& self) -> void {
            
            CPU_EXECUTOR_SETUP(SchemeType);

            // 锁，强制每个值都串行执行
            static std::mutex cgo_mutex;
            std::lock_guard<std::mutex> lock(cgo_mutex);

            // 1. 获取输入
            // ciphertexts[0] 是 x, ciphertexts[1] 是 y_init
            if (ciphertexts.size() < 2) {
                throw std::runtime_error("Goldschmidt_Reciprocal requires 2 ciphertext inputs.");
            }

            auto w = ciphertexts[0]->copy();
            auto y = ciphertexts[1]->copy();

            // 实时获取 slots 和 base_scale
            uint64_t slots = context->get_parameter().get_n() / 2;
            double base_scale = context->get_parameter().get_default_scale();
            auto init_level = w.get_level();

            std::cout << "before w level：" << w.get_level() << " y level：" << y.get_level() << std::endl;

            if (w.get_level() > y.get_level()) {
                w = context->drop_level(w, w.get_level() - y.get_level());
            } else if (y.get_level() > w.get_level()) {
                y = context->drop_level(y, y.get_level() - w.get_level());
            }

            std::cout << "after w level：" << w.get_level() << " y level：" << y.get_level() << std::endl;
            // 增加范围处理，能够支持超过2的输入，但是会额外消耗一层
            CkksCiphertext3 a_3 = context->mult(w, y);
            CkksCiphertext a_new = context->relinearize(a_3);
            w = context->rescale(a_new, base_scale);

            // goldschmidt迭代，一次迭代消耗一层
            for (int i = 0; i < iterations; ++i) {
                // 1. 计算 r = 2.0 - w
                // 构造匹配 w 当前 Level 和 Scale 的常数 2.0
                std::vector<double> two_vec(slots, 2.0);
                std::vector<double> one_vec(slots, 1.0);
                CkksPlaintext two_pt = context->encode(two_vec, w.get_level(), w.get_scale());
                CkksPlaintext one_pt = context->encode(one_vec, w.get_level(), w.get_scale());

                auto zero_ct = context->sub(w, w);  // 0 (密文)
                auto minus_w = context->sub(zero_ct, w);  // 0-w=-w（密文）
                auto r = context->add_plain(minus_w, two_pt);  // r = 2.0 - w

                // 2. 更新 w = w * r (使 w 逐渐逼近 1)
                CkksCiphertext3 w_3 = context->mult(w, r);
                CkksCiphertext w_new = context->relinearize(w_3);
                w_new = context->rescale(w_new, base_scale);

                // 3. 更新 y = y * r (使 y 逐渐逼近 1/x)
                CkksCiphertext3 y_3 = context->mult(y, r);
                CkksCiphertext y_new = context->relinearize(y_3);
                y_new = context->rescale(y_new, base_scale);

                // 4. 步进赋值
                w = std::move(w_new);
                y = std::move(y_new);
            }

            output = std::static_pointer_cast<Handle>(
                std::make_shared<CiphertextType>(std::move(y)));
        };
    } else {
        throw std::runtime_error("Goldschmidt_Reciprocal only supported for CKKS");
    }
}


// Explicit template instantiations
template void bind_cpu_add<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_add<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_sub<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_sub<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_neg<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_neg<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_mult<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_mult<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_relin<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_relin<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_rescale<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_rescale<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_drop_level<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_rotate_col<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_rotate_col<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_rotate_row<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_rotate_row<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_cmpac_sum<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_cmpac_sum<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_cmp_sum<HEScheme::BFV>(ComputeNode& node);
template void bind_cpu_cmp_sum<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_bootstrap<HEScheme::CKKS>(ComputeNode& node);

template void bind_cpu_poly_eval<HEScheme::CKKS>(ComputeNode& node); // 新增多项式计算
template void bind_cpu_newton_reciprocal<HEScheme::CKKS>(ComputeNode& node); // 迭代法计算
template void bind_cpu_goldschmidt_reciprocal<HEScheme::CKKS>(ComputeNode& node); // goldschmidt计算



// Wrapper function for ExecutorBinder (callable from mega_ag.cpp)
void bind_cpu_executor(ComputeNode& node, Algo algorithm) {
    switch (algorithm) {
        case ALGO_BFV:
            switch (node.op_type) {
                case OperationType::ADD: bind_cpu_add<HEScheme::BFV>(node); break;
                case OperationType::SUB: bind_cpu_sub<HEScheme::BFV>(node); break;
                case OperationType::NEGATE: bind_cpu_neg<HEScheme::BFV>(node); break;
                case OperationType::MULTIPLY: bind_cpu_mult<HEScheme::BFV>(node); break;
                case OperationType::RELINEARIZE: bind_cpu_relin<HEScheme::BFV>(node); break;
                case OperationType::RESCALE: bind_cpu_rescale<HEScheme::BFV>(node); break;
                case OperationType::ROTATE_COL: bind_cpu_rotate_col<HEScheme::BFV>(node); break;
                case OperationType::ROTATE_ROW: bind_cpu_rotate_row<HEScheme::BFV>(node); break;
                case OperationType::MAC_W_PARTIAL_SUM: bind_cpu_cmpac_sum<HEScheme::BFV>(node); break;
                case OperationType::MAC_WO_PARTIAL_SUM: bind_cpu_cmp_sum<HEScheme::BFV>(node); break;
                default: throw std::runtime_error("Unsupported operation type for CPU BFV");
            }
            break;
        case ALGO_CKKS:
            switch (node.op_type) {
                case OperationType::ADD: bind_cpu_add<HEScheme::CKKS>(node); break;
                case OperationType::SUB: bind_cpu_sub<HEScheme::CKKS>(node); break;
                case OperationType::NEGATE: bind_cpu_neg<HEScheme::CKKS>(node); break;
                case OperationType::MULTIPLY: bind_cpu_mult<HEScheme::CKKS>(node); break;
                case OperationType::RELINEARIZE: bind_cpu_relin<HEScheme::CKKS>(node); break;
                case OperationType::RESCALE: bind_cpu_rescale<HEScheme::CKKS>(node); break;
                case OperationType::DROP_LEVEL: bind_cpu_drop_level<HEScheme::CKKS>(node); break;
                case OperationType::ROTATE_COL: bind_cpu_rotate_col<HEScheme::CKKS>(node); break;
                case OperationType::ROTATE_ROW: bind_cpu_rotate_row<HEScheme::CKKS>(node); break;
                case OperationType::MAC_W_PARTIAL_SUM: bind_cpu_cmpac_sum<HEScheme::CKKS>(node); break;
                case OperationType::MAC_WO_PARTIAL_SUM: bind_cpu_cmp_sum<HEScheme::CKKS>(node); break;
                case OperationType::BOOTSTRAP: bind_cpu_bootstrap<HEScheme::CKKS>(node); break;
                case OperationType::POLY_EVAL:bind_cpu_poly_eval<HEScheme::CKKS>(node); break; // 新增多项式算子注册
                case OperationType::NEWTON_RECIPROCAL:bind_cpu_newton_reciprocal<HEScheme::CKKS>(node); break; // 新增迭代算子注册
                case OperationType::GOLDSCHMIDT_RECIPROCAL:bind_cpu_goldschmidt_reciprocal<HEScheme::CKKS>(node); break; // 新增goldschmidt算子注册
                default: throw std::runtime_error("Unsupported operation type for CPU CKKS");
            }
            break;
        default: throw std::runtime_error("Unknown algorithm type for CPU");
    }
}

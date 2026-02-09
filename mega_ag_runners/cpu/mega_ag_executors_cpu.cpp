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
                default: throw std::runtime_error("Unsupported operation type for CPU CKKS");
            }
            break;
        default: throw std::runtime_error("Unknown algorithm type for CPU");
    }
}

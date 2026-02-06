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

#include <chrono>
#include <cmath>
#include <array>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "fhe_lib_v2.h"
#include "cxx_fhe_task.h"
#include "utils.h"

using namespace cxx_sdk_v2;
using namespace std;

class LattigoDBfvFixture {
public:
    LattigoDBfvFixture()
        : N{8192}, level{2}, t{65537}, n_parties(3), sigma_smudging(3.2), param{BfvParameter::create_parameter(N, t)} {
        for (int i = 0; i < 16; i++) {
            seed.push_back(i);
        }
        for (int party_id = 0; party_id < n_parties; party_id++) {
            contexts[party_id] = DBfvContext::create_random_context(param, seed, sigma_smudging);
        }
    }

protected:
    int N;
    int level;
    uint64_t t;
    int n_parties;
    double sigma_smudging;
    vector<uint8_t> seed;
    BfvParameter param;

    std::map<int, DBfvContext> contexts;
};

void gen_pk(int n_parties, int c_party_id, std::map<int, DBfvContext>& contexts) {
    std::map<int, CkgContext> ckg_contexts;
    for (int i = 0; i < n_parties; i++) {
        ckg_contexts[i] = CkgContext::create_context(contexts[i]);
    }

    std::map<int, PublicKeyShare> pk_shares;
    for (int i = 0; i < n_parties; i++) {
        pk_shares[i] = ckg_contexts[i].gen_public_key_share();
    }

    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            pk_shares[c_party_id] =
                ckg_contexts[c_party_id].aggregate_public_key_share(pk_shares[i], pk_shares[c_party_id]);
        }
    }

    ckg_contexts[c_party_id].set_public_key(pk_shares[c_party_id]);
}

void gen_rlk(int n_parties, int c_party_id, std::map<int, DBfvContext>& contexts) {
    std::map<int, RkgContext> rkg_contexts;
    for (int i = 0; i < n_parties; i++) {
        rkg_contexts[i] = RkgContext::create_context(contexts[i]);
    }

    std::map<int, RelinKeyShare> rlk_shares_round_one;
    std::map<int, SecretKey> eph_sk;
    for (int i = 0; i < n_parties; i++) {
        std::pair<RelinKeyShare, SecretKey> share = rkg_contexts[i].gen_relin_key_share_round_one();
        rlk_shares_round_one[i] = RelinKeyShare(std::move(share.first));
        eph_sk[i] = SecretKey(std::move(share.second));
    }

    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            rlk_shares_round_one[c_party_id] = rkg_contexts[c_party_id].aggregate_relin_key_share(
                rlk_shares_round_one[c_party_id], rlk_shares_round_one[i]);
        }
    }

    std::map<int, RelinKeyShare> rlk_shares_round_two;
    for (int i = 0; i < n_parties; i++) {
        rlk_shares_round_two[i] =
            rkg_contexts[i].gen_relin_key_share_round_two(eph_sk[i], rlk_shares_round_one[c_party_id]);
    }

    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            rlk_shares_round_two[c_party_id] = rkg_contexts[c_party_id].aggregate_relin_key_share(
                rlk_shares_round_two[c_party_id], rlk_shares_round_two[i]);
        }
    }

    rkg_contexts[c_party_id].set_relin_key(rlk_shares_round_one[c_party_id], rlk_shares_round_two[c_party_id]);
}

void gen_glk(int n_parties,
             int c_party_id,
             std::map<int, DBfvContext>& contexts,
             const std::vector<int32_t>& rots,
             bool include_swap_rows = false) {
    std::map<int, RtgContext> rtg_contexts;
    for (int i = 0; i < n_parties; i++) {
        rtg_contexts[i] = RtgContext::create_context(contexts[i]);
    }

    std::map<int, std::vector<GaloisKeyShare>> shares;
    for (int i = 0; i < n_parties; i++) {
        shares[i] = rtg_contexts[i].gen_share(rots, include_swap_rows);
    }
    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            shares[c_party_id] = rtg_contexts[c_party_id].aggregate_share(shares[c_party_id], shares[i]);
        }
    }

    rtg_contexts[c_party_id].set_galois_key(rots, include_swap_rows, shares[c_party_id]);
}

BfvPlaintextRingt
e2s_decrypt(int n_parties, int c_party_id, std::map<int, DBfvContext>& contexts, const BfvCiphertext& x_ct) {
    std::map<int, E2sContext> e2s_contexts;
    for (int i = 0; i < n_parties; i++) {
        e2s_contexts[i] = E2sContext::create_context(contexts[i]);
    }

    std::map<int, E2sPublicShare> public_shares;
    std::map<int, AdditiveShare> secret_shares;
    for (int i = 0; i < n_parties; i++) {
        std::pair<E2sPublicShare, AdditiveShare> share = e2s_contexts[i].gen_public_share(x_ct);
        public_shares[i] = E2sPublicShare(std::move(share.first));
        secret_shares[i] = AdditiveShare(std::move(share.second));
    }

    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            public_shares[c_party_id] =
                e2s_contexts[c_party_id].aggregate_public_share(public_shares[c_party_id], public_shares[i]);
        }
    }

    secret_shares[c_party_id] =
        e2s_contexts[c_party_id].get_secret_share(x_ct, public_shares[c_party_id], secret_shares[c_party_id]);

    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            secret_shares[c_party_id] = e2s_contexts[c_party_id].aggregate_secret_share(
                contexts[c_party_id], secret_shares[c_party_id], secret_shares[i]);
        }
    }

    BfvPlaintextRingt y_pt =
        e2s_contexts[c_party_id].set_plaintext_ringt(contexts[c_party_id], secret_shares[c_party_id]);
    return y_pt;
}

TEST_CASE_METHOD(LattigoDBfvFixture, "BFV encrypt-decrypt") {
    int c_party_id = 0;
    gen_pk(n_parties, c_party_id, contexts);

    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);

    BfvContext bfv_context = contexts[c_party_id].get_bfv_context();
    BfvPlaintext x_pt = bfv_context.encode(x_mg, level);
    BfvCiphertext x_ct = bfv_context.encrypt_asymmetric(x_pt);

    BfvPlaintextRingt y_pt = e2s_decrypt(n_parties, c_party_id, contexts, x_ct);
    vector<uint64_t> y_mg = bfv_context.decode_ringt(y_pt);

    print_message(y_mg.data(), "y_mg", 10);
    REQUIRE(y_mg == x_mg);
}

TEST_CASE_METHOD(LattigoDBfvFixture, "BFV encrypt-decrypt s2e and s2e") {
    int c_party_id = 0;
    gen_pk(n_parties, c_party_id, contexts);

    std::map<int, E2sContext> e2s_contexts;
    std::map<int, S2eContext> s2e_contexts;
    for (int i = 0; i < n_parties; i++) {
        e2s_contexts[i] = E2sContext::create_context(contexts[i]);
        s2e_contexts[i] = S2eContext::create_context(contexts[i]);
    }

    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);

    BfvContext bfv_context = contexts[c_party_id].get_bfv_context();
    BfvPlaintext x_pt = bfv_context.encode(x_mg, level);
    BfvCiphertext x_ct = bfv_context.encrypt_asymmetric(x_pt);

    std::map<int, E2sPublicShare> e2s_public_shares;
    std::map<int, AdditiveShare> secret_shares;
    for (int i = 0; i < n_parties; i++) {
        std::pair<E2sPublicShare, AdditiveShare> share = e2s_contexts[i].gen_public_share(x_ct);
        e2s_public_shares[i] = E2sPublicShare(std::move(share.first));
        secret_shares[i] = AdditiveShare(std::move(share.second));
    }
    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            e2s_public_shares[c_party_id] =
                e2s_contexts[c_party_id].aggregate_public_share(e2s_public_shares[c_party_id], e2s_public_shares[i]);
        }
    }

    secret_shares[c_party_id] =
        e2s_contexts[c_party_id].get_secret_share(x_ct, e2s_public_shares[c_party_id], secret_shares[c_party_id]);

    std::map<int, S2ePublicShare> s2e_shares;
    for (int i = 0; i < n_parties; i++) {
        s2e_shares[i] = s2e_contexts[i].gen_public_share(secret_shares[i]);
    }

    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            s2e_shares[c_party_id] =
                s2e_contexts[c_party_id].aggregate_public_share(s2e_shares[c_party_id], s2e_shares[i]);
        }
    }

    BfvCiphertext y_ct = s2e_contexts[c_party_id].set_ciphertetext(s2e_shares[c_party_id]);

    BfvPlaintextRingt y_pt = e2s_decrypt(n_parties, c_party_id, contexts, y_ct);
    vector<uint64_t> y_mg = bfv_context.decode_ringt(y_pt);

    print_message(y_mg.data(), "y_mg", 10);
    REQUIRE(y_mg == x_mg);
}

TEST_CASE_METHOD(LattigoDBfvFixture, "BFV ct multiply ct and relin") {
    int c_party_id = 0;
    gen_pk(n_parties, c_party_id, contexts);
    gen_rlk(n_parties, c_party_id, contexts);

    BfvContext bfv_context = contexts[c_party_id].get_bfv_context();

    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
    }
    BfvPlaintext x_pt = bfv_context.encode(x_mg, level);
    BfvPlaintext y_pt = bfv_context.encode(y_mg, level);
    BfvCiphertext x_ct = bfv_context.encrypt_asymmetric(x_pt);
    BfvCiphertext y_ct = bfv_context.encrypt_asymmetric(y_pt);

    BfvCiphertext3 z_ct3 = bfv_context.mult(x_ct, y_ct);
    BfvCiphertext z_ct = bfv_context.relinearize(z_ct3);

    BfvPlaintextRingt z_pt = e2s_decrypt(n_parties, c_party_id, contexts, z_ct);
    vector<uint64_t> z_mg = bfv_context.decode_ringt(z_pt);

    print_message(z_mg.data(), "z_mg", 10);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoDBfvFixture, "BFV advanced rotate col") {
    int c_party_id = 0;
    vector<int32_t> steps = {-100, 902, 3007};
    gen_pk(n_parties, c_party_id, contexts);
    gen_glk(n_parties, c_party_id, contexts, steps);

    int n_col = N / 2;

    vector<uint64_t> x_mg;
    for (int i = 0; i < n_col; i++) {
        x_mg.push_back((uint64_t)i);
    }

    BfvContext bfv_context = contexts[c_party_id].get_bfv_context();
    BfvPlaintext x_pt = bfv_context.encode(x_mg, level);
    BfvCiphertext x_ct = bfv_context.encrypt_asymmetric(x_pt);

    auto z_ct = bfv_context.advanced_rotate_cols(x_ct, steps);

    for (int i = 0; i < steps.size(); i++) {
        BfvPlaintextRingt z_pt = e2s_decrypt(n_parties, c_party_id, contexts, z_ct[steps[i]]);
        vector<uint64_t> z_mg = bfv_context.decode_ringt(z_pt);

        print_message(x_mg.data(), "x_mg", 20);
        print_message(z_mg.data(), "z_mg", 20);

        vector<uint64_t> y;
        for (int k = 0; k < n_col; k++) {
            y.push_back(z_mg[(k - steps[i] + n_col) % n_col]);
        }

        print_message(y.data(), "y_mg", 20);

        REQUIRE(y == x_mg);
    }
}

TEST_CASE_METHOD(LattigoDBfvFixture, "BFV rotate row") {
    int c_party_id = 0;
    gen_pk(n_parties, c_party_id, contexts);
    gen_glk(n_parties, c_party_id, contexts, vector<int32_t>{}, true);

    int n_col = N / 2;

    vector<uint64_t> x_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
    }

    BfvContext bfv_context = contexts[c_party_id].get_bfv_context();
    BfvPlaintext x_pt = bfv_context.encode(x_mg, level);
    BfvCiphertext x_ct = bfv_context.encrypt_asymmetric(x_pt);

    auto z_ct = bfv_context.rotate_rows(x_ct);

    BfvPlaintextRingt z_pt = e2s_decrypt(n_parties, c_party_id, contexts, z_ct);
    vector<uint64_t> z_mg = bfv_context.decode_ringt(z_pt);

    vector<uint64_t> y;
    for (int k = 0; k < n_col * 2; k++) {
        if (k < n_col) {
            y.push_back(x_mg[k + n_col]);
        } else {
            y.push_back(x_mg[k - n_col]);
        }
    }

    print_message(x_mg.data(), "x_mg", 20);
    print_message(z_mg.data(), "z_mg", 20);

    REQUIRE(y == z_mg);
}

TEST_CASE_METHOD(LattigoDBfvFixture, "BFV refresh") {
    int c_party_id = 0;
    gen_pk(n_parties, c_party_id, contexts);

    std::map<int, RefreshContext> refresh_contexts;
    for (int i = 0; i < n_parties; i++) {
        refresh_contexts[i] = RefreshContext::create_context(contexts[i]);
    }

    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);

    BfvContext bfv_context = contexts[c_party_id].get_bfv_context();
    BfvPlaintext x_pt = bfv_context.encode(x_mg, level);
    BfvCiphertext x_ct = bfv_context.encrypt_asymmetric(x_pt);

    std::map<int, RefreshShare> shares;
    for (int i = 0; i < n_parties; i++) {
        shares[i] = refresh_contexts[i].gen_share(x_ct);
    }
    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            shares[c_party_id] = refresh_contexts[c_party_id].aggregate_share(shares[c_party_id], shares[i]);
        }
    }

    BfvCiphertext y_ct = refresh_contexts[c_party_id].finalize(x_ct, shares[c_party_id]);

    BfvPlaintextRingt y_pt = e2s_decrypt(n_parties, c_party_id, contexts, y_ct);
    vector<uint64_t> y_mg = bfv_context.decode_ringt(y_pt);

    print_message(y_mg.data(), "y_mg", 10);
    REQUIRE(y_mg == x_mg);
}

TEST_CASE_METHOD(LattigoDBfvFixture, "BFV refresh and permute") {
    int c_party_id = 0;
    gen_pk(n_parties, c_party_id, contexts);

    std::map<int, RefreshAndPermuteContext> refresh_and_permute_contexts;
    for (int i = 0; i < n_parties; i++) {
        refresh_and_permute_contexts[i] = RefreshAndPermuteContext::create_context(contexts[i]);
    }

    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);

    BfvContext bfv_context = contexts[c_party_id].get_bfv_context();
    BfvPlaintext x_pt = bfv_context.encode(x_mg, level);
    BfvCiphertext x_ct = bfv_context.encrypt_asymmetric(x_pt);

    vector<uint64_t> permutes;
    for (int i = 0; i < N; i++) {
        permutes.push_back((uint64_t)N - i - 1);
    }

    std::map<int, RefreshAndPermuteShare> shares;
    for (int i = 0; i < n_parties; i++) {
        shares[i] = refresh_and_permute_contexts[i].gen_share(x_ct, permutes);
    }
    for (int i = 0; i < n_parties; i++) {
        if (i != c_party_id) {
            shares[c_party_id] =
                refresh_and_permute_contexts[c_party_id].aggregate_share(shares[c_party_id], shares[i]);
        }
    }

    BfvCiphertext y_ct = refresh_and_permute_contexts[c_party_id].transform(x_ct, permutes, shares[c_party_id]);

    BfvPlaintextRingt y_pt = e2s_decrypt(n_parties, c_party_id, contexts, y_ct);
    vector<uint64_t> y_mg = bfv_context.decode_ringt(y_pt);

    print_message(y_mg.data(), "y_mg", 10);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (y_mg[i] != x_mg[permutes[i]] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

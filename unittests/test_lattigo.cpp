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
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "fhe_lib_v2.h"
#include "utils.h"

using namespace fhe_ops_lib;
using namespace std;

class LattigoBfvFixture {
public:
    LattigoBfvFixture()
        : N{16384}, level{5}, t{65537}, param{BfvParameter::create_parameter(N, t)}, max_level{param.get_max_level()},
          context{BfvContext::create_random_context(param)} {}

protected:
    int N;
    int level;
    uint64_t t;
    BfvParameter param;
    int min_level;
    int max_level;
    BfvContext context;
};

TEST_CASE_METHOD(LattigoBfvFixture, "BFV encode-decode") {
    vector<uint64_t> x_vector(N);
    for (int i = 0; i < N; i++) {
        x_vector[i] = i;
    }
    vector<uint64_t> x_mg(x_vector);
    BfvPlaintext x_pt = context.encode(x_mg, level);
    vector<uint64_t> y_mg = context.decode(x_pt);

    REQUIRE(y_mg == x_mg);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV encode_coeffs-decode_coeffs") {
    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);
    BfvPlaintext x_pt = context.encode_coeffs(x_mg, level);
    vector<uint64_t> y_mg = context.decode_coeffs(x_pt);

    REQUIRE(y_mg == x_mg);
}

// TEST_CASE_METHOD(LattigoBfvFixture, "BFV bitwise_encode-decode") {
//     vector<uint64_t> x_vector;
//     for (int i = 0; i < N; i++) {
//         x_vector.push_back((uint64_t)i);
//     }
//     vector<uint64_t> x_mg(x_vector);

//     int t_len = int(ceil(log2(context.get_parameter().get_t())));
//     vector<vector<uint64_t>> x_bit_mg(t_len);
//     for (int i = 0; i < t_len; i++) {
//         x_bit_mg[i].resize(x_mg.size());
//         for (int j = 0; j < x_mg.size(); j++) {
//             x_bit_mg[i][j] = (x_mg[j] >> i) & 1;
//         }
//     }

//     std::vector<BfvPlaintext> x_bit_pts = context.bitwise_encode(x_mg, level);
//     REQUIRE(x_bit_pts.size() == t_len);
//     for (int i = 0; i < x_bit_pts.size(); i++) {
//         vector<uint64_t> y_bit_mg = context.decode(x_bit_pts[i]);
//         REQUIRE(y_bit_mg == x_bit_mg[i]);
//     }
// }

TEST_CASE_METHOD(LattigoBfvFixture, "BFV encrypt-decrypt") {
    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvPlaintext y_pt = context.decrypt(x_ct);
    vector<uint64_t> y_mg = context.decode(y_pt);

    REQUIRE(y_mg == x_mg);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV encode_coeffs-encrypt-decrypt-decode_coeffs") {
    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);
    BfvPlaintext x_pt = context.encode_coeffs(x_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvPlaintext y_pt = context.decrypt(x_ct);
    vector<uint64_t> y_mg = context.decode_coeffs(y_pt);

    REQUIRE(y_mg == x_mg);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV sym_encrypt-decrypt") {
    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvCiphertext x_ct = context.encrypt_symmetric(x_pt);

    BfvPlaintext y_pt = context.decrypt(x_ct);
    vector<uint64_t> y_mg = context.decode(y_pt);

    REQUIRE(y_mg == x_mg);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV CompressedCiphertext encrypt-decrypt") {
    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvCompressedCiphertext x_ctc = context.encrypt_symmetric_compressed(x_pt);

    BfvCiphertext x_ct = context.compressed_ciphertext_to_ciphertext(x_ctc);

    BfvPlaintext y_pt = context.decrypt(x_ct);
    vector<uint64_t> y_mg = context.decode(y_pt);

    REQUIRE(y_mg == x_mg);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct sub ct") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    vector<uint64_t> z_true;
    for (int i = 0; i < N; i++) {
        x_mg.push_back(uint64_t(i * 3));
        y_mg.push_back(uint64_t(i + 1));
        z_true.push_back(uint64_t(x_mg[i] - y_mg[i] + t) % t);
    }
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintext y_pt = context.encode(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    BfvCiphertext z_ct = context.sub(x_ct, y_ct);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode(z_pt);

    print_message(z_mg.data(), "z_mg", 10);
    REQUIRE(z_mg == z_true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct multiply pt") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
    }
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintext y_pt = context.encode(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvCiphertext z_ct3 = context.mult_plain(x_ct, y_pt);

    BfvPlaintext z_pt = context.decrypt(z_ct3);
    vector<uint64_t> z_mg = context.decode(z_pt);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct multiply pt_coeffs") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
    }

    vector<uint64_t> z_true;
    for (int i = 0; i < (x_mg.size() - 1) * (y_mg.size() - 1) + 1; i++) {
        z_true.push_back((uint64_t)0);
        int k = i < x_mg.size() - 1 ? i : x_mg.size() - 1;
        for (int j = 0; j <= k; j++) {
            if (i - j < y_mg.size()) {
                z_true[i] += (x_mg[j] * y_mg[i - j]) % t;
            }
        }
    }

    BfvPlaintext x_pt = context.encode_coeffs(x_mg, level);
    BfvPlaintext y_pt = context.encode_coeffs(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvCiphertext z_ct3 = context.mult_plain(x_ct, y_pt);

    BfvPlaintext z_pt = context.decrypt(z_ct3);
    vector<uint64_t> z_mg = context.decode_coeffs(z_pt);

    bool equal = true;
    for (int i = 0; i < z_true.size(); i++) {
        if (z_mg[i] != z_true[i] % t) {
            equal = false;
        }
    }
    for (int i = z_true.size(); i < N; i++) {
        if (z_mg[i] != 0) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct multiply pt_ringt") {
    vector<uint64_t> x_mg(N);
    vector<uint64_t> y_mg(N);
    vector<uint64_t> z_true(N);
    for (int i = 0; i < N; i++) {
        x_mg[i] = i;
        y_mg[i] = i + 1;
        z_true[i] = x_mg[i] * y_mg[i] % t;
    }

    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintextRingt y_pt = context.encode_ringt(y_mg);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvCiphertext z_ct = context.mult_plain_ringt(x_ct, y_pt);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode(z_pt);

    REQUIRE(z_mg == z_true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct multiply pt_coeffs_ringt") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(i);
        y_mg.push_back(i + 1);
    }
    vector<uint64_t> z_true;
    for (int i = 0; i < (x_mg.size() - 1) * (y_mg.size() - 1) + 1; i++) {
        z_true.push_back((uint64_t)0);
        int k = i < x_mg.size() - 1 ? i : x_mg.size() - 1;
        for (int j = 0; j <= k; j++) {
            if (i - j < y_mg.size()) {
                z_true[i] += (x_mg[j] * y_mg[i - j]) % t;
            }
        }
    }

    BfvPlaintext x_pt = context.encode_coeffs(x_mg, level);
    BfvPlaintextRingt y_pt = context.encode_coeffs_ringt(y_mg);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvCiphertext z_ct = context.mult_plain_ringt(x_ct, y_pt);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode_coeffs(z_pt);

    bool equal = true;
    for (int i = 0; i < z_true.size(); i++) {
        if (z_mg[i] != z_true[i] % t) {
            equal = false;
        }
    }
    for (int i = z_true.size(); i < N; i++) {
        if (z_mg[i] != 0) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct multiply scalar") {
    vector<uint64_t> x_mg;
    for (int i = 0; i < 8192 * 2; i++) {
        x_mg.push_back(i);
    }

    for (int y = -2; y <= 2; y++) {
        vector<uint64_t> z_true;
        for (int i = 0; i < x_mg.size(); i++) {
            z_true.push_back((i * y + 10 * t) % t);
        }

        BfvPlaintext x_pt = context.encode(x_mg, level);
        BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

        BfvCiphertext z_ct = context.mult_scalar(x_ct, y);

        BfvPlaintext z_pt = context.decrypt(z_ct);
        vector<uint64_t> z_mg = context.decode(z_pt);

        print_message(z_mg.data(), "z_mg", 10);
        REQUIRE(z_mg == z_true);
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ringt_to_pt") {
    vector<uint64_t> y_mg;
    for (int i = 0; i < N; i++) {
        y_mg.push_back((uint64_t)(i + 1));
    }
    BfvPlaintextRingt y_ptrt = context.encode_ringt(y_mg);

    BfvPlaintext y_pt = context.ringt_to_pt(y_ptrt, level);
    BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    BfvPlaintext z_pt = context.decrypt(y_ct);
    vector<uint64_t> z_mg = context.decode(z_pt);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (z_mg[i] != y_mg[i] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ringt_to_mul-mult_plain_mul") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
    }
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintextRingt y_pt = context.encode_ringt(y_mg);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvPlaintextMul y_pt_mul = context.ringt_to_mul(y_pt, level);
    BfvCiphertext z_ct = context.mult_plain_mul(x_ct, y_pt_mul);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode(z_pt);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV coeff_ringt_to_mul-mult_plain_mul") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
    }
    vector<uint64_t> z_true;
    for (int i = 0; i < (x_mg.size() - 1) * (y_mg.size() - 1) + 1; i++) {
        z_true.push_back((uint64_t)0);
        int k = i < x_mg.size() - 1 ? i : x_mg.size() - 1;
        for (int j = 0; j <= k; j++) {
            if (i - j < y_mg.size()) {
                z_true[i] += (x_mg[j] * y_mg[i - j]) % t;
            }
        }
    }

    BfvPlaintext x_pt = context.encode_coeffs(x_mg, level);
    BfvPlaintextRingt y_pt = context.encode_coeffs_ringt(y_mg);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvPlaintextMul y_pt_mul = context.ringt_to_mul(y_pt, level);
    BfvCiphertext z_ct = context.mult_plain_mul(x_ct, y_pt_mul);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode_coeffs(z_pt);

    bool equal = true;
    for (int i = 0; i < z_true.size(); i++) {
        if (z_mg[i] != z_true[i] % t) {
            equal = false;
        }
    }
    for (int i = z_true.size(); i < N; i++) {
        if (z_mg[i] != 0) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct multiply pt_mul") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
    }
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintextMul y_pt = context.encode_mul(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvCiphertext z_ct = context.mult_plain_mul(x_ct, y_pt);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode(z_pt);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct multiply pt_coeffs_mul") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < 20; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
    }
    vector<uint64_t> z_true;
    for (int i = 0; i < (x_mg.size() - 1) * (y_mg.size() - 1) + 1; i++) {
        z_true.push_back((uint64_t)0);
        int k = i < x_mg.size() - 1 ? i : x_mg.size() - 1;
        for (int j = 0; j <= k; j++) {
            if (i - j < y_mg.size()) {
                z_true[i] += (x_mg[j] * y_mg[i - j]) % t;
            }
        }
    }

    BfvPlaintext x_pt = context.encode_coeffs(x_mg, level);
    BfvPlaintextMul y_pt = context.encode_coeffs_mul(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvCiphertext z_ct = context.mult_plain_mul(x_ct, y_pt);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode_coeffs(z_pt);

    bool equal = true;
    for (int i = 0; i < z_true.size(); i++) {
        if (z_mg[i] != z_true[i] % t) {
            equal = false;
        }
    }
    for (int i = z_true.size(); i < N; i++) {
        if (z_mg[i] != 0) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct multiply ct") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
    }
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintext y_pt = context.encode(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    BfvCiphertext3 z_ct3 = context.mult(x_ct, y_ct);

    BfvPlaintext z_pt = context.decrypt(z_ct3);
    vector<uint64_t> z_mg = context.decode(z_pt);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV rescale") {
    vector<uint64_t> x_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
    }

    for (int level = 1; level <= 2; level++) {
        SECTION("level " + to_string(level)) {
            BfvPlaintext x_pt = context.encode(x_mg, level);
            BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            BfvCiphertext y_ct = context.rescale(x_ct);
            REQUIRE(y_ct.get_level() == x_ct.get_level() - 1);

            BfvPlaintext y_pt = context.decrypt(y_ct);
            vector<uint64_t> y_mg = context.decode(y_pt);

            REQUIRE(y_mg == x_mg);
        }
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ct multiply ct and relin") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        BfvPlaintext x_pt = context.encode(x_mg, level);
        BfvPlaintext y_pt = context.encode(y_mg, level);
        BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
        BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

        auto start = chrono::high_resolution_clock::now();
        BfvCiphertext3 z_ct3 = context.mult(x_ct, y_ct);
        BfvCiphertext z_ct = context.relinearize(z_ct3);
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
        fprintf(stderr, "mult_relin time: %.4f ms\n", double(duration.count()));

        BfvPlaintext z_pt = context.decrypt(z_ct);
        vector<uint64_t> z_mg = context.decode(z_pt);

        bool equal = true;
        for (int i = 0; i < N; i++) {
            if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
                equal = false;
            }
        }
        REQUIRE(equal == true);
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV rotate col") {
    vector<uint64_t> x_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
    }

    vector<int32_t> steps = {-10};
    context.gen_rotation_keys();
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    auto z_ct = context.rotate_cols(x_ct, steps);

    for (int i = 0; i < steps.size(); i++) {
        BfvPlaintext z_pt = context.decrypt(z_ct[steps[i]]);
        vector<uint64_t> z_mg = context.decode(z_pt);

        print_message(x_mg.data(), "x_mg", 20);
        print_message(z_mg.data(), "z_mg", 20);
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV advanced rotate col") {
    vector<uint64_t> x_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
    }

    vector<int32_t> steps = {-1, 2};
    context.gen_rotation_keys_for_rotations(steps);
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    auto z_ct = context.advanced_rotate_cols(x_ct, steps);

    for (int i = 0; i < steps.size(); i++) {
        BfvPlaintext z_pt = context.decrypt(z_ct[steps[i]]);
        vector<uint64_t> z_mg = context.decode(z_pt);

        print_message(x_mg.data(), "x_mg", 20);
        print_message(z_mg.data(), "z_mg", 20);
    }
}

// TEST_CASE_METHOD(LattigoBfvFixture, "BFV equal to") {
//     vector<uint64_t> x_mg;
//     vector<uint64_t> y_mg;
//     for (int i = 0; i < N; i++) {
//         x_mg.push_back((uint64_t)i);
//         if (i < 10) {
//             y_mg.push_back((uint64_t)i);
//         } else if (i > 3000) {
//             y_mg.push_back((uint64_t)(i + 5));
//         } else {
//             y_mg.push_back((uint64_t)(i - 5));
//         }
//     }

//     vector<uint64_t> z_true;
//     for (int i = 0; i < N; i++) {
//         if (x_mg[i] == y_mg[i]) {
//             z_true.push_back((uint64_t)1);
//         } else {
//             z_true.push_back((uint64_t)0);
//         }
//     }

//     vector<BfvPlaintext> x_bit_pts = context.bitwise_encode(x_mg, level);
//     vector<BfvPlaintext> y_bit_pts = context.bitwise_encode(y_mg, level);

//     vector<BfvCiphertext> x_bit_cts(x_bit_pts.size());
//     vector<BfvCiphertext> y_bit_cts(y_bit_pts.size());
//     for (int i = 0; i < x_bit_cts.size(); i++) {
//         x_bit_cts[i] = context.encrypt_asymmetric(x_bit_pts[i]);
//         y_bit_cts[i] = context.encrypt_asymmetric(y_bit_pts[i]);
//     }

//     BfvCiphertext z_ct = context.equal_to(x_bit_cts, y_bit_cts);
//     BfvPlaintext z_pt = context.decrypt(z_ct);
//     vector<uint64_t> z_mg = context.decode(z_pt);
//     print_message(z_mg.data(), "z_mg", 20);
//     REQUIRE(z_mg == z_true);
// }

// TEST_CASE_METHOD(LattigoBfvFixture, "BFV less than") {
//     vector<uint64_t> x_mg;
//     vector<uint64_t> y_mg;
//     for (int i = 0; i < N; i++) {
//         x_mg.push_back((uint64_t)i);
//         if (i < 10) {
//             y_mg.push_back((uint64_t)i + 5);
//         } else if (i > 30) {
//             y_mg.push_back((uint64_t)i);
//         } else {
//             y_mg.push_back((uint64_t)(i - 2));
//         }
//     }

//     vector<uint64_t> z_true;
//     for (int i = 0; i < N; i++) {
//         if (x_mg[i] < y_mg[i]) {
//             z_true.push_back((uint64_t)1);
//         } else {
//             z_true.push_back((uint64_t)0);
//         }
//     }

//     vector<BfvPlaintext> x_bit_pts = context.bitwise_encode(x_mg, level);
//     vector<BfvPlaintext> y_bit_pts = context.bitwise_encode(y_mg, level);

//     vector<BfvCiphertext> x_bit_cts(x_bit_pts.size());
//     vector<BfvCiphertext> y_bit_cts(y_bit_pts.size());
//     for (int i = 0; i < x_bit_cts.size(); i++) {
//         x_bit_cts[i] = context.encrypt_asymmetric(x_bit_pts[i]);
//         y_bit_cts[i] = context.encrypt_asymmetric(y_bit_pts[i]);
//     }

//     BfvCiphertext z_ct = context.less_than(x_bit_cts, y_bit_cts);
//     BfvPlaintext z_pt = context.decrypt(z_ct);
//     vector<uint64_t> z_mg = context.decode(z_pt);

//     REQUIRE(z_mg == z_true);
// }

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ciphertext info") {
    vector<uint64_t> x_vector;
    for (int i = 0; i < N; i++) {
        x_vector.push_back((uint64_t)i);
    }
    vector<uint64_t> x_mg(x_vector);
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    fprintf(stderr, "level=%d\n", x_ct.get_level());
    fprintf(stderr, "coeff[0][0][0]=%lx\n", x_ct.get_coeff(0, 0, 0));
    fprintf(stderr, "coeff[1][level][N-1]=%lx\n", x_ct.get_coeff(1, level, N - 1));
    REQUIRE(x_ct.get_level() == level);
}

TEST_CASE("BFV ciphertext serialization", "") {
    int N = 8192;
    int level = 2;
    uint64_t t = 65537;
    vector<BfvParameter> params;
    params.push_back(move(BfvParameter::create_parameter(N, t)));

    for (BfvParameter& param : params) {
        BfvContext context = BfvContext::create_random_context(param);

        vector<uint64_t> x_mg;
        for (int i = 0; i < N; i++) {
            x_mg.push_back((uint64_t)(i + 3));
        }
        BfvPlaintext x_pt = context.encode(x_mg, level);
        BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

        vector<uint8_t> x_data = x_ct.serialize(param);
        fprintf(stderr, "ct size: %zu bytes\n", x_data.size());
        BfvCiphertext y_ct = BfvCiphertext::deserialize(x_data);

        BfvPlaintext y_pt = context.decrypt(y_ct);
        vector<uint64_t> y_mg = context.decode(y_pt);

        print_message(x_mg.data(), "x_mg", 20);
        print_message(y_mg.data(), "y_mg", 20);

        REQUIRE(y_mg == x_mg);
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV ciphertext compressed serialization", "") {
    vector<uint64_t> x_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)(i + 3));
    }
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvCompressedCiphertext x_ctc = context.encrypt_symmetric_compressed(x_pt);

    vector<uint8_t> x_data = x_ctc.serialize(param);
    fprintf(stderr, "ct size: %zu bytes\n", x_data.size());
    BfvCompressedCiphertext y_ctc = BfvCompressedCiphertext::deserialize(x_data);

    BfvCiphertext y_ct = context.compressed_ciphertext_to_ciphertext(y_ctc);

    BfvPlaintext y_pt = context.decrypt(y_ct);
    vector<uint64_t> y_mg = context.decode(y_pt);

    print_message(x_mg.data(), "x_mg", 20);
    print_message(y_mg.data(), "y_mg", 20);

    REQUIRE(y_mg == x_mg);
}

TEST_CASE("BFV compute and serialize", "") {
    int N = 8192;
    int level = 1;
    uint64_t t = 65537;
    BfvParameter param = BfvParameter::create_parameter(N, t);
    BfvContext context = BfvContext::create_random_context(param);

    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    vector<uint64_t> z_true;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
        z_true.push_back((x_mg[i] * y_mg[i]) % t);
    }
    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintext y_pt = context.encode(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    BfvCiphertext z_ct = context.rescale(context.relinearize(context.mult(x_ct, y_ct)));

    vector<uint8_t> z_data = z_ct.serialize(param, 13, 6);
    fprintf(stderr, "ct size: %zu bytes\n", z_data.size());
    BfvCiphertext z_ct_de = BfvCiphertext::deserialize(z_data);

    BfvPlaintext z_pt = context.decrypt(z_ct_de);
    vector<uint64_t> z_mg = context.decode(z_pt);

    print_message(z_true.data(), "z_true", 20);
    print_message(z_mg.data(), "z_mg", 20);

    REQUIRE(z_true == z_mg);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV secret context serialization", "") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    vector<uint64_t> z_true;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
        z_true.push_back((uint64_t)(i * (i + 1)));
    }

    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintext y_pt = context.encode(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    vector<uint8_t> secret_context_data = context.serialize();
    fprintf(stderr, "secret_context size: %zu bytes\n", secret_context_data.size());
    BfvContext deserialized_context = BfvContext::deserialize(secret_context_data);

    BfvCiphertext3 z_ct3 = deserialized_context.mult(x_ct, y_ct);
    BfvCiphertext z_ct = deserialized_context.relinearize(z_ct3);

    BfvPlaintext z_pt = deserialized_context.decrypt(z_ct);
    vector<uint64_t> z_mg = deserialized_context.decode(z_pt);

    print_message(z_mg.data(), "z_mg", 10);
    print_message(z_true.data(), "z_true", 10);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV secret context advanced serialization", "") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    vector<uint64_t> z_true;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
        z_true.push_back((uint64_t)(i * (i + 1)));
    }

    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintext y_pt = context.encode(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    vector<uint8_t> secret_context_data = context.serialize_advanced();
    fprintf(stderr, "secret_context size: %zu bytes\n", secret_context_data.size());
    BfvContext deserialized_context = BfvContext::deserialize_advanced(secret_context_data);

    BfvCiphertext3 z_ct3 = deserialized_context.mult(x_ct, y_ct);
    BfvCiphertext z_ct = deserialized_context.relinearize(z_ct3);

    BfvPlaintext z_pt = deserialized_context.decrypt(z_ct);
    vector<uint64_t> z_mg = deserialized_context.decode(z_pt);

    print_message(z_mg.data(), "z_mg", 10);
    print_message(z_true.data(), "z_true", 10);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV public context serialization", "") {
    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    vector<uint64_t> z_true;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i);
        y_mg.push_back((uint64_t)(i + 1));
        z_true.push_back((uint64_t)(i * (i + 1)));
    }

    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvPlaintext y_pt = context.encode(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    BfvContext public_context = context.make_public_context();
    vector<uint8_t> public_context_data = public_context.serialize();
    fprintf(stderr, "public_context size: %zu bytes\n", public_context_data.size());
    BfvContext deserialized_public_context = BfvContext::deserialize(public_context_data);

    BfvCiphertext3 z_ct3 = deserialized_public_context.mult(x_ct, y_ct);
    BfvCiphertext z_ct = deserialized_public_context.relinearize(z_ct3);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode(z_pt);

    print_message(z_mg.data(), "z_mg", 10);
    print_message(z_true.data(), "z_true", 10);

    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
            equal = false;
        }
    }
    REQUIRE(equal == true);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV public context advanced serialization", "") {
    for (int level = 1; level <= max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            context = BfvContext::create_random_context(param, level);

            vector<uint64_t> x_mg;
            vector<uint64_t> y_mg;
            vector<uint64_t> z_true;
            for (int i = 0; i < N; i++) {
                x_mg.push_back((uint64_t)i);
                y_mg.push_back((uint64_t)(i + 1));
                z_true.push_back((uint64_t)(i * (i + 1)));
            }

            BfvPlaintext x_pt = context.encode(x_mg, level);
            BfvPlaintext y_pt = context.encode(y_mg, level);
            BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
            BfvCiphertext y_ct = context.encrypt_asymmetric(y_pt);

            BfvContext public_context = context.make_public_context();
            vector<uint8_t> public_context_data = public_context.serialize_advanced();
            fprintf(stderr, "public_context size: %zu bytes\n", public_context_data.size());
            BfvContext deserialized_public_context = BfvContext::deserialize_advanced(public_context_data);

            BfvCiphertext3 z_ct3 = deserialized_public_context.mult(x_ct, y_ct);
            BfvCiphertext z_ct = deserialized_public_context.relinearize(z_ct3);

            BfvPlaintext z_pt = context.decrypt(z_ct);
            vector<uint64_t> z_mg = context.decode(z_pt);

            print_message(z_mg.data(), "z_mg", 10);
            print_message(z_true.data(), "z_true", 10);

            bool equal = true;
            for (int i = 0; i < N; i++) {
                if (z_mg[i] != x_mg[i] * y_mg[i] % t) {
                    equal = false;
                }
            }
            REQUIRE(equal == true);
        }
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV public context advanced serialization and encrypt", "") {
    for (int level = 1; level <= max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            context = BfvContext::create_random_context(param, level);

            BfvContext public_context = context.make_public_context();
            vector<uint8_t> public_context_data = public_context.serialize_advanced();
            fprintf(stderr, "public_context size: %zu bytes\n", public_context_data.size());
            BfvContext deserialized_public_context = BfvContext::deserialize_advanced(public_context_data);

            vector<uint64_t> x_mg;
            for (int i = 0; i < N; i++) {
                x_mg.push_back((uint64_t)i);
            }

            BfvPlaintext x_pt = deserialized_public_context.encode(x_mg, level);
            BfvCiphertext x_ct = deserialized_public_context.encrypt_asymmetric(x_pt);

            BfvPlaintext y_pt = context.decrypt(x_ct);
            vector<uint64_t> y_mg = context.decode(y_pt);

            print_message(x_mg.data(), "x_mg", 10);
            print_message(y_mg.data(), "y_mg", 10);

            REQUIRE(y_mg == x_mg);
        }
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV public context serialization and rotate") {
    vector<uint64_t> x_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back((uint64_t)i);
    }

    int n_slot = N / 2;

    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    vector<int32_t> steps = {100, 200, 4, 80, 8, 10, 24 - 900};
    context.gen_rotation_keys();

    BfvContext public_context = context.make_public_context();
    vector<uint8_t> public_context_data = public_context.serialize();
    fprintf(stderr, "public_context size: %zu bytes\n", public_context_data.size());
    BfvContext deserialized_public_context = BfvContext::deserialize(public_context_data);
    auto y_ct = deserialized_public_context.rotate_cols(x_ct, steps);

    for (int k = 0; k < steps.size(); k++) {
        vector<uint64_t> y_true(n_slot);
        for (int i = 0; i < 10; i++) {
            y_true[(i - steps[k] + n_slot) % n_slot] = (uint64_t)i;
        }

        BfvPlaintext y_pt = context.decrypt(y_ct[steps[k]]);
        vector<uint64_t> y_mg = context.decode(y_pt);

        bool equal = true;
        for (int i = 0; i < 10; i++) {
            if (y_mg[i] != y_true[i] % t) {
                equal = false;
            }
        }
        REQUIRE(equal == true);
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV public context advanced serialization and rotate") {
    for (int level = 1; level <= max_level; level++) {
        SECTION("lv=" + to_string(level)) {
            context = BfvContext::create_random_context(param, level);
            context.gen_rotation_keys(level);

            vector<uint64_t> x_mg;
            for (int i = 0; i < 10; i++) {
                x_mg.push_back((uint64_t)i);
            }

            int n_slot = N / 2;

            BfvPlaintext x_pt = context.encode(x_mg, level);
            BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            vector<int32_t> steps = {100, 200, 4, 80, 8, 10, 24 - 900};

            BfvContext public_context = context.make_public_context(false, false, true);
            vector<uint8_t> public_context_data = public_context.serialize_advanced();
            fprintf(stderr, "public_context size: %zu bytes\n", public_context_data.size());
            BfvContext deserialized_public_context = BfvContext::deserialize_advanced(public_context_data);
            auto y_ct = deserialized_public_context.rotate_cols(x_ct, steps);

            for (int k = 0; k < steps.size(); k++) {
                vector<uint64_t> y_true(n_slot);
                for (int i = 0; i < 10; i++) {
                    y_true[(i - steps[k] + n_slot) % n_slot] = (uint64_t)i;
                }

                BfvPlaintext y_pt = context.decrypt(y_ct[steps[k]]);
                vector<uint64_t> y_mg = context.decode(y_pt);

                bool equal = true;
                for (int i = 0; i < 10; i++) {
                    if (y_mg[i] != y_true[i] % t) {
                        equal = false;
                    }
                }
                REQUIRE(equal == true);
            }
        }
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV public context serialization and advanced rotate") {
    context = BfvContext::create_random_context(param, level);
    vector<int32_t> steps = {100, 200, 4, 80, -900};
    context.gen_rotation_keys_for_rotations(steps, level);

    vector<uint64_t> x_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back((uint64_t)i);
    }

    int n_slot = N / 2;

    BfvPlaintext x_pt = context.encode(x_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvContext public_context = context.make_public_context(false, false, true);
    vector<uint8_t> public_context_data = public_context.serialize_advanced();
    fprintf(stderr, "public_context size: %zu bytes\n", public_context_data.size());
    BfvContext deserialized_public_context = BfvContext::deserialize_advanced(public_context_data);
    auto y_ct = deserialized_public_context.advanced_rotate_cols(x_ct, steps);

    for (int k = 0; k < steps.size(); k++) {
        vector<uint64_t> y_true(n_slot);
        for (int i = 0; i < 10; i++) {
            y_true[(i - steps[k] + n_slot) % n_slot] = (uint64_t)i;
        }

        BfvPlaintext y_pt = context.decrypt(y_ct[steps[k]]);
        vector<uint64_t> y_mg = context.decode(y_pt);

        bool equal = true;
        for (int i = 0; i < 10; i++) {
            if (y_mg[i] != y_true[i] % t) {
                equal = false;
            }
        }
        REQUIRE(equal == true);
    }
}

class LattigoCkksFixture {
public:
    LattigoCkksFixture()
        : N{16384}, n_slot{N / 2}, level{5}, param{CkksParameter::create_parameter(N)},
          context{CkksContext::create_random_context(param)}, max_level{param.get_max_level()},
          default_scale{param.get_default_scale()} {}

protected:
    int N;
    int n_slot;
    int level;
    CkksParameter param;
    CkksContext context;
    int min_level;
    int max_level;
    double default_scale;
};

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS encode-decode") {
    vector<double> x_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
    }

    for (int level = 1; level <= max_level; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            vector<double> y_mg = context.decode(x_pt);
            REQUIRE(compare_double_vectors(y_mg, x_mg, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS encode coeffs-decode coeffs") {
    vector<double> x_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back(double(i));
    }

    for (int level = 1; level <= max_level; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode_coeffs(x_mg, level, default_scale);
            vector<double> y_mg = context.decode_coeffs(x_pt);
            REQUIRE(compare_double_vectors(y_mg, x_mg, N, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS encode_complex-encode_decode") {
    vector<double> x_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
    }

    for (int level = 1; level <= max_level; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode_complex(x_mg, level, default_scale);
            vector<double> y_mg = context.decode_complex(x_pt);
            REQUIRE(compare_double_vectors(y_mg, x_mg, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS encrypt-decrypt") {
    vector<double> x_mg;
    for (int i = 0; i < n_slot; i++) {
        x_mg.push_back(double(i));
    }

    for (int level = 1; level <= max_level; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            CkksPlaintext y_pt = context.decrypt(x_ct);
            vector<double> y_mg = context.decode(y_pt);

            REQUIRE(compare_double_vectors(y_mg, x_mg, n_slot, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS CompressedCiphertext encrypt-decrypt") {
    vector<double> x_mg;
    for (int i = 0; i < n_slot; i++) {
        x_mg.push_back(double(i));
    }

    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksCompressedCiphertext x_ctc = context.encrypt_symmetric_compressed(x_pt);

    CkksCiphertext x_ct = context.compressed_ciphertext_to_ciphertext(x_ctc);

    CkksPlaintext y_pt = context.decrypt(x_ct);
    vector<double> y_mg = context.decode(y_pt);

    REQUIRE(compare_double_vectors(y_mg, x_mg, n_slot, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS encode_coeffs-encrypt-decrypt-decode_coeffs") {
    vector<double> x_mg;
    for (int i = 0; i < n_slot; i++) {
        x_mg.push_back(double(i));
    }

    for (int level = 1; level <= max_level; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode_coeffs(x_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            CkksPlaintext y_pt = context.decrypt(x_ct);
            vector<double> y_mg = context.decode_coeffs(y_pt);

            REQUIRE(compare_double_vectors(y_mg, x_mg, n_slot, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct add pt") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * 2 + 1));
    }

    for (int level = 1; level < 6; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            CkksCiphertext z_ct = context.add_plain(x_ct, y_pt);

            CkksPlaintext z_pt = context.decrypt(z_ct);
            vector<double> z_mg = context.decode(z_pt);

            REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct add pt_ringt") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * 2 + 1));
    }

    for (int level = 1; level < 6; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksPlaintextRingt y_pt = context.encode_ringt(y_mg, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            CkksCiphertext z_ct = context.add_plain_ringt(x_ct, y_pt);

            CkksPlaintext z_pt = context.decrypt(z_ct);
            vector<double> z_mg = context.decode(z_pt);

            REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct add ct") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * 2 + 1));
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    CkksCiphertext z_ct = context.add(x_ct, y_ct);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct sub ct") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i * 3));
        y_mg.push_back(double(i + 1));
        z_true.push_back(x_mg[i] - y_mg[i]);
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    CkksCiphertext z_ct = context.sub(x_ct, y_ct);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct sub pt_ringt") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i - i - 1));  // i - (i+1) = -1
    }

    for (int level = 0; level < 6; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksPlaintextRingt y_pt = context.encode_ringt(y_mg, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            CkksCiphertext z_ct = context.sub_plain_ringt(x_ct, y_pt);

            CkksPlaintext z_pt = context.decrypt(z_ct);
            vector<double> z_mg = context.decode(z_pt);

            REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct multiply pt") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * (i + 1)));
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    CkksCiphertext z_ct = context.mult_plain(x_ct, y_pt);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    for (int i = 0; i < 10; i++) {
        cout << z_mg[i] << ", ";
    }

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct multiply pt_coeffs") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
    }

    for (int i = 0; i < (x_mg.size() - 1) * (y_mg.size() - 1) + 1; i++) {
        z_true.push_back(double(0));
        int k = i < x_mg.size() - 1 ? i : x_mg.size() - 1;
        for (int j = 0; j <= k; j++) {
            if (i - j < y_mg.size()) {
                z_true[i] += x_mg[j] * y_mg[i - j];
            }
        }
    }

    CkksPlaintext x_pt = context.encode_coeffs(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode_coeffs(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    CkksCiphertext z_ct = context.mult_plain(x_ct, y_pt);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode_coeffs(z_pt);

    for (int i = 0; i < 10; i++) {
        cout << z_mg[i] << ", ";
    }
    REQUIRE(compare_double_vectors(z_mg, z_true, z_true.size(), 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct multiply pt_mul") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * (i + 1)));
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintextMul y_pt = context.encode_mul(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    CkksCiphertext z_ct = context.mult_plain_mul(x_ct, y_pt);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    print_double_message(z_mg.data(), "z_mg", 10);

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct multiply pt_coeffs_mul") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
    }
    for (int i = 0; i < (x_mg.size() - 1) * (y_mg.size() - 1) + 1; i++) {
        z_true.push_back(0.0);
        int k = i < x_mg.size() - 1 ? i : x_mg.size() - 1;
        for (int j = 0; j <= k; j++) {
            if (i - j < y_mg.size()) {
                z_true[i] += x_mg[j] * y_mg[i - j];
            }
        }
    }

    CkksPlaintext x_pt = context.encode_coeffs(x_mg, level, default_scale);
    CkksPlaintextMul y_pt = context.encode_coeffs_mul(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    CkksCiphertext z_ct = context.mult_plain_mul(x_ct, y_pt);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode_coeffs(z_pt);

    for (int i = 0; i < 10; i++) {
        cout << z_mg[i] << ", ";
    }

    REQUIRE(compare_double_vectors(z_mg, z_true, z_true.size(), 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct multiply pt_ringt") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * (i + 1)));
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksPlaintextRingt y_pt_rt = context.encode_ringt(y_mg, default_scale);
    CkksPlaintextMul y_pt = context.ringt_to_mul(y_pt_rt, level);

    CkksCiphertext z_ct = context.mult_plain_mul(x_ct, y_pt);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    for (int i = 0; i < 10; i++) {
        cout << z_mg[i] << ", ";
    }

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct multiply pt_coeffs_ringt") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
    }
    for (int i = 0; i < (x_mg.size() - 1) * (y_mg.size() - 1) + 1; i++) {
        z_true.push_back(double(0));
        int k = i < x_mg.size() - 1 ? i : x_mg.size() - 1;
        for (int j = 0; j <= k; j++) {
            if (i - j < y_mg.size()) {
                z_true[i] += x_mg[j] * y_mg[i - j];
            }
        }
    }
    CkksPlaintext x_pt = context.encode_coeffs(x_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksPlaintextRingt y_pt_rt = context.encode_coeffs_ringt(y_mg, default_scale);
    CkksPlaintextMul y_pt = context.ringt_to_mul(y_pt_rt, level);

    CkksCiphertext z_ct = context.mult_plain_mul(x_ct, y_pt);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode_coeffs(z_pt);

    for (int i = 0; i < 10; i++) {
        cout << z_mg[i] << ", ";
    }

    REQUIRE(compare_double_vectors(z_mg, z_true, z_true.size(), 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct multiply ct") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * (i + 1)));
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    CkksCiphertext3 z_ct3 = context.mult(x_ct, y_ct);

    CkksPlaintext z_pt = context.decrypt(z_ct3);
    vector<double> z_mg = context.decode(z_pt);

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ct multiply ct and relin") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(i + 10.1);
        y_mg.push_back(i + 11.2);
        z_true.push_back((i + 10.1) * (i + 11.2));
    }

    min_level = 1;

    for (int level = min_level; level <= max_level; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
            CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

            auto start = chrono::high_resolution_clock::now();
            CkksCiphertext3 z_ct3 = context.mult(x_ct, y_ct);
            CkksCiphertext z_ct1 = context.relinearize(z_ct3);
            auto end = chrono::high_resolution_clock::now();
            auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
            fprintf(stderr, "mult_relin time: %.4f ms\n", double(duration.count()));

            CkksPlaintext z_pt = context.decrypt(z_ct1);
            vector<double> z_mg = context.decode(z_pt);

            for (int i = 0; i < 10; i++) {
                cout << z_mg[i] << ", ";
            }

            REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS complex ct multiply ct and relin") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
    }
    for (int i = 0; i < 5; i++) {
        double x_r = x_mg[i * 2];
        double x_i = x_mg[i * 2 + 1];
        double y_r = y_mg[i * 2];
        double y_i = y_mg[i * 2 + 1];
        z_true.push_back(x_r * y_r - x_i * y_i);
        z_true.push_back(x_r * y_i + x_i * y_r);
    }

    for (int level = 5; level <= 5; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode_complex(x_mg, level, default_scale);
            CkksPlaintext y_pt = context.encode_complex(y_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
            CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

            CkksCiphertext3 z_ct3 = context.mult(x_ct, y_ct);
            CkksCiphertext z_ct1 = context.relinearize(z_ct3);

            CkksPlaintext z_pt = context.decrypt(z_ct1);
            vector<double> z_mg = context.decode_complex(z_pt);

            for (int i = 0; i < 10; i++) {
                cout << z_mg[i] << ", ";
            }

            REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS rescale") {
    vector<double> x_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
    }

    for (int level = 1; level <= 5; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale * default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            CkksCiphertext y_ct = context.rescale(x_ct, default_scale);
            REQUIRE(y_ct.get_level() == x_ct.get_level() - 1);
            REQUIRE(fabs(y_ct.get_scale() / default_scale - 1.0) < 0.01);

            CkksPlaintext y_pt = context.decrypt(y_ct);
            vector<double> y_mg = context.decode(y_pt);

            REQUIRE(compare_double_vectors(y_mg, x_mg, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS drop level") {
    vector<double> x_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    CkksCiphertext y_ct = context.drop_level(x_ct);
    REQUIRE(y_ct.get_level() == x_ct.get_level() - 1);
    REQUIRE(fabs(y_ct.get_scale() / default_scale - 1.0) < 0.01);

    CkksPlaintext y_pt = context.decrypt(y_ct);
    vector<double> y_mg = context.decode(y_pt);

    REQUIRE(compare_double_vectors(y_mg, x_mg, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS rotate") {
    const double INPUT_RANGE_ABS = 2.0;
    vector<double> x_mg;
    for (int i = 0; i < N / 2; i++) {
        x_mg.push_back((double(rand()) / RAND_MAX * 2.0 - 1.0) * INPUT_RANGE_ABS);
    }

    vector<int32_t> steps = {19, 200, 4001, 8, 10, -20, -900};
    context.gen_rotation_keys();

    for (int level = 1; level <= max_level; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            double tolerance = 1.0e-3;
            auto y_ct = context.rotate(x_ct, steps);

            for (int i = 0; i < steps.size(); i++) {
                CkksPlaintext y_pt = context.decrypt(y_ct[steps[i]]);
                vector<double> y_mg = context.decode(y_pt);

                vector<double> y_true(n_slot);
                for (int j = 0; j < N / 2; j++) {
                    y_true[(j - steps[i] + n_slot) % n_slot] = x_mg[j];
                }

                fprintf(stderr, "step=%d\n", steps[i]);
                print_double_message(y_mg.data(), "y_mg", 10);
                print_double_message(y_true.data(), "y_true", 10);

                REQUIRE(compare_double_vectors_w_offset(y_mg, y_true, 10, tolerance, -steps[i], n_slot) == false);
            }
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS advanced rotate") {
    const double INPUT_RANGE_ABS = 2.0;
    vector<double> x_mg;
    for (int i = 0; i < N / 2; i++) {
        x_mg.push_back((double(rand()) / RAND_MAX * 2.0 - 1.0) * INPUT_RANGE_ABS);
    }

    vector<int32_t> steps = {19, 200, 4001, 8, 10, -20, -900};
    context.gen_rotation_keys_for_rotations(steps);

    for (int level = 1; level <= max_level; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

            double tolerance = 1.0e-3;
            auto y_ct = context.advanced_rotate(x_ct, steps);

            for (int i = 0; i < steps.size(); i++) {
                CkksPlaintext y_pt = context.decrypt(y_ct[steps[i]]);
                vector<double> y_mg = context.decode(y_pt);

                vector<double> y_true(n_slot);
                for (int j = 0; j < N / 2; j++) {
                    y_true[(j - steps[i] + n_slot) % n_slot] = x_mg[j];
                }

                REQUIRE(compare_double_vectors_w_offset(y_mg, y_true, 10, tolerance, -steps[i], n_slot) == false);
            }
        }
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS make public context") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * (i + 1)));
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    CkksContext public_context = context.make_public_context();
    CkksCiphertext3 z_ct3 = public_context.mult(x_ct, y_ct);
    CkksCiphertext z_ct = public_context.relinearize(z_ct3);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ciphertext serialization", "") {
    vector<double> x_mg;
    for (int i = 0; i < N / 2; i++) {
        x_mg.push_back(double(i - 3));
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    vector<uint8_t> x_data = x_ct.serialize(param);
    fprintf(stderr, "ct size: %zu bytes\n", x_data.size());
    CkksCiphertext y_ct = CkksCiphertext::deserialize(x_data);

    CkksPlaintext y_pt = context.decrypt(y_ct);
    vector<double> y_mg = context.decode(y_pt);

    print_double_message(x_mg.data(), "x_mg", 20);
    print_double_message(y_mg.data(), "y_mg", 20);

    REQUIRE(compare_double_vectors(y_mg, x_mg, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ciphertext compressed serialization", "") {
    vector<double> x_mg;
    for (int i = 0; i < N / 2; i++) {
        x_mg.push_back(double(i - 3));
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksCompressedCiphertext x_ctc = context.encrypt_symmetric_compressed(x_pt);

    vector<uint8_t> x_data = x_ctc.serialize(param);
    cout << x_data.size() << endl;
    CkksCompressedCiphertext y_ctc = CkksCompressedCiphertext::deserialize(x_data);

    CkksCiphertext y_ct = context.compressed_ciphertext_to_ciphertext(y_ctc);

    CkksPlaintext y_pt = context.decrypt(y_ct);
    vector<double> y_mg = context.decode(y_pt);

    print_double_message(x_mg.data(), "x_mg", 20);
    print_double_message(y_mg.data(), "y_mg", 20);

    REQUIRE(compare_double_vectors(y_mg, x_mg, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS ciphertext compressed serialization and add") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < N / 2; i++) {
        x_mg.push_back(double(i - 3));
        y_mg.push_back(double(i - 2));
        z_true.push_back(x_mg[i] + y_mg[i]);
    }
    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCompressedCiphertext x_ctc = context.encrypt_symmetric_compressed(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    vector<uint8_t> x_data = x_ctc.serialize(param);

    CkksCompressedCiphertext x_ctc_de = CkksCompressedCiphertext::deserialize(x_data);
    CkksCiphertext x_ct = context.compressed_ciphertext_to_ciphertext(x_ctc_de);
    CkksCiphertext z_ct = context.add(x_ct, y_ct);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    print_double_message(z_true.data(), "z_true", 20);
    print_double_message(z_mg.data(), "z_mg", 20);

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS public context serialization", "") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * (i + 1)));
    }

    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    CkksContext public_context = context.make_public_context();
    vector<uint8_t> public_context_data = public_context.serialize();
    cout << public_context_data.size() << endl;
    CkksContext deserialized_public_context = CkksContext::deserialize(public_context_data);

    CkksCiphertext3 z_ct3 = deserialized_public_context.mult(x_ct, y_ct);
    CkksCiphertext z_ct = deserialized_public_context.relinearize(z_ct3);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS public context advanced serialization", "") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * (i + 1)));
    }

    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    CkksContext public_context = context.make_public_context();
    vector<uint8_t> public_context_data = public_context.serialize_advanced();
    cout << public_context_data.size() << endl;
    CkksContext deserialized_public_context = CkksContext::deserialize_advanced(public_context_data);

    CkksCiphertext3 z_ct3 = deserialized_public_context.mult(x_ct, y_ct);
    CkksCiphertext z_ct = deserialized_public_context.relinearize(z_ct3);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS public context serialization and rotate") {
    vector<double> x_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
    }

    vector<int32_t> steps = {19, 200, 4001, 8, 10, -20, -900};
    context.gen_rotation_keys();

    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    CkksContext public_context = context.make_public_context();
    vector<uint8_t> public_context_data = public_context.serialize();
    CkksContext deserialized_public_context = CkksContext::deserialize(public_context_data);

    auto y_ct = deserialized_public_context.rotate(x_ct, steps);
    for (int i = 0; i < steps.size(); i++) {
        vector<double> y_true(n_slot);
        for (int j = 0; j < 10; j++) {
            y_true[(j - steps[i] + n_slot) % n_slot] = double(j);
        }

        CkksPlaintext y_pt = context.decrypt(y_ct[steps[i]]);
        vector<double> y_mg = context.decode(y_pt);

        REQUIRE(compare_double_vectors_w_offset(y_mg, y_true, 10, 0.01, -steps[i], n_slot) == false);
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS public context advanced serialization and rotate") {
    vector<double> x_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
    }

    vector<int32_t> steps = {19, 200, 4001, 8, 10, -20, -900};
    context.gen_rotation_keys();

    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    CkksContext public_context = context.make_public_context();
    vector<uint8_t> public_context_data = public_context.serialize_advanced();
    CkksContext deserialized_public_context = CkksContext::deserialize_advanced(public_context_data);

    auto y_ct = deserialized_public_context.rotate(x_ct, steps);
    for (int i = 0; i < steps.size(); i++) {
        vector<double> y_true(n_slot);
        for (int j = 0; j < 10; j++) {
            y_true[(j - steps[i] + n_slot) % n_slot] = double(j);
        }

        CkksPlaintext y_pt = context.decrypt(y_ct[steps[i]]);
        vector<double> y_mg = context.decode(y_pt);

        REQUIRE(compare_double_vectors_w_offset(y_mg, y_true, 10, 0.01, -steps[i], n_slot) == false);
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS public context serialization and advanced rotate") {
    vector<double> x_mg;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
    }

    vector<int32_t> steps = {19, 200, 4001, 8, 10, -20, -900};
    context.gen_rotation_keys_for_rotations(steps);

    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    CkksContext public_context = context.make_public_context();
    vector<uint8_t> public_context_data = public_context.serialize();
    CkksContext deserialized_public_context = CkksContext::deserialize(public_context_data);

    auto y_ct = deserialized_public_context.advanced_rotate(x_ct, steps);
    for (int i = 0; i < steps.size(); i++) {
        vector<double> y_true(n_slot);
        for (int j = 0; j < 10; j++) {
            y_true[(j - steps[i] + n_slot) % n_slot] = double(j);
        }

        CkksPlaintext y_pt = context.decrypt(y_ct[steps[i]]);
        vector<double> y_mg = context.decode(y_pt);

        REQUIRE(compare_double_vectors_w_offset(y_mg, y_true, 10, 0.01, -steps[i], n_slot) == false);
    }
}

TEST_CASE("CKKS generate context with seed") {
    int N = 16384;
    CkksParameter param = CkksParameter::create_parameter(N);

    vector<uint8_t> seed(64);
    for (int i = 0; i < 64; i++) {
        seed[i] = i + 1;
    }
    CkksContext context_0 = CkksContext::create_random_context_with_seed(param, seed);
    CkksContext context_1 = CkksContext::create_random_context_with_seed(param, seed);

    SecretKey sk_0 = context_0.extract_secret_key();
    CkksContext sk_0_context = CkksContext::create_empty_context(param);
    sk_0_context.set_context_secret_key(sk_0);
    auto sk_0_bytes = sk_0_context.serialize();

    SecretKey sk_1 = context_1.extract_secret_key();
    CkksContext sk_1_context = CkksContext::create_empty_context(param);
    sk_1_context.set_context_secret_key(sk_1);
    auto sk_1_bytes = sk_1_context.serialize();

    REQUIRE(sk_0_bytes == sk_1_bytes);

    PublicKey pk_0 = context_0.extract_public_key();
    CkksContext pk_0_context = CkksContext::create_empty_context(param);
    pk_0_context.set_context_public_key(pk_0);
    auto pk_0_bytes = pk_0_context.serialize();

    PublicKey pk_1 = context_1.extract_public_key();
    CkksContext pk_1_context = CkksContext::create_empty_context(param);
    pk_1_context.set_context_public_key(pk_1);
    auto pk_1_bytes = pk_1_context.serialize();

    REQUIRE(pk_0_bytes != pk_1_bytes);
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV encode error") {
    SECTION("length=0") {
        vector<uint64_t> x_mg(0);
        REQUIRE_THROWS_WITH(context.encode(x_mg, level), "Invalid message length.");
    }
    SECTION("length=N+1") {
        vector<uint64_t> x_mg(N + 1);
        REQUIRE_THROWS_WITH(context.encode(x_mg, level), "Invalid message length.");
    }
    SECTION("level = -1") {
        vector<uint64_t> x_mg(N);
        REQUIRE_THROWS_WITH(context.encode(x_mg, -1), "Invalid level.");
    }
    SECTION("level = 6") {
        vector<uint64_t> x_mg(N);
        REQUIRE_THROWS_WITH(context.encode(x_mg, 6), "Invalid level.");
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV encode ringt error") {
    SECTION("length=0") {
        vector<uint64_t> x_mg(0);
        REQUIRE_THROWS_WITH(context.encode_ringt(x_mg), "Invalid message length.");
    }
    SECTION("length=N+1") {
        vector<uint64_t> x_mg(N + 1);
        REQUIRE_THROWS_WITH(context.encode_ringt(x_mg), "Invalid message length.");
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV encrypt_symmetric error") {
    SECTION("context with no sk") {
        BfvContext public_context = context.make_public_context();
        vector<uint64_t> x_mg(1, 0);
        BfvPlaintext x_pt = context.encode(x_mg, level);
        REQUIRE_THROWS_WITH(public_context.encrypt_symmetric(x_pt),
                            "Context does not have sk and the corresponding encryptor.");
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV encrypt_symmetric_compressed error") {
    SECTION("context with no sk") {
        BfvContext public_context = context.make_public_context();
        vector<uint64_t> x_mg(1, 0);
        BfvPlaintext x_pt = context.encode(x_mg, level);
        REQUIRE_THROWS_WITH(public_context.encrypt_symmetric_compressed(x_pt),
                            "Context does not have sk and the corresponding encryptor.");
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV decrypt error") {
    SECTION("context with no sk") {
        BfvContext public_context = context.make_public_context();
        vector<uint64_t> x_mg(1, 0);
        BfvPlaintext x_pt = context.encode(x_mg, level);
        BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);
        REQUIRE_THROWS_WITH(public_context.decrypt(x_ct), "Context does not have sk and decryptor.");
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS decrypt error") {
    SECTION("context with no sk") {
        CkksContext public_context = context.make_public_context();
        vector<double> x_mg(1, 0.0);
        CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
        CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
        REQUIRE_THROWS_WITH(public_context.decrypt(x_ct), "Context does not have sk and decryptor.");
    }
}

TEST_CASE_METHOD(LattigoBfvFixture, "BFV add error") {
    SECTION("different levels") {
        vector<uint64_t> x0_mg{0};
        vector<uint64_t> x1_mg{0};
        BfvPlaintext x0_pt = context.encode(x0_mg, 1);
        BfvPlaintext x1_pt = context.encode(x1_mg, 2);
        BfvCiphertext x0_ct = context.encrypt_asymmetric(x0_pt);
        BfvCiphertext x1_ct = context.encrypt_asymmetric(x1_pt);
        REQUIRE_THROWS_WITH(context.add(x0_ct, x1_ct), "x0 and x1 have different levels.");
    }
}

class LattigoCkksBtpFixture {
public:
    LattigoCkksBtpFixture()
        : level{5}, param{CkksBtpParameter::create_parameter()}, context{CkksBtpContext::create_random_context(param)},
          default_scale{pow(2, 40)} {}

protected:
    int level;
    CkksBtpParameter param;
    CkksBtpContext context;
    double default_scale;
};

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP encode-decode", "[.]") {
    vector<double> x_mg;
    for (int i = 0; i < 4096; i++) {
        x_mg.push_back(double(i));
    }

    for (int level = 1; level <= 5; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            vector<double> y_mg = context.decode(x_pt);
            REQUIRE(compare_double_vectors(y_mg, x_mg, 4096, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP encrypt-decrypt", "[.]") {
    vector<double> x_mg;
    for (int i = 0; i < 4096; i++) {
        x_mg.push_back(double(i));
    }

    for (int level = 1; level <= 5; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_symmetric(x_pt);

            CkksPlaintext y_pt = context.decrypt(x_ct);
            vector<double> y_mg = context.decode(x_pt);
            REQUIRE(compare_double_vectors(y_mg, x_mg, 4096, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP ct multiply pt_ringt", "[.]") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * (i + 1)));
    }
    for (int level = 1; level <= 2; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
            CkksPlaintextRingt y_pt_rt = context.encode_ringt(y_mg, default_scale);
            CkksPlaintextMul y_pt = context.ringt_to_mul(y_pt_rt, level);

            CkksCiphertext z_ct = context.mult_plain_mul(x_ct, y_pt);

            CkksPlaintext z_pt = context.decrypt(z_ct);
            vector<double> z_mg = context.decode(z_pt);

            for (int i = 0; i < 10; i++) {
                cout << z_mg[i] << ", ";
            }

            REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP ct multiply ct and relin", "[.]") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(i + 10.1);
        y_mg.push_back(i + 11.2);
        z_true.push_back((i + 10.1) * (i + 11.2));
    }

    for (int level = 1; level <= 2; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_symmetric(x_pt);
            CkksCiphertext y_ct = context.encrypt_symmetric(y_pt);

            CkksCiphertext3 z_ct3 = context.mult(x_ct, y_ct);
            CkksCiphertext z_ct1 = context.relinearize(z_ct3);
            CkksCiphertext z_ct = context.rescale(z_ct1, default_scale);

            CkksPlaintext z_pt = context.decrypt(z_ct);
            vector<double> z_mg = context.decode(z_pt);

            print_double_message(z_mg.data(), "w_mg", 10);
            REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP bootstrap", "[.]") {
    vector<double> x_mg;
    for (int i = 0; i < 4096; i++) {
        x_mg.push_back(double(i));
    }

    for (int level = 5; level <= 5; level++) {
        SECTION("level " + to_string(level)) {
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_symmetric(x_pt);

            CkksCiphertext y_ct = context.bootstrap(x_ct);

            CkksPlaintext y_pt = context.decrypt(x_ct);
            vector<double> y_mg = context.decode(x_pt);
            print_double_message(y_mg.data(), "y_mg", 10);
            REQUIRE(compare_double_vectors(y_mg, x_mg, 4096, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP multiply and bootstrap", "[.]") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(1.0 + i * 0.1);
        y_mg.push_back(2.0);
        z_true.push_back(x_mg[i] * y_mg[i]);
    }
    print_double_message(x_mg.data(), "x_mg", 10);
    print_double_message(y_mg.data(), "y_mg", 10);

    for (int level = 3; level <= 3; level++) {
        SECTION("level " + to_string(level)) {
            // It seems the scale of the input ciphertext of bootstrapping must be an exact power of 2.
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
            CkksCiphertext x_ct = context.encrypt_symmetric(x_pt);
            CkksCiphertext y_ct = context.encrypt_symmetric(y_pt);

            CkksCiphertext3 z_ct3 = context.mult(x_ct, y_ct);
            CkksCiphertext z_ct = context.relinearize(z_ct3);
            z_ct = context.rescale(z_ct, default_scale);
            z_ct = context.drop_level(z_ct, 2);
            auto input_scale = z_ct.get_scale();
            z_ct.set_scale(default_scale);
            z_ct = context.bootstrap(z_ct);
            z_ct.set_scale(input_scale);

            CkksPlaintext z_pt = context.decrypt(z_ct);
            vector<double> z_mg = context.decode(z_pt);
            print_double_message(z_mg.data(), "z_mg", 10);
            fprintf(stderr, "z_ct level=%d, log scale=%f", z_ct.get_level(), log2(z_ct.get_scale()));
            REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
        }
    }
}

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP multiple multiply and bootstrap", "[.]") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(1.0 + i * 0.1);
        y_mg.push_back(1.1);
        z_true.push_back(x_mg[i] * y_mg[i]);
    }
    print_double_message(x_mg.data(), "x_mg", 10);
    print_double_message(y_mg.data(), "y_mg", 10);

    for (int level = 6; level <= 6; level++) {
        SECTION("level " + to_string(level)) {
            // It seems the scale of the input ciphertext of bootstrapping must be an exact power of 2.
            CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
            CkksPlaintext y_pt = context.encode(y_mg, level, double(0x10000500001));
            CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
            CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

            CkksCiphertext z_ct = std::move(x_ct);
            for (int r = 0; r < 20; r++) {
                z_ct = context.relinearize(context.mult(z_ct, y_ct));
                z_ct = context.rescale(z_ct, default_scale);
                z_ct = context.bootstrap(z_ct);

                CkksPlaintext z_pt = context.decrypt(z_ct);
                vector<double> z_mg = context.decode(z_pt);
                print_double_message(z_mg.data(), "z_mg", 10);
                fprintf(stderr, "z_ct level=%d, log scale=%f\n", z_ct.get_level(), log2(z_ct.get_scale()));
            }
        }
    }
}

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP multiple multiply to level 0 and bootstrap", "[.]") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(1.0 + i * 0.1);
        y_mg.push_back(1.1);
        z_true.push_back(x_mg[i] * y_mg[i]);
    }
    print_double_message(x_mg.data(), "x_mg", 10);
    print_double_message(y_mg.data(), "y_mg", 10);

    // It seems the scale of the input ciphertext of bootstrapping must be an exact power of 2.
    CkksPlaintext x_pt = context.encode(x_mg, 9, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, 1, double(0x10000140001));
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    CkksCiphertext z_ct = std::move(x_ct);
    for (int r = 0; r < 20; r++) {
        for (int j = 0; j < 8; j++) {
            z_ct = context.drop_level(z_ct);
            fprintf(stderr, "z_ct level=%d, log scale=%f\n", z_ct.get_level(), log2(z_ct.get_scale()));
        }
        z_ct = context.relinearize(context.mult(z_ct, y_ct));
        z_ct = context.rescale(z_ct, default_scale);
        fprintf(stderr, "z_ct level=%d, log scale=%f\n", z_ct.get_level(), log2(z_ct.get_scale()));
        z_ct = context.bootstrap(z_ct);

        CkksPlaintext z_pt = context.decrypt(z_ct);
        vector<double> z_mg = context.decode(z_pt);
        print_double_message(z_mg.data(), "z_mg", 10);
        fprintf(stderr, "z_ct level=%d, log scale=%f\n", z_ct.get_level(), log2(z_ct.get_scale()));
    }
}

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP public context serialization", "[.]") {
    vector<double> x_mg;
    vector<double> y_mg;
    vector<double> z_true;
    for (int i = 0; i < 10; i++) {
        x_mg.push_back(double(i));
        y_mg.push_back(double(i + 1));
        z_true.push_back(double(i * (i + 1)));
    }

    CkksPlaintext x_pt = context.encode(x_mg, level, default_scale);
    CkksPlaintext y_pt = context.encode(y_mg, level, default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext y_ct = context.encrypt_asymmetric(y_pt);

    CkksBtpContext public_context = context.make_public_context();
    auto start0 = chrono::high_resolution_clock::now();
    vector<uint8_t> public_context_data = public_context.serialize();
    cout << public_context_data.size() << endl;
    auto end0 = chrono::high_resolution_clock::now();
    auto duration0 = chrono::duration_cast<chrono::milliseconds>(end0 - start0);
    fprintf(stderr, "serialize time: %.4f ms\n", double(duration0.count()));

    auto start1 = chrono::high_resolution_clock::now();
    CkksBtpContext deserialized_public_context = CkksBtpContext::deserialize(public_context_data);
    auto end1 = chrono::high_resolution_clock::now();
    auto duration1 = chrono::duration_cast<chrono::milliseconds>(end1 - start1);
    fprintf(stderr, "deserialize time: %.4f ms\n", double(duration1.count()));

    CkksCiphertext3 z_ct3 = deserialized_public_context.mult(x_ct, y_ct);
    CkksCiphertext z_ct = deserialized_public_context.relinearize(z_ct3);
    z_ct = context.bootstrap(z_ct);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);

    print_double_message(z_mg.data(), "z_mg", 10);
    REQUIRE(compare_double_vectors(z_mg, z_true, 10, 0.01) == false);
}

TEST_CASE_METHOD(LattigoCkksBtpFixture, "CKKS BTP public context serialization - multi-threaded", "[.]") {
    // Thread synchronization
    std::mutex result_mutex;
    std::atomic<int> successful_threads{0};
    std::atomic<int> failed_threads{0};

    const int num_threads = 1;
    const int operations_per_thread = 5;

    // Prepare different test data for each thread
    vector<vector<double>> thread_x_data(num_threads);
    vector<vector<double>> thread_y_data(num_threads);
    vector<vector<double>> thread_expected(num_threads);

    for (int t = 0; t < num_threads; t++) {
        for (int i = 0; i < 10; i++) {
            double x_val = double(t * 10 + i);
            double y_val = double(t * 10 + i + 1);
            thread_x_data[t].push_back(x_val);
            thread_y_data[t].push_back(y_val);
            thread_expected[t].push_back(x_val * y_val);
        }
    }

    auto start_serialize = chrono::high_resolution_clock::now();
    vector<uint8_t> context_data = context.serialize();
    auto end_serialize = chrono::high_resolution_clock::now();
    auto serialize_duration = chrono::duration_cast<chrono::milliseconds>(end_serialize - start_serialize);
    fprintf(stderr, "Context serialization time: %.4f ms\n", double(serialize_duration.count()));

    auto start_deserialize = chrono::high_resolution_clock::now();
    CkksBtpContext deserialized_context = CkksBtpContext::deserialize(context_data);
    auto end_deserialize = chrono::high_resolution_clock::now();
    auto deserialize_duration = chrono::duration_cast<chrono::milliseconds>(end_deserialize - start_deserialize);
    fprintf(stderr, "Context deserialization time: %.4f ms\n", double(deserialize_duration.count()));

    // use this replace to compare with context serialize-deserialize
    // auto deserialized_context = move(context);

    deserialized_context.resize_copies(num_threads);

    auto thread_worker = [&](int thread_id) {
        try {
            auto& _context = deserialized_context.get_copy(thread_id);
            CkksPlaintext x_pt = _context.encode(thread_x_data[thread_id], level, default_scale);
            CkksPlaintext y_pt = _context.encode(thread_y_data[thread_id], level, default_scale);
            CkksCiphertext x_ct = _context.encrypt_asymmetric(x_pt);
            CkksCiphertext y_ct = _context.encrypt_asymmetric(y_pt);

            for (int op = 0; op < operations_per_thread; op++) {
                CkksCiphertext3 mult_result = _context.mult(x_ct, y_ct);

                CkksCiphertext relin_result = _context.relinearize(mult_result);

                CkksCiphertext bootstrap_result = _context.bootstrap(relin_result);

                CkksPlaintext decrypted_pt = _context.decrypt(bootstrap_result);
                vector<double> decrypted_values = _context.decode(decrypted_pt);

                {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    // fprintf(stderr, "Thread %d, Op %d results:\n", thread_id, op);
                    // print_double_message(decrypted_values.data(), "decrypted", 10);
                }

                bool results_valid =
                    (compare_double_vectors(decrypted_values, thread_expected[thread_id], 10, 0.01) == false);

                if (!results_valid) {
                    failed_threads++;
                    return;
                }
            }

            {
                std::lock_guard<std::mutex> lock(result_mutex);
                fprintf(stderr, "Thread %d completed successfully\n", thread_id);
            }
            successful_threads++;

        } catch (const std::exception& e) {
            {
                std::lock_guard<std::mutex> lock(result_mutex);
                fprintf(stderr, "Thread %d failed with exception: %s\n", thread_id, e.what());
            }
            failed_threads++;
        }
    };

    auto start_computation = chrono::high_resolution_clock::now();
    vector<std::thread> threads;
    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back(thread_worker, t);
    }

    for (auto& thread : threads) {
        thread.join();
    }
    auto end_computation = chrono::high_resolution_clock::now();
    auto computation_duration = chrono::duration_cast<chrono::milliseconds>(end_computation - start_computation);

    fprintf(stderr, "Multi-threaded computation time: %.4f ms\n", double(computation_duration.count()));
    fprintf(stderr, "Successful threads: %d, Failed threads: %d\n", successful_threads.load(), failed_threads.load());

    REQUIRE(successful_threads.load() == num_threads);
    REQUIRE(failed_threads.load() == 0);
}

TEST_CASE("BFV power-of-2 plaintext modulus encrypt-decrypt") {
    int N = 8192;
    uint64_t t = 1 << 10;
    BfvParameter param = BfvParameter::create_parameter(N, t);
    BfvContext context = BfvContext::create_random_context(param);
    int level = 2;

    vector<uint64_t> x_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i % t);
    }
    BfvPlaintext x_pt = context.encode_coeffs(x_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvPlaintext y_pt = context.decrypt(x_ct);
    vector<uint64_t> y_mg = context.decode_coeffs(y_pt);
    print_message(y_mg.data(), "y_mg", 8);

    REQUIRE(y_mg == x_mg);
}

TEST_CASE("BFV power-of-2 plaintext modulus ct multiply pt") {
    int N = 8192;
    uint64_t t = 1 << 12;
    BfvParameter param = BfvParameter::create_parameter(N, t);
    BfvContext context = BfvContext::create_random_context(param);
    int level = 2;

    vector<uint64_t> x_mg;
    vector<uint64_t> y_mg;
    for (int i = 0; i < N; i++) {
        x_mg.push_back((uint64_t)i % t);
        y_mg.push_back((uint64_t)(i + 1) % t);
    }
    vector<uint64_t> z_true = polynomial_multiplication(N, t, x_mg, y_mg);

    BfvPlaintext x_pt = context.encode_coeffs(x_mg, level);
    BfvPlaintext y_pt = context.encode_coeffs(y_mg, level);
    BfvCiphertext x_ct = context.encrypt_asymmetric(x_pt);

    BfvCiphertext z_ct = context.mult_plain(x_ct, y_pt);

    BfvPlaintext z_pt = context.decrypt(z_ct);
    vector<uint64_t> z_mg = context.decode_coeffs(z_pt);
    print_message(z_mg.data(), "z_mg", 8);

    REQUIRE(z_mg == z_true);
}

TEST_CASE("BFV decode_coeff benchmark") {
    int n_repeat = 10000;
    vector<uint64_t> ts = {65537, 1 << 10};
    for (uint64_t t : ts) {
        int N = 8192;
        BfvParameter param = BfvParameter::create_parameter(N, t);
        BfvContext context = BfvContext::create_random_context(param);
        int level = 1;

        vector<uint64_t> x_mg;
        for (int i = 0; i < N; i++) {
            x_mg.push_back((uint64_t)i % t);
        }
        BfvPlaintext x_pt = context.encode_coeffs(x_mg, level);

        auto start = chrono::high_resolution_clock::now();
        for (int i = 0; i < n_repeat; i++) {
            vector<uint64_t> y_mg = context.decode_coeffs(x_pt);
            REQUIRE(y_mg == x_mg);
        }
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
        fprintf(stderr, "t=%lu, decode time: %.4f ms\n", t, double(duration.count()) / n_repeat);
    }
}

TEST_CASE_METHOD(LattigoCkksFixture, "CKKS poly-eval-step-function") {
    double left = -8;
    double right = 8;
    double degree = 255;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<double> distrib(left, right);

    vector<double> x_mg;
    for (int i = 0; i < n_slot; i++) {
        x_mg.push_back(distrib(gen));
    }

    CkksPlaintext x_pt = context.encode(x_mg, param.get_max_level(), default_scale);
    CkksCiphertext x_ct = context.encrypt_asymmetric(x_pt);
    CkksCiphertext z_ct = context.poly_eval_step_function(x_ct, left, right, degree, 0);

    CkksPlaintext z_pt = context.decrypt(z_ct);
    vector<double> z_mg = context.decode(z_pt);
    print_double_message(z_mg.data(), "z_mg", 8);

    vector<double> z_true;
    for (int i = 0; i < n_slot; i++) {
        z_true.emplace_back(step_function(x_mg[i]));
    }

    double epsilon = 0.5;
    REQUIRE(compare_double_vectors(z_mg, z_true, n_slot, epsilon) == false);
}

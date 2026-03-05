#pragma once

#include <string>
#include "runner.h"
#include "test_config.hpp"

using namespace std;

string fpga_base_path = test_config::fpga_base_path;
string gpu_base_path = test_config::gpu_base_path;

class FpgaFixture {
public:
    FpgaFixture() {
        FpgaDevice::init();
    }

    ~FpgaFixture() {
        FpgaDevice::free();
    }
};

class BfvFpgaFixture : public FpgaFixture {
public:
    BfvFpgaFixture() : n{8192}, t{0x1b4001}, param{GenBfvFpgaParam(t)}, ctx(seal::SEALContext(param)) {}

protected:
    uint64_t n;
    uint64_t t;
    seal::EncryptionParameters param;
    seal::SEALContext ctx;
};

class TestBfvFpgaFixture : public BfvFpgaFixture {
public:
    TestBfvFpgaFixture() : n_op{4}, level{int(param.coeff_modulus().size()) - 2} {}

protected:
    int n_op;
    int level;
};

class CkksFpgaFixture : public FpgaFixture {
public:
    CkksFpgaFixture()
        : n{8192}, n_slot{n / 2}, default_scale(pow(2.0, 31)), param{GenCkksFpgaParam()},
          ctx(seal::SEALContext(param)) {}

protected:
    uint64_t n;
    uint64_t n_slot;
    double default_scale;
    seal::EncryptionParameters param;
    seal::SEALContext ctx;
};

class TestCkksFpgaFixture : public CkksFpgaFixture {
public:
    TestCkksFpgaFixture() : n_op{4}, level(int(param.coeff_modulus().size()) - 2) {}

protected:
    int n_op;
    int level;
};

seal::EncryptionParameters GenBfvParam(uint64_t plain_modulus) {
    int N = 8192;
    const vector<seal::Modulus> qp = {0x3fffffffef8001, 0x4000000011c001, 0x40000000120001, 0x7ffffffffb4001};
    seal::EncryptionParameters param(seal::scheme_type::bfv);
    param.set_poly_modulus_degree(N);
    param.set_plain_modulus(plain_modulus);
    param.set_coeff_modulus(qp);

    return param;
}

seal::EncryptionParameters GenCkksParam() {
    int N = 8192;
    const vector<seal::Modulus> qp = {0x1fffec001,  // 33 + 5 x 30 + 35
                                      0x3fff4001,  0x3ffe8001, 0x40020001, 0x40038001, 0x3ffc0001, 0x800004001};
    seal::EncryptionParameters param(seal::scheme_type::ckks);
    param.set_poly_modulus_degree(N);
    param.set_coeff_modulus(qp);

    return param;
}

class BfvGpuFixture {
public:
    BfvGpuFixture() : n{8192}, t{65537}, param{GenBfvParam(65537)}, ctx(seal::SEALContext(param)) {}

protected:
    uint64_t n;
    uint64_t t;
    seal::EncryptionParameters param;
    seal::SEALContext ctx;
};

class TestBfvGpuFixture : public BfvGpuFixture {
public:
    TestBfvGpuFixture() : n_op{4}, level{int(param.coeff_modulus().size()) - 2} {}

protected:
    int n_op;
    int level;
};

class CkksGpuFixture {
public:
    CkksGpuFixture()
        : n{8192}, n_slot{8192 / 2}, default_scale(1 << 30), param{GenCkksParam()}, ctx(seal::SEALContext(param)) {}

protected:
    uint64_t n;
    uint64_t n_slot;
    double default_scale;
    seal::EncryptionParameters param;
    seal::SEALContext ctx;
};

class TestCkksGpuFixture : public CkksGpuFixture {
public:
    TestCkksGpuFixture() : n_op{4}, level(int(param.coeff_modulus().size()) - 2) {}

protected:
    int n_op;
    int level;
};

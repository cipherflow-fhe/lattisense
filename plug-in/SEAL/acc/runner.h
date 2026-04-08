#ifndef RUNNER_H
#define RUNNER_H

#include <fstream>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <typeindex>

extern "C" {
#include "fpga_ops_wrapper.h"
#include "log/log.h"
#include "fhe_types_v2.h"
#include "wrapper.h"
#include "structs_v2.h"
}
#include <seal/seal.h>
#include "argument.h"

class FheTask {
public:
    FheTask() = default;

    FheTask(const std::string& project_path);

    FheTask(const FheTask& other) = delete;

    FheTask(FheTask&& other) {
        std::swap(_project_path, other._project_path);
    }

    void operator=(const FheTask& other) = delete;

    void operator=(FheTask&& other) {
        std::swap(_project_path, other._project_path);
    }

    ~FheTask();

    uint64_t set_parameter(const seal::EncryptionParameters& params);

protected:
    std::string _project_path = "";
    nlohmann::json _task_signature;
    nlohmann::json _param_json;

    fhe_task_handle task_handle = nullptr;

    std::vector<CArgument> input_args;
    std::vector<CArgument> output_args;

    void new_args(int n_in_args, int n_out_args);
    void free_args();
};

class FheTaskGpu : public FheTask {
public:
    using FheTask::FheTask;

    FheTaskGpu(const std::string& project_path);

    ~FheTaskGpu();

    uint64_t run(seal::SEALContext* context,
                 const seal::RelinKeys* rlk,
                 const seal::GaloisKeys* glk,
                 const std::vector<SealVectorArgument>& args);

private:
    void bind_abi_executors(int mf_nbits);
};

class FheTaskFpga : public FheTask {
public:
    using FheTask::FheTask;

    FheTaskFpga(const std::string& project_path);

    FheTaskFpga(const FheTaskFpga& other) = delete;

    FheTaskFpga(FheTaskFpga&& other);

    void operator=(const FheTaskFpga& other) = delete;

    void operator=(FheTaskFpga&& other);

    ~FheTaskFpga();

    uint64_t run(seal::SEALContext* context,
                 const seal::RelinKeys* rlk,
                 const seal::GaloisKeys* glk,
                 const std::vector<SealVectorArgument>& args);

private:
    void bind_abi_executors(int mf_nbits);
};

class FpgaDevice {
public:
    FpgaDevice(const FpgaDevice& other) = delete;

    void operator=(const FpgaDevice& other) = delete;

    /**
     * Initializes the FPGA accelerator device.
     * @return None.
     */
    static int init();

    /**
     * Releases the FPGA accelerator device resources.
     * @return None.
     */
    static int free();

private:
    FpgaDevice() {}

    ~FpgaDevice() {
        free();
    }

    static FpgaDevice _instance;  ///< Device singleton object
    static bool _in_use;          ///< Device in-use flag
};

seal::EncryptionParameters GenBfvFpgaParam(uint64_t plain_modulus);
seal::EncryptionParameters GenCkksFpgaParam();

#endif  // RUNNER_H
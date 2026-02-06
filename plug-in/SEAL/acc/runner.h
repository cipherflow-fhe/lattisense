#ifndef RUNNER_H
#define RUNNER_H

#include <fstream>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <typeindex>

extern "C" {
#include "log/log.h"
#include "fhe_types_v2.h"
#include "wrapper.h"
#include "structs_v2.h"
}
#include <seal/seal.h>
#include "c_struct_import_export.h"

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

    fhe_task_handle task_handle;
};

// Check signature functions
void check_parameter(seal::SEALContext* context, const nlohmann::json& param_json);

int check_signatures(seal::SEALContext* context,
                     const seal::RelinKeys& rlk,
                     const seal::GaloisKeys& glk,
                     const std::vector<SealVectorArgument>& seal_args,
                     const nlohmann::json& task_sig_json,
                     bool online_phase);

#endif  // RUNNER_H
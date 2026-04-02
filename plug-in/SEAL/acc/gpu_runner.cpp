#include "runner.h"
#include "check_sig.h"
#include "abi_bridge_executors.h"
#include "nlohmann/json.hpp"

using namespace std;

int GPU_MFORM_BITS = 0;

FheTaskGpu::FheTaskGpu(const std::string& project_path) : FheTask{project_path} {
    task_handle = create_fhe_gpu_task(project_path.c_str());
    bind_abi_executors(GPU_MFORM_BITS);
}

FheTaskGpu::~FheTaskGpu() {
    release_fhe_gpu_task(task_handle);
}

void FheTaskGpu::bind_abi_executors(int mf_nbits) {
    ExecutorFunc abi_export = create_seal_abi_export_executor(mf_nbits);
    ExecutorFunc abi_import = create_seal_abi_import_executor();

    bind_gpu_task_abi_bridge_executors(task_handle, reinterpret_cast<void*>(&abi_export),
                                       reinterpret_cast<void*>(&abi_import));
}

uint64_t FheTaskGpu::run(seal::SEALContext* context,
                         const seal::RelinKeys* rlk,
                         const seal::GaloisKeys* glk,
                         const std::vector<SealVectorArgument>& args) {
    int n_in_args = 0, n_out_args = 0;
    n_in_args = check_signatures(context, *rlk, *glk, args, _task_signature);
    n_out_args = args.size() - n_in_args;

    // Check parameter
    check_parameter(context, _param_json);

    nlohmann::json key_signature = _task_signature["key"];

    auto& params = context->key_context_data()->parms();
    auto scheme = params.scheme();
    uint64_t param_id = set_parameter(params);
    set_seal_context(context, param_id);

    new_args(n_in_args, n_out_args);

    export_arguments(args, input_args, output_args);

    export_public_keys(rlk, glk, key_signature, input_args);

    int ret =
        run_fhe_gpu_task(task_handle, input_args.data(), input_args.size(), output_args.data(), output_args.size());

    clear_seal_context();

    if (ret != 0) {
        throw std::runtime_error("Failed to run GPU project");
    }

    return 0;
}

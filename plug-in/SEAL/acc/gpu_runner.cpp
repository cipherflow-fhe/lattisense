#include "runner.h"
#include "nlohmann/json.hpp"

using namespace std;

int GPU_MFORM_BITS = 0;

FheTaskGpu::FheTaskGpu(const std::string& project_path) : FheTask{project_path} {
    task_handle = create_fhe_gpu_task(project_path.c_str());
}

FheTaskGpu::~FheTaskGpu() {
    release_fhe_gpu_task(task_handle);
}

uint64_t FheTaskGpu::run(seal::SEALContext* context,
                         const seal::RelinKeys* rlk,
                         const seal::GaloisKeys* glk,
                         const std::vector<SealVectorArgument>& args) {
    int n_in_args = 0, n_out_args = 0;
    n_in_args = check_signatures(context, *rlk, *glk, args, _task_signature, true);
    n_out_args = args.size() - n_in_args;

    // Check parameter
    check_parameter(context, _param_json);

    nlohmann::json key_signature = _task_signature["key"];

    auto& params = context->key_context_data()->parms();
    int N = params.poly_modulus_degree();
    auto scheme = params.scheme();
    auto& key_context_data = *context->key_context_data();
    auto ntt_tables = iter(key_context_data.small_ntt_tables());

    Algo algo;
    if (scheme == seal::scheme_type::bfv) {
        algo = Algo::ALGO_BFV;
    } else if (scheme == seal::scheme_type::ckks) {
        algo = Algo::ALGO_CKKS;
    } else {
        throw std::runtime_error("context type error");
    }

    uint64_t param_id = set_parameter(params);

    new_args(n_in_args, n_out_args);

    export_arguments(args, input_args, output_args, ntt_tables, N, param_id);

    export_public_keys(rlk, glk, key_signature, input_args, param_id, params.scheme(), ntt_tables, GPU_MFORM_BITS);

    fhe_task_handle task_handle = create_fhe_gpu_task(_project_path.c_str());
    int ret = run_fhe_gpu_task(task_handle, input_args.data(), input_args.size(), output_args.data(),
                               output_args.size(), algo);
    if (ret != 0) {
        throw std::runtime_error("Failed to run GPU project");
    }

    import_arguments(args, n_in_args, output_args, ntt_tables, N, param_id);

    return 0;
}
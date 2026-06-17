#include "runner.h"

FheTask::FheTask(const std::string& project_path) : _project_path{project_path} {
    std::ifstream sig_file;
    std::string sig_file_path = _project_path + "/task_signature.json";
    sig_file.open(sig_file_path);
    if (!sig_file.is_open()) {
        throw std::runtime_error("Cannot open task signature file " + sig_file_path);
    }
    _task_signature = nlohmann::json::parse(sig_file);
    sig_file.close();

    std::ifstream param_file;
    std::string param_file_path = _project_path + "/fhe_parameter.json";
    param_file.open(param_file_path);
    if (!param_file.is_open()) {
        throw std::runtime_error("Cannot open fhe_parameter file " + param_file_path);
    }
    _param_json = nlohmann::json::parse(param_file);
}

FheTask::~FheTask() {
    free_args();
}

void FheTask::new_args(int n_in_args, int n_out_args) {
    free_args();
    input_args.resize(n_in_args, CArgument{});
    output_args.resize(n_out_args, CArgument{});
}

void FheTask::free_args() {
    for (auto& arg : input_args) {
        free(arg.data);
        arg.data = nullptr;
    }
    for (auto& arg : output_args) {
        free(arg.data);
        arg.data = nullptr;
    }
    input_args.clear();
    output_args.clear();
}

uint64_t FheTask::set_parameter(const seal::EncryptionParameters& params) {
    seal::Modulus special_prime = params.coeff_modulus().back();
    int N = params.poly_modulus_degree();

    std::vector<uint64_t> q, p;
    for (const auto& modulus : params.coeff_modulus()) {
        if (modulus != special_prime) {
            q.push_back(modulus.value());
        } else {
            p.push_back(modulus.value());
        }
    }

    uint64_t id;
    if (params.scheme() == seal::scheme_type::bfv) {
        uint64_t t = params.plain_modulus().value();
        id = c_set_bfv_parameter(N, t, q.data(), q.size(), p.data(), p.size());
    } else {
        id = c_set_ckks_parameter(N, q.data(), q.size(), p.data(), p.size());
    }
    return id;
}
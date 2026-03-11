#include "runner.h"

FheTask::FheTask(const std::string& project_path) : _project_path{project_path} {
    std::ifstream sig_file;
    sig_file.open(_project_path + "/task_signature.json");
    _task_signature = nlohmann::json::parse(sig_file);
    sig_file.close();

    // Load mega_ag.json for parameter checking
    std::ifstream mega_ag_file;
    mega_ag_file.open(_project_path + "/mega_ag.json");
    nlohmann::json mega_ag_json = nlohmann::json::parse(mega_ag_file);
    mega_ag_file.close();
    _param_json = mega_ag_json["parameter"];
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
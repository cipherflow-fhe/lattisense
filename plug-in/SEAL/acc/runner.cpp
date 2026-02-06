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
    input_args.resize(n_in_args);
    output_args.resize(n_out_args);
}

void FheTask::free_args() {
    for (int i = 0; i < input_args.size(); i++) {
        for (int j = 0; j < input_args[i].size; j++) {
            switch (input_args[i].type) {
                case DataType::TYPE_CIPHERTEXT: free_ciphertext(&((CCiphertext*)input_args[i].data)[j], false); break;
                case DataType::TYPE_PLAINTEXT: free_plaintext(&((CPlaintext*)input_args[i].data)[j], false); break;
                case DataType::TYPE_RELIN_KEY: free_relin_key(&((CRelinKey*)input_args[i].data)[j], false); break;
                case DataType::TYPE_GALOIS_KEY: free_galois_key(&((CGaloisKey*)input_args[i].data)[j], false); break;
            }
        }
    }
    input_args.clear();

    for (int i = 0; i < output_args.size(); i++) {
        for (int j = 0; j < output_args[i].size; j++) {
            switch (output_args[i].type) {
                case DataType::TYPE_CIPHERTEXT: free_ciphertext(&((CCiphertext*)output_args[i].data)[j], false); break;
                default: throw std::runtime_error("Unsupported output type");
            }
        }
    }
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
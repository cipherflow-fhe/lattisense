#include "runner.h"
#include <stdexcept>

static std::map<SealArgumentType, std::string> seal_argument_type_str_map = {
    {SealArgumentType::RELIN_KEY, "rlk"},
    {SealArgumentType::GALOIS_KEY, "glk"},
    {SealArgumentType::PLAINTEXT, "pt"},
    {SealArgumentType::CIPHERTEXT, "ct"},
};

static std::map<std::string, SealArgumentType> str_seal_argument_type_map = {
    {"rlk", SealArgumentType::RELIN_KEY},      {"glk", SealArgumentType::GALOIS_KEY},
    {"pt_ringt", SealArgumentType::PLAINTEXT}, {"pt", SealArgumentType::PLAINTEXT},
    {"ct", SealArgumentType::CIPHERTEXT},
};

static void check_with_sig(const SealVectorArgument& seal_arg,
                           const std::string& expected_id,
                           SealArgumentType expected_type,
                           const std::vector<size_t>& expected_shape,
                           int expected_level) {
    if (seal_arg.arg_id != expected_id) {
        std::string message = "For argument " + seal_arg.arg_id + ", expected id is " + expected_id +
                              ", but input id is " + seal_arg.arg_id + ".";
        throw std::runtime_error(message);
    }

    if (seal_arg.type != expected_type) {
        std::string message = "For argument " + seal_arg.arg_id + ", expected type is " +
                              seal_argument_type_str_map[expected_type] + ", but input type is " +
                              seal_argument_type_str_map[seal_arg.type] + ".";
        throw std::runtime_error(message);
    }

    int expected_size = 1;
    for (auto x : expected_shape) {
        expected_size *= x;
    }
    if (seal_arg.flat_data.size() != expected_size) {
        std::string message = "For argument " + seal_arg.arg_id + ", expected size is " +
                              std::to_string(expected_size) + ", but input size is " +
                              std::to_string(seal_arg.flat_data.size()) + ".";
        throw std::runtime_error(message);
    }

    if (seal_arg.level != expected_level) {
        std::string message = "For argument " + seal_arg.arg_id + ", expected level is " +
                              std::to_string(expected_level) + ", but input level is " +
                              std::to_string(seal_arg.level) + ".";
        throw std::runtime_error(message);
    }
}

static void
check_key_signatures(const seal::RelinKeys& rlk, const seal::GaloisKeys& glk, const nlohmann::json& key_signature) {
    int rlk_level_sig = key_signature["rlk"].get<int>();
    if (rlk_level_sig >= 0) {
        int rlk_level = rlk.key(2)[0].data().coeff_modulus_size() - 1;
        if (rlk_level_sig > rlk_level) {
            throw std::runtime_error("Level of relin key is smaller than the expected level.");
        }
    }

    if (!key_signature["glk"].empty()) {
        for (auto& item : key_signature["glk"].items()) {
            uint64_t gal_el = stoul(item.key());
            int glk_level_sig = item.value().get<int>();
            auto& ksk = glk.key(gal_el);
            int ksk_level = ksk[0].data().coeff_modulus_size() - 1;
            if (glk_level_sig > ksk_level) {
                throw std::runtime_error("Level of Galois key is smaller than the expected level.");
            }
        }
    }
}

void check_parameter(seal::SEALContext* context, const nlohmann::json& param_json) {
    if (!param_json.contains("n")) {
        throw std::runtime_error("Parameter JSON missing 'n' field");
    }
    if (!param_json.contains("q")) {
        throw std::runtime_error("Parameter JSON missing 'q' field");
    }

    int expected_n = param_json["n"].get<int>();
    std::vector<uint64_t> expected_q = param_json["q"].get<std::vector<uint64_t>>();

    auto& params = context->key_context_data()->parms();
    int actual_n = params.poly_modulus_degree();

    if (actual_n != expected_n) {
        throw std::runtime_error("Parameter N mismatch: expected " + std::to_string(expected_n) + ", got " +
                                 std::to_string(actual_n));
    }

    if (params.scheme() == seal::scheme_type::bfv) {
        // Check t for BFV
        if (param_json.contains("t")) {
            uint64_t expected_t = param_json["t"].get<uint64_t>();
            uint64_t actual_t = params.plain_modulus().value();
            if (actual_t != expected_t) {
                throw std::runtime_error("BFV parameter t mismatch: expected " + std::to_string(expected_t) + ", got " +
                                         std::to_string(actual_t));
            }
        }
    }

    // Check Q moduli
    auto& coeff_modulus = params.coeff_modulus();

    // Separate Q and P moduli (last modulus is special prime P)
    int q_count = coeff_modulus.size();
    int p_count = 0;

    if (param_json.contains("p")) {
        std::vector<uint64_t> expected_p = param_json["p"].get<std::vector<uint64_t>>();
        p_count = expected_p.size();
        q_count = coeff_modulus.size() - p_count;

        // Check Q count
        if (q_count != expected_q.size()) {
            throw std::runtime_error("Parameter Q count mismatch: expected " + std::to_string(expected_q.size()) +
                                     ", got " + std::to_string(q_count));
        }

        // Check each Q value
        for (int i = 0; i < expected_q.size(); i++) {
            if (coeff_modulus[i].value() != expected_q[i]) {
                throw std::runtime_error("Parameter Q[" + std::to_string(i) + "] mismatch: expected " +
                                         std::to_string(expected_q[i]) + ", got " +
                                         std::to_string(coeff_modulus[i].value()));
            }
        }

        // Check P count
        if (p_count != expected_p.size()) {
            throw std::runtime_error("Parameter P count mismatch: expected " + std::to_string(expected_p.size()) +
                                     ", got " + std::to_string(p_count));
        }

        // Check each P value
        for (int i = 0; i < expected_p.size(); i++) {
            if (coeff_modulus[q_count + i].value() != expected_p[i]) {
                throw std::runtime_error("Parameter P[" + std::to_string(i) + "] mismatch: expected " +
                                         std::to_string(expected_p[i]) + ", got " +
                                         std::to_string(coeff_modulus[q_count + i].value()));
            }
        }
    } else {
        // No P specified, all moduli are Q
        if (coeff_modulus.size() != expected_q.size()) {
            throw std::runtime_error("Parameter Q count mismatch: expected " + std::to_string(expected_q.size()) +
                                     ", got " + std::to_string(coeff_modulus.size()));
        }

        for (int i = 0; i < expected_q.size(); i++) {
            if (coeff_modulus[i].value() != expected_q[i]) {
                throw std::runtime_error("Parameter Q[" + std::to_string(i) + "] mismatch: expected " +
                                         std::to_string(expected_q[i]) + ", got " +
                                         std::to_string(coeff_modulus[i].value()));
            }
        }
    }
}

int check_signatures(seal::SEALContext* context,
                     const seal::RelinKeys& rlk,
                     const seal::GaloisKeys& glk,
                     const std::vector<SealVectorArgument>& seal_args,
                     const nlohmann::json& task_sig_json,
                     bool online_phase) {
    int algo;
    if (context->key_context_data()->parms().scheme() == seal::scheme_type::bfv) {
        algo = 0;
        if (task_sig_json["algorithm"] != "BFV") {
            throw std::runtime_error("algo error");
        }
    } else if (context->key_context_data()->parms().scheme() == seal::scheme_type::ckks) {
        algo = 1;
        if (task_sig_json["algorithm"] != "CKKS") {
            throw std::runtime_error("algo error");
        }
    } else {
        throw std::runtime_error("context type error");
    }

    check_key_signatures(rlk, glk, task_sig_json["key"]);

    auto data_sig_json = online_phase ? task_sig_json["online"].get<std::vector<nlohmann::json>>() :
                                        task_sig_json["offline"].get<std::vector<nlohmann::json>>();

    int n_in_args = 0;

    for (int i = 0; i < seal_args.size(); i++) {
        std::string expected_id = data_sig_json[i]["id"].get<std::string>();
        SealArgumentType expected_type = str_seal_argument_type_map[data_sig_json[i]["type"].get<std::string>()];
        std::vector<uint64_t> expected_shape = data_sig_json[i]["size"].get<std::vector<uint64_t>>();
        int expected_level = data_sig_json[i]["level"].get<int>();
        check_with_sig(seal_args[i], expected_id, expected_type, expected_shape, expected_level);

        std::string phase = data_sig_json[i]["phase"].get<std::string>();
        if (phase == "in" or phase == "offline") {
            n_in_args++;
        }
    }

    return n_in_args;
}

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

#include "precision.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace fhe_ops_lib {

std::string PrecisionStats::toString() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    oss << "\n┌─────────┬───────┬───────┬───────┐\n";
    oss << "│    Log2 │ REAL  │ IMAG  │ L2    │\n";
    oss << "├─────────┼───────┼───────┼───────┤\n";
    oss << "│MIN Prec │ " << std::setw(5) << MINLog2Prec.Real << " │ " << std::setw(5) << MINLog2Prec.Imag << " │ "
        << std::setw(5) << MINLog2Prec.L2 << " │\n";
    oss << "│MAX Prec │ " << std::setw(5) << MAXLog2Prec.Real << " │ " << std::setw(5) << MAXLog2Prec.Imag << " │ "
        << std::setw(5) << MAXLog2Prec.L2 << " │\n";
    oss << "│AVG Prec │ " << std::setw(5) << AVGLog2Prec.Real << " │ " << std::setw(5) << AVGLog2Prec.Imag << " │ "
        << std::setw(5) << AVGLog2Prec.L2 << " │\n";
    oss << "│MED Prec │ " << std::setw(5) << MEDLog2Prec.Real << " │ " << std::setw(5) << MEDLog2Prec.Imag << " │ "
        << std::setw(5) << MEDLog2Prec.L2 << " │\n";
    oss << "│STD Prec │ " << std::setw(5) << STDLog2Prec.Real << " │ " << std::setw(5) << STDLog2Prec.Imag << " │ "
        << std::setw(5) << STDLog2Prec.L2 << " │\n";
    oss << "├─────────┼───────┼───────┼───────┤\n";
    oss << "│MIN Err  │ " << std::setw(5) << MINLog2Err.Real << " │ " << std::setw(5) << MINLog2Err.Imag << " │ "
        << std::setw(5) << MINLog2Err.L2 << " │\n";
    oss << "│MAX Err  │ " << std::setw(5) << MAXLog2Err.Real << " │ " << std::setw(5) << MAXLog2Err.Imag << " │ "
        << std::setw(5) << MAXLog2Err.L2 << " │\n";
    oss << "│AVG Err  │ " << std::setw(5) << AVGLog2Err.Real << " │ " << std::setw(5) << AVGLog2Err.Imag << " │ "
        << std::setw(5) << AVGLog2Err.L2 << " │\n";
    oss << "│MED Err  │ " << std::setw(5) << MEDLog2Err.Real << " │ " << std::setw(5) << MEDLog2Err.Imag << " │ "
        << std::setw(5) << MEDLog2Err.L2 << " │\n";
    oss << "│STD Err  │ " << std::setw(5) << STDLog2Err.Real << " │ " << std::setw(5) << STDLog2Err.Imag << " │ "
        << std::setw(5) << STDLog2Err.L2 << " │\n";
    oss << "└─────────┴───────┴───────┴───────┘\n";
    return oss.str();
}

void PrecisionStats::calcCDF(const std::vector<double>& precs, std::vector<DistEntry>& res) {
    std::vector<double> sorted_precs = precs;
    std::sort(sorted_precs.begin(), sorted_precs.end());

    if (sorted_precs.empty()) {
        res.clear();
        return;
    }

    const double min_prec = sorted_precs.front();
    const double max_prec = sorted_precs.back();
    res.assign(cdfResol, DistEntry{});

    for (int i = 0; i < cdfResol; i++) {
        const double cur_prec =
            min_prec + static_cast<double>(i) * (max_prec - min_prec) / static_cast<double>(cdfResol);
        for (int count_smaller = 0; count_smaller < static_cast<int>(sorted_precs.size()); count_smaller++) {
            if (sorted_precs[count_smaller] >= cur_prec) {
                res[i].Prec = cur_prec;
                res[i].Count = count_smaller;
                break;
            }
        }
    }
}

PrecisionStats PrecisionAnalyzer::GetPrecisionStats(CkksContext& context,
                                                    const std::vector<double>& vWant,
                                                    const CkksPlaintext& element,
                                                    bool compute_cdf) {
    std::vector<double> values_test;
    context.decode(element, values_test);
    return GetPrecisionStats(vWant, values_test, context.parameter().log_default_scale(), compute_cdf);
}

PrecisionStats PrecisionAnalyzer::GetPrecisionStats(CkksContext& context,
                                                    const std::vector<double>& vWant,
                                                    const CkksCiphertext& element,
                                                    bool compute_cdf) {
    CkksPlaintext decrypted_plain = context.decrypt(element);
    std::vector<double> values_test;
    context.decode(decrypted_plain, values_test);
    return GetPrecisionStats(vWant, values_test, context.parameter().log_default_scale(), compute_cdf);
}

PrecisionStats PrecisionAnalyzer::GetPrecisionStats(CkksContext& context,
                                                    const std::vector<std::complex<double>>& vWant,
                                                    const CkksPlaintext& element,
                                                    bool compute_cdf) {
    std::vector<std::complex<double>> values_test;
    context.decode(element, values_test);
    return GetPrecisionStats(vWant, values_test, context.parameter().log_default_scale(), compute_cdf);
}

PrecisionStats PrecisionAnalyzer::GetPrecisionStats(CkksContext& context,
                                                    const std::vector<std::complex<double>>& vWant,
                                                    const CkksCiphertext& element,
                                                    bool compute_cdf) {
    CkksPlaintext decrypted_plain = context.decrypt(element);
    std::vector<std::complex<double>> values_test;
    context.decode(decrypted_plain, values_test);
    return GetPrecisionStats(vWant, values_test, context.parameter().log_default_scale(), compute_cdf);
}

PrecisionStats PrecisionAnalyzer::GetPrecisionStats(const std::vector<double>& vWant,
                                                    const std::vector<double>& vTest,
                                                    double log2_scale,
                                                    bool compute_cdf) {
    std::vector<std::complex<double>> complex_want;
    std::vector<std::complex<double>> complex_test;
    complex_want.reserve(vWant.size());
    complex_test.reserve(vTest.size());

    for (double value : vWant) {
        complex_want.emplace_back(value, 0.0);
    }

    for (double value : vTest) {
        complex_test.emplace_back(value, 0.0);
    }

    return GetPrecisionStats(complex_want, complex_test, log2_scale, compute_cdf);
}

PrecisionStats PrecisionAnalyzer::GetPrecisionStats(const std::vector<std::complex<double>>& vWant,
                                                    const std::vector<std::complex<double>>& vTest,
                                                    double log2_scale,
                                                    bool compute_cdf) {
    if (vWant.size() != vTest.size()) {
        throw std::invalid_argument("input vectors must have the same size");
    }

    if (vWant.empty()) {
        throw std::invalid_argument("input vectors must not be empty");
    }

    PrecisionStats prec;
    prec.Log2Scale = log2_scale;

    const double slots = static_cast<double>(vWant.size());
    std::vector<double> log2_prec_real(vWant.size());
    std::vector<double> log2_prec_imag(vWant.size());
    std::vector<double> log2_prec_l2(vWant.size());

    double log2_avg_prec_real = 0.0;
    double log2_avg_prec_imag = 0.0;
    double log2_avg_prec_l2 = 0.0;
    double log2_max_prec_real = 0.0;
    double log2_max_prec_imag = 0.0;
    double log2_max_prec_l2 = 0.0;
    double log2_min_prec_real = 1e10;
    double log2_min_prec_imag = 1e10;
    double log2_min_prec_l2 = 1e10;
    double log2_std_prec_real = 0.0;
    double log2_std_prec_imag = 0.0;
    double log2_std_prec_l2 = 0.0;

    for (size_t i = 0; i < vWant.size(); i++) {
        const double err_real = vTest[i].real() - vWant[i].real();
        const double err_imag = vTest[i].imag() - vWant[i].imag();
        const double err_l2 = std::sqrt(err_real * err_real + err_imag * err_imag);

        log2_prec_real[i] = log2Precision(err_real, log2_scale);
        log2_prec_imag[i] = log2Precision(err_imag, log2_scale);
        log2_prec_l2[i] = log2Precision(err_l2, log2_scale);

        log2_avg_prec_real += log2_prec_real[i];
        log2_avg_prec_imag += log2_prec_imag[i];
        log2_avg_prec_l2 += log2_prec_l2[i];

        log2_max_prec_real = std::max(log2_max_prec_real, log2_prec_real[i]);
        log2_max_prec_imag = std::max(log2_max_prec_imag, log2_prec_imag[i]);
        log2_max_prec_l2 = std::max(log2_max_prec_l2, log2_prec_l2[i]);

        log2_min_prec_real = std::min(log2_min_prec_real, log2_prec_real[i]);
        log2_min_prec_imag = std::min(log2_min_prec_imag, log2_prec_imag[i]);
        log2_min_prec_l2 = std::min(log2_min_prec_l2, log2_prec_l2[i]);
    }

    log2_avg_prec_real /= slots;
    log2_avg_prec_imag /= slots;
    log2_avg_prec_l2 /= slots;

    for (double value : log2_prec_real) {
        const double centered = value - log2_avg_prec_real;
        log2_std_prec_real += centered * centered;
    }

    for (double value : log2_prec_imag) {
        const double centered = value - log2_avg_prec_imag;
        log2_std_prec_imag += centered * centered;
    }

    for (double value : log2_prec_l2) {
        const double centered = value - log2_avg_prec_l2;
        log2_std_prec_l2 += centered * centered;
    }

    const double std_denominator = slots > 1.0 ? slots - 1.0 : 1.0;

    prec.MINLog2Prec = Stats{log2_min_prec_real, log2_min_prec_imag, log2_min_prec_l2};
    prec.MAXLog2Prec = Stats{std::min(log2_max_prec_real, log2_scale), std::min(log2_max_prec_imag, log2_scale),
                             std::min(log2_max_prec_l2, log2_scale)};
    prec.AVGLog2Prec = Stats{log2_avg_prec_real, log2_avg_prec_imag, log2_avg_prec_l2};
    prec.MEDLog2Prec = Stats{calcMedian(log2_prec_real), calcMedian(log2_prec_imag), calcMedian(log2_prec_l2)};
    prec.STDLog2Prec =
        Stats{std::sqrt(log2_std_prec_real / std_denominator), std::sqrt(log2_std_prec_imag / std_denominator),
              std::sqrt(log2_std_prec_l2 / std_denominator)};

    prec.MAXLog2Err =
        Stats{log2_scale - prec.MINLog2Prec.Real, log2_scale - prec.MINLog2Prec.Imag, log2_scale - prec.MINLog2Prec.L2};
    prec.MINLog2Err =
        Stats{log2_scale - prec.MAXLog2Prec.Real, log2_scale - prec.MAXLog2Prec.Imag, log2_scale - prec.MAXLog2Prec.L2};
    prec.AVGLog2Err =
        Stats{log2_scale - prec.AVGLog2Prec.Real, log2_scale - prec.AVGLog2Prec.Imag, log2_scale - prec.AVGLog2Prec.L2};
    prec.MEDLog2Err =
        Stats{log2_scale - prec.MEDLog2Prec.Real, log2_scale - prec.MEDLog2Prec.Imag, log2_scale - prec.MEDLog2Prec.L2};
    prec.STDLog2Err = prec.STDLog2Prec;

    if (compute_cdf) {
        prec.cdfResol = 500;
        prec.calcCDF(log2_prec_real, prec.RealDist);
        prec.calcCDF(log2_prec_imag, prec.ImagDist);
        prec.calcCDF(log2_prec_l2, prec.L2Dist);
    }

    return prec;
}

double PrecisionAnalyzer::calcMedian(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    const size_t index = values.size() / 2;
    if ((values.size() & 1) == 1 || index + 1 == values.size()) {
        return values[index];
    }
    return (values[index - 1] + values[index]) / 2.0;
}

double PrecisionAnalyzer::log2Precision(double err, double log2_scale) {
    double value = -std::log2(std::abs(err));
    if (std::isinf(value)) {
        value = log2_scale;
    }
    return value;
}

}  // namespace fhe_ops_lib

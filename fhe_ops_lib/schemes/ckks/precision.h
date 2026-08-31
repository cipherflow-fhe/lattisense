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

#ifndef CKKS_PRECISION_H
#define CKKS_PRECISION_H

#include <complex>
#include <string>
#include <vector>

#include "ckks.h"

namespace fhe_ops_lib {

struct Stats {
    double Real = 0.0;
    double Imag = 0.0;
    double L2 = 0.0;
};

struct DistEntry {
    double Prec = 0.0;
    int Count = 0;
};

struct PrecisionStats {
    Stats MINLog2Prec;
    Stats MAXLog2Prec;
    Stats AVGLog2Prec;
    Stats MEDLog2Prec;
    Stats STDLog2Prec;

    Stats MINLog2Err;
    Stats MAXLog2Err;
    Stats AVGLog2Err;
    Stats MEDLog2Err;
    Stats STDLog2Err;

    double Log2Scale = 0.0;

    std::vector<DistEntry> RealDist;
    std::vector<DistEntry> ImagDist;
    std::vector<DistEntry> L2Dist;

    int cdfResol = 500;

    std::string toString() const;

    void calcCDF(const std::vector<double>& precs, std::vector<DistEntry>& res);
};

class PrecisionAnalyzer {
public:
    static PrecisionStats GetPrecisionStats(CkksContext& context,
                                            const std::vector<double>& vWant,
                                            const CkksPlaintext& element,
                                            bool compute_cdf = false);

    static PrecisionStats GetPrecisionStats(CkksContext& context,
                                            const std::vector<double>& vWant,
                                            const CkksCiphertext& element,
                                            bool compute_cdf = false);

    static PrecisionStats GetPrecisionStats(CkksContext& context,
                                            const std::vector<std::complex<double>>& vWant,
                                            const CkksPlaintext& element,
                                            bool compute_cdf = false);

    static PrecisionStats GetPrecisionStats(CkksContext& context,
                                            const std::vector<std::complex<double>>& vWant,
                                            const CkksCiphertext& element,
                                            bool compute_cdf = false);

    static PrecisionStats GetPrecisionStats(const std::vector<double>& vWant,
                                            const std::vector<double>& vTest,
                                            double log2_scale = 40.0,
                                            bool compute_cdf = false);

    static PrecisionStats GetPrecisionStats(const std::vector<std::complex<double>>& vWant,
                                            const std::vector<std::complex<double>>& vTest,
                                            double log2_scale = 40.0,
                                            bool compute_cdf = false);

private:
    static double calcMedian(std::vector<double> values);
    static double log2Precision(double err, double log2_scale);
};

}  // namespace fhe_ops_lib

#endif  // CKKS_PRECISION_H

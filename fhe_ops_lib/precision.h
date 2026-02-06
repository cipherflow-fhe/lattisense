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

#ifndef PRECISION_H
#define PRECISION_H

#include <vector>
#include <string>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "fhe_lib_v2.h"

namespace fhe_ops_lib {

/**
 * @brief Stats structure for storing precision statistics of complex values including real part, imaginary part, and L2
 * norm
 */
struct Stats {
    double Real, Imag, L2;

    Stats() : Real(0.0), Imag(0.0), L2(0.0) {}
    Stats(double real, double imag, double l2) : Real(real), Imag(imag), L2(l2) {}
};

/**
 * @brief Distribution entry structure
 */
struct DistEntry {
    double Prec;
    int Count;

    DistEntry() : Prec(0.0), Count(0) {}
    DistEntry(double prec, int count) : Prec(prec), Count(count) {}
};

/**
 * @brief PrecisionStats structure for storing comprehensive precision statistics of CKKS plaintext
 */
struct PrecisionStats {
    Stats MaxDelta;
    Stats MinDelta;
    Stats MaxPrecision;
    Stats MinPrecision;
    Stats MeanDelta;
    Stats MeanPrecision;
    Stats MedianDelta;
    Stats MedianPrecision;
    double STDFreq;
    double STDTime;

    std::vector<DistEntry> RealDist, ImagDist, L2Dist;
    int cdfResol;

    PrecisionStats() : STDFreq(0.0), STDTime(0.0), cdfResol(500) {}

    /**
     * @brief Return a formatted string representation of precision statistics
     */
    std::string toString() const;

    /**
     * @brief Calculate cumulative distribution function
     */
    void calcCDF(const std::vector<double>& precs, std::vector<DistEntry>& res);
};

/**
 * @brief PrecisionAnalyzer class providing CKKS precision analysis functionality
 */
class PrecisionAnalyzer {
public:
    /**
     * @brief Analyze CKKS plaintext precision statistics
     * @param context CKKS context
     * @param vWant Vector of expected values
     * @param element Plaintext to analyze
     * @param logSlots Logarithm of the number of slots
     * @param sigma Noise parameter
     * @return Precision statistics
     */
    static PrecisionStats GetPrecisionStats(CkksContext& context,
                                            const std::vector<double>& vWant,
                                            const CkksPlaintext& element,
                                            int logSlots,
                                            double sigma = 3.2);

    /**
     * @brief Analyze CKKS ciphertext precision statistics
     * @param context CKKS context
     * @param vWant Vector of expected values
     * @param element Ciphertext to analyze
     * @param logSlots Logarithm of the number of slots
     * @param sigma Noise parameter
     * @return Precision statistics
     */
    static PrecisionStats GetPrecisionStats(CkksContext& context,
                                            const std::vector<double>& vWant,
                                            const CkksCiphertext& element,
                                            int logSlots,
                                            double sigma = 3.2);

    /**
     * @brief Analyze precision statistics between two vectors
     * @param vWant Vector of expected values
     * @param vTest Vector of test values
     * @param logSlots Logarithm of the number of slots
     * @param sigma Noise parameter
     * @return Precision statistics
     */
    static PrecisionStats GetPrecisionStats(const std::vector<double>& vWant,
                                            const std::vector<double>& vTest,
                                            int logSlots,
                                            double sigma = 3.2);

private:
    /**
     * @brief Core implementation of precision statistics computation
     */
    static PrecisionStats GetPrecisionStatsImpl(const std::vector<double>& vWant,
                                                const std::vector<double>& vTest,
                                                int logSlots,
                                                double sigma);

    /**
     * @brief Convert delta values to precision values (log2(1/delta))
     */
    static Stats deltaToPrecision(const Stats& delta);

    /**
     * @brief Calculate median statistics
     */
    static Stats calcMedian(const std::vector<Stats>& values);

    /**
     * @brief Calculate error standard deviation
     */
    static double calculateErrorSTD(const std::vector<double>& wanted, const std::vector<double>& test, double scale);
};

}  // namespace fhe_ops_lib

#endif  // PRECISION_H
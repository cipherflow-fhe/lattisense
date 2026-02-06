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
#include "fhe_lib_v2.h"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace fhe_ops_lib {

std::string PrecisionStats::toString() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    oss << "\n┌─────────┬───────┬───────┬───────┐\n";
    oss << "│    Log2 │ REAL  │ IMAG  │ L2    │\n";
    oss << "├─────────┼───────┼───────┼───────┤\n";
    oss << "│MIN Prec │ " << std::setw(5) << MinPrecision.Real << " │ " << std::setw(5) << MinPrecision.Imag << " │ "
        << std::setw(5) << MinPrecision.L2 << " │\n";
    oss << "│MAX Prec │ " << std::setw(5) << MaxPrecision.Real << " │ " << std::setw(5) << MaxPrecision.Imag << " │ "
        << std::setw(5) << MaxPrecision.L2 << " │\n";
    oss << "│AVG Prec │ " << std::setw(5) << MeanPrecision.Real << " │ " << std::setw(5) << MeanPrecision.Imag << " │ "
        << std::setw(5) << MeanPrecision.L2 << " │\n";
    oss << "│MED Prec │ " << std::setw(5) << MedianPrecision.Real << " │ " << std::setw(5) << MedianPrecision.Imag
        << " │ " << std::setw(5) << MedianPrecision.L2 << " │\n";
    oss << "└─────────┴───────┴───────┴───────┘\n";
    oss << "Err STD Slots  : " << std::setw(5) << std::log2(STDFreq) << " Log2\n";
    oss << "Err STD Coeffs : " << std::setw(5) << std::log2(STDTime) << " Log2\n";

    return oss.str();
}

void PrecisionStats::calcCDF(const std::vector<double>& precs, std::vector<DistEntry>& res) {
    std::vector<double> sortedPrecs = precs;
    std::sort(sortedPrecs.begin(), sortedPrecs.end());

    if (sortedPrecs.empty())
        return;

    double minPrec = sortedPrecs[0];
    double maxPrec = sortedPrecs[sortedPrecs.size() - 1];

    res.resize(cdfResol);

    for (int i = 0; i < cdfResol; i++) {
        double curPrec = minPrec + static_cast<double>(i) * (maxPrec - minPrec) / static_cast<double>(cdfResol);

        int countSmaller = 0;
        for (double p : sortedPrecs) {
            if (p >= curPrec) {
                break;
            }
            countSmaller++;
        }

        res[i].Prec = curPrec;
        res[i].Count = countSmaller;
    }
}

// PrecisionAnalyzer implementation
PrecisionStats PrecisionAnalyzer::GetPrecisionStats(CkksContext& context,
                                                    const std::vector<double>& vWant,
                                                    const CkksPlaintext& element,
                                                    int logSlots,
                                                    double sigma) {
    // Decode plaintext to get test values
    std::vector<double> valuesTest = context.decode(element);

    return GetPrecisionStatsImpl(vWant, valuesTest, logSlots, sigma);
}

PrecisionStats PrecisionAnalyzer::GetPrecisionStats(CkksContext& context,
                                                    const std::vector<double>& vWant,
                                                    const CkksCiphertext& element,
                                                    int logSlots,
                                                    double sigma) {
    // Decrypt ciphertext then decode to get test values
    CkksPlaintext decryptedPlain = context.decrypt(element);
    std::vector<double> valuesTest = context.decode(decryptedPlain);

    return GetPrecisionStatsImpl(vWant, valuesTest, logSlots, sigma);
}

PrecisionStats PrecisionAnalyzer::GetPrecisionStats(const std::vector<double>& vWant,
                                                    const std::vector<double>& vTest,
                                                    int logSlots,
                                                    double sigma) {
    return GetPrecisionStatsImpl(vWant, vTest, logSlots, sigma);
}

PrecisionStats PrecisionAnalyzer::GetPrecisionStatsImpl(const std::vector<double>& vWant,
                                                        const std::vector<double>& vTest,
                                                        int logSlots,
                                                        double sigma) {
    PrecisionStats prec;

    if (vWant.size() != vTest.size()) {
        throw std::invalid_argument("Input vectors must have the same size");
    }

    size_t slots = vWant.size();
    std::vector<Stats> diff(slots);

    prec.MaxDelta = Stats(0, 0, 0);
    prec.MinDelta = Stats(1, 1, 1);
    prec.MeanDelta = Stats(0, 0, 0);

    prec.cdfResol = 500;

    std::vector<double> precReal(slots);
    std::vector<double> precImag(slots);
    std::vector<double> precL2(slots);

    for (size_t i = 0; i < slots; i++) {
        // For real values, imaginary part is 0
        double deltaReal = std::abs(vTest[i] - vWant[i]);
        double deltaImag = 0.0;      // Assuming we're processing real values
        double deltaL2 = deltaReal;  // For real numbers, L2 norm equals absolute value

        // Avoid log(0)
        deltaReal = std::max(deltaReal, 1e-16);
        deltaImag = std::max(deltaImag, 1e-16);
        deltaL2 = std::max(deltaL2, 1e-16);

        precReal[i] = std::log2(1.0 / deltaReal);
        precImag[i] = std::log2(1.0 / deltaImag);
        precL2[i] = std::log2(1.0 / deltaL2);

        diff[i].Real = deltaReal;
        diff[i].Imag = deltaImag;
        diff[i].L2 = deltaL2;

        prec.MeanDelta.Real += deltaReal;
        prec.MeanDelta.Imag += deltaImag;
        prec.MeanDelta.L2 += deltaL2;

        if (deltaReal > prec.MaxDelta.Real)
            prec.MaxDelta.Real = deltaReal;
        if (deltaImag > prec.MaxDelta.Imag)
            prec.MaxDelta.Imag = deltaImag;
        if (deltaL2 > prec.MaxDelta.L2)
            prec.MaxDelta.L2 = deltaL2;

        if (deltaReal < prec.MinDelta.Real)
            prec.MinDelta.Real = deltaReal;
        if (deltaImag < prec.MinDelta.Imag)
            prec.MinDelta.Imag = deltaImag;
        if (deltaL2 < prec.MinDelta.L2)
            prec.MinDelta.L2 = deltaL2;
    }

    prec.calcCDF(precReal, prec.RealDist);
    prec.calcCDF(precImag, prec.ImagDist);
    prec.calcCDF(precL2, prec.L2Dist);

    prec.MinPrecision = deltaToPrecision(prec.MaxDelta);
    prec.MaxPrecision = deltaToPrecision(prec.MinDelta);

    prec.MeanDelta.Real /= static_cast<double>(slots);
    prec.MeanDelta.Imag /= static_cast<double>(slots);
    prec.MeanDelta.L2 /= static_cast<double>(slots);
    prec.MeanPrecision = deltaToPrecision(prec.MeanDelta);

    prec.MedianDelta = calcMedian(diff);
    prec.MedianPrecision = deltaToPrecision(prec.MedianDelta);

    // Calculate standard deviation
    double defaultScale = std::pow(2.0, 40);  // Default scale
    prec.STDFreq = calculateErrorSTD(vWant, vTest, defaultScale);
    prec.STDTime = prec.STDFreq;  // For simplicity, use the same calculation

    return prec;
}

Stats PrecisionAnalyzer::deltaToPrecision(const Stats& delta) {
    return Stats(std::log2(1.0 / delta.Real), std::log2(1.0 / delta.Imag), std::log2(1.0 / delta.L2));
}

Stats PrecisionAnalyzer::calcMedian(const std::vector<Stats>& values) {
    if (values.empty())
        return Stats();

    // Sort real, imaginary, and L2 parts separately
    std::vector<double> realParts, imagParts, l2Parts;
    for (const auto& val : values) {
        realParts.push_back(val.Real);
        imagParts.push_back(val.Imag);
        l2Parts.push_back(val.L2);
    }

    std::sort(realParts.begin(), realParts.end());
    std::sort(imagParts.begin(), imagParts.end());
    std::sort(l2Parts.begin(), l2Parts.end());

    size_t index = values.size() / 2;

    if (values.size() % 2 == 1 || index + 1 == values.size()) {
        return Stats(realParts[index], imagParts[index], l2Parts[index]);
    }

    return Stats((realParts[index] + realParts[index + 1]) / 2.0, (imagParts[index] + imagParts[index + 1]) / 2.0,
                 (l2Parts[index] + l2Parts[index + 1]) / 2.0);
}

double
PrecisionAnalyzer::calculateErrorSTD(const std::vector<double>& wanted, const std::vector<double>& test, double scale) {
    if (wanted.size() != test.size() || wanted.empty())
        return 0.0;

    double sumSquaredError = 0.0;
    for (size_t i = 0; i < wanted.size(); i++) {
        double diff = wanted[i] - test[i];
        sumSquaredError += diff * diff;
    }

    return std::sqrt(sumSquaredError / wanted.size()) / scale;
}

}  // namespace fhe_ops_lib
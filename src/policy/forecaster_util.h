// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_FORECASTER_UTIL_H
#define BITCOIN_POLICY_FORECASTER_UTIL_H

#include <policy/feerate.h>

#include <optional>
#include <string>

enum class ForecastType {};

struct ForecastResult {
    struct ForecastOptions {
        CFeeRate low_priority_estimate{CFeeRate(0)};
        CFeeRate high_priority_estimate{CFeeRate(0)};
        unsigned int block_height{0};
        ForecastType forecaster;
    };

    ForecastOptions opt;
    std::optional<std::string> error_message;

    ForecastResult(ForecastResult::ForecastOptions& options, const std::optional<std::string> error_ptr)
        : opt(options), error_message(error_ptr) {}

    bool empty() const
    {
        return opt.low_priority_estimate == CFeeRate(0) && opt.high_priority_estimate == CFeeRate(0);
    }

    bool operator<(const ForecastResult& forecast) const
    {
        return opt.low_priority_estimate < forecast.opt.high_priority_estimate;
    }

    ~ForecastResult() = default;
};

#endif // BITCOIN_POLICY_FORECASTER_UTIL_H

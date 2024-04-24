// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license. See the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <policy/fee_estimator.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/forecaster.h>
#include <policy/forecaster_util.h>


void FeeEstimator::RegisterForecaster(std::shared_ptr<Forecaster> forecaster)
{
    forecasters.emplace(forecaster->m_forecastType, forecaster);
}

std::pair<ForecastResult, std::vector<std::string>> FeeEstimator::GetFeeEstimateFromForecasters(unsigned int targetBlocks)
{
    ForecastResult::ForecastOptions opts;
    ForecastResult forecast = ForecastResult(opts, std::nullopt);

    std::vector<std::string> err_messages;

    // TODO: Perform sanity checks; call forecasters and select the one.
    if (!forecast.empty()) {
        LogPrint(BCLog::ESTIMATEFEE, "FeeEst: Block height %s, low priority feerate %s %s/kvB, high priority feerate %s %s/kvB.\n",
                 forecast.opt.block_height, forecast.opt.low_priority_estimate.GetFeePerK(),
                 CURRENCY_ATOM, forecast.opt.high_priority_estimate.GetFeePerK(), CURRENCY_ATOM);
    }
    return std::make_pair(forecast, err_messages);
};

unsigned int FeeEstimator::MaxForecastingTarget()
{
    unsigned int max_target = 0;
    for (auto& forecaster : forecasters) {
        max_target = std::max(forecaster.second->MaxTarget(), max_target);
    }
    if (block_policy_estimator.has_value()) {
        max_target = std::max(max_target, block_policy_estimator.value()->HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE));
    }
    return max_target;
}

// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license. See the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_FORECASTERS_MEMPOOL_H
#define BITCOIN_POLICY_FORECASTERS_MEMPOOL_H

#include <logging.h>
#include <policy/fee_estimator.h>
#include <policy/feerate.h>
#include <policy/forecaster.h>
#include <policy/forecaster_util.h>
#include <sync.h>
#include <util/time.h>

#include <chrono>

class Chainstate;
class CTxMemPool;

// Fee rate estimates above this confirmation target are not reliable,
// mempool condition might likely change.
const unsigned int MEMPOOL_FORECAST_MAX_TARGET{2};
static const std::chrono::seconds CACHE_LIFE{30};


/**
 * CachedMempoolEstimates holds a cache of recent forecast.
 * We only provide fresh estimates if the last cached fee rate
 * forecast ages more than CACHE_LIFE.
 */
struct CachedMempoolEstimates {
private:
    mutable Mutex cache_mutex;
    BlockPercentiles fee_estimate GUARDED_BY(cache_mutex);
    NodeClock::time_point last_updated GUARDED_BY(cache_mutex){NodeClock::now() - CACHE_LIFE - std::chrono::seconds(1)};

    bool isStale() const EXCLUSIVE_LOCKS_REQUIRED(cache_mutex)
    {
        AssertLockHeld(cache_mutex);
        return (last_updated + CACHE_LIFE) < NodeClock::now();
    }

public:
    CachedMempoolEstimates() {}
    CachedMempoolEstimates(const CachedMempoolEstimates&) = delete;
    CachedMempoolEstimates& operator=(const CachedMempoolEstimates&) = delete;

    std::optional<BlockPercentiles> get() const EXCLUSIVE_LOCKS_REQUIRED(!cache_mutex)
    {
        LOCK(cache_mutex);
        if (isStale()) return std::nullopt;
        LogPrint(BCLog::ESTIMATEFEE, "%s: cache is not stale, using cached value\n", forecastTypeToString(ForecastType::MEMPOOL_FORECAST));
        return fee_estimate;
    }

    void update(const BlockPercentiles& new_fee_estimate) EXCLUSIVE_LOCKS_REQUIRED(!cache_mutex)
    {
        LOCK(cache_mutex);
        fee_estimate = new_fee_estimate;
        last_updated = NodeClock::now();
        LogPrint(BCLog::ESTIMATEFEE, "%s: updated cache\n", forecastTypeToString(ForecastType::MEMPOOL_FORECAST));
    }
};

/** \class MemPoolForecaster
 * This fee estimate forecaster estimates the fee rate that a transaction will pay
 * to be included in a block as soon as possible.
 * It uses the unconfirmed transactions in the mempool to generate the next block template
 * that will likely be mined.
 * The percentile fee rate's are computed, and the bottom 25th percentile and 50th percentile fee rate's are returned.
 */
class MemPoolForecaster : public Forecaster
{
private:
    CTxMemPool* m_mempool;
    Chainstate* m_chainstate;
    mutable CachedMempoolEstimates cache;

public:
    MemPoolForecaster(CTxMemPool* mempool, Chainstate* chainstate)
        : Forecaster(ForecastType::MEMPOOL_FORECAST), m_mempool(mempool), m_chainstate(chainstate) {};
    ~MemPoolForecaster() = default;

    /**
     * Estimate the fee rate from mempool transactions given a confirmation target.
     * @param[in] targetBlocks The confirmation target to provide estimate for.
     * @return The forecasted fee rates.
     */
    ForecastResult EstimateFee(unsigned int targetBlocks) override;

    /* Return the maximum confirmation target this forecaster can forecast */
    unsigned int MaxTarget() override
    {
        return MEMPOOL_FORECAST_MAX_TARGET;
    }
};
#endif // BITCOIN_POLICY_FORECASTERS_MEMPOOL_H

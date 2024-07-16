// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <cstdint>
#include <memory>

class TxOrphanage;
class TxRequestTracker;
class CRollingBloomFilter;

namespace node {
class TxDownloadImpl;

class TxDownloadManager {
    const std::unique_ptr<TxDownloadImpl> m_impl;

public:
    explicit TxDownloadManager();
    ~TxDownloadManager();

    // Get references to internal data structures. Outside access to these data structures should be
    // temporary and removed later once logic has been moved internally.
    TxOrphanage& GetOrphanageRef();
    TxRequestTracker& GetTxRequestRef();
    CRollingBloomFilter& GetRecentRejectsRef();
    CRollingBloomFilter& GetRecentRejectsReconsiderableRef();
    CRollingBloomFilter& GetRecentConfirmedRef();
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H

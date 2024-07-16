// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <cstdint>
#include <memory>

class CBlock;
class CBlockIndex;
class CRollingBloomFilter;
class CTxMemPool;
class TxOrphanage;
class TxRequestTracker;
enum class ChainstateRole;
namespace node {
class TxDownloadImpl;

struct TxDownloadOptions {
    /** Read-only reference to mempool. */
    const CTxMemPool& m_mempool;
};

class TxDownloadManager {
    const std::unique_ptr<TxDownloadImpl> m_impl;

public:
    explicit TxDownloadManager(const TxDownloadOptions& options);
    ~TxDownloadManager();

    // Get references to internal data structures. Outside access to these data structures should be
    // temporary and removed later once logic has been moved internally.
    TxOrphanage& GetOrphanageRef();
    TxRequestTracker& GetTxRequestRef();
    CRollingBloomFilter& GetRecentRejectsRef();
    CRollingBloomFilter& GetRecentRejectsReconsiderableRef();
    CRollingBloomFilter& GetRecentConfirmedRef();

    // Responses to chain events. TxDownloadManager is not an actual client of ValidationInterface, these are called through PeerManager.
    void ActiveTipChange();
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock);
    void BlockDisconnected();
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H

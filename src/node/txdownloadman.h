// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <net.h>
#include <policy/packages.h>

#include <cstdint>
#include <memory>

class CBlock;
class CBlockIndex;
class CRollingBloomFilter;
class CTxMemPool;
class GenTxid;
class TxOrphanage;
class TxRequestTracker;
enum class ChainstateRole;
namespace node {
class TxDownloadImpl;

/** Maximum number of in-flight transaction requests from a peer. It is not a hard limit, but the threshold at which
 *  point the OVERLOADED_PEER_TX_DELAY kicks in. */
static constexpr int32_t MAX_PEER_TX_REQUEST_IN_FLIGHT = 100;
/** Maximum number of transactions to consider for requesting, per peer. It provides a reasonable DoS limit to
 *  per-peer memory usage spent on announcements, while covering peers continuously sending INVs at the maximum
 *  rate (by our own policy, see INVENTORY_BROADCAST_PER_SECOND) for several minutes, while not receiving
 *  the actual transaction (from any peer) in response to requests for them. */
static constexpr int32_t MAX_PEER_TX_ANNOUNCEMENTS = 5000;
/** How long to delay requesting transactions via txids, if we have wtxid-relaying peers */
static constexpr auto TXID_RELAY_DELAY{2s};
/** How long to delay requesting transactions from non-preferred peers */
static constexpr auto NONPREF_PEER_TX_DELAY{2s};
/** How long to delay requesting transactions from overloaded peers (see MAX_PEER_TX_REQUEST_IN_FLIGHT). */
static constexpr auto OVERLOADED_PEER_TX_DELAY{2s};
/** How long to wait before downloading a transaction from an additional peer */
static constexpr auto GETDATA_TX_INTERVAL{60s};
struct TxDownloadOptions {
    /** Read-only reference to mempool. */
    const CTxMemPool& m_mempool;
    /** RNG provided by caller. */
    FastRandomContext& m_rng;
};
struct TxDownloadConnectionInfo {
    /** Whether this peer is preferred for transaction download. */
    const bool m_preferred;
    /** Whether this peer has Relay permissions. */
    const bool m_relay_permissions;
    /** Whether this peer supports wtxid relay. */
    const bool m_wtxid_relay;
};
struct PackageToValidate {
    Package m_txns;
    std::vector<NodeId> m_senders;
    /** Construct a 1-parent-1-child package. */
    explicit PackageToValidate(const CTransactionRef& parent,
                               const CTransactionRef& child,
                               NodeId parent_sender,
                               NodeId child_sender) :
        m_txns{parent, child},
        m_senders{parent_sender, child_sender}
    {}

    // Move ctor
    PackageToValidate(PackageToValidate&& other) : m_txns{std::move(other.m_txns)}, m_senders{std::move(other.m_senders)} {}

    // Move assignment
    PackageToValidate& operator=(PackageToValidate&& other) {
        this->m_txns = std::move(other.m_txns);
        this->m_senders = std::move(other.m_senders);
        return *this;
    }

    std::string ToString() const {
        Assume(m_txns.size() == 2);
        return strprintf("parent %s (wtxid=%s, sender=%d) + child %s (wtxid=%s, sender=%d)",
                         m_txns.front()->GetHash().ToString(),
                         m_txns.front()->GetWitnessHash().ToString(),
                         m_senders.front(),
                         m_txns.back()->GetHash().ToString(),
                         m_txns.back()->GetWitnessHash().ToString(),
                         m_senders.back());
    }
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

    /** Check whether we already have this gtxid in:
     *  - mempool
     *  - orphanage
     *  - m_recent_rejects
     *  - m_recent_rejects_reconsiderable (if include_reconsiderable = true)
     *  - m_recent_confirmed_transactions
     *  */
    bool AlreadyHaveTx(const GenTxid& gtxid, bool include_reconsiderable);

    /** Creates a new PeerInfo. Saves the connection info to calculate tx announcement delays later. */
    void ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info);

    /** Deletes all txrequest announcements and orphans for a given peer. */
    void DisconnectedPeer(NodeId nodeid);

    /** New inv has been received. May be added as a candidate to txrequest. */
    bool AddTxAnnouncement(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now, bool p2p_inv);

    /** Get getdata requests to send. */
    std::vector<GenTxid> GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time);

    /** Should be called when a notfound for a tx has been received. */
    void ReceivedNotFound(NodeId nodeid, const std::vector<uint256>& txhashes);

    /** Look for a child of this transaction in the orphanage to form a 1-parent-1-child package,
     * skipping any combinations that have already been tried. Return the resulting package along with
     * the senders of its respective transactions, or std::nullopt if no package is found. */
    std::optional<PackageToValidate> Find1P1CPackage(const CTransactionRef& ptx, NodeId nodeid);

    /** Respond to successful transaction submission to mempool */
    void MempoolAcceptedTx(const CTransactionRef& tx);
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H

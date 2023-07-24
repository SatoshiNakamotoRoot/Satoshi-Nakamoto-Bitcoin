// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXORPHANAGE_H
#define BITCOIN_TXORPHANAGE_H

#include <net.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <map>
#include <set>

/** A class to track orphan transactions (failed on TX_MISSING_INPUTS)
 * Since we cannot distinguish orphans from bad transactions with
 * non-existent inputs, we heavily limit the number of orphans
 * we keep and the duration we keep them for.
 */
class TxOrphanage {
public:
    /** Add a new orphan transaction. If the tx already exists, add this peer to its list of announcers.
     * parent_txids should contain a (de-duplicated) list of txids of this transaction's missing parents.
      @returns true if the transaction was added as a new orphan. */
    bool AddTx(const CTransactionRef& tx, NodeId peer, const std::vector<Txid>& parent_txids) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Get orphan transaction by wtxid. Returns nullptr if we don't have it anymore. */
    CTransactionRef GetTx(const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Check if we already have an orphan transaction (by txid or wtxid) */
    bool HaveTx(const GenTxid& gtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Extract a transaction from a peer's work set
     *  Returns nullptr if there are no transactions to work on.
     *  Otherwise returns the transaction reference, and removes
     *  it from the work set.
     */
    CTransactionRef GetTxToReconsider(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    int EraseTx(const Wtxid& txid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase all orphans announced by a peer (eg, after that peer disconnects) */
    void EraseForPeer(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase all orphans included in or invalidated by a new block */
    void EraseForBlock(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Limit the orphanage to the given maximum */
    void LimitOrphans(unsigned int max_orphans, FastRandomContext& rng) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Add any orphans that list a particular tx as a parent into the from peer's work set */
    void AddChildrenToWorkSet(const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);;

    /** Does this peer have any work to do? */
    bool HaveTxToReconsider(NodeId peer) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Get all children of this parent. */
    std::vector<CTransactionRef> GetChildren(const CTransactionRef& parent, NodeId peer) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Return how many entries exist in the orphange */
    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_orphans.size();
    }

    /** Get an orphan's parent_txids, or std::nullopt if the orphan is not present. */
    std::optional<std::vector<Txid>> GetParentTxids(const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

protected:
    /** Guards orphan transactions */
    mutable Mutex m_mutex;

    struct OrphanTx {
        CTransactionRef tx;
        NodeId fromPeer;
        int64_t nTimeExpire;
        size_t list_pos;
        /** Txids of the missing parents to request. Determined by peerman. */
        std::vector<Txid> parent_txids;
    };

    /** Map from txid to orphan transaction record. Limited by
     *  -maxorphantx/DEFAULT_MAX_ORPHAN_TRANSACTIONS */
    std::map<Txid, OrphanTx> m_orphans GUARDED_BY(m_mutex);

    /** Which peer provided the orphans that need to be reconsidered */
    std::map<NodeId, std::set<Txid>> m_peer_work_set GUARDED_BY(m_mutex);

    using OrphanMap = decltype(m_orphans);

    struct IteratorComparator
    {
        template<typename I>
        bool operator()(const I& a, const I& b) const
        {
            return &(*a) < &(*b);
        }
    };

    /** Index from the parents' COutPoint into the m_orphans. Used
     *  to remove orphan transactions from the m_orphans */
    std::map<COutPoint, std::set<OrphanMap::iterator, IteratorComparator>> m_outpoint_to_orphan_it GUARDED_BY(m_mutex);

    /** Orphan transactions in vector for quick random eviction */
    std::vector<OrphanMap::iterator> m_orphan_list GUARDED_BY(m_mutex);

    /** Index from wtxid into the m_orphans to lookup orphan
     *  transactions using their witness ids. */
    std::map<Wtxid, OrphanMap::iterator> m_wtxid_to_orphan_it GUARDED_BY(m_mutex);

    /** Erase an orphan by wtxid */
    int EraseTxNoLock(const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
};

#endif // BITCOIN_TXORPHANAGE_H

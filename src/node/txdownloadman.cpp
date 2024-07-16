// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownloadman.h>
#include <node/txdownload_impl.h>

namespace node {

TxDownloadManager::TxDownloadManager(const TxDownloadOptions& options) :
    m_impl{std::make_unique<TxDownloadImpl>(options)}
{}
TxDownloadManager::~TxDownloadManager() = default;

TxOrphanage& TxDownloadManager::GetOrphanageRef()
{
    return m_impl->m_orphanage;
}
TxRequestTracker& TxDownloadManager::GetTxRequestRef()
{
    return m_impl->m_txrequest;
}
CRollingBloomFilter& TxDownloadManager::GetRecentRejectsRef()
{
    return m_impl->m_recent_rejects;
}
CRollingBloomFilter& TxDownloadManager::GetRecentRejectsReconsiderableRef()
{
    return m_impl->m_recent_rejects_reconsiderable;
}
CRollingBloomFilter& TxDownloadManager::GetRecentConfirmedRef()
{
    return m_impl->m_recent_confirmed_transactions;
}
void TxDownloadManager::ActiveTipChange()
{
    m_impl->ActiveTipChange();
}
void TxDownloadManager::BlockConnected(const std::shared_ptr<const CBlock>& pblock)
{
    m_impl->BlockConnected(pblock);
}
void TxDownloadManager::BlockDisconnected()
{
    m_impl->BlockDisconnected();
}

void TxDownloadManager::ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info)
{
    m_impl->ConnectedPeer(nodeid, info);
}
void TxDownloadManager::DisconnectedPeer(NodeId nodeid)
{
    m_impl->DisconnectedPeer(nodeid);
}
bool TxDownloadManager::AddTxAnnouncement(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now, bool p2p_inv)
{
    return m_impl->AddTxAnnouncement(peer, gtxid, now, p2p_inv);
}
std::vector<GenTxid> TxDownloadManager::GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time)
{
    return m_impl->GetRequestsToSend(nodeid, current_time);
}

void TxDownloadManager::ReceivedNotFound(NodeId nodeid, const std::vector<uint256>& txhashes)
{
    m_impl->ReceivedNotFound(nodeid, txhashes);
}
void TxDownloadManager::MempoolAcceptedTx(const CTransactionRef& tx)
{
    m_impl->MempoolAcceptedTx(tx);
}
RejectedTxTodo TxDownloadManager::MempoolRejectedTx(const CTransactionRef& ptx, const TxValidationState& state, NodeId nodeid, bool maybe_add_new_orphan)
{
        return m_impl->MempoolRejectedTx(ptx, state, nodeid, maybe_add_new_orphan);
}
void TxDownloadManager::MempoolRejectedPackage(const Package& package)
{
    m_impl->MempoolRejectedPackage(package);
}
std::pair<bool, std::optional<PackageToValidate>> TxDownloadManager::ReceivedTx(NodeId nodeid, const CTransactionRef& ptx)
{
    return m_impl->ReceivedTx(nodeid, ptx);
}
bool TxDownloadManager::HaveMoreWork(NodeId nodeid) const
{
    return m_impl->HaveMoreWork(nodeid);
}
CTransactionRef TxDownloadManager::GetTxToReconsider(NodeId nodeid)
{
    return m_impl->GetTxToReconsider(nodeid);
}
} // namespace node

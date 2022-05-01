// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownloadman.h>
#include <node/txdownload_impl.h>

namespace node {

TxDownloadManager::TxDownloadManager() :
    m_impl{std::make_unique<TxDownloadImpl>()}
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

} // namespace node

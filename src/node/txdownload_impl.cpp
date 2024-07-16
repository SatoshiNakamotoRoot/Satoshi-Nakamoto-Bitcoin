// Copyright (c) 2023
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownload_impl.h>
#include <node/txdownloadman.h>

#include <chain.h>
#include <consensus/validation.h>
#include <txmempool.h>
#include <validation.h>
#include <validationinterface.h>

namespace node {
void TxDownloadImpl::ActiveTipChange()
{
    // If the chain tip has changed, previously rejected transactions might now be invalid, e.g. due
    // to a timelock. Reset the rejection filters to give those transactions another chance if we
    // see them again.
    m_recent_rejects.reset();
    m_recent_rejects_reconsiderable.reset();
}

void TxDownloadImpl::BlockConnected(const std::shared_ptr<const CBlock>& pblock)
{
    m_orphanage.EraseForBlock(*pblock);

    for (const auto& ptx : pblock->vtx) {
        m_recent_confirmed_transactions.insert(ptx->GetHash().ToUint256());
        if (ptx->HasWitness()) {
            m_recent_confirmed_transactions.insert(ptx->GetWitnessHash().ToUint256());
        }
    }
    for (const auto& ptx : pblock->vtx) {
        m_txrequest.ForgetTxHash(ptx->GetHash());
        m_txrequest.ForgetTxHash(ptx->GetWitnessHash());
    }
}

void TxDownloadImpl::BlockDisconnected()
{
    // To avoid relay problems with transactions that were previously
    // confirmed, clear our filter of recently confirmed transactions whenever
    // there's a reorg.
    // This means that in a 1-block reorg (where 1 block is disconnected and
    // then another block reconnected), our filter will drop to having only one
    // block's worth of transactions in it, but that should be fine, since
    // presumably the most common case of relaying a confirmed transaction
    // should be just after a new block containing it is found.
    m_recent_confirmed_transactions.reset();
}
} // namespace node

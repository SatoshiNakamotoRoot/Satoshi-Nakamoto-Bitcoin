// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <key_io.h>
#include <miner.h>
#include <outputtype.h>
#include <pow.h>
#include <script/standard.h>
#include <validation.h>
#include <validationinterface.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif

const std::string ADDRESS_BCRT1_UNSPENDABLE = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xueyj";

#ifdef ENABLE_WALLET
std::string getnewaddress(CWallet& w)
{
    constexpr auto output_type = OutputType::BECH32;
    CTxDestination dest;
    std::string error;
    if (!w.GetNewDestination(output_type, "", dest, error)) assert(false);

    return EncodeDestination(dest);
}

void importaddress(CWallet& wallet, const std::string& address)
{
    auto spk_man = wallet.GetLegacyScriptPubKeyMan();
    LOCK(wallet.cs_wallet);
    AssertLockHeld(spk_man->cs_wallet);
    const auto dest = DecodeDestination(address);
    assert(IsValidDestination(dest));
    const auto script = GetScriptForDestination(dest);
    wallet.MarkDirty();
    assert(!spk_man->HaveWatchOnly(script));
    if (!spk_man->AddWatchOnly(script, 0 /* nCreateTime */)) assert(false);
    wallet.SetAddressBook(dest, /* label */ "", "receive");
}
#endif // ENABLE_WALLET

CTxIn generatetoaddress(const std::string& address)
{
    const auto dest = DecodeDestination(address);
    assert(IsValidDestination(dest));
    const auto coinbase_script = GetScriptForDestination(dest);

    return MineBlock(coinbase_script);
}

CTxIn MineBlock(const CScript& coinbase_scriptPubKey)
{
    auto block = PrepareBlock(coinbase_scriptPubKey);
    return *MineBlock(block);
}

Optional<CTxIn> MineBlock(std::shared_ptr<CBlock>& block)
{
    const auto idx = GetWitnessCommitmentIndex(*block);
    if (idx != -1) {
        // Refresh witness commitment, in case a tx has been added or modified
        CMutableTransaction tx_cb{*block->vtx[0]};
        tx_cb.vout.erase(tx_cb.vout.begin() + idx);
        block->vtx[0] = MakeTransactionRef(std::move(tx_cb));
        LOCK(cs_main);
        GenerateCoinbaseCommitment(*block, ChainActive().Tip()->pprev, Params().GetConsensus());
    }
    // Refresh merkle root, in case a tx has been added or modified
    block->hashMerkleRoot = BlockMerkleRoot(*block);

    while (!CheckProofOfWork(block->GetHash(), block->nBits, Params().GetConsensus())) {
        ++block->nNonce;
        assert(block->nNonce);
    }

    bool processed{ProcessNewBlock(Params(), block, true, nullptr)};
    assert(processed);

    // TODO: Return nothing if the block was invalid

    return CTxIn{block->vtx[0]->GetHash(), 0};
}

std::shared_ptr<CBlock> PrepareBlock(const CScript& coinbase_scriptPubKey)
{
    auto block = std::make_shared<CBlock>(
        BlockAssembler{Params()}
            .CreateNewBlock(coinbase_scriptPubKey)
            ->block);

    LOCK(cs_main);
    block->nTime = ::ChainActive().Tip()->GetMedianTimePast() + 1;
    block->hashMerkleRoot = BlockMerkleRoot(*block);

    return block;
}

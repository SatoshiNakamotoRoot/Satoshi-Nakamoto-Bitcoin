# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

@0xc77d03df6a41b505;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/mp/proxy.capnp";
$Proxy.include("ipc/capnp/mining.h");
$Proxy.includeTypes("ipc/capnp/mining-types.h");

using Common = import "common.capnp";

interface Mining $Proxy.wrap("interfaces::Mining") {
    isTestChain @0 (context :Proxy.Context) -> (result: Bool);
    isInitialBlockDownload @1 (context :Proxy.Context) -> (result: Bool);
    getTipHash @2 (context :Proxy.Context) -> (result: Data);
    createNewBlock @3 (context :Proxy.Context, scriptPubKey: Data, useMempool: Bool) -> (result: CBlockTemplate);
    processNewBlock @4 (context :Proxy.Context, block: Data) -> (newBlock: Bool, result: Bool);
    getTransactionsUpdated @5 (context :Proxy.Context) -> (result: UInt32);
    testBlockValidity @6 (context :Proxy.Context, block: Data, checkMerkleRoot: Bool) -> (state: BlockValidationState, result: Bool);
}

struct CBlockTemplate $Proxy.wrap("node::CBlockTemplate")
{
    block @0 :Data;
    vTxFees @1 :List(UInt64);
    vTxSigOpsCost @2 :List(UInt64);
    vchCoinbaseCommitment @3 :Data;
}

struct BlockValidationState {
    mode @0 :Int32;
    result @1 :Int32;
    rejectReason @2 :Text;
    debugMessage @3 :Text;
}

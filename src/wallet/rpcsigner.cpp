// Copyright (c) 2018-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/rpcdump.h>
#include <wallet/rpcsigner.h>
#include <wallet/rpcwallet.h>

#ifdef HAVE_BOOST_PROCESS

static UniValue enumeratesigners(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"enumeratesigners\n",
                "Returns a list of external signers from -signer and associates them\n"
                "with the wallet until you stop bitcoind.\n",
                {},
                RPCResult{
                    "{\n"
                    "  \"signers\" : [                              (json array of objects)\n"
                    "    {\n"
                    "      \"masterkeyfingerprint\" : \"fingerprint\" (string) Master key fingerprint\n"
                    "    }\n"
                    "    ,...\n"
                    "  ]\n"
                    "}\n"
                },
                RPCExamples{""}
            }.ToString()
        );
    }

    const std::string command = gArgs.GetArg("-signer", DEFAULT_EXTERNAL_SIGNER);
    if (command == "") throw JSONRPCError(RPC_WALLET_ERROR, "Error: restart bitcoind with -signer=<cmd>");
    std::string chain = gArgs.GetChainName();
    const bool mainnet = chain == CBaseChainParams::MAIN;
    UniValue signers;
    try {
        signers = ExternalSigner::Enumerate(command, pwallet->m_external_signers, mainnet);
    } catch (const ExternalSignerException& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }
    UniValue result(UniValue::VOBJ);
    result.pushKV("signers", signers);
    return result;
}

ExternalSigner *GetSignerForJSONRPCRequest(const JSONRPCRequest& request, int index, CWallet* pwallet) {
    if (pwallet->m_external_signers.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "First call enumeratesigners");
    }

    // If no fingerprint is specified, return the only available signer
    if (request.params.size() < size_t(index + 1) || request.params[index].isNull()) {
        if (pwallet->m_external_signers.size() > 1) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Multiple signers found, please specify which to use");
        }
        return &pwallet->m_external_signers.front();
    }

    const std::string fingerprint = request.params[index].get_str();
    for (ExternalSigner &candidate : pwallet->m_external_signers) {
        if (candidate.m_fingerprint == fingerprint) return &candidate;
    }
    throw JSONRPCError(RPC_WALLET_ERROR, "Signer fingerprint not found");
}

UniValue signerdissociate(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"signerdissociate",
                "Disossociates external signer from the wallet.\n",
                {
                    {"fingerprint", RPCArg::Type::STR, /* default_val */ "", "Master key fingerprint of signer"},
                },
                RPCResult{"null"},
                RPCExamples{""}
            }.ToString()
        );
    }

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 0, pwallet);

    assert(signer != nullptr);
    std::vector<ExternalSigner>::iterator position = std::find(pwallet->m_external_signers.begin(), pwallet->m_external_signers.end(), *signer);
    if (position != pwallet->m_external_signers.end()) pwallet->m_external_signers.erase(position);

    return NullUniValue;
}

std::unique_ptr<Descriptor> ParseDescriptor(const UniValue &descriptor_val, bool must_be_solveable = true, bool must_be_ranged = false) {
    if (!descriptor_val.isStr()) JSONRPCError(RPC_WALLET_ERROR, "Unexpect result");
    FlatSigningProvider provider;
    const std::string desc_str = descriptor_val.getValStr();
    std::unique_ptr<Descriptor> desc = Parse(desc_str, provider, true);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor: %s", desc_str));
    }
    if (!desc->IsRange()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor must be ranged");
    }
    if (!desc->IsSolvable()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor must be solvable");
    }
    return desc;
}

UniValue signerfetchkeys(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"signerfetchkeys",
                "Obtains keys from external signer and imports them into the wallet.\n"
                "Call enumeratesigners before using this.\n",
                {
                    {"account",     RPCArg::Type::NUM, /* default_val */ "0", "BIP32 account to use"},
                    {"fingerprint", RPCArg::Type::STR, /* default_val */ "", "Master key fingerprint of signer"}
                },
                RPCResult{
                    "[{ \"success\": true }"
                },
                RPCExamples{""}
            }.ToString()
        );
    }

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 1, pwallet);

    int account = 0;
    if (!request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        account = request.params[0].get_int();
    }

    UniValue signer_res = signer->getDescriptors(account);
    if (!signer_res.isObject()) throw JSONRPCError(RPC_WALLET_ERROR, "Unexpect result");
    const UniValue& receive_descriptor_vals = find_value(signer_res, "receive");
    const UniValue& change_descriptor_vals = find_value(signer_res, "internal");
    if (!receive_descriptor_vals.isArray()) throw JSONRPCError(RPC_WALLET_ERROR, "Unexpect result");
    if (!change_descriptor_vals.isArray()) throw JSONRPCError(RPC_WALLET_ERROR, "Unexpect result");

    // Parse and check descriptors
    std::vector<std::unique_ptr<Descriptor>> receive_descriptors;
    std::vector<std::unique_ptr<Descriptor>> change_descriptors;

    for (const UniValue& desc : receive_descriptor_vals.get_array().getValues()) {
        receive_descriptors.push_back(ParseDescriptor(desc, true, true));
    }

    for (const UniValue& desc : change_descriptor_vals.get_array().getValues()) {
        change_descriptors.push_back(ParseDescriptor(desc, true, true));
    }

    // Use importmulti to process the descriptors:
    // TODO: extract reusable non-RPC code from importmulti
    UniValue importdata(UniValue::VARR);

    uint64_t keypool_target_size = 0;
    keypool_target_size = gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE);

    if (keypool_target_size == 0) throw JSONRPCError(RPC_WALLET_ERROR, "-keypool must be > 0");

    UniValue receive_key_data(UniValue::VOBJ);

    // Pick receive descriptor based on address_type
    // TODO: after #15567, remove desc_prefix stuff and use desc->GetAddressType()
    std::string desc_prefix = "";
    switch (pwallet->m_default_address_type) {
    case OutputType::LEGACY: {
        desc_prefix = "pkh(";
        break;
    }
    case OutputType::P2SH_SEGWIT: {
        desc_prefix = "sh(wpkh(";
        break;
    }
    case OutputType::BECH32: {
        desc_prefix = "wpkh(";
        break;
    }
    default:
        assert(false);
    }

    std::unique_ptr<Descriptor> match_desc;
    for (auto&& desc : receive_descriptors) {
        if (desc->ToString().find(desc_prefix) == 0) {
            match_desc = std::move(desc);
            break;
        }
    }

    if (!match_desc) throw JSONRPCError(RPC_WALLET_ERROR, "No descriptor found for wallet address type");
    receive_key_data.pushKV("desc", match_desc->ToString());

    UniValue receive_range(UniValue::VARR);
    // TODO: base range start and end on what's currently in the keypool
    receive_range.push_back(0);
    receive_range.push_back(keypool_target_size - 1);
    receive_key_data.pushKV("range", receive_range);
    receive_key_data.pushKV("internal", false);
    receive_key_data.pushKV("keypool", true);
    receive_key_data.pushKV("watchonly", true);
    importdata.push_back(receive_key_data);

    UniValue change_key_data(UniValue::VOBJ);

    // Pick change descriptor based on address_type
    const OutputType change_type = pwallet->m_default_change_type == OutputType::CHANGE_AUTO ? pwallet->m_default_address_type : pwallet->m_default_change_type;

    // TODO: after #15567, remove desc_prefix stuff and use desc->GetAddressType()
    switch (change_type) {
    case OutputType::LEGACY: {
        desc_prefix = "pkh(";
        break;
    }
    case OutputType::P2SH_SEGWIT: {
        desc_prefix = "sh(wpkh(";
        break;
    }
    case OutputType::BECH32: {
        desc_prefix = "wpkh(";
        break;
    }
    default:
        assert(false);
    }

    match_desc.reset(nullptr);
    for (auto&& desc : change_descriptors) {
        if (desc->ToString().find(desc_prefix) == 0) {
            match_desc = std::move(desc);
            break;
        }
    }

    if (!match_desc) throw JSONRPCError(RPC_WALLET_ERROR, "No descriptor found for wallet change address type");
    change_key_data.pushKV("desc", match_desc->ToString());

    UniValue change_range(UniValue::VARR);
    // TODO: base range start and end on what's currently in the keypool
    change_range.push_back(0);
    change_range.push_back(keypool_target_size - 1);
    change_key_data.pushKV("range", change_range);
    change_key_data.pushKV("internal", true);
    change_key_data.pushKV("keypool", true);
    change_key_data.pushKV("watchonly", true);
    importdata.push_back(change_key_data);

    UniValue result(UniValue::VARR);
    {
        auto locked_chain = pwallet->chain().lock();
        const Optional<int> tip_height = locked_chain->getHeight();
        int64_t now = tip_height ? locked_chain->getBlockMedianTimePast(*tip_height) : 0;
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(pwallet);
        for (const UniValue& data : importdata.getValues()) {
            // TODO: prevent inserting the same key twice
            result.push_back(ProcessImport(pwallet, data, now));
        }
    }

    // TODO: after the import, fetch a random key from the wallet (part of the import)
    // and ask the signer to sign a message (may require user approval on device).
    // Check the returned signature.
    // This ensures that the device can actually sign with this key and no data
    // corruption occured en route.
    // Note that this doesn't guarantee the device can sign for any script involving this key.

    return result;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                                actor (function)                argNames
    //  --------------------- ------------------------          -----------------------         ----------
    { "signer",             "enumeratesigners",                 &enumeratesigners,              {} },
    { "signer",             "signerdissociate",                 &signerdissociate,              {"fingerprint"} },
    { "signer",             "signerfetchkeys",                  &signerfetchkeys,               {"account", "fingerprint"} },
};
// clang-format on

void RegisterSignerRPCCommands(interfaces::Chain& chain, std::vector<std::unique_ptr<interfaces::Handler>>& handlers)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        handlers.emplace_back(chain.handleRpc(commands[vcidx]));
}
#endif // HAVE_BOOST_PROCESS

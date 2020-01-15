#ifndef BITCOIN_SRC_VBK_CONFIG_HPP
#define BITCOIN_SRC_VBK_CONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "vbk/typed_wrapper.hpp"
#include <array>
#include <cstdint>
#include <uint256.h>

#ifndef VBK_NUM_KEYSTONES
/// number of keystones stored in ContextInfoContainer
// after change of this number, you need to re-generate genesis blocks (main, test, regtest)
#define VBK_NUM_KEYSTONES 2u
#endif

namespace VeriBlock {

using KeystoneArray = std::array<uint256, VBK_NUM_KEYSTONES>;

using AltchainId = TypedWrapper<int64_t, struct AltchainIdTag>;

struct Config {
    // unique index to this chain; network id across chains
    AltchainId index = AltchainId(0x3ae6ca);

    uint32_t btc_header_size = 80;
    uint32_t vbk_header_size = 64;
    uint32_t max_pop_script_size = 150000; // TODO: figure out number
    uint32_t max_vtb_size = 100000;        // TODO: figure out number
    uint32_t min_vtb_size = 1;             // TODO: figure out number
    uint32_t max_atv_size = 100000;        // TODO: figure out numer
    uint32_t min_atv_size = 1;             // TODO: figure out number

    uint32_t max_future_block_time = 10 * 60; // 10 minutes

    uint32_t keystone_interval = 5;
    uint32_t keystone_finality_delay = 50;
    uint32_t amnesty_period = 20;

    /// The maximum allowed weight for the PoP transaction
    uint32_t max_pop_tx_weight = 150000;

    /// The maximum allowed number of PoP transaction in a block
    uint32_t max_pop_tx_amount = 50;
    /// The maximum allowed number of "UpdateContext" transactions in a block
    uint32_t max_update_context_tx_amount = 1;


    /////// Pop Rewards section start
    uint32_t POP_REWARD_PERCENTAGE = 40;
    int32_t POP_REWARD_SETTLEMENT_INTERVAL = 400;
    int32_t POP_REWARD_PAYMENT_DELAY = 500;
    int32_t POP_DIFFICULTY_AVERAGING_INTERVAL = 50;
    
    // how many payout rounds we have
    uint32_t payoutRounds = 4;

    // keystone is on 4th round (numeration starts from 0)
    uint32_t keystoneRound = 3;

    // we gradually increase the reward for every consecutive payout round
    std::vector<std::string> roundRatios = { "0.97", "1.03", "1.07", "3.00" };

    // the score when the rewards starts decreasing
    std::string startOfDecreasingLine = "100.0";

    // this is the length of the decreasing part of the reward curve
    std::string widthOfDecreasingLineNormal = "100.0";

    // this is the length of the decreasing part of the reward curve for keystone block
    std::string widthOfDecreasingLineKeystone = "200.0";

    // we decrease each score point to 80% of initial value when difficulty is above 1.0
    std::string aboveIntendedPayoutMultiplierNormal = "0.8000";

    // we decrease each keystone score point to 57% of initial value when difficulty is above 1.0
    std::string aboveIntendedPayoutMultiplierKeystone = "0.5735";

    // we limit the maximum rewards to 200% for normal PoP
    std::string maxRewardThresholdNormal = "200.0";

    // we limit the maximum rewards to 300% for keystone PoP
    std::string maxRewardThresholdKeystone = "300.0";

    // we score each VeriBlock and lower the reward for late blocks
    std::vector<std::string> relativeScoreLookupTable = {"1.0", "1.0", "1.0", "1.0", "1.0", "1.0", "1.0", "1.0", "1.0", "1.0", "1.0", "1.0", "0.48296816", "0.31551694", "0.23325824", "0.18453616", "0.15238463", "0.12961255", "0.11265630", "0.09955094", "0.08912509", "0.08063761", "0.07359692", "0.06766428", "0.06259873", "0.05822428", "0.05440941", "0.05105386", "0.04807993", "0.04542644", "0.04304458", "0.04089495", "0.03894540", "0.03716941", "0.03554497", "0.03405359", "0.03267969", "0.03141000", "0.03023319", "0.02913950", "0.02812047", "0.02716878", "0.02627801", "0.02544253", "0.02465739", "0.02391820", "0.02322107", "0.02256255", "0.02193952", "0.02134922"};

    // use flat score on 3rd round
    int32_t flatScoreRound = 2;
    bool flatScoreRoundUse = true;


    /////// Pop Rewards section end

    // GRPC config
    std::string service_port = "19012";
    std::string service_ip = "127.0.0.1";

    //Alt service bootstrap blocks
    //Veriblock blocks
    std::vector<std::string> bootstrap_veriblock_blocks = {"000212B90002500640D2DCFDD047AF3F197C2BB743C05C2619919657462191847838E067A540836ABBE2C5AB1AA8DA98602D68C05DFB5C010405F5E1584D4024", "000212BA0002539544FC18F77FD997B080D52BB743C05C2619919657462191847838E067FF19E383F41F4B8A586142E47DB3B6225DFB5C080405F5E15876C544", "000212BB0002304FB9683DAFC9396A7F36492BB743C05C2619919657462191847838E067A87CF5F304B4E102B104320C5CBA33B85DFB5C500405F5E15A2670DE", "000212BC00025870BF9AD09BF0137D74551A2BB743C05C2619919657462191847838E06718A87B5E2923426270A6554112B0A7945DFB5C930405F5E1265B82D7", "000212BD000221C1F97385FB4F50D012571E2BB743C05C2619919657462191847838E067AAE01CA8E166338760880FC2C68466645DFB5CE60405F5E15DA9ACE9", "000212BE00025DB805D6B59D588982F60CF92BB743C05C2619919657462191847838E06703925057C5DC7A36080403CD446EF1B95DFB5E2F0405F5E1656929E3", "000212BF00024B0D40593576A382CD58DA5E2BB743C05C2619919657462191847838E0673C67D352F821E84195F9393C70A37BA15DFB5E7F0405F5E13425A20A", "000212C000022E28E85F3B565A9CE3A6D36F2BB743C05C2619919657462191847838E067B9321B6449970FB663B56210261D2AE75DFB5E800405F5E16742DE63", "000212C100022EABFB8FAF228721BA705F282BB743C05C2619919657462191847838E067C1D55AED879E3C2A39AD3DA4C72AA32C5DFB5EA10405F5E1351804AE", "000212C20002D918744D237CB620F05C04CB2BB743C05C2619919657462191847838E0673EFCD8817DD5C7DC3F71BCC71C992C1D5DFB5F0F0405F5E1382F2CCB", "000212C30002083EB27D9F62BE9FC7E178472BB743C05C2619919657462191847838E067AC554CC2C3E2942460A742093FA20F8D5DFB5F100405F5E138362725", "000212C4000282B9C1AF739155679954D27D2BB743C05C2619919657462191847838E067CEC2574589471F8635D3C85BC56803245DFB5F120405F5E13843B8A3", "000212C500028BD2113E1525CF7B7176DF782BB743C05C2619919657462191847838E0671B597D4BAE12B2A71CF670D6910608DF5DFB5F3C0405F5E139720FCD", "000212C600022E6EB382CD9D47641B43314C2BB743C05C2619919657462191847838E067073821D2D8891A8610B8C18897ED065A5DFB5F570405F5E16A8BEC2E", "000212C70002C1B622B7A4AB48CA23EAB9242BB743C05C2619919657462191847838E06731D8269A8DF296193B158E7059DA3E3C5DFB5FBF0405F5E16EC2628B", "000212C80002129B6280D651E9FC3D46799D2BB743C05C2619919657462191847838E067718CC361844278EAB1BD9E1FB387D0F45DFB5FC70405F5E16DAF3C66"};
    std::vector<std::string> bootstrap_bitcoin_blocks = {"000000204E2FE8861AF5135B650512F2197DA6F57EA4AE495959E2A3E5850000000000005C1C10A2A023B0375ABF924E0F04D36F1F645E5B906DEBCD59D1E9AAADA9029A0E56FB5DFFFF001B75696A5B", "000000208A55C72B18AF0884EBE94F035E3EF3F581C9BF2915F54EDBB3530000000000005BEF944BBC852CA367D9B771DC7060DBE373E78095758C03E0822B9EC0257579C056FB5DFFFF001B9E787E4A", "00000020615F9BFDF41FADEEC01BB69ED6A3B4751A1E6A3B3901554356E800000000000004E28DC3633A798A42113304FB3E23F2C34FB64BF16F85C96387D4336D1524A5FE57FB5DFFFF001BB06B5D3D", "00000020313C38FDA19B2DC29CD0B0C3A5D402B29DD99019573F7D03E049000000000000A27BB8E349594A307997AE3E27BB4B767E4FB61D5E6053DDDD12F41E67DA39E46058FB5DFFFF001BA234951F", "00000020AB142C1020A85F5F94A64FAF1073E10631BBA606F6895568C179000000000000B6DDC3FF20EF1AFD4070521270CCD9E9606CCCE4A21C1F4189F18A55A2496DB59258FB5DFFFF001B5114DFFD", "00000020F74C38CBF19627902641C66BEB42934DB826EEDDBE538D2B0AAF00000000000070551E97C33CE1B1E357984683606F0FBAAE1E79D350CFFA489A34CF0C8FA1DAF658FB5DFFFF001BD5A959BC", "00000020FDF387285B7C1444B37F5F4C68AEAE3C50D1B4E5989C123F2B2E000000000000026EBDB6D235AAC2E31EC757FFBF5A1B99CB7FFE9B8334EA618AA0BDA74806E43759FB5DFFFF001BACF5113C", "00000020862AA943B501E24F122BA508D444FDA9E6ED720D01C9C5FC254900000000000090BDE5548BEB2AAA1809A4CF667F72E6A1F82A221E58C7BF6E463E338BC64C74A959FB5DFFFF001B0957D25B", "000000207CE1E81B69DC90653C8652D7E897F66D7CF49C7D17AAF087A21E00000000000016D70855883C41BA77CA41BE3A30D3EC902132E317C29F2BFB298531DD54C09D6C5AFB5DFFFF001B36E17BC4", "0000002076FBC13AFFEABF306C9F00B7F046B3FC3257F6F4D9D96BE45E5600000000000011B793687891A9E218046C5A9DC5552F2DE86B4B6CFA6E70CC5F4F15F66FEEC6B25AFB5DFFFF001B1825B521", "00000020AA5B1689B9B745A265EF864C18E74E0615FD0ED4F919D2725A8E000000000000C5F543263E5D3A794FE3D4BE20CE131B134B32336FC2FBABDBE7E62F02A3F5A17A5BFB5DFFFF001BEDC8CF53", "000000200AD01BDE5BD4221A3CEF8A5DECB199B4B999D5157A48F20E9F1D000000000000E73841C91619662B365D690BD054F8A005C8DB2E22063872F91F3FD5E305AF05EB5BFB5DFFFF001B6BAA1754", "00000020BFA07C30A017FCEB97F0B738E4CCFB937809AFC370CDB93EECDC000000000000C0C55F28309FDB0F0EF745F9BA3118462529DFAE84B280578EBBF9F31E40DBC0C15EFB5DFFFF001BC597988F", "000000208791BB6E32BD11121C3BF13EBEF976C555CDC1D20C5CD60DCE56000000000000A4A861D7B9813C8BACB6C0C79BD6568C81DB4FEA90460375127BDDF2C425722BCD5EFB5DFFFF001B91F6168A", "000000206AB5E7E62B060B31171533EDFC60D473B2C4381768BAA5AD1D97000000000000EB6CCCE2E6FB36E7E75E0A0941691BF36053BD676A510C35CFFFB2A16A8621B56F5FFB5DFFFF001BB14CAEAD", "00000020E2EEC323DA41F7F3387E8E4F1BF313EDFD2247788CBA378900040000000000002878DE94F86A20B384C0B0FC6BAAD61EBB0DCDC7126684072CCAD3EE624905060F60FB5DFFFF001B2CBAA52B"};
    uint32_t bitcoin_first_block_height = 1628985;
};

} // namespace VeriBlock

#endif //BITCOIN_SRC_VBK_CONFIG_HPP

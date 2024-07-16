#ifndef BITCOIN_INDEX_BIP352_H
#define BITCOIN_INDEX_BIP352_H

#include <coins.h>
#include <index/base.h>
#include <pubkey.h>

class COutPoint;
class CBlockUndo;

static constexpr bool DEFAULT_BIP352_INDEX{false};
static constexpr bool DEFAULT_BIP352_CT_INDEX{false};

/**
 * This index is used to look up the tweaked sum of eligible public keys for a
 * given transaction hash. See BIP352.
 *
 * Currently only silent payments v0 exists. Future versions may expand the
 * existing index or create a (perhaps overlapping) new one.
 */
class BIP352Index final : public BaseIndex
{
public:
    /**
     * For each block hash we store and array of transactions. For each
     * transaction we store:
     * - the tweaked pubkey sum
     * - the highest output amount (for dust filtering)
     */
    using tweak_index_entry = std::vector<std::pair<CPubKey, uint8_t>>;
    static constexpr uint8_t dust_shift{4}; // Hexasat
    /* Maximum dust threshold that we can filter */
    static constexpr CAmount max_dust_threshold{CAmount(UINT8_MAX - 1) << dust_shift};

    class DB;

private:
    const std::unique_ptr<DB> m_db;

    /**  Whether this index has transaction cut-through enabled */
    bool m_cut_through{false};

    bool AllowPrune() const override { return false; }

    /**
     * Derive the silent payment tweaked public key for every block transaction.
     *
     *
     * @param[in] txs all block transactions
     * @param[in] block_undo block undo data
     * @param[out] index_entry the tweaked public keys, only for transactions that have one
     * @return false if something went wrong
     */
    bool GetSilentPaymentKeys(std::vector<CTransactionRef> txs, CBlockUndo& block_undo, tweak_index_entry& index_entry);

protected:
    bool CustomAppend(const interfaces::BlockInfo& block) override;

    BaseIndex::DB& GetDB() const override;
public:

    explicit BIP352Index(bool cut_through, std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    // Destructor is declared because this class contains a unique_ptr to an incomplete type.
    virtual ~BIP352Index() override;

    bool FindSilentPayment(const uint256& block_hash, tweak_index_entry& index_entry) const;
};

/// The global BIP325 index. May be null.
extern std::unique_ptr<BIP352Index> g_bip352_index;

/// The global BIP325 with transaction cut-through index. May be null.
extern std::unique_ptr<BIP352Index> g_bip352_ct_index;


#endif // BITCOIN_INDEX_BIP352_H

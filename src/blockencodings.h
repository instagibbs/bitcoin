// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKENCODINGS_H
#define BITCOIN_BLOCKENCODINGS_H

#include <crypto/siphash.h>
#include <primitives/block.h>

#include <functional>
#include <span>
#include <unordered_map>

class CTxMemPool;
class BlockValidationState;
namespace Consensus {
struct Params;
};

// Transaction compression schemes for compact block relay can be introduced by writing
// an actual formatter here.
using TransactionCompression = DefaultFormatter;

class DifferenceFormatter
{
    uint64_t m_shift = 0;

public:
    template<typename Stream, typename I>
    void Ser(Stream& s, I v)
    {
        if (v < m_shift || v >= std::numeric_limits<uint64_t>::max()) throw std::ios_base::failure("differential value overflow");
        WriteCompactSize(s, v - m_shift);
        m_shift = uint64_t(v) + 1;
    }
    template<typename Stream, typename I>
    void Unser(Stream& s, I& v)
    {
        uint64_t n = ReadCompactSize(s);
        m_shift += n;
        if (m_shift < n || m_shift >= std::numeric_limits<uint64_t>::max() || m_shift < std::numeric_limits<I>::min() || m_shift > std::numeric_limits<I>::max()) throw std::ios_base::failure("differential value overflow");
        v = I(m_shift++);
    }
};

class BlockTransactionsRequest {
public:
    // A BlockTransactionsRequest message
    uint256 blockhash;
    std::vector<uint16_t> indexes;

    SERIALIZE_METHODS(BlockTransactionsRequest, obj)
    {
        READWRITE(obj.blockhash, Using<VectorFormatter<DifferenceFormatter>>(obj.indexes));
    }
};

class BlockTransactions {
public:
    // A BlockTransactions message
    uint256 blockhash;
    std::vector<CTransactionRef> txn;

    BlockTransactions() = default;
    explicit BlockTransactions(const BlockTransactionsRequest& req) :
        blockhash(req.blockhash), txn(req.indexes.size()) {}

    SERIALIZE_METHODS(BlockTransactions, obj)
    {
        READWRITE(obj.blockhash, TX_WITH_WITNESS(Using<VectorFormatter<TransactionCompression>>(obj.txn)));
    }
};

// Dumb serialization/storage-helper for CBlockHeaderAndShortTxIDs and PartiallyDownloadedBlock
struct PrefilledTransaction {
    // Used as an offset since last prefilled tx in CBlockHeaderAndShortTxIDs,
    // as a proper transaction-in-block-index in PartiallyDownloadedBlock
    uint16_t index;
    CTransactionRef tx;

    SERIALIZE_METHODS(PrefilledTransaction, obj) { READWRITE(COMPACTSIZE(obj.index), TX_WITH_WITNESS(Using<TransactionCompression>(obj.tx))); }
};

typedef enum ReadStatus_t
{
    READ_STATUS_OK,
    READ_STATUS_INVALID, // Invalid object, peer is sending bogus crap
    READ_STATUS_FAILED, // Failed to process object
} ReadStatus;

class CBlockHeaderAndShortTxIDs {
    mutable std::optional<PresaltedSipHasher> m_hasher;
    uint64_t nonce;

    void FillShortTxIDSelector() const;

    friend class PartiallyDownloadedBlock;

protected:
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

public:
    static constexpr int SHORTTXIDS_LENGTH = 6;

    CBlockHeader header;

    /**
     * Dummy for deserialization
     */
    CBlockHeaderAndShortTxIDs() = default;

    /**
     * @param[in]  nonce  This should be randomly generated, and is used for the siphash secret key
     */
    CBlockHeaderAndShortTxIDs(const CBlock& block, uint64_t nonce);

    uint64_t GetShortID(const Wtxid& wtxid) const;

    size_t BlockTxCount() const { return shorttxids.size() + prefilledtxn.size(); }

    SERIALIZE_METHODS(CBlockHeaderAndShortTxIDs, obj)
    {
        READWRITE(obj.header, obj.nonce, Using<VectorFormatter<CustomUintFormatter<SHORTTXIDS_LENGTH>>>(obj.shorttxids), obj.prefilledtxn);
        if (ser_action.ForRead()) {
            if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max()) {
                throw std::ios_base::failure("indexes overflowed 16 bits");
            }
            obj.FillShortTxIDSelector();
        }
    }
};

class PartiallyDownloadedBlock {
protected:
    std::vector<CTransactionRef> txn_available;
    size_t prefilled_count = 0, mempool_count = 0, extra_count = 0, orphan_count = 0;
    const CTxMemPool* pool;

    // Lifecycle of a PartiallyDownloadedBlock. Retained match state
    // (m_shorttxids/m_have_txn) is only valid in the INITIALIZED state, which is
    // why a second matching pass (TryFillFromExtra) is gated on it.
    enum class State { EMPTY, INITIALIZED, FILLED };
    State m_state{State::EMPTY};

    // Retained from InitData so a follow-up matching pass can resolve
    // still-missing slots. m_have_txn is NOT equivalent to (txn_available[i] !=
    // nullptr): a short-ID collision blacklists a slot by resetting
    // txn_available[i] while leaving m_have_txn[i] == true ("force a request,
    // do not guess"). The second pass must consult m_have_txn for correctness.
    std::unordered_map<uint64_t, uint16_t> m_shorttxids;
    std::vector<bool> m_have_txn;

    // Match a single candidate transaction against the still-missing short-ID
    // slots, filling or blacklisting as appropriate. attribution_count is the
    // per-source stat counter to bump on a fill (extra_count or orphan_count).
    void MatchExtraTransaction(const CBlockHeaderAndShortTxIDs& cmpctblock,
                               const CTransactionRef& tx, size_t& attribution_count);

public:
    CBlockHeader header;

    // Can be overridden for testing
    using IsBlockMutatedFn = std::function<bool(const CBlock&, bool)>;
    IsBlockMutatedFn m_check_block_mutated_mock{nullptr};

    explicit PartiallyDownloadedBlock(CTxMemPool* poolIn) : pool(poolIn) {}

    // extra_txn is a list of extra transactions to look at, in <witness hash, reference> form
    ReadStatus InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<Wtxid, CTransactionRef>>& extra_txn);

    // Lazy second pass: try to fill still-missing slots from additional candidate
    // transactions (e.g. the orphanage). Must be called after a successful
    // InitData and before FillBlock, with the SAME cmpctblock. Repeatable and
    // idempotent for already-seen transactions.
    ReadStatus TryFillFromExtra(const CBlockHeaderAndShortTxIDs& cmpctblock,
                                std::span<const CTransactionRef> extra);

    bool IsTxAvailable(size_t index) const;
    // Serialized size (with witness) of the transaction available at index, or 0 if
    // the slot is not currently available. Only meaningful in the INITIALIZED state.
    size_t GetTxSize(size_t index) const;
    // segwit_active enforces witness mutation checks just before reporting a healthy status
    ReadStatus FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing, bool segwit_active);
};

#endif // BITCOIN_BLOCKENCODINGS_H

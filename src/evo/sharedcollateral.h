// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_SHAREDCOLLATERAL_H
#define BITCOIN_EVO_SHAREDCOLLATERAL_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <serialize.h>

#include <cstdint>
#include <vector>

class CProRegTx;
class CTransaction;
class TxValidationState;
class UniValue;
class uint256;

// Prototype implementation of the shared masternode collateral covenant
// (dashpay/dips#187, "Decentralized Masternode Shares", Draft). The share table
// extends the version 4 (MultiPayout) ProRegTx payload; the collateral output of
// a shared registration must be exactly the 7-byte template below, and can only
// be spent by a valid ProDisTx.

namespace SharedCollateral {

// "DSHC" OP_DROP OP_TRUE - exact-script match, never prefix
static const std::vector<unsigned char> TEMPLATE_BYTES{0x04, 0x44, 0x53, 0x48, 0x43, 0x75, 0x51};

inline CScript TemplateScript()
{
    return CScript(TEMPLATE_BYTES.begin(), TEMPLATE_BYTES.end());
}

inline bool IsTemplateScript(const CScript& script)
{
    return script.size() == TEMPLATE_BYTES.size() &&
           std::equal(script.begin(), script.end(), TEMPLATE_BYTES.begin());
}

static constexpr uint8_t MIN_SHARES{2};
static constexpr uint8_t MAX_SHARES{8};
static constexpr CAmount MIN_SHARE_AMOUNT{100 * COIN};
static constexpr uint32_t MAX_EARLY_PERIOD_BLOCKS{420480}; // ~2 years at 2.5-minute blocks
static constexpr size_t COMPACT_SIG_SIZE{65};

} // namespace SharedCollateral

class CCollateralShare
{
public:
    CAmount amount{0};
    CScript refundScript;  // immutable principal refund destination (P2PKH/P2SH)
    CScript rewardScript;  // reward destination; empty means "use refundScript"
    CKeyID ownerKeyID;     // immutable share owner key

    SERIALIZE_METHODS(CCollateralShare, obj)
    {
        READWRITE(obj.amount, obj.refundScript, obj.rewardScript, obj.ownerKeyID);
    }

    bool operator==(const CCollateralShare& rhs) const
    {
        return amount == rhs.amount && refundScript == rhs.refundScript &&
               rewardScript == rhs.rewardScript && ownerKeyID == rhs.ownerKeyID;
    }
    bool operator!=(const CCollateralShare& rhs) const { return !(*this == rhs); }

    std::string ToString() const;
};

using CollateralShareList = std::vector<CCollateralShare>;

// Context-free validity of a share table (spec 4.5 rules 6-10, minus the
// collateral-sum rule, which needs the transaction's collateral output).
bool IsShareTableTriviallyValid(const CollateralShareList& shares, const CKeyID& keyIDVoting,
                                uint32_t nEarlyPeriodBlocks, CAmount nEarlyPenalty,
                                TxValidationState& state);

// SharedRegConsentHash (spec 4.5): binds every participant's registration consent to
// the funding prevouts, all outputs, the full share table, the penalty terms, and the
// registrar configuration. joinSigs sign this digest.
uint256 ComputeSharedRegConsentHash(const CProRegTx& proTx, const CTransaction& tx);

// ProDisTx (spec 4.6): the consensus-enforced dissolution that is the ONLY way the
// template collateral can move. It refunds every participant to their immutable refund
// script, applying the early-period penalty on a unilateral early exit.
class CProDisTx
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_PROVIDER_DISSOLVE;

    uint16_t nVersion{1};
    uint256 proTxHash;    // the shared masternode being dissolved
    uint16_t actorIndex{0};  // index into the share table of the actor (pays penalty + fee)
    // sigCount is implied by vecSigs.size(): 1 = unilateral, sharesCount = unanimous.
    std::vector<std::vector<unsigned char>> vecSigs; // 65-byte compact sigs over SharedDisHash

    SERIALIZE_METHODS(CProDisTx, obj)
    {
        READWRITE(obj.nVersion, obj.proTxHash, obj.actorIndex);
        uint8_t sig_count{0};
        SER_WRITE(obj, sig_count = static_cast<uint8_t>(obj.vecSigs.size()));
        READWRITE(sig_count);
        SER_READ(obj, obj.vecSigs.assign(sig_count, std::vector<unsigned char>(SharedCollateral::COMPACT_SIG_SIZE)));
        for (auto& sig : obj.vecSigs) {
            SER_WRITE(obj, if (sig.size() != SharedCollateral::COMPACT_SIG_SIZE) throw std::ios_base::failure("ProDisTx sig must be 65 bytes"));
            READWRITE(Span{sig});
        }
    }

    std::string ToString() const;
    [[nodiscard]] UniValue ToJson() const;
};

// ProUpShareTx (spec 4.7): updates exactly one share's rewardScript; everything else
// about the share is immutable for the life of the masternode.
class CProUpShareTx
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_PROVIDER_UPDATE_SHARE;

    uint16_t nVersion{1};
    uint256 proTxHash;
    uint16_t shareIndex{0};
    CScript rewardScript;   // new reward script (P2PKH/P2SH), or empty for "use refundScript"
    uint256 inputsHash;
    std::vector<unsigned char> vchSig; // by shares[shareIndex].ownerKeyID over the payload hash

    SERIALIZE_METHODS(CProUpShareTx, obj)
    {
        READWRITE(obj.nVersion, obj.proTxHash, obj.shareIndex, obj.rewardScript, obj.inputsHash);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(obj.vchSig);
        }
    }

    std::string ToString() const;
    [[nodiscard]] UniValue ToJson() const;
};

// SharedDisHash (spec 4.6): commits to the transaction's actual input and outputs directly,
// plus proTxHash, actorIndex, and sigCount (which selects the mode). The empty-scriptSig
// rule plus low-S signatures pin every free byte, making the ProDisTx txid non-malleable.
uint256 ComputeSharedDisHash(const CProDisTx& disTx, const CTransaction& tx, uint8_t sigCount);

#endif // BITCOIN_EVO_SHAREDCOLLATERAL_H

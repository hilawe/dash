// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_SHAREDCOLLATERAL_H
#define BITCOIN_EVO_SHAREDCOLLATERAL_H

#include <consensus/amount.h>
#include <pubkey.h>
#include <script/script.h>
#include <serialize.h>

#include <cstdint>
#include <vector>

class CProRegTx;
class CTransaction;
class TxValidationState;
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

#endif // BITCOIN_EVO_SHAREDCOLLATERAL_H

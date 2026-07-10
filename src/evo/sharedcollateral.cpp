// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/sharedcollateral.h>

#include <clientversion.h>
#include <consensus/validation.h>
#include <evo/netinfo.h>
#include <evo/providertx.h>
#include <evo/specialtx.h>
#include <hash.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <set>

std::string CCollateralShare::ToString() const
{
    CTxDestination dest;
    std::string payee = ExtractDestination(refundScript, dest) ? EncodeDestination(dest) : "unknown";
    return strprintf("CCollateralShare(amount=%d.%08d, refund=%s, reward=%s, ownerKey=%s)",
                     amount / COIN, amount % COIN, payee,
                     rewardScript.empty() ? "(refund)" : HexStr(rewardScript), ownerKeyID.ToString());
}

static bool IsValidShareScript(const CScript& script)
{
    return script.IsPayToPublicKeyHash() || script.IsPayToScriptHash();
}

// Does `script` pay P2PKH to `keyID`? (P2PK is not expressible via CKeyID-only
// comparison at this layer; the spec's P2PK case is covered because share scripts
// must be P2PKH or P2SH, so P2PK never appears in a share table.)
static bool PaysToKeyID(const CScript& script, const CKeyID& keyID)
{
    CTxDestination dest;
    return ExtractDestination(script, dest) && dest == CTxDestination(PKHash(keyID));
}

bool IsShareTableTriviallyValid(const CollateralShareList& shares, const CKeyID& keyIDVoting,
                                uint32_t nEarlyPeriodBlocks, CAmount nEarlyPenalty,
                                TxValidationState& state)
{
    if (shares.size() < SharedCollateral::MIN_SHARES || shares.size() > SharedCollateral::MAX_SHARES) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-shares-count");
    }

    CAmount min_amount{std::numeric_limits<CAmount>::max()};
    std::set<CKeyID> seen_keys;
    std::set<CScript> seen_refunds;
    for (const auto& share : shares) {
        if (share.amount < SharedCollateral::MIN_SHARE_AMOUNT || !MoneyRange(share.amount)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-share-amount");
        }
        min_amount = std::min(min_amount, share.amount);

        if (share.ownerKeyID.IsNull() || !seen_keys.emplace(share.ownerKeyID).second) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-share-owner-key");
        }
        if (!IsValidShareScript(share.refundScript) ||
            !seen_refunds.emplace(share.refundScript).second) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-share-refund");
        }
        // rewardScript: empty means "use refundScript"; otherwise same restrictions
        if (!share.rewardScript.empty() && !IsValidShareScript(share.rewardScript)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-share-reward");
        }
        if (SharedCollateral::IsTemplateScript(share.refundScript) ||
            SharedCollateral::IsTemplateScript(share.rewardScript)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-share-template-dest");
        }
    }

    // no refund/reward script may pay any share owner key or the voting key
    // (key separation: owner-key compromise must never endanger principal)
    for (const auto& share : shares) {
        for (const auto& other : shares) {
            if (PaysToKeyID(share.refundScript, other.ownerKeyID) ||
                PaysToKeyID(share.rewardScript, other.ownerKeyID)) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-share-key-reuse");
            }
        }
        if (PaysToKeyID(share.refundScript, keyIDVoting) || PaysToKeyID(share.rewardScript, keyIDVoting)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-share-key-reuse");
        }
    }

    if (nEarlyPenalty < 0 || nEarlyPenalty >= min_amount) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-share-penalty");
    }
    if (nEarlyPeriodBlocks > SharedCollateral::MAX_EARLY_PERIOD_BLOCKS) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-share-early-period");
    }
    return true;
}

static uint256 CalcTxOutputsHash(const CTransaction& tx)
{
    CHashWriter hw(SER_GETHASH, CLIENT_VERSION);
    for (const auto& out : tx.vout) {
        hw << out;
    }
    return hw.GetHash();
}

uint256 ComputeSharedRegConsentHash(const CProRegTx& proTx, const CTransaction& tx)
{
    // spec 4.5: "DashSharedMNReg" || payload version || tx version || tx type ||
    // tx nLockTime || inputsHash || outputsHash || type || mode || netInfo and
    // Platform fields || keyIdVoting || pubKeyOperator || operatorReward ||
    // shares || earlyPeriodBlocks || earlyPenalty
    CHashWriter hw(SER_GETHASH, CLIENT_VERSION);
    hw << std::string("DashSharedMNReg");
    hw << proTx.nVersion;
    hw << tx.nVersion;
    hw << tx.nType;
    hw << tx.nLockTime;
    hw << CalcTxInputsHash(tx);
    hw << CalcTxOutputsHash(tx);
    hw << proTx.nType;
    hw << proTx.nMode;
    hw << NetInfoSerWrapper(const_cast<std::shared_ptr<NetInfoInterface>&>(proTx.netInfo),
                            proTx.nVersion >= ProTxVersion::ExtAddr);
    hw << proTx.platformNodeID << proTx.platformP2PPort << proTx.platformHTTPPort;
    hw << proTx.keyIDVoting;
    hw << proTx.pubKeyOperator;
    hw << proTx.nOperatorReward;
    hw << proTx.shares;
    hw << proTx.nEarlyPeriodBlocks;
    hw << proTx.nEarlyPenalty;
    return hw.GetHash();
}

uint256 ComputeSharedDisHash(const CProDisTx& disTx, const CTransaction& tx, uint8_t sigCount)
{
    // spec 4.6: "DashSharedMNDissolve" || payload version || tx version || tx type ||
    // tx nLockTime || all input prevouts || all input sequences || all outputs ||
    // proTxHash || actorIndex || sigCount
    CHashWriter hw(SER_GETHASH, CLIENT_VERSION);
    hw << std::string("DashSharedMNDissolve");
    hw << disTx.nVersion;
    hw << tx.nVersion;
    hw << tx.nType;
    hw << tx.nLockTime;
    for (const auto& in : tx.vin) hw << in.prevout;
    for (const auto& in : tx.vin) hw << in.nSequence;
    for (const auto& out : tx.vout) hw << out;
    hw << disTx.proTxHash;
    hw << disTx.actorIndex;
    hw << sigCount;
    return hw.GetHash();
}

std::string CProDisTx::ToString() const
{
    return strprintf("CProDisTx(nVersion=%d, proTxHash=%s, actorIndex=%d, sigCount=%d)",
                     nVersion, proTxHash.ToString(), actorIndex, vecSigs.size());
}

UniValue CProDisTx::ToJson() const
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("version", nVersion);
    ret.pushKV("proTxHash", proTxHash.ToString());
    ret.pushKV("actorIndex", actorIndex);
    ret.pushKV("sigCount", (uint64_t)vecSigs.size());
    ret.pushKV("mode", vecSigs.size() == 1 ? "unilateral" : "unanimous");
    return ret;
}

std::string CProUpShareTx::ToString() const
{
    return strprintf("CProUpShareTx(nVersion=%d, proTxHash=%s, shareIndex=%d)",
                     nVersion, proTxHash.ToString(), shareIndex);
}

UniValue CProUpShareTx::ToJson() const
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("version", nVersion);
    ret.pushKV("proTxHash", proTxHash.ToString());
    ret.pushKV("shareIndex", shareIndex);
    if (CTxDestination d; !rewardScript.empty() && ExtractDestination(rewardScript, d)) {
        ret.pushKV("rewardAddress", EncodeDestination(d));
    }
    ret.pushKV("inputsHash", inputsHash.ToString());
    return ret;
}

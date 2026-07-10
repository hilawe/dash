// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/sharedcollateral.h>

#include <clientversion.h>
#include <coins.h>
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

bool SharedCollateral::IsCanonicalCompactSig(const std::vector<unsigned char>& sig)
{
    if (sig.size() != COMPACT_SIG_SIZE) return false;
    // header byte: 27 + recid(0..3) + (compressed ? 4 : 0), i.e. 27..34
    if (sig[0] < 27 || sig[0] > 34) return false;
    // reject high-S: S (the last 32 bytes, big-endian) must be <= n/2, where n is the
    // secp256k1 group order. n/2 = 0x7FFFFFFF...5D576E7357A4501DDFE92F46681B20A0.
    static const unsigned char HALF_ORDER[32] = {
        0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0,
    };
    for (size_t i = 0; i < 32; ++i) {
        const unsigned char s = sig[1 + 32 + i];
        if (s < HALF_ORDER[i]) return true;   // strictly below at this byte => low-S
        if (s > HALF_ORDER[i]) return false;  // strictly above => high-S
    }
    return true; // exactly n/2 is permitted (canonical)
}

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

bool CheckTemplateSpendCreation(const CTransaction& tx, const CCoinsViewCache& view, TxValidationState& state)
{
    // spend rule: a template output may be spent only by a ProDisTx (which is further validated
    // to be a valid dissolution of the masternode owning that outpoint in CheckProDisTx).
    const bool isDissolve = tx.IsSpecialTxVersion() && tx.nType == TRANSACTION_PROVIDER_DISSOLVE;
    if (!isDissolve && !tx.IsCoinBase()) {
        for (const auto& in : tx.vin) {
            const Coin& coin = view.AccessCoin(in.prevout);
            if (!coin.IsSpent() && SharedCollateral::IsTemplateScript(coin.out.scriptPubKey)) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-txns-template-spend");
            }
        }
    }
    // creation rule: a template output may be created only in a shared registration. The exact
    // collateral slot and single-occurrence are enforced in CheckProRegTx, which also rejects a
    // template output in a NON-shared registration, so here a template output is allowed only in
    // a provider-register transaction and forbidden everywhere else, the coinbase included.
    const bool isRegister = tx.IsSpecialTxVersion() && tx.nType == TRANSACTION_PROVIDER_REGISTER;
    if (!isRegister) {
        for (const auto& out : tx.vout) {
            if (SharedCollateral::IsTemplateScript(out.scriptPubKey)) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-txns-template-create");
            }
        }
    }
    return true;
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

// CProDisTx::ToJson() defined in evo/core_write.cpp (libbitcoin_common, like the other
// special-tx payload JSON writers, so that common-layer consumers like dash-tx link)

std::string CProUpShareTx::ToString() const
{
    return strprintf("CProUpShareTx(nVersion=%d, proTxHash=%s, shareIndex=%d)",
                     nVersion, proTxHash.ToString(), shareIndex);
}

// CProUpShareTx::ToJson() defined in evo/core_write.cpp (see the note above)

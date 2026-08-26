// Copyright (c) 2018-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/specialtxman.h>

#include <chainlock/chainlock.h>
#include <chainlock/clsig.h>
#include <chainlock/handler.h>
#include <evo/assetlocktx.h>
#include <evo/cbtx.h>
#include <evo/creditpool.h>
#include <evo/deterministicmns.h>
#include <evo/mnhftx.h>
#include <evo/netinfo.h>
#include <evo/sharedcollateral.h>
#include <evo/simplifiedmns.h>
#include <llmq/blockprocessor.h>
#include <llmq/commitment.h>
#include <llmq/quorumsman.h>
#include <llmq/utils.h>
#include <messagesigner.h>
#include <util/helpers.h>

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <hash.h>
#include <primitives/block.h>
#include <util/system.h>
#include <validation.h>

static bool AddNetInfoEntries(const std::shared_ptr<NetInfoInterface>& net_info, NetInfoPurpose purpose,
                              const NetInfoList& entries, BlockValidationState& state)
{
    for (const auto& entry : entries) {
        if (const auto ret{net_info->AddEntry(purpose, entry.ToStringAddrPort())}; ret != NetInfoStatus::Success) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-netinfo-version");
        }
    }
    return true;
}

static bool SetStateVersion(CDeterministicMNState& state_mn, uint16_t nVersion, MnType nType,
                            BlockValidationState& state)
{
    const bool needs_extended = nVersion >= ProTxVersion::ExtAddr;
    if (state_mn.nVersion == nVersion && state_mn.netInfo->CanStorePlatform() == needs_extended) {
        return true;
    }

    auto converted_netinfo{NetInfoInterface::MakeNetInfo(nVersion)};
    if (needs_extended) {
        if (!AddNetInfoEntries(converted_netinfo, NetInfoPurpose::CORE_P2P,
                               state_mn.netInfo->GetEntries(NetInfoPurpose::CORE_P2P), state)) {
            return false;
        }
        if (state_mn.netInfo->CanStorePlatform()) {
            if (!AddNetInfoEntries(converted_netinfo, NetInfoPurpose::PLATFORM_P2P,
                                   state_mn.netInfo->GetEntries(NetInfoPurpose::PLATFORM_P2P), state) ||
                !AddNetInfoEntries(converted_netinfo, NetInfoPurpose::PLATFORM_HTTPS,
                                   state_mn.netInfo->GetEntries(NetInfoPurpose::PLATFORM_HTTPS), state)) {
                return false;
            }
        } else if (nType == MnType::Evo && !state_mn.netInfo->IsEmpty()) {
            const CNetAddr addr{state_mn.netInfo->GetPrimary()};
            if ((state_mn.platformP2PPort != 0 &&
                 converted_netinfo->AddEntry(NetInfoPurpose::PLATFORM_P2P,
                                             CService(addr, state_mn.platformP2PPort).ToStringAddrPort()) != NetInfoStatus::Success) ||
                (state_mn.platformHTTPPort != 0 &&
                 converted_netinfo->AddEntry(NetInfoPurpose::PLATFORM_HTTPS,
                                             CService(addr, state_mn.platformHTTPPort).ToStringAddrPort()) != NetInfoStatus::Success)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-netinfo-version");
            }
        }
        state_mn.platformP2PPort = 0;
        state_mn.platformHTTPPort = 0;
    } else {
        if (!AddNetInfoEntries(converted_netinfo, NetInfoPurpose::CORE_P2P,
                               state_mn.netInfo->GetEntries(NetInfoPurpose::CORE_P2P), state)) {
            return false;
        }
        if (nType == MnType::Evo && state_mn.netInfo->CanStorePlatform() && !state_mn.netInfo->IsEmpty()) {
            const auto p2p_entries{state_mn.netInfo->GetEntries(NetInfoPurpose::PLATFORM_P2P)};
            const auto http_entries{state_mn.netInfo->GetEntries(NetInfoPurpose::PLATFORM_HTTPS)};
            state_mn.platformP2PPort = p2p_entries.empty() ? 0 : p2p_entries.front().GetPort();
            state_mn.platformHTTPPort = http_entries.empty() ? 0 : http_entries.front().GetPort();
        }
    }

    state_mn.nVersion = nVersion;
    state_mn.netInfo = std::move(converted_netinfo);
    return true;
}

static bool CheckCbTxBestChainlock(const CCbTx& cbTx, const CBlockIndex* pindex, const Consensus::Params& consensus_params,
                                   const CChain& chain, const llmq::CQuorumManager& qman,
                                   const chainlock::Chainlocks& chainlocks, BlockValidationState& state)
{
    if (cbTx.nVersion < CCbTx::Version::CLSIG_AND_BALANCE) {
        return true;
    }

    static Mutex cached_mutex;
    static const CBlockIndex* cached_pindex GUARDED_BY(cached_mutex){nullptr};
    static std::optional<std::pair<CBLSSignature, uint32_t>> cached_chainlock GUARDED_BY(cached_mutex){std::nullopt};

    auto best_clsig = chainlocks.GetBestChainLock();
    if (best_clsig.getHeight() == pindex->nHeight - 1 && cbTx.bestCLHeightDiff == 0 &&
        cbTx.bestCLSignature == best_clsig.getSig()) {
        // matches our best clsig which still hold values for the previous block
        LOCK(cached_mutex);
        cached_chainlock = std::make_pair(cbTx.bestCLSignature, cbTx.bestCLHeightDiff);
        cached_pindex = pindex;
        return true;
    }

    std::optional<std::pair<CBLSSignature, uint32_t>> prevBlockCoinbaseChainlock{std::nullopt};
    if (LOCK(cached_mutex); cached_pindex == pindex->pprev) {
        prevBlockCoinbaseChainlock = cached_chainlock;
    }
    if (!prevBlockCoinbaseChainlock.has_value()) {
        prevBlockCoinbaseChainlock = GetNonNullCoinbaseChainlock(pindex->pprev);
    }
    // If std::optional prevBlockCoinbaseChainlock is empty, then up to the previous block, coinbase Chainlock is null.
    if (prevBlockCoinbaseChainlock.has_value()) {
        // Previous block Coinbase has a non-null Chainlock: current block's Chainlock must be non-null and at least as new as the previous one
        if (!cbTx.bestCLSignature.IsValid()) {
            // IsNull() doesn't exist for CBLSSignature: we assume that a non valid BLS sig is null
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-null-clsig");
        }
        if (cbTx.bestCLHeightDiff > prevBlockCoinbaseChainlock.value().second + 1) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-older-clsig");
        }
    }

    // IsNull() doesn't exist for CBLSSignature: we assume that a valid BLS sig is non-null
    if (cbTx.bestCLSignature.IsValid()) {
        int curBlockCoinbaseCLHeight = pindex->nHeight - static_cast<int>(cbTx.bestCLHeightDiff) - 1;
        if (best_clsig.getHeight() == curBlockCoinbaseCLHeight && best_clsig.getSig() == cbTx.bestCLSignature) {
            // matches our best (but outdated) clsig, no need to verify it again
            LOCK(cached_mutex);
            cached_chainlock = std::make_pair(cbTx.bestCLSignature, cbTx.bestCLHeightDiff);
            cached_pindex = pindex;
            return true;
        }
        uint256 curBlockCoinbaseCLBlockHash = pindex->GetAncestor(curBlockCoinbaseCLHeight)->GetBlockHash();
        chainlock::ChainLockSig clsig{curBlockCoinbaseCLHeight, curBlockCoinbaseCLBlockHash, cbTx.bestCLSignature};
        llmq::VerifyRecSigStatus ret = chainlock::VerifyChainLock(consensus_params, chain, qman, clsig);
        if (ret != llmq::VerifyRecSigStatus::Valid) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-invalid-clsig");
        }
        LOCK(cached_mutex);
        cached_chainlock = std::make_pair(cbTx.bestCLSignature, cbTx.bestCLHeightDiff);
        cached_pindex = pindex;
    } else if (cbTx.bestCLHeightDiff != 0) {
        // Null bestCLSignature is allowed only with bestCLHeightDiff = 0
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-cldiff");
    }

    return true;
}

static bool CheckSpecialTxInner(CDeterministicMNManager& dmnman, llmq::CQuorumSnapshotManager& qsnapman,
                                const ChainstateManager& chainman, const llmq::CQuorumManager& qman,
                                const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache& view,
                                const std::optional<CRangesSet>& indexes, bool check_sigs, TxValidationState& state)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);

    if (!tx.HasExtraPayloadField())
        return true;

    if (!DeploymentActiveAfter(pindexPrev, chainman.GetConsensus(), Consensus::DEPLOYMENT_DIP0003)) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-tx-type-dip3-inactive");
    }

    try {
        switch (tx.nType) {
        case TRANSACTION_PROVIDER_REGISTER:
            return CheckProRegTx(tx, pindexPrev, dmnman, view, chainman, state, check_sigs);
        case TRANSACTION_PROVIDER_UPDATE_SERVICE:
            return CheckProUpServTx(tx, pindexPrev, dmnman, chainman, state, check_sigs);
        case TRANSACTION_PROVIDER_UPDATE_REGISTRAR:
            return CheckProUpRegTx(tx, pindexPrev, dmnman, view, chainman, state, check_sigs);
        case TRANSACTION_PROVIDER_UPDATE_REVOKE:
            return CheckProUpRevTx(tx, pindexPrev, dmnman, chainman, state, check_sigs);
        case TRANSACTION_COINBASE: {
            if (!tx.IsCoinBase()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cbtx-invalid");
            }
            if (const auto opt_cbTx = GetTxPayload<CCbTx>(tx)) {
                return CheckCbTx(*opt_cbTx, pindexPrev, state);
            } else {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cbtx-payload");
            }
        }
        case TRANSACTION_QUORUM_COMMITMENT:
            return llmq::CheckLLMQCommitment({dmnman, qsnapman, chainman, pindexPrev}, tx, state);
        case TRANSACTION_MNHF_SIGNAL:
            return CheckMNHFTx(chainman, qman, tx, pindexPrev, state);
        case TRANSACTION_ASSET_LOCK:
            return CheckAssetLockTx(tx, state);
        case TRANSACTION_ASSET_UNLOCK:
            return CheckAssetUnlockTx(chainman.m_blockman, qman, tx, pindexPrev, indexes, state);
        case TRANSACTION_PROVIDER_DISSOLVE:
            return CheckProDisTx(tx, pindexPrev, dmnman, chainman, state, check_sigs);
        case TRANSACTION_PROVIDER_UPDATE_SHARE:
            return CheckProUpShareTx(tx, pindexPrev, dmnman, chainman, state, check_sigs);
        }
    } catch (const std::exception& e) {
        LogPrintf("%s -- failed: %s\n", __func__, e.what());
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-check-special-tx");
    }

    return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-tx-type-check");
}

bool CSpecialTxProcessor::CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool check_sigs, TxValidationState& state)
{
    AssertLockHeld(::cs_main);
    return CheckSpecialTxInner(m_dmnman, m_qsnapman, m_chainman, m_qman, tx, pindexPrev, view, std::nullopt, check_sigs,
                               state);
}

static void HandleQuorumCommitment(const llmq::CFinalCommitment& qc, const std::vector<CDeterministicMNCPtr>& members,
                                   bool debugLogs, CDeterministicMNList& mnList)
{
    for (size_t i = 0; i < members.size(); i++) {
        if (!mnList.HasMN(members[i]->proTxHash)) {
            continue;
        }
        if (!qc.validMembers[i]) {
            // punish MN for failed DKG participation
            // The idea is to immediately ban a MN when it fails 2 DKG sessions with only a few blocks in-between
            // If there were enough blocks between failures, the MN has a chance to recover as he reduces his penalty by 1 for every block
            // If it however fails 3 times in the timespan of a single payment cycle, it should definitely get banned
            mnList.PoSePunish(members[i]->proTxHash, mnList.CalcPenalty(66), debugLogs);
        }
    }
}

bool CSpecialTxProcessor::BuildNewListFromBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindexPrev,
                                                const CCoinsViewCache& view, bool debugLogs,
                                                BlockValidationState& state, CDeterministicMNList& mnListRet)
{
    AssertLockHeld(cs_main);
    CDeterministicMNList oldList = m_dmnman.GetListForBlock(pindexPrev);
    return RebuildListFromBlock(block, pindexPrev, oldList, view, debugLogs, state, mnListRet);
}

bool CSpecialTxProcessor::RebuildListFromBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindexPrev,
                                                const CDeterministicMNList& prevList, const CCoinsViewCache& view,
                                                bool debugLogs, BlockValidationState& state,
                                                CDeterministicMNList& mnListRet)
{
    // Verify that prevList either represents an empty/initial state (default-constructed),
    // or it matches the previous block's hash.
    assert(prevList == CDeterministicMNList() || prevList.GetBlockHash() == pindexPrev->GetBlockHash());

    int nHeight = pindexPrev->nHeight + 1;

    CDeterministicMNList newList = prevList;
    newList.SetBlockHash(uint256()); // we can't know the final block hash, so better not return a (invalid) block hash
    newList.SetHeight(nHeight);

    auto payee = prevList.GetMNPayee(pindexPrev);

    // we iterate the prevList here and update the newList
    // this is only valid as long these have not diverged at this point, which is the case as long as we don't add
    // code above this loop that modifies newList
    prevList.ForEachMN(/*onlyValid=*/false, [&pindexPrev, &newList, this](const auto& dmn) {
        if (!dmn.pdmnState->confirmedHash.IsNull()) {
            // already confirmed
            return;
        }
        // this works on the previous block, so confirmation will happen one block after nMasternodeMinimumConfirmations
        // has been reached, but the block hash will then point to the block at nMasternodeMinimumConfirmations
        int nConfirmations = pindexPrev->nHeight - dmn.pdmnState->nRegisteredHeight;
        if (nConfirmations >= this->m_consensus_params.nMasternodeMinimumConfirmations) {
            auto newState = std::make_shared<CDeterministicMNState>(*dmn.pdmnState);
            newState->UpdateConfirmedHash(dmn.proTxHash, pindexPrev->GetBlockHash());
            newList.UpdateMN(dmn.proTxHash, newState);
        }
    });

    newList.DecreaseScores();

    const bool isMNRewardReallocation{
        DeploymentActiveAfter(pindexPrev, m_chainman.GetConsensus(), Consensus::DEPLOYMENT_MN_RR)};
    const bool is_v24_deployed{DeploymentActiveAfter(pindexPrev, m_chainman, Consensus::DEPLOYMENT_V24)};

    // dips#187 template spend/creation enforcement, gated on v24 and applied to
    // EVERY transaction including the coinbase, so a template output cannot be created outside a
    // shared registration and template collateral cannot be spent except by a ProDisTx.
    if (is_v24_deployed) {
        // `view` reflects the pre-block UTXO set, so it does not see a template output created
        // earlier in THIS block. Track those outpoints in transaction order so a same-block
        // create-then-spend by a non-ProDisTx is still caught.
        std::set<COutPoint> block_template_outpoints;
        for (const auto& ptx : block.vtx) {
            // vtx[0] is a null placeholder while CreateNewBlock is still assembling our own
            // coinbase; at block CONNECTION every entry (coinbase included) is populated and
            // checked, which is the path that matters for validating someone else's block.
            if (!ptx) continue;
            TxValidationState tx_state;
            if (!CheckTemplateSpendCreation(*ptx, view, tx_state)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, tx_state.GetRejectReason());
            }
            const bool isDissolve = ptx->IsSpecialTxVersion() && ptx->nType == TRANSACTION_PROVIDER_DISSOLVE;
            if (!isDissolve && !ptx->IsCoinBase()) {
                for (const auto& in : ptx->vin) {
                    if (block_template_outpoints.count(in.prevout)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-template-spend");
                    }
                }
            }
            for (size_t n = 0; n < ptx->vout.size(); ++n) {
                if (SharedCollateral::IsTemplateScript(ptx->vout[n].scriptPubKey)) {
                    block_template_outpoints.emplace(ptx->GetHash(), n);
                }
            }
        }
    }

    // we skip the coinbase
    for (int i = 1; i < (int)block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];

        if (!tx.IsSpecialTxVersion()) {
            // only interested in special TXs
            continue;
        }

        if (tx.nType == TRANSACTION_PROVIDER_REGISTER) {
            const auto opt_proTx = GetTxPayload<CProRegTx>(tx);
            if (!opt_proTx) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-payload");
            }
            auto& proTx = *opt_proTx;

            auto dmn = std::make_shared<CDeterministicMN>(newList.GetTotalRegisteredCount(), proTx.nType);
            dmn->proTxHash = tx.GetHash();

            // collateralOutpoint is either pointing to an external collateral or to the ProRegTx itself
            if (proTx.collateralOutpoint.hash.IsNull()) {
                dmn->collateralOutpoint = COutPoint(tx.GetHash(), proTx.collateralOutpoint.n);
            } else {
                dmn->collateralOutpoint = proTx.collateralOutpoint;
            }

            // Complain about spent collaterals only when we process the tip.
            // This is safe because blocks below the tip were verified
            // when they were connected initially.
            if (!view.GetBestBlock().IsNull()) {
                Coin coin;
                CAmount expectedCollateral = GetMnType(proTx.nType).collat_amount;
                if (!proTx.collateralOutpoint.hash.IsNull() && (!view.GetCoin(dmn->collateralOutpoint, coin) ||
                                                                coin.IsSpent() || coin.out.nValue != expectedCollateral)) {
                    // should actually never get to this point as CheckProRegTx should have handled this case.
                    // We do this additional check nevertheless to be 100% sure
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-collateral");
                }
            }

            auto replacedDmn = newList.GetMNByCollateral(dmn->collateralOutpoint);
            if (replacedDmn != nullptr) {
                // This might only happen with a ProRegTx that refers an external collateral
                // In that case the new ProRegTx will replace the old one. This means the old one is removed
                // and the new one is added like a completely fresh one, which is also at the bottom of the payment list
                newList.RemoveMN(replacedDmn->proTxHash);
                if (debugLogs) {
                    LogPrintf("%s -- MN %s removed from list because collateral was used for " /* Continued */
                              "a new ProRegTx. collateralOutpoint=%s, nHeight=%d, mapCurMNs.allMNsCount=%d\n",
                              __func__, replacedDmn->proTxHash.ToString(), dmn->collateralOutpoint.ToStringShort(),
                              nHeight, newList.GetCounts().total());
                }
            }

            for (const auto& entry : proTx.netInfo->GetEntries()) {
                if (const auto service_opt{entry.GetAddrPort()}) {
                    if (newList.HasUniqueProperty(*service_opt)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-dup-netinfo-entry");
                    }
                } else if (const auto domain_opt{entry.GetDomainPort()}) {
                    if (newList.HasUniqueProperty(*domain_opt)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-dup-netinfo-entry");
                    }
                } else {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-netinfo-entry");
                }
            }
            if (newList.HasUniqueProperty(proTx.keyIDOwner) || newList.HasUniqueProperty(proTx.pubKeyOperator)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-dup-key");
            }

            dmn->nOperatorReward = proTx.nOperatorReward;

            auto dmnState = std::make_shared<CDeterministicMNState>(proTx);
            dmnState->nRegisteredHeight = nHeight;
            if (proTx.netInfo->IsEmpty()) {
                // start in banned pdmnState as we need to wait for a ProUpServTx
                dmnState->BanIfNotBanned(nHeight);
            }
            dmn->pdmnState = dmnState;

            newList.AddMN(dmn);

            if (debugLogs) {
                LogPrintf("%s -- MN %s added at height %d: %s\n", __func__, tx.GetHash().ToString(), nHeight,
                          proTx.ToString());
            }
        } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_SERVICE) {
            const auto opt_proTx = GetTxPayload<CProUpServTx>(tx);
            if (!opt_proTx) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-payload");
            }

            for (const auto& entry : opt_proTx->netInfo->GetEntries()) {
                if (const auto service_opt{entry.GetAddrPort()}) {
                    if (newList.HasUniqueProperty(*service_opt) &&
                        newList.GetUniquePropertyMN(*service_opt)->proTxHash != opt_proTx->proTxHash) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-dup-netinfo-entry");
                    }
                } else if (const auto domain_opt{entry.GetDomainPort()}) {
                    if (newList.HasUniqueProperty(*domain_opt) &&
                        newList.GetUniquePropertyMN(*domain_opt)->proTxHash != opt_proTx->proTxHash) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-dup-netinfo-entry");
                    }
                } else {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-netinfo-entry");
                }
            }

            auto dmn = newList.GetMN(opt_proTx->proTxHash);
            if (!dmn) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-hash");
            }
            if (opt_proTx->nType != dmn->nType) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-type-mismatch");
            }
            if (!IsValidMnType(opt_proTx->nType)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-type");
            }

            auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
            const uint16_t current_version{static_cast<uint16_t>(newState->nVersion)};
            const uint16_t target_version{is_v24_deployed ? std::max<uint16_t>(current_version, opt_proTx->nVersion) : current_version};
            if (is_v24_deployed) {
                // Extended addresses support in v24 means that the version can be updated
                newState->nVersion = opt_proTx->nVersion;
            }
            newState->netInfo = opt_proTx->netInfo;
            newState->scriptOperatorPayout = opt_proTx->scriptOperatorPayout;
            if (opt_proTx->nType == MnType::Evo) {
                newState->platformNodeID = opt_proTx->platformNodeID;
                if (opt_proTx->nVersion < ProTxVersion::ExtAddr) {
                    newState->platformP2PPort = opt_proTx->platformP2PPort;
                    newState->platformHTTPPort = opt_proTx->platformHTTPPort;
                } else {
                    // From ExtAddr onwards the Platform ports are stored in netInfo. Clear the
                    // legacy scalar fields (which a legacy registration may have left set) so the
                    // in-memory state matches its serialized form, which omits them for ExtAddr
                    // (see CDeterministicMNState serialization). Otherwise a stale value would
                    // survive in diff-reconstructed lists but vanish through a snapshot round-trip.
                    newState->platformP2PPort = 0;
                    newState->platformHTTPPort = 0;
                }
            }
            if (is_v24_deployed && !SetStateVersion(*newState, target_version, dmn->nType, state)) {
                return false;
            }
            if (newState->IsBanned()) {
                // only revive when all keys are set. A shared masternode (dips#187) has a null
                // keyIDOwner; its ownership is carried by the share owner keys, so treat a
                // non-empty share table as satisfying the owner-key requirement.
                const bool owner_keys_set{!newState->keyIDOwner.IsNull() || !newState->shares.empty()};
                if (newState->pubKeyOperator != CBLSLazyPublicKey() && !newState->keyIDVoting.IsNull() &&
                    owner_keys_set) {
                    newState->Revive(nHeight);
                    if (debugLogs) {
                        LogPrintf("%s -- MN %s revived at height %d\n", __func__, opt_proTx->proTxHash.ToString(), nHeight);
                    }
                }
            }

            newList.UpdateMN(opt_proTx->proTxHash, newState);
            if (debugLogs) {
                LogPrintf("%s -- MN %s updated at height %d: %s\n", __func__, opt_proTx->proTxHash.ToString(), nHeight,
                          opt_proTx->ToString());
            }
        } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_REGISTRAR) {
            const auto opt_proTx = GetTxPayload<CProUpRegTx>(tx);
            if (!opt_proTx) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-payload");
            }

            auto dmn = newList.GetMN(opt_proTx->proTxHash);
            if (!dmn) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-hash");
            }
            auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
            const uint16_t old_version{static_cast<uint16_t>(newState->nVersion)};
            const bool operator_changed{newState->pubKeyOperator != opt_proTx->pubKeyOperator};
            const uint16_t target_version{is_v24_deployed ? std::max<uint16_t>(old_version, opt_proTx->nVersion)
                                                          : (operator_changed ? opt_proTx->nVersion : old_version)};
            if (operator_changed) {
                // reset all operator related fields and put MN into PoSe-banned state in case the operator key changes
                newState->ResetOperatorFields();
                newState->BanIfNotBanned(nHeight);
                newState->pubKeyOperator = opt_proTx->pubKeyOperator;
            }
            newState->keyIDVoting = opt_proTx->keyIDVoting;
            if (!SetStateVersion(*newState, target_version, dmn->nType, state)) {
                return false;
            }
            if (operator_changed) {
                newState->pubKeyOperator.SetLegacy(target_version == ProTxVersion::LegacyBLS);
            }
            if (target_version >= ProTxVersion::MultiPayout) {
                newState->payouts = opt_proTx->nVersion >= ProTxVersion::MultiPayout
                    ? opt_proTx->payouts
                    : LegacyPayoutAsList(opt_proTx->scriptPayout);
                newState->scriptPayout.clear();
            } else {
                newState->scriptPayout = opt_proTx->scriptPayout;
                newState->payouts.clear();
            }

            newList.UpdateMN(opt_proTx->proTxHash, newState);

            if (debugLogs) {
                LogPrintf("%s -- MN %s updated at height %d: %s\n", __func__, opt_proTx->proTxHash.ToString(), nHeight,
                          opt_proTx->ToString());
            }
        } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_SHARE) {
            // dips#187: apply a share reward-script update to deterministic state.
            const auto opt_ptx = GetTxPayload<CProUpShareTx>(tx);
            if (!opt_ptx) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-proupsharetx-payload");
            }
            auto dmn = newList.GetMN(opt_ptx->proTxHash);
            if (!dmn || dmn->pdmnState->shares.empty() || opt_ptx->shareIndex >= dmn->pdmnState->shares.size()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-proupsharetx-mn");
            }
            auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
            newState->shares[opt_ptx->shareIndex].rewardScript = opt_ptx->rewardScript;
            newList.UpdateMN(opt_ptx->proTxHash, newState);
            if (debugLogs) {
                LogPrintf("%s -- MN %s share %d reward updated at height %d\n", __func__,
                          opt_ptx->proTxHash.ToString(), opt_ptx->shareIndex, nHeight);
            }
        } else if (tx.nType == TRANSACTION_PROVIDER_UPDATE_REVOKE) {
            const auto opt_proTx = GetTxPayload<CProUpRevTx>(tx);
            if (!opt_proTx) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-payload");
            }

            auto dmn = newList.GetMN(opt_proTx->proTxHash);
            if (!dmn) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-hash");
            }
            auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
            const uint16_t old_version{static_cast<uint16_t>(newState->nVersion)};
            newState->ResetOperatorFields();
            if (old_version >= ProTxVersion::MultiPayout && !SetStateVersion(*newState, old_version, dmn->nType, state)) {
                return false;
            }
            newState->BanIfNotBanned(nHeight);
            newState->nRevocationReason = opt_proTx->nReason;

            newList.UpdateMN(opt_proTx->proTxHash, newState);

            if (debugLogs) {
                LogPrintf("%s -- MN %s revoked operator key at height %d: %s\n", __func__,
                          opt_proTx->proTxHash.ToString(), nHeight, opt_proTx->ToString());
            }
        } else if (tx.nType == TRANSACTION_QUORUM_COMMITMENT) {
            const auto opt_qc = GetTxPayload<llmq::CFinalCommitmentTxPayload>(tx);
            if (!opt_qc) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-qc-payload");
            }
            if (!opt_qc->commitment.IsNull()) {
                const auto& llmq_params_opt = Params().GetLLMQ(opt_qc->commitment.llmqType);
                if (!llmq_params_opt.has_value()) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-qc-commitment-type");
                }
                int qcnHeight = int(opt_qc->nHeight);
                int quorumHeight = qcnHeight - (qcnHeight % llmq_params_opt->dkgInterval) +
                                   int(opt_qc->commitment.quorumIndex);
                auto pQuorumBaseBlockIndex = pindexPrev->GetAncestor(quorumHeight);
                if (!pQuorumBaseBlockIndex || pQuorumBaseBlockIndex->GetBlockHash() != opt_qc->commitment.quorumHash) {
                    // we should actually never get into this case as validation should have caught it...but let's be sure
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-qc-quorum-hash");
                }

                // The commitment has already been validated at this point, so it's safe to use members of it

                const auto members = llmq::utils::GetAllQuorumMembers(opt_qc->commitment.llmqType,
                                                                      {m_dmnman, m_qsnapman, m_chainman,
                                                                       pQuorumBaseBlockIndex});
                HandleQuorumCommitment(opt_qc->commitment, members, debugLogs, newList);
            }
        }
    }

    // we skip the coinbase
    for (int i = 1; i < (int)block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];

        // check if any existing MN collateral is spent by this transaction
        for (const auto& in : tx.vin) {
            auto dmn = newList.GetMNByCollateral(in.prevout);
            if (dmn && dmn->collateralOutpoint == in.prevout) {
                newList.RemoveMN(dmn->proTxHash);

                if (debugLogs) {
                    LogPrintf("%s -- MN %s removed from list because collateral was spent. " /* Continued */
                              "collateralOutpoint=%s, nHeight=%d, mapCurMNs.allMNsCount=%d\n",
                              __func__, dmn->proTxHash.ToString(), dmn->collateralOutpoint.ToStringShort(), nHeight,
                              newList.GetCounts().total());
                }
            }
        }
    }

    // The payee for the current block was determined by the previous block's list, but it might have disappeared in the
    // current block. We still pay that MN one last time, however.
    if (auto dmn = payee ? newList.GetMN(payee->proTxHash) : nullptr) {
        auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
        newState->nLastPaidHeight = nHeight;
        // Starting from v19 and until MNRewardReallocation, EvoNodes will be paid 4 blocks in a row
        // No need to check if v19 is active, since EvoNode ProRegTxes are allowed only after v19 activation
        // Note: If the payee wasn't found in the current block that's fine
        if (dmn->nType == MnType::Evo && !isMNRewardReallocation) {
            ++newState->nConsecutivePayments;
            if (debugLogs) {
                LogPrint(BCLog::MNPAYMENTS, "%s -- MN %s is an EvoNode, bumping nConsecutivePayments to %d\n", __func__,
                         dmn->proTxHash.ToString(), newState->nConsecutivePayments);
            }
        }
        newList.UpdateMN(payee->proTxHash, newState);
    }

    // reset nConsecutivePayments on non-paid EvoNodes
    auto newList2 = newList;
    newList2.ForEachMN(/*onlyValid=*/false, [&](const auto& dmn) {
        if (dmn.nType != MnType::Evo) return;
        if (payee != nullptr && dmn.proTxHash == payee->proTxHash && !isMNRewardReallocation) return;
        if (dmn.pdmnState->nConsecutivePayments == 0) return;
        if (debugLogs) {
            LogPrint(BCLog::MNPAYMENTS, "%s -- MN %s, reset nConsecutivePayments %d->0\n", __func__,
                     dmn.proTxHash.ToString(), dmn.pdmnState->nConsecutivePayments);
        }
        auto newState = std::make_shared<CDeterministicMNState>(*dmn.pdmnState);
        newState->nConsecutivePayments = 0;
        newList.UpdateMN(dmn.proTxHash, newState);
    });

    mnListRet = newList;

    return true;
}

bool CSpecialTxProcessor::ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, const CCoinsViewCache& view, bool fJustCheck,
                                                   bool fCheckCbTxMerkleRoots, BlockValidationState& state, std::optional<MNListUpdates>& updatesRet)
{
    AssertLockHeld(::cs_main);

    try {
        static int64_t nTimeLoop = 0;
        static int64_t nTimeQuorum = 0;
        static int64_t nTimeDMN = 0;
        static int64_t nTimeMerkleMNL = 0;
        static int64_t nTimeMerkleQuorums = 0;
        static int64_t nTimeCbTxCL = 0;
        static int64_t nTimeMnehf = 0;
        static int64_t nTimePayload = 0;
        static int64_t nTimeCreditPool = 0;

        int64_t nTime1 = GetTimeMicros();

        std::optional<CCbTx> opt_cbTx{std::nullopt};
        if (fCheckCbTxMerkleRoots && block.vtx.size() > 0 && block.vtx[0]->nType == TRANSACTION_COINBASE) {
            const auto& tx = block.vtx[0];
            if (!tx->IsCoinBase()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-invalid");
            }
            if (opt_cbTx = GetTxPayload<CCbTx>(*tx); opt_cbTx) {
                TxValidationState tx_state;
                if (!CheckCbTx(*opt_cbTx, pindex->pprev, tx_state)) {
                    assert(tx_state.GetResult() == TxValidationResult::TX_CONSENSUS ||
                           tx_state.GetResult() == TxValidationResult::TX_BAD_SPECIAL);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, tx_state.GetRejectReason(),
                                         strprintf("Special Transaction check failed (tx hash %s) %s",
                                                   tx->GetHash().ToString(), tx_state.GetDebugMessage()));
                }
            } else {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-payload");
            }
        }
        if (fCheckCbTxMerkleRoots) {
            // To ensure that opt_cbTx is not missing when it's supposed to be
            if (DeploymentActiveAt(*pindex, m_consensus_params, Consensus::DEPLOYMENT_DIP0003) && !opt_cbTx.has_value()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-version");
            }
        }

        int64_t nTime2 = GetTimeMicros();
        nTimePayload += nTime2 - nTime1;
        LogPrint(BCLog::BENCHMARK, "      - GetTxPayload: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1),
                 nTimePayload * 0.000001);

        CRangesSet indexes;
        if (DeploymentActiveAt(*pindex, m_consensus_params, Consensus::DEPLOYMENT_V20)) {
            CCreditPool creditPool{m_cpoolman.GetCreditPool(pindex->pprev)};
            LogPrint(BCLog::CREDITPOOL, "CSpecialTxProcessor::%s -- CCreditPool is %s\n", __func__, creditPool.ToString());
            indexes = std::move(creditPool.indexes);
        }

        for (size_t i = 0; i < block.vtx.size(); ++i) {
            // we validated CCbTx above, starts from the 2nd transaction
            if (i == 0 && block.vtx[i]->nType == TRANSACTION_COINBASE) continue;

            const auto ptr_tx = block.vtx[i];
            TxValidationState tx_state;
            // At this moment CheckSpecialTx() may fail by 2 possible ways:
            // consensus failures and "TX_BAD_SPECIAL"
            if (!CheckSpecialTxInner(m_dmnman, m_qsnapman, m_chainman, m_qman, *ptr_tx, pindex->pprev, view, indexes,
                                     fCheckCbTxMerkleRoots, tx_state)) {
                assert(tx_state.GetResult() == TxValidationResult::TX_CONSENSUS || tx_state.GetResult() == TxValidationResult::TX_BAD_SPECIAL);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, tx_state.GetRejectReason(),
                                 strprintf("Special Transaction check failed (tx hash %s) %s", ptr_tx->GetHash().ToString(), tx_state.GetDebugMessage()));
            }
        }

        int64_t nTime3 = GetTimeMicros();
        nTimeLoop += nTime3 - nTime2;
        LogPrint(BCLog::BENCHMARK, "      - Loop: %.2fms [%.2fs]\n", 0.001 * (nTime3 - nTime2), nTimeLoop * 0.000001);

        if (opt_cbTx.has_value()) {
            if (!CheckCreditPoolDiffForBlock(block, pindex, *opt_cbTx, state)) {
                return error("CSpecialTxProcessor: CheckCreditPoolDiffForBlock for block %s failed with %s",
                             pindex->GetBlockHash().ToString(), state.ToString());
            }
        }

        int64_t nTime4 = GetTimeMicros();
        nTimeCreditPool += nTime4 - nTime3;
        LogPrint(BCLog::BENCHMARK, "      - CheckCreditPoolDiffForBlock: %.2fms [%.2fs]\n", 0.001 * (nTime4 - nTime3),
                 nTimeCreditPool * 0.000001);

        if (!m_qblockman.ProcessBlock(block, pindex, state, fJustCheck, fCheckCbTxMerkleRoots)) {
            // pass the state returned by the function above
            return false;
        }

        int64_t nTime5 = GetTimeMicros();
        nTimeQuorum += nTime5 - nTime4;
        LogPrint(BCLog::BENCHMARK, "      - m_qblockman.ProcessBlock: %.2fms [%.2fs]\n", 0.001 * (nTime5 - nTime4),
                 nTimeQuorum * 0.000001);

        CDeterministicMNList mn_list;
        if (DeploymentActiveAt(*pindex, m_consensus_params, Consensus::DEPLOYMENT_DIP0003)) {
            if (!BuildNewListFromBlock(block, pindex->pprev, view, true, state, mn_list)) {
                // pass the state returned by the function above
                return false;
            }
            mn_list.SetBlockHash(pindex->GetBlockHash());

            if (!fJustCheck && !m_dmnman.ProcessBlock(block, pindex, state, mn_list, updatesRet)) {
                // pass the state returned by the function above
                return false;
            }
        }

        int64_t nTime6 = GetTimeMicros();
        nTimeDMN += nTime6 - nTime5;
        LogPrint(BCLog::BENCHMARK, "      - m_dmnman.ProcessBlock: %.2fms [%.2fs]\n", 0.001 * (nTime6 - nTime5),
                 nTimeDMN * 0.000001);

        if (opt_cbTx.has_value()) {
            uint256 calculatedMerkleRootMNL;
            if (!CalcCbTxMerkleRootMNList(calculatedMerkleRootMNL, mn_list.to_sml(), state)) {
                // pass the state returned by the function above
                return false;
            }
            if (calculatedMerkleRootMNL != opt_cbTx->merkleRootMNList) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-mnmerkleroot");
            }

            int64_t nTime6_1 = GetTimeMicros();
            nTimeMerkleMNL += nTime6_1 - nTime6;
            LogPrint(BCLog::BENCHMARK, "      - CalcCbTxMerkleRootMNList: %.2fms [%.2fs]\n",
                     0.001 * (nTime6_1 - nTime6), nTimeMerkleMNL * 0.000001);

            if (opt_cbTx->nVersion >= CCbTx::Version::MERKLE_ROOT_QUORUMS) {
                uint256 calculatedMerkleRootQuorums;
                if (!CalcCbTxMerkleRootQuorums(block, pindex->pprev, m_qblockman, calculatedMerkleRootQuorums, state)) {
                    // pass the state returned by the function above
                    return false;
                }
                if (calculatedMerkleRootQuorums != opt_cbTx->merkleRootQuorums) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-quorummerkleroot");
                }
            }

            int64_t nTime6_2 = GetTimeMicros();
            nTimeMerkleQuorums += nTime6_2 - nTime6_1;

            LogPrint(BCLog::BENCHMARK, "      - CalcCbTxMerkleRootQuorums: %.2fms [%.2fs]\n",
                     0.001 * (nTime6_2 - nTime6_1), nTimeMerkleQuorums * 0.000001);

            if (!CheckCbTxBestChainlock(*opt_cbTx, pindex, m_consensus_params, m_chainman.ActiveChain(), m_qman,
                                        m_chainlocks, state)) {
                // pass the state returned by the function above
                return false;
            }

            int64_t nTime6_3 = GetTimeMicros();
            nTimeCbTxCL += nTime6_3 - nTime6_2;
            LogPrint(BCLog::BENCHMARK, "      - CheckCbTxBestChainlock: %.2fms [%.2fs]\n",
                     0.001 * (nTime6_3 - nTime6_2), nTimeCbTxCL * 0.000001);
        }

        int64_t nTime7 = GetTimeMicros();

        if (!m_mnhfman.ProcessBlock(block, pindex, fJustCheck, state)) {
            // pass the state returned by the function above
            return false;
        }

        int64_t nTime8 = GetTimeMicros();
        nTimeMnehf += nTime8 - nTime7;
        LogPrint(BCLog::BENCHMARK, "      - m_mnhfman.ProcessBlock: %.2fms [%.2fs]\n", 0.001 * (nTime8 - nTime7),
                 nTimeMnehf * 0.000001);

        if (DeploymentActiveAfter(pindex, m_consensus_params, Consensus::DEPLOYMENT_V19) && bls::bls_legacy_scheme.load()) {
            // NOTE: The block next to the activation is the one that is using new rules.
            // V19 activated just activated, so we must switch to the new rules here.
            bls::bls_legacy_scheme.store(false);
            LogPrintf("CSpecialTxProcessor::%s -- bls_legacy_scheme=%d\n", __func__, bls::bls_legacy_scheme.load());
        }
    } catch (const std::exception& e) {
        LogPrintf("CSpecialTxProcessor::%s -- FAILURE! %s\n", __func__, e.what());
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "failed-procspectxsinblock");
    }

    return true;
}

bool CSpecialTxProcessor::UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, std::optional<MNListUpdates>& updatesRet)
{
    AssertLockHeld(::cs_main);

    auto bls_legacy_scheme = bls::bls_legacy_scheme.load();

    try {
        if (!DeploymentActiveAt(*pindex, m_consensus_params, Consensus::DEPLOYMENT_V19) && !bls_legacy_scheme) {
            // NOTE: The block next to the activation is the one that is using new rules.
            // Removing the activation block here, so we must switch back to the old rules.
            bls::bls_legacy_scheme.store(true);
            LogPrintf("CSpecialTxProcessor::%s -- bls_legacy_scheme=%d\n", __func__, bls::bls_legacy_scheme.load());
        }

        if (!m_mnhfman.UndoBlock(block, pindex)) {
            return false;
        }

        if (!m_dmnman.UndoBlock(pindex, updatesRet)) {
            return false;
        }

        if (!m_qblockman.UndoBlock(block, pindex)) {
            return false;
        }
    } catch (const std::exception& e) {
        bls::bls_legacy_scheme.store(bls_legacy_scheme);
        LogPrintf("CSpecialTxProcessor::%s -- bls_legacy_scheme=%d\n", __func__, bls::bls_legacy_scheme.load());
        return error(strprintf("CSpecialTxProcessor::%s -- FAILURE! %s\n", __func__, e.what()).c_str());
    }

    return true;
}

bool CSpecialTxProcessor::CheckCreditPoolDiffForBlock(const CBlock& block, const CBlockIndex* pindex, const CCbTx& cbTx,
                                                      BlockValidationState& state)
{
    AssertLockHeld(::cs_main);

    if (!DeploymentActiveAt(*pindex, m_consensus_params, Consensus::DEPLOYMENT_DIP0008)) return true;
    if (!DeploymentActiveAt(*pindex, m_consensus_params, Consensus::DEPLOYMENT_V20)) return true;

    try {
        const CAmount blockSubsidy = GetBlockSubsidy(pindex, m_consensus_params);
        const auto creditPoolDiff = GetCreditPoolDiffForBlock(m_cpoolman, block,
                                                              pindex->pprev, m_consensus_params, blockSubsidy, state);
        if (!creditPoolDiff.has_value()) return false;

        const CAmount target_balance{cbTx.creditPoolBalance};
        // But it maybe not included yet in previous block yet; in this case value must be 0
        const CAmount locked_calculated{creditPoolDiff->GetTotalLocked()};
        if (target_balance != locked_calculated) {
            LogPrintf("CSpecialTxProcessor::%s -- mismatched locked amount in CbTx: %lld against re-calculated: %lld\n", __func__, target_balance, locked_calculated);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-assetlocked-amount");
        }

    } catch (const std::exception& e) {
        LogPrintf("CSpecialTxProcessor::%s -- FAILURE! %s\n", __func__, e.what());
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "failed-checkcreditpooldiff");
    }

    return true;
}

template <typename ProTx>
static bool CheckService(const ProTx& proTx, TxValidationState& state)
{
    switch (proTx.netInfo->Validate()) {
    case NetInfoStatus::BadAddress:
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-netinfo-addr");
    case NetInfoStatus::BadPort:
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-netinfo-port");
    case NetInfoStatus::BadType:
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-netinfo-addr-type");
    case NetInfoStatus::NotRoutable:
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-netinfo-addr-unroutable");
    case NetInfoStatus::Malformed:
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-netinfo-bad");
    case NetInfoStatus::Success:
        return true;
    // Shouldn't be possible during self-checks
    case NetInfoStatus::BadInput:
    case NetInfoStatus::Duplicate:
    case NetInfoStatus::MaxLimit:
        assert(false);
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

template <typename ProTx>
static bool CheckPlatformFields(const ProTx& proTx, bool is_extended_addr, TxValidationState& state)
{
    if (proTx.platformNodeID.IsNull()) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-platform-nodeid");
    }

    if (is_extended_addr) {
        // platformHTTPPort and platformP2PPort have been subsumed by netInfo. They should always be zero.
        if (proTx.platformP2PPort != 0) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-platform-p2p-port");
        }
        if (proTx.platformHTTPPort != 0) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-platform-http-port");
        }
        return true;
    }

    if (::IsNodeOnMainnet()) {
        if (proTx.platformP2PPort != ::MainParams().GetDefaultPlatformP2PPort()) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-platform-p2p-port");
        }
        if (proTx.platformHTTPPort != ::MainParams().GetDefaultPlatformHTTPPort()) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-platform-http-port");
        }
    }
    if (proTx.platformP2PPort == ::MainParams().GetDefaultPort()) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-platform-p2p-port");
    }
    if (proTx.platformHTTPPort == ::MainParams().GetDefaultPort()) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-platform-http-port");
    }

    const uint16_t core_port{proTx.netInfo->GetPrimary().GetPort()};
    if (proTx.platformP2PPort == proTx.platformHTTPPort || proTx.platformP2PPort == core_port ||
        proTx.platformHTTPPort == core_port) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-platform-dup-ports");
    }

    return true;
}

template <typename ProTx>
static bool CheckHashSig(const ProTx& proTx, const PKHash& pkhash, TxValidationState& state)
{
    if (std::string strError; !CHashSigner::VerifyHash(::SerializeHash(proTx), ToKeyID(pkhash), proTx.vchSig, strError)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-sig");
    }
    return true;
}

template <typename ProTx>
static bool CheckStringSig(const ProTx& proTx, const PKHash& pkhash, TxValidationState& state)
{
    if (std::string strError;
        !CMessageSigner::VerifyMessage(ToKeyID(pkhash), proTx.vchSig, proTx.MakeSignString(), strError)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-sig");
    }
    return true;
}

template <typename ProTx>
static bool CheckHashSig(const ProTx& proTx, const CBLSPublicKey& pubKey, TxValidationState& state)
{
    if (!proTx.sig.VerifyInsecure(pubKey, ::SerializeHash(proTx))) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-sig");
    }
    return true;
}

template <typename ProTx>
static std::optional<ProTx> GetValidatedPayload(const CTransaction& tx, gsl::not_null<const CBlockIndex*> pindexPrev,
                                                const ChainstateManager& chainman, TxValidationState& state)
{
    if (tx.nType != ProTx::SPECIALTX_TYPE) {
        state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-type");
        return std::nullopt;
    }

    auto opt_ptx = GetTxPayload<ProTx>(tx);
    if (!opt_ptx) {
        state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-payload");
        return std::nullopt;
    }
    if (!opt_ptx->IsTriviallyValid(pindexPrev, chainman, state)) {
        // pass the state returned by the function above
        return std::nullopt;
    }
    return opt_ptx;
}

/**
 * Validates potential changes to masternode state version by ProTx transaction version
 * @param[in]  pindexPrev    Previous block index to validate DEPLOYMENT_V24 activation
 * @param[in]  tx_type       Special transaction type
 * @param[in]  state_version Current masternode state version
 * @param[in]  tx_version    Proposed transaction version
 * @param[out] state         This may be set to an Error state if any error occurred processing them
 * @returns                  true if version change is valid or DEPLOYMENT_V24 is not active
 */
static bool IsVersionChangeValid(gsl::not_null<const CBlockIndex*> pindexPrev, const uint16_t tx_type,
                                 const uint16_t state_version, const uint16_t tx_version,
                                 const ChainstateManager& chainman, TxValidationState& state)
{
    if (!DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_V24)) {
        // New restrictions only apply after v24 deployment
        return true;
    }

    if (state_version >= ProTxVersion::BasicBLS && tx_version == ProTxVersion::LegacyBLS) {
        // Don't allow legacy scheme versioned transactions after upgrading to basic scheme
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-version-downgrade");
    }

    if (state_version == ProTxVersion::LegacyBLS && tx_version > ProTxVersion::BasicBLS) {
        // Nodes using the legacy scheme must first upgrade to the basic scheme before upgrading further
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-version-upgrade");
    }

    if (tx_type != TRANSACTION_PROVIDER_UPDATE_SERVICE && tx_version == ProTxVersion::ExtAddr) {
        // Only new entries (ProRegTx) and service updates (ProUpServTx) can use ExtAddr versioning
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-version-tx-type");
    }
    if (tx_type != TRANSACTION_PROVIDER_UPDATE_REGISTRAR && tx_version == ProTxVersion::MultiPayout) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-version-tx-type");
    }

    return true;
}

bool CheckProRegTx(const CTransaction& tx, gsl::not_null<const CBlockIndex*> pindexPrev,
                   CDeterministicMNManager& dmnman, const CCoinsViewCache& view, const ChainstateManager& chainman,
                   TxValidationState& state, bool check_sigs)
{
    const auto opt_ptx = GetValidatedPayload<CProRegTx>(tx, pindexPrev, chainman, state);
    if (!opt_ptx) {
        // pass the state returned by the function above
        return false;
    }

    const bool is_v24_active{DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_V24)};

    // No longer allow legacy scheme masternode registration
    if (is_v24_active && opt_ptx->nVersion < ProTxVersion::BasicBLS) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-version-disallowed");
    }

    // It's allowed to set addr to 0, which will put the MN into PoSe-banned state and require a ProUpServTx to be
    // issues later. If any of both is set, it must be valid however
    if (!opt_ptx->netInfo->IsEmpty() && !CheckService(*opt_ptx, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (opt_ptx->nType == MnType::Evo) {
        if (!CheckPlatformFields(*opt_ptx, opt_ptx->nVersion >= ProTxVersion::ExtAddr, state)) {
            return false;
        }
    }

    CTxDestination collateralTxDest;
    const PKHash* keyForPayloadSig = nullptr;
    COutPoint collateralOutpoint;

    CAmount expectedCollateral = GetMnType(opt_ptx->nType).collat_amount;

    if (opt_ptx->IsShared()) {
        // dips#187 shared registration: the collateral is internal, is exactly the
        // template script, and the share amounts sum to the required collateral.
        // Ownership is proved by the joinSigs over SharedRegConsentHash, not by a
        // collateral key, so there is no keyForPayloadSig and no payout-key-safety check.
        if (!opt_ptx->collateralOutpoint.hash.IsNull()) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-shared-collateral-external");
        }
        if (opt_ptx->collateralOutpoint.n >= tx.vout.size()) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-collateral-index");
        }
        const CTxOut& collOut = tx.vout[opt_ptx->collateralOutpoint.n];
        if (collOut.nValue != expectedCollateral) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-collateral");
        }
        if (!SharedCollateral::IsTemplateScript(collOut.scriptPubKey)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-shared-collateral-script");
        }
        CAmount shareSum{0};
        for (const auto& share : opt_ptx->shares) shareSum += share.amount;
        if (shareSum != expectedCollateral) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-shared-collateral-sum");
        }
        // the template may appear only as this one collateral output (spec 4.11 creation rule)
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            if (SharedCollateral::IsTemplateScript(tx.vout[i].scriptPubKey) && i != opt_ptx->collateralOutpoint.n) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-shared-collateral-extra");
            }
        }
        collateralOutpoint = COutPoint(tx.GetHash(), opt_ptx->collateralOutpoint.n);
    } else if (!opt_ptx->collateralOutpoint.hash.IsNull()) {
        Coin coin;
        if (!view.GetCoin(opt_ptx->collateralOutpoint, coin) || coin.IsSpent() || coin.out.nValue != expectedCollateral) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-collateral");
        }

        if (!ExtractDestination(coin.out.scriptPubKey, collateralTxDest)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-collateral-dest");
        }

        // Extract key from collateral. This only works for P2PK and P2PKH collaterals and will fail for P2SH.
        // Issuer of this ProRegTx must prove ownership with this key by signing the ProRegTx
        keyForPayloadSig = std::get_if<PKHash>(&collateralTxDest);
        if (!keyForPayloadSig) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-collateral-pkh");
        }

        collateralOutpoint = opt_ptx->collateralOutpoint;
    } else {
        if (opt_ptx->collateralOutpoint.n >= tx.vout.size()) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-collateral-index");
        }
        if (tx.vout[opt_ptx->collateralOutpoint.n].nValue != expectedCollateral) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-collateral");
        }

        if (!ExtractDestination(tx.vout[opt_ptx->collateralOutpoint.n].scriptPubKey, collateralTxDest)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-collateral-dest");
        }

        collateralOutpoint = COutPoint(tx.GetHash(), opt_ptx->collateralOutpoint.n);
    }

    // dips#187: a NON-shared registration must not create any template output.
    // A shared registration is allowed exactly one, at its collateral slot, enforced above.
    if (!opt_ptx->IsShared()) {
        for (const auto& out : tx.vout) {
            if (SharedCollateral::IsTemplateScript(out.scriptPubKey)) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-template-output");
            }
        }
    }

    // don't allow reuse of collateral key for other keys (don't allow people to put the collateral key onto an online server)
    // this check applies to internal and external collateral, but internal collaterals are not necessarily a P2PKH
    // (shared registrations have no collateral key and derive owner payouts from the share table, so this is skipped)
    if (!opt_ptx->IsShared() &&
        !IsPayoutListKeySafe(GetOwnerPayouts(opt_ptx->nVersion, opt_ptx->scriptPayout, opt_ptx->payouts),
                             collateralTxDest, opt_ptx->keyIDOwner, opt_ptx->keyIDVoting,
                             opt_ptx->nVersion >= ProTxVersion::MultiPayout, state)) return false;

    if (pindexPrev) {
        auto mnList = dmnman.GetListForBlock(pindexPrev);

        // only allow reusing of addresses when it's for the same collateral (which replaces the old MN)
        for (const auto& entry : opt_ptx->netInfo->GetEntries()) {
            if (const auto service_opt{entry.GetAddrPort()}) {
                if (mnList.HasUniqueProperty(*service_opt) &&
                    mnList.GetUniquePropertyMN(*service_opt)->collateralOutpoint != collateralOutpoint) {
                    return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-netinfo-entry");
                }
            } else if (const auto domain_opt{entry.GetDomainPort()}) {
                if (mnList.HasUniqueProperty(*domain_opt) &&
                    mnList.GetUniquePropertyMN(*domain_opt)->collateralOutpoint != collateralOutpoint) {
                    return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-netinfo-entry");
                }
            } else {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-netinfo-entry");
            }
        }

        // never allow duplicate keys, even if this ProTx would replace an existing MN.
        // For a shared registration the owner keys are the share owner keys; each must
        // be unique across the whole masternode list (dips#187 spec 4.9).
        if (mnList.HasUniqueProperty(opt_ptx->pubKeyOperator)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-key");
        }
        if (opt_ptx->IsShared()) {
            for (const auto& share : opt_ptx->shares) {
                if (mnList.HasUniqueProperty(share.ownerKeyID)) {
                    return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-key");
                }
            }
        } else if (mnList.HasUniqueProperty(opt_ptx->keyIDOwner)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-key");
        }

        // never allow duplicate platformNodeIds for EvoNodes
        if (opt_ptx->nType == MnType::Evo) {
            if (mnList.HasUniqueProperty(opt_ptx->platformNodeID)) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-platformnodeid");
            }
        }

        if (!DeploymentDIP0003Enforced(pindexPrev->nHeight, Params().GetConsensus())) {
            if (opt_ptx->keyIDOwner != opt_ptx->keyIDVoting) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-key-not-same");
            }
        }
    }

    if (!CheckInputsHash(tx, *opt_ptx, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (opt_ptx->IsShared()) {
        // dips#187: every participant consents to the exact registration by signing
        // SharedRegConsentHash with their share owner key. The digest binds the funding
        // prevouts and all outputs, so co-signer txid malleability cannot invalidate it
        // (this is the property that closes co-signer malleability). The collateral payload sig must be empty.
        if (!opt_ptx->vchSig.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-sig");
        }
        if (check_sigs) {
            const uint256 consentHash = ComputeSharedRegConsentHash(*opt_ptx, tx);
            for (size_t i = 0; i < opt_ptx->shares.size(); ++i) {
                if (!SharedCollateral::IsCanonicalCompactSig(opt_ptx->vecJoinSigs[i])) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-joinsig-noncanonical");
                }
                std::string strError;
                if (!CHashSigner::VerifyHash(consentHash, opt_ptx->shares[i].ownerKeyID,
                                             opt_ptx->vecJoinSigs[i], strError)) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-joinsig");
                }
            }
        }
    } else if (keyForPayloadSig) {
        // collateral is not part of this ProRegTx, so we must verify ownership of the collateral
        if (check_sigs && !CheckStringSig(*opt_ptx, *keyForPayloadSig, state)) {
            // pass the state returned by the function above
            return false;
        }
    } else {
        // collateral is part of this ProRegTx, so we know the collateral is owned by the issuer
        if (!opt_ptx->vchSig.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-sig");
        }
    }

    return true;
}

bool CheckProDisTx(const CTransaction& tx, gsl::not_null<const CBlockIndex*> pindexPrev,
                   CDeterministicMNManager& dmnman, const ChainstateManager& chainman,
                   TxValidationState& state, bool check_sigs)
{
    // dips#187 ProDisTx: the only transaction permitted to spend template collateral. It
    // refunds every participant to their immutable refund script, applying the early-period
    // penalty on a unilateral early exit. Because the refund destinations are covenant-fixed
    // and nothing is pre-signed against the funding txid, a dishonest co-funder cannot
    // redirect another participant's principal (this is the exit path that closes co-signer malleability).
    if (!DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_V24)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-prodistx-inactive");
    }
    const auto opt_dis = GetTxPayload<CProDisTx>(tx);
    if (!opt_dis) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-payload");
    }
    if (opt_dis->nVersion == 0 || opt_dis->nVersion > 1) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-version");
    }

    auto mnList = dmnman.GetListForBlock(pindexPrev);
    auto dmn = mnList.GetMN(opt_dis->proTxHash);
    if (!dmn || dmn->pdmnState->shares.empty()) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-mn");
    }
    const auto& shares = dmn->pdmnState->shares;
    const uint16_t sharesCount = static_cast<uint16_t>(shares.size());

    // exactly one input: the collateral outpoint, with an empty scriptSig
    if (tx.vin.size() != 1 || tx.vin[0].prevout != dmn->collateralOutpoint) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-input");
    }
    if (!tx.vin[0].scriptSig.empty()) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-scriptsig");
    }

    if (opt_dis->actorIndex >= sharesCount) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-actor");
    }
    const uint8_t sigCount = static_cast<uint8_t>(opt_dis->vecSigs.size());
    const bool unanimous = (sigCount == sharesCount);
    const bool unilateral = (sigCount == 1);
    if (!unanimous && !unilateral) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-sigcount");
    }

    // penalty math (spec 4.6). spendHeight is the height of the block containing this tx.
    const int spendHeight = pindexPrev->nHeight + 1;
    const bool early = (spendHeight - dmn->pdmnState->nRegisteredHeight) < (int)dmn->pdmnState->nEarlyPeriodBlocks;
    const CAmount requiredPenalty = (unanimous || !early) ? 0 : dmn->pdmnState->nEarlyPenalty;

    // output rules (spec 4.6): one output per non-actor share i paying shares[i].refundScript
    // in share order, optionally one final actor output. Minimum-based, with two ceilings
    // (rules 5 and 6 below): overpaying the penalty is valid only up to the CONFIGURED
    // earlyPenalty, and the fee is capped. Both ceilings are height-independent, unlike
    // requiredPenalty, which is what keeps validity monotone under chain progress.
    const uint16_t a = opt_dis->actorIndex;
    CAmount W{0};
    for (uint16_t i = 0; i < sharesCount; ++i) if (i != a) W += shares[i].amount;
    // Registration enforces that the share amounts sum exactly to the required collateral,
    // so the share table is the authority on what the covenant output holds.
    const CAmount collateralValue = W + shares[a].amount;

    size_t nonActorCount = sharesCount - 1;
    if (tx.vout.size() < nonActorCount || tx.vout.size() > nonActorCount + 1) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-outcount");
    }
    CAmount bonusSum{0};
    size_t outIdx = 0;
    for (uint16_t i = 0; i < sharesCount; ++i) {
        if (i == a) continue;
        const CTxOut& out = tx.vout[outIdx];
        if (out.scriptPubKey != shares[i].refundScript) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-refund-script");
        }
        const CAmount bonus = out.nValue - shares[i].amount;
        // element-wise floor with a wide intermediate (a duff-scale product overflows int64)
        const CAmount minBonus = W > 0 ? SharedCollateral::MulDiv(requiredPenalty, shares[i].amount, W) : 0;
        if (bonus < minBonus) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-refund-min");
        }
        bonusSum += bonus;
        ++outIdx;
    }
    if (bonusSum < requiredPenalty) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-penalty");
    }
    // rule 6: a unilateral dissolution may not overpay the penalty beyond the configured
    // earlyPenalty. Unanimous dissolutions are deliberately NOT constrained here: every
    // share owner signed these exact outputs, so they may distribute bonuses freely above
    // the per-share minimums. The ceiling is nEarlyPenalty, not requiredPenalty, so that a
    // standby paying the full penalty stays valid after the early period ends.
    if (unilateral && bonusSum > dmn->pdmnState->nEarlyPenalty) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-bonus-ceiling");
    }
    // rule 5: the fee is the collateral value less every output, and it is capped. Without
    // this, a dissolution could pay the actor's whole share to miners as fee.
    CAmount outSum{0};
    for (const auto& out : tx.vout) {
        if (out.nValue < 0 || !MoneyRange(out.nValue)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-outvalue");
        }
        outSum += out.nValue;
    }
    if (outSum > collateralValue) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-outsum");
    }
    if (collateralValue - outSum > SharedCollateral::MAX_DIS_FEE) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-fee-ceiling");
    }
    // optional actor output must pay the actor's refund script
    if (tx.vout.size() == nonActorCount + 1) {
        if (tx.vout.back().scriptPubKey != shares[a].refundScript) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-prodistx-actor-script");
        }
    }

    if (check_sigs) {
        const uint256 disHash = ComputeSharedDisHash(*opt_dis, tx, sigCount);
        std::string strError;
        if (unilateral) {
            if (!SharedCollateral::IsCanonicalCompactSig(opt_dis->vecSigs[0]) ||
                !CHashSigner::VerifyHash(disHash, shares[a].ownerKeyID, opt_dis->vecSigs[0], strError)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-prodistx-sig");
            }
        } else {
            for (uint16_t i = 0; i < sharesCount; ++i) {
                if (!SharedCollateral::IsCanonicalCompactSig(opt_dis->vecSigs[i]) ||
                    !CHashSigner::VerifyHash(disHash, shares[i].ownerKeyID, opt_dis->vecSigs[i], strError)) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-prodistx-sig");
                }
            }
        }
    }

    return true;
}

bool CheckProUpShareTx(const CTransaction& tx, gsl::not_null<const CBlockIndex*> pindexPrev,
                       CDeterministicMNManager& dmnman, const ChainstateManager& chainman,
                       TxValidationState& state, bool check_sigs)
{
    // dips#187 ProUpShareTx: updates exactly one share's rewardScript with that share owner's
    // signature. Every other share field is immutable for the life of the masternode.
    if (!DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_V24)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-proupsharetx-inactive");
    }
    const auto opt_ptx = GetTxPayload<CProUpShareTx>(tx);
    if (!opt_ptx) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-proupsharetx-payload");
    }
    if (opt_ptx->nVersion == 0 || opt_ptx->nVersion > 1) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-proupsharetx-version");
    }

    auto mnList = dmnman.GetListForBlock(pindexPrev);
    auto dmn = mnList.GetMN(opt_ptx->proTxHash);
    if (!dmn || dmn->pdmnState->shares.empty()) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-proupsharetx-mn");
    }
    const auto& shares = dmn->pdmnState->shares;
    if (opt_ptx->shareIndex >= shares.size()) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-proupsharetx-index");
    }
    // the new reward script is subject to the same restrictions as at registration
    if (!opt_ptx->rewardScript.empty()) {
        if (!opt_ptx->rewardScript.IsPayToPublicKeyHash() && !opt_ptx->rewardScript.IsPayToScriptHash()) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-proupsharetx-reward");
        }
        if (SharedCollateral::IsTemplateScript(opt_ptx->rewardScript)) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-proupsharetx-template-dest");
        }
        CTxDestination dest;
        if (ExtractDestination(opt_ptx->rewardScript, dest)) {
            for (const auto& share : shares) {
                if (dest == CTxDestination(PKHash(share.ownerKeyID))) {
                    return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-proupsharetx-key-reuse");
                }
            }
            if (dest == CTxDestination(PKHash(dmn->pdmnState->keyIDVoting))) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-proupsharetx-key-reuse");
            }
        }
    }

    if (!CheckInputsHash(tx, *opt_ptx, state)) {
        return false;
    }
    // The canonical (65-byte, low-S) requirement covers EVERY signature this DIP introduces,
    // ProUpShareTx included, not only joinSigs and dissolution signatures. CheckHashSig
    // recovers through RecoverCompact, which normalizes S internally and therefore accepts a
    // high-S variant of a valid signature: same signer, same digest, different bytes, and so
    // a different transaction id that a third party can produce. Gated on check_sigs to match
    // the joinSigs and ProDisTx canonical checks and every other payload signature check in
    // this file, all of which a node skips in the same ranges where it skips signature
    // validation outright.
    if (check_sigs) {
        if (!SharedCollateral::IsCanonicalCompactSig(opt_ptx->vchSig)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-proupsharetx-sig-noncanonical");
        }
        if (!CheckHashSig(*opt_ptx, PKHash(shares[opt_ptx->shareIndex].ownerKeyID), state)) {
            return false;
        }
    }
    return true;
}

bool CheckProUpServTx(const CTransaction& tx, gsl::not_null<const CBlockIndex*> pindexPrev, CDeterministicMNManager& dmnman,
                      const ChainstateManager& chainman, TxValidationState& state, bool check_sigs)
{
    const auto opt_ptx = GetValidatedPayload<CProUpServTx>(tx, pindexPrev, chainman, state);
    if (!opt_ptx) {
        // pass the state returned by the function above
        return false;
    }

    if (!CheckService(*opt_ptx, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (opt_ptx->nType == MnType::Evo) {
        if (!CheckPlatformFields(*opt_ptx, opt_ptx->nVersion >= ProTxVersion::ExtAddr, state)) {
            return false;
        }
    }

    auto mnList = dmnman.GetListForBlock(pindexPrev);
    auto dmn = mnList.GetMN(opt_ptx->proTxHash);
    if (!dmn) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-hash");
    }

    if (!IsVersionChangeValid(pindexPrev, tx.nType, dmn->pdmnState->nVersion, opt_ptx->nVersion, chainman, state)) {
        // pass the state returned by the function above
        return false;
    }

    // don't allow updating to addresses already used by other MNs
    for (const auto& entry : opt_ptx->netInfo->GetEntries()) {
        if (const auto service_opt{entry.GetAddrPort()}) {
            if (mnList.HasUniqueProperty(*service_opt) &&
                mnList.GetUniquePropertyMN(*service_opt)->proTxHash != opt_ptx->proTxHash) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-netinfo-entry");
            }
        } else if (const auto domain_opt{entry.GetDomainPort()}) {
            if (mnList.HasUniqueProperty(*domain_opt) &&
                mnList.GetUniquePropertyMN(*domain_opt)->proTxHash != opt_ptx->proTxHash) {
                return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-netinfo-entry");
            }
        } else {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-netinfo-entry");
        }
    }

    // don't allow updating to platformNodeIds already used by other EvoNodes
    if (opt_ptx->nType == MnType::Evo) {
        if (mnList.HasUniqueProperty(opt_ptx->platformNodeID) &&
            mnList.GetUniquePropertyMN(opt_ptx->platformNodeID)->proTxHash != opt_ptx->proTxHash) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-platformnodeid");
        }
    }

    if (opt_ptx->scriptOperatorPayout != CScript()) {
        if (dmn->nOperatorReward == 0) {
            // don't allow setting operator reward payee in case no operatorReward was set
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-operator-payee");
        }
        if (!opt_ptx->scriptOperatorPayout.IsPayToPublicKeyHash() && !opt_ptx->scriptOperatorPayout.IsPayToScriptHash()) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-operator-payee");
        }
    }

    // we can only check the signature if pindexPrev != nullptr and the MN is known
    if (!CheckInputsHash(tx, *opt_ptx, state)) {
        // pass the state returned by the function above
        return false;
    }
    if (check_sigs && !CheckHashSig(*opt_ptx, dmn->pdmnState->pubKeyOperator.Get(), state)) {
        // pass the state returned by the function above
        return false;
    }

    return true;
}

bool CheckProUpRegTx(const CTransaction& tx, gsl::not_null<const CBlockIndex*> pindexPrev,
                     CDeterministicMNManager& dmnman, const CCoinsViewCache& view, const ChainstateManager& chainman,
                     TxValidationState& state, bool check_sigs)
{
    const auto opt_ptx = GetValidatedPayload<CProUpRegTx>(tx, pindexPrev, chainman, state);
    if (!opt_ptx) {
        // pass the state returned by the function above
        return false;
    }

    auto mnList = dmnman.GetListForBlock(pindexPrev);
    auto dmn = mnList.GetMN(opt_ptx->proTxHash);
    if (!dmn) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-hash");
    }

    // dips#187: a shared masternode's registrar fields are updatable ONLY by a
    // ProUpSharedRegTx carrying every share owner's signature. Rejecting the plain
    // ProUpRegTx explicitly matters because the only thing otherwise standing in its way is
    // that a shared registration's legacy keyIDOwner is all zeros, so the owner-key check
    // below would have to recover a public key hashing to the null key ID. That is a
    // preimage problem rather than a rule, it is not evaluated at all when check_sigs is
    // false, and it would leave this function free to overwrite the operator and voting keys
    // of a masternode whose owner authority lives in the share table.
    if (!dmn->pdmnState->shares.empty()) {
        return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-shared-upreg");
    }

    if (!IsVersionChangeValid(pindexPrev, tx.nType, dmn->pdmnState->nVersion, opt_ptx->nVersion, chainman, state)) {
        // pass the state returned by the function above
        return false;
    }

    const auto owner_payouts = GetOwnerPayouts(opt_ptx->nVersion, opt_ptx->scriptPayout, opt_ptx->payouts);
    if (!IsPayoutListTriviallyValid(owner_payouts, dmn->pdmnState->keyIDOwner, opt_ptx->keyIDVoting, state)) return false;

    Coin coin;
    if (!view.GetCoin(dmn->collateralOutpoint, coin) || coin.IsSpent()) {
        // this should never happen (there would be no dmn otherwise)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-collateral");
    }

    // don't allow reuse of collateral key for other keys (don't allow people to put the collateral key onto an online server)
    CTxDestination collateralTxDest;
    if (!ExtractDestination(coin.out.scriptPubKey, collateralTxDest)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-collateral-dest");
    }
    const bool check_payout_collateral_reuse{
        std::max<uint16_t>(dmn->pdmnState->nVersion, opt_ptx->nVersion) >= ProTxVersion::MultiPayout};
    if (!IsPayoutListKeySafe(owner_payouts, collateralTxDest, dmn->pdmnState->keyIDOwner, opt_ptx->keyIDVoting,
                             check_payout_collateral_reuse, state)) return false;

    if (mnList.HasUniqueProperty(opt_ptx->pubKeyOperator)) {
        auto otherDmn = mnList.GetUniquePropertyMN(opt_ptx->pubKeyOperator);
        if (opt_ptx->proTxHash != otherDmn->proTxHash) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-dup-key");
        }
    }

    if (!DeploymentDIP0003Enforced(pindexPrev->nHeight, Params().GetConsensus())) {
        if (dmn->pdmnState->keyIDOwner != opt_ptx->keyIDVoting) {
            return state.Invalid(TxValidationResult::TX_BAD_SPECIAL, "bad-protx-key-not-same");
        }
    }

    if (!CheckInputsHash(tx, *opt_ptx, state)) {
        // pass the state returned by the function above
        return false;
    }
    if (check_sigs && !CheckHashSig(*opt_ptx, PKHash(dmn->pdmnState->keyIDOwner), state)) {
        // pass the state returned by the function above
        return false;
    }

    return true;
}

bool CheckProUpRevTx(const CTransaction& tx, gsl::not_null<const CBlockIndex*> pindexPrev, CDeterministicMNManager& dmnman,
                     const ChainstateManager& chainman, TxValidationState& state, bool check_sigs)
{
    const auto opt_ptx = GetValidatedPayload<CProUpRevTx>(tx, pindexPrev, chainman, state);
    if (!opt_ptx) {
        // pass the state returned by the function above
        return false;
    }

    auto mnList = dmnman.GetListForBlock(pindexPrev);
    auto dmn = mnList.GetMN(opt_ptx->proTxHash);
    if (!dmn) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-hash");
    }

    if (!IsVersionChangeValid(pindexPrev, tx.nType, dmn->pdmnState->nVersion, opt_ptx->nVersion, chainman, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (!CheckInputsHash(tx, *opt_ptx, state)) {
        // pass the state returned by the function above
        return false;
    }
    if (check_sigs && !CheckHashSig(*opt_ptx, dmn->pdmnState->pubKeyOperator.Get(), state)) {
        // pass the state returned by the function above
        return false;
    }

    return true;
}

bool IsStandardSpecialTx(const CTransaction& tx, std::string& reason)
{
    if (!tx.IsSpecialTxVersion()) return true;

    if (tx.nType != TRANSACTION_ASSET_LOCK) return true;

    // Each input is referenced by Platform's funding state transition; beyond this
    // many inputs that state transition exceeds Platform's ~20 kB size limit.
    static constexpr size_t MAX_STANDARD_ASSET_LOCK_INPUTS{100};
    if (tx.vin.size() > MAX_STANDARD_ASSET_LOCK_INPUTS) {
        reason = "assetlocktx-too-many-inputs";
        return false;
    }

    constexpr int max_tx_size_for_platform = 20480;
    if (tx.GetTotalSize() > max_tx_size_for_platform) {
        reason = "assetlocktx-too-big";
        return false;
    }

    if (const auto opt_assetLockTx = GetTxPayload<CAssetLockPayload>(tx);
        opt_assetLockTx.has_value() && opt_assetLockTx->getVersion() >= 2) {
        reason = "assetlocktx-version-2";
        return false;
    }

    return true;
}

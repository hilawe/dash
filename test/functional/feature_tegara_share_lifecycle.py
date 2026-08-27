#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The two dips#187 lifecycle paths the other Tegara tests never reach.

feature_tegara_shared_collateral.py covers registration, the template-spend refusal, and a
UNILATERAL early dissolution. Two paths in the covenant were implemented in consensus and never
exercised by any test, which this test closes:

  1. ProUpShareTx (spec 4.7). A share owner rotates their own reward script with a single
     signature. Everything else about the share stays immutable for the life of the masternode,
     and the reward script is subject to the same restrictions as at registration.
  2. UNANIMOUS dissolution (spec 4.6). Every participant signs, so the early-period penalty does
     not apply and each participant is refunded exactly their share. This is the contrast with
     the unilateral path, where the actor pays a penalty that the non-actors collect.

Both run against one three-participant masternode, in lifecycle order: register, rotate a reward
script, refuse the malformed rotations, then exit unanimously during the early period.
"""
import struct

from test_framework.messages import CTransaction, from_hex
from test_framework.test_framework import DashTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    softfork_active,
)

V24_ACTIVATION_THRESHOLD = 100
COIN = 100000000
DISSOLVE_FEE = 100000  # the RPC's flat default, paid from the actor's share


class TegaraShareLifecycleTest(DashTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.set_dash_test_params(1, 0, extra_args=[[
            f"-vbparams=v24:{self.mocktime}:999999999999:{V24_ACTIVATION_THRESHOLD}:10:8:6:5:0",
            "-acceptnonstdtxn=1",
        ]])

    def activate_v24(self):
        while not softfork_active(self.nodes[0], "v24"):
            self.bump_mocktime(50)
            self.generate(self.nodes[0], 50, sync_fun=self.no_op)
        assert softfork_active(self.nodes[0], "v24")

    def confirm(self):
        self.bump_mocktime(10 * 60 + 1)
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)

    def run_test(self):
        node = self.nodes[0]
        self.activate_v24()
        self.generate(node, 120, sync_fun=self.no_op)

        refunds = [node.getnewaddress() for _ in range(3)]
        owners = [node.getnewaddress() for _ in range(3)]
        voting = node.getnewaddress()
        operator = node.bls("generate")["public"]
        fund_addr = node.getnewaddress()
        node.sendtoaddress(fund_addr, 1002)
        self.confirm()

        amounts = [400, 300, 300]
        shares = [{"amount": a, "refund": r, "owner": o}
                  for a, r, o in zip(amounts, refunds, owners)]
        early_penalty = 5
        early_period = 500  # long enough that the unanimous exit below is still "early"

        self.log.info("register a three-participant shared masternode")
        txid = node.protxsharedregister(
            shares, operator, voting, 0, early_period, early_penalty, fund_addr)
        self.confirm()
        registered_height = node.protx("info", txid)["state"]["registeredHeight"]

        before = node.protx("info", txid)["state"]["shares"]
        assert_equal(len(before), 3)
        assert_equal([s["amount"] for s in before], [a * COIN for a in amounts])
        assert_equal([s["refundAddress"] for s in before], refunds)
        # no reward script was registered, so each share falls back to its refund script and the
        # state carries no rewardAddress at all
        assert all("rewardAddress" not in s for s in before)

        self.log.info("share 1 rotates its own reward script (ProUpShareTx)")
        new_reward = node.getnewaddress()
        up_txid = node.protxupdateshare(txid, 1, new_reward, fund_addr)
        self.confirm()

        raw_up = node.getrawtransaction(up_txid, 1)
        assert_equal(raw_up["type"], 11)  # TRANSACTION_PROVIDER_UPDATE_SHARE
        assert_equal(raw_up["proUpShareTx"]["proTxHash"], txid)
        assert_equal(raw_up["proUpShareTx"]["shareIndex"], 1)

        after = node.protx("info", txid)["state"]["shares"]
        assert_equal(after[1]["rewardAddress"], new_reward)
        # the rotation touched exactly one field of exactly one share. Amounts, refund scripts
        # and owner keys are immutable for the life of the masternode.
        assert_equal([s["amount"] for s in after], [s["amount"] for s in before])
        assert_equal([s["refundAddress"] for s in after], [s["refundAddress"] for s in before])
        assert_equal([s["ownerKeyID"] for s in after], [s["ownerKeyID"] for s in before])
        assert all("rewardAddress" not in after[i] for i in (0, 2))
        # and the masternode's own terms did not move either
        state_after = node.protx("info", txid)["state"]
        assert_equal(state_after["earlyPenalty"], early_penalty * COIN)
        assert_equal(state_after["earlyPeriodBlocks"], early_period)
        assert_equal(state_after["registeredHeight"], registered_height)

        self.log.info("malformed rotations are refused by the builder")
        # an index outside the share table. NOTE this is the BUILDER's own parameter check, not
        # a consensus rule; the consensus rule is exercised separately below.
        assert_raises_rpc_error(-8, "shareIndex out of range",
                                node.protxupdateshare, txid, 3, node.getnewaddress(), fund_addr)
        # the reward script may not reuse a share owner key, which would collapse two roles.
        # These two DO reach consensus: the address is valid, so the builder emits and the
        # pre-check returns the consensus rejection verbatim.
        assert_raises_rpc_error(None, "bad-proupsharetx-key-reuse",
                                node.protxupdateshare, txid, 0, owners[2], fund_addr)
        # nor the voting key
        assert_raises_rpc_error(None, "bad-proupsharetx-key-reuse",
                                node.protxupdateshare, txid, 0, voting, fund_addr)
        # a refused rotation changes nothing
        assert_equal(node.protx("info", txid)["state"]["shares"], after)

        self.log.info("consensus refuses a rotation the share owner did not authorize")
        # Everything above would still pass if consensus stopped checking the signature at all,
        # because the builder only ever signs with the RIGHT owner key. These two cases close
        # that: build a valid rotation for share 0, then rewrite the share index in the payload
        # and submit it raw. The signature was made over the payload as it stood, so it no
        # longer authorizes what the transaction now asks for.
        #
        # Payload layout (CProUpShareTx): nVersion (2 bytes) + proTxHash (32) + shareIndex (2),
        # so the index sits at offset 34, little-endian.
        valid_hex = node.protxupdateshare(txid, 0, node.getnewaddress(), fund_addr, False)

        def with_share_index(idx):
            tx = from_hex(CTransaction(), valid_hex)
            pl = tx.vExtraPayload
            tx.vExtraPayload = pl[:34] + struct.pack("<H", idx) + pl[36:]
            tx.rehash()
            return tx.serialize().hex()

        # index 1 is IN range, so the index rule passes and the signature is checked. It was made
        # by share 0's owner over a payload naming share 0, so it does not authorize share 1.
        assert_raises_rpc_error(-26, "bad-protx-sig", node.sendrawtransaction, with_share_index(1))
        # index 7 is out of range, and consensus refuses it on its own rule, which is checked
        # before the signature. This is the rule the builder's parameter check hides above.
        assert_raises_rpc_error(-26, "bad-proupsharetx-index",
                                node.sendrawtransaction, with_share_index(7))
        # both refusals left the share table untouched
        assert_equal(node.protx("info", txid)["state"]["shares"], after)

        self.log.info("consensus refuses a high-S rotation signature")
        # The low-S rule is what makes these transaction identifiers non-malleable, and it is
        # the ONLY rule here a third party can break without any key: for every valid
        # signature (r, s) there is a second valid one (r, n - s), by the same signer over the
        # same digest, with different bytes and therefore a different transaction identifier.
        # RecoverCompact normalises S internally, so it accepts both and the rule has to be an
        # explicit check.
        #
        # Negating S is the whole mutation. It flips the recovery id's parity, so the header
        # byte moves by one, and the result still recovers the same public key.
        SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        valid_sig_hex = node.protxupdateshare(txid, 0, node.getnewaddress(), fund_addr, False)
        high_s_tx = from_hex(CTransaction(), valid_sig_hex)
        pl = bytearray(high_s_tx.vExtraPayload)
        # the payload ends with a compactSize-prefixed 65-byte compact signature
        assert_equal(pl[-66], 65)
        sig = pl[-65:]
        header, r, s = sig[0], sig[1:33], int.from_bytes(sig[33:], "big")
        assert 0 < s < SECP256K1_N // 2, "the wallet should have produced a low-S signature"
        flipped = bytes([header ^ 1]) + bytes(r) + (SECP256K1_N - s).to_bytes(32, "big")
        assert_greater_than(int.from_bytes(flipped[33:], "big"), SECP256K1_N // 2)  # now high-S
        pl[-65:] = flipped
        high_s_tx.vExtraPayload = bytes(pl)
        high_s_tx.rehash()
        assert_raises_rpc_error(-26, "bad-proupsharetx-sig-noncanonical",
                                node.sendrawtransaction, high_s_tx.serialize().hex())
        assert_equal(node.protx("info", txid)["state"]["shares"], after)

        self.log.info("every owner together rotates the registrar keys (ProUpSharedRegTx)")
        # spec 4.8. A shared masternode's legacy keyIDOwner is null, so the plain ProUpRegTx
        # path cannot authorize it; this payload, carrying one signature per share in share
        # order, is the only route to the operator and voting keys.
        new_operator = node.bls("generate")["public"]
        new_voting = node.getnewaddress()
        reg_txid = node.protxupdatesharedregistrar(txid, new_operator, new_voting, fund_addr)
        self.confirm()

        raw_reg = node.getrawtransaction(reg_txid, 1)
        assert_equal(raw_reg["type"], 12)  # TRANSACTION_PROVIDER_UPDATE_SHARED_REGISTRAR
        assert_equal(raw_reg["proUpSharedRegTx"]["proTxHash"], txid)
        assert_equal(raw_reg["proUpSharedRegTx"]["sigCount"], 3)  # one per share, not a threshold

        reg_state = node.protx("info", txid)["state"]
        assert_equal(reg_state["pubKeyOperator"], new_operator)
        assert_equal(reg_state["votingAddress"], new_voting)
        # The registrar update reaches the registrar fields and NOTHING else: the share table,
        # the penalty terms and the operator reward are all out of its scope.
        assert_equal(reg_state["shares"], after)
        assert_equal(reg_state["earlyPenalty"], early_penalty * COIN)
        assert_equal(reg_state["earlyPeriodBlocks"], early_period)
        # Changing the operator key bans the masternode, matching ProUpRegTx: the new operator
        # has not proved service yet. Revival is an ordinary ProUpServTx, which the null
        # keyIDOwner does not prevent.
        assert_greater_than(reg_state["PoSeBanHeight"], 0)

        self.log.info("the registrar update refuses a voting key that collides with a payee")
        # The registration payee-reuse rule, applied in reverse: at registration no share script
        # may pay the voting key, and here the voting key is what moves, so it must not land on
        # a script already in use. Share 1 was rotated above, so its EFFECTIVE payee is the new
        # reward script rather than its refund script, and both are checked.
        assert_raises_rpc_error(None, "bad-proupsharedregtx-key-reuse",
                                node.protxupdatesharedregistrar, txid, new_operator, refunds[0], fund_addr)
        assert_raises_rpc_error(None, "bad-proupsharedregtx-key-reuse",
                                node.protxupdatesharedregistrar, txid, new_operator, new_reward, fund_addr)

        self.log.info("the registrar update requires one signature per share, not fewer")
        # Build a valid update, then drop the last signature and decrement the count. Consensus
        # must refuse on the count alone: a shared masternode has no unilateral registrar path,
        # so "enough" signatures is never a subset of the owners.
        valid_reg = node.protxupdatesharedregistrar(txid, node.bls("generate")["public"],
                                                    node.getnewaddress(), fund_addr, False)
        short_tx = from_hex(CTransaction(), valid_reg)
        payload = bytearray(short_tx.vExtraPayload)
        # offsets asserted, not assumed: version(2) proTxHash(32) operator(48) voting(20)
        # inputsHash(32) = 134, then the signature count, then 65 bytes per signature
        SIGCOUNT_OFFSET = 2 + 32 + 48 + 20 + 32
        assert_equal(len(payload), SIGCOUNT_OFFSET + 1 + 65 * 3)
        assert_equal(payload[SIGCOUNT_OFFSET], 3)
        payload[SIGCOUNT_OFFSET] = 2          # claim two signatures
        del payload[-65:]                     # and actually carry two
        short_tx.vExtraPayload = bytes(payload)
        short_tx.rehash()
        assert_raises_rpc_error(-26, "bad-proupsharedregtx-sigcount",
                                node.sendrawtransaction, short_tx.serialize().hex())

        self.log.info("the registrar update binds each signature to its own share, in order")
        # Signature i must be by share i's owner. Swapping two signatures keeps the count and
        # the signer SET identical, so only the per-position binding can refuse it. Without
        # that binding a valid set could be permuted into a different reading.
        swap_reg = node.protxupdatesharedregistrar(txid, node.bls("generate")["public"],
                                                   node.getnewaddress(), fund_addr, False)
        swap_tx = from_hex(CTransaction(), swap_reg)
        payload = bytearray(swap_tx.vExtraPayload)
        assert_equal(payload[SIGCOUNT_OFFSET], 3)
        sig0_at = SIGCOUNT_OFFSET + 1
        sig1_at = sig0_at + 65
        sig0 = bytes(payload[sig0_at:sig0_at + 65])
        sig1 = bytes(payload[sig1_at:sig1_at + 65])
        assert sig0 != sig1  # distinct owners, so the swap is a real change
        payload[sig0_at:sig0_at + 65] = sig1
        payload[sig1_at:sig1_at + 65] = sig0
        swap_tx.vExtraPayload = bytes(payload)
        swap_tx.rehash()
        assert_raises_rpc_error(-26, "bad-proupsharedregtx-sig",
                                node.sendrawtransaction, swap_tx.serialize().hex())

        # none of the four refusals moved any state
        assert_equal(node.protx("info", txid)["state"]["shares"], after)
        assert_equal(node.protx("info", txid)["state"]["votingAddress"], new_voting)

        self.log.info("a plain ProUpRegTx cannot touch a shared masternode's registrar")
        # The counterpart to the rule above: ProUpSharedRegTx is the ONLY route to a shared
        # masternode's registrar fields, so the ordinary ProUpRegTx must be refused for one.
        # Deleting that rule and re-running showed what refuses this otherwise, which is the
        # collateral-destination lookup: a shared masternode's collateral is the covenant
        # template and carries no address. That is an incidental refusal from a check meant
        # for collateral key reuse, which is the reason to state the rule explicitly.
        #
        # No RPC can build this (the wallet has no key for a null keyIDOwner), so the payload
        # is assembled by hand. It only has to DESERIALIZE and pass trivial validation to reach
        # the rule: the shared-masternode check sits ahead of the inputs-hash and signature
        # checks, so both can be left unsatisfied here.
        unspent = next(u for u in node.listunspent() if u["amount"] > 10)
        # a deliberately huge fee, so appending the payload cannot drop the fee rate below the
        # relay floor and answer before consensus does
        raw = node.createrawtransaction(
            [{"txid": unspent["txid"], "vout": unspent["vout"]}],
            {node.getnewaddress(): float(unspent["amount"]) - 1})
        signed = node.signrawtransactionwithwallet(raw)["hex"]
        upreg = from_hex(CTransaction(), signed)

        payout_script = bytes.fromhex(node.validateaddress(node.getnewaddress())["scriptPubKey"])
        voting_script = bytes.fromhex(node.validateaddress(node.getnewaddress())["scriptPubKey"])
        # the voting key id is sliced out of a P2PKH script, which is only valid for the exact
        # form OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG; assert it rather than assume,
        # or a different script type would silently yield the wrong 20 bytes
        assert_equal(len(voting_script), 25)
        assert_equal(voting_script[:3].hex(), "76a914")
        # Version 4 ON PURPOSE, matching the masternode's own state version. An earlier draft
        # used version 3, and with the shared-masternode rule disabled that payload was refused
        # by the VERSION-CHANGE rule instead, which would have made this test prove only that
        # something refuses it rather than that this rule does.
        payload = b""
        payload += struct.pack("<H", 4)                       # nVersion: MultiPayout
        payload += bytes.fromhex(txid)[::-1]                  # proTxHash: the SHARED masternode
        payload += struct.pack("<H", 0)                       # nMode, only 0 is valid
        payload += bytes.fromhex(node.bls("generate")["public"])   # pubKeyOperator, 48 bytes
        payload += voting_script[3:23]                        # keyIDVoting
        payload += b"\x01"                                    # one payout entry
        payload += bytes([len(payout_script)]) + payout_script
        payload += struct.pack("<H", 10000)                   # the whole owner reward
        payload += b"\x00" * 32                               # inputsHash, not reached
        payload += b"\x00"                                    # empty signature, not reached
        upreg.nVersion = 3
        upreg.nType = 3                                       # TRANSACTION_PROVIDER_UPDATE_REGISTRAR
        upreg.vExtraPayload = payload
        upreg.rehash()
        assert_raises_rpc_error(-26, "bad-protx-shared-upreg",
                                node.sendrawtransaction, upreg.serialize().hex())

        self.log.info("all three participants dissolve unanimously, during the early period")
        height_before = node.getblockcount()
        assert_greater_than(registered_height + early_period, height_before + 1)  # still early
        received_before = [node.getreceivedbyaddress(r, 0) for r in refunds]

        dis_txid = node.protxshareddissolve(txid, 0, "unanimous")
        self.confirm()

        assert txid not in [d["proTxHash"] for d in node.protx("list", "registered", True)]

        dis = node.getrawtransaction(dis_txid, 1)
        assert_equal(dis["type"], 10)  # TRANSACTION_PROVIDER_DISSOLVE
        # the digest commits sigCount, which is what pins the mode: three signatures, not one
        assert_equal(dis["proDisTx"]["sigCount"], 3)
        assert_equal(dis["proDisTx"]["actorIndex"], 0)

        # exact duffs, not rounded DASH: valueSat is the integer the node recorded
        pays = {o["scriptPubKey"]["address"]: o["valueSat"] for o in dis["vout"]
                if "address" in o["scriptPubKey"]}
        # THE POINT OF THE UNANIMOUS MODE. No penalty applies even inside the early period, so
        # the two non-actors are paid exactly their share, with none of the bonus a unilateral
        # exit would have handed them, and the actor is short only the flat fee.
        assert_equal(pays[refunds[1]], 300 * COIN)
        assert_equal(pays[refunds[2]], 300 * COIN)
        assert_equal(pays[refunds[0]], 400 * COIN - DISSOLVE_FEE)
        # nothing else was paid out: no extra output resembling a penalty redistribution. Count and
        # sum the RAW vout, not the address-keyed map above, which would collapse two outputs paying
        # the same address and drop any output with no address at all.
        assert_equal(len(dis["vout"]), 3)
        assert_equal(sum(o["valueSat"] for o in dis["vout"]), 1000 * COIN - DISSOLVE_FEE)
        # every participant's principal actually arrived at its own immutable refund address
        received_after = [node.getreceivedbyaddress(r, 0) for r in refunds]
        for i in range(3):
            assert_greater_than(received_after[i], received_before[i])

        self.log.info("ProUpShareTx rotates one reward script under one owner signature, and a "
                      "unanimous dissolution refunds every share in full with no penalty")


if __name__ == "__main__":
    TegaraShareLifecycleTest().main()

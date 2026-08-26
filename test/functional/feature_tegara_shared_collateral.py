#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tegara prototype of dips#187 shared masternode collateral.

Drives the shared-collateral covenant on regtest through the prototype RPCs and
demonstrates that it closes co-signer transaction-identifier malleability. The point of
the failure mode was that a pre-signed multi-party refund is broken by first-party txid malleability
because Dash has no SegWit. The covenant removes the pre-signed artifact entirely: refund
rights live in consensus state keyed by proTxHash, so:

  - the collateral cannot be moved except by a consensus-validated ProDisTx,
  - a participant's principal returns to an immutable refund script recorded at
    registration, with no counterparty cooperation and nothing pre-signed to malleate.

The test registers a two-participant shared masternode, shows a normal transaction cannot
spend the template collateral, dissolves it unilaterally during the early period, and
confirms every participant's principal landed at its immutable refund address.
"""
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


class TegaraSharedCollateralTest(DashTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.set_dash_test_params(1, 0, extra_args=[[
            f"-vbparams=v24:{self.mocktime}:999999999999:{V24_ACTIVATION_THRESHOLD}:10:8:6:5:0",
            "-acceptnonstdtxn=1",
            # the node type case below appends a platform node id to a payload the wallet
            # already fee-rated, so the transaction grows by 20 bytes and the POLICY fee
            # floor would answer before consensus does. Dropping the floor keeps the
            # consensus rule the thing being tested; nothing else here depends on it.
            "-minrelaytxfee=0",
        ]])

    def activate_v24(self):
        while not softfork_active(self.nodes[0], "v24"):
            self.bump_mocktime(50)
            self.generate(self.nodes[0], 50, sync_fun=self.no_op)
        assert softfork_active(self.nodes[0], "v24")

    def run_test(self):
        node = self.nodes[0]
        self.activate_v24()
        # mature coinbases so the wallet can fund a 1000 DASH collateral
        self.generate(node, 120, sync_fun=self.no_op)

        # two participants, 500 DASH each, distinct refund and owner keys
        refund0, refund1 = node.getnewaddress(), node.getnewaddress()
        owner0, owner1 = node.getnewaddress(), node.getnewaddress()
        voting = node.getnewaddress()
        operator = node.bls("generate")["public"]
        fund_addr = node.getnewaddress()
        node.sendtoaddress(fund_addr, 1001)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        shares = [
            {"amount": 500, "refund": refund0, "owner": owner0},
            {"amount": 500, "refund": refund1, "owner": owner1},
        ]
        early_penalty = 5  # DASH, < min share (100)
        early_period = 100

        self.log.info("share-table validation rejects malformed registrations")
        # shares must sum to the collateral (1000 DASH)
        bad_sum = [{"amount": 400, "refund": refund0, "owner": owner0},
                   {"amount": 500, "refund": refund1, "owner": owner1}]
        assert_raises_rpc_error(None, "bad-protx-shared-collateral-sum", node.protxsharedregister,
                                bad_sum, operator, voting, 0, early_period, early_penalty, fund_addr)
        # each share must be at least 100 DASH
        bad_small = [{"amount": 950, "refund": refund0, "owner": owner0},
                     {"amount": 50, "refund": refund1, "owner": owner1}]
        assert_raises_rpc_error(None, "bad-protx-share-amount", node.protxsharedregister,
                                bad_small, operator, voting, 0, early_period, early_penalty, fund_addr)
        # owner keys must be distinct
        dup_owner = [{"amount": 500, "refund": refund0, "owner": owner0},
                     {"amount": 500, "refund": refund1, "owner": owner0}]
        assert_raises_rpc_error(None, "bad-protx-share-owner-key", node.protxsharedregister,
                                dup_owner, operator, voting, 0, early_period, early_penalty, fund_addr)
        # the penalty must be below the minimum share
        assert_raises_rpc_error(None, "bad-protx-share-penalty", node.protxsharedregister,
                                shares, operator, voting, 0, early_period, 600, fund_addr)

        self.log.info("consensus refuses a shared registration that is not a regular masternode")
        # THE SCOPE RULE THE PROPOSAL RESTS ON. dips#187 shares apply to regular
        # masternodes only, and a shared payload naming the evolution type is refused at
        # consensus. Nothing else in this suite exercised that rule, so a change removing
        # it would have gone unnoticed.
        #
        # The builder RPC cannot produce the case (it sets the regular type itself), so it
        # is built the way the dissolution negatives are: take a valid, signed, UNSUBMITTED
        # registration and change exactly one field. The payload carries its version and
        # type as its first two fields, and an evolution payload carries a platform node id
        # after the inputs hash, so the mutation sets the type and appends that id, leaving
        # a payload that deserializes as the evolution form rather than one that fails to
        # parse. Trivial validation runs before the consent signatures are verified, so the
        # type rule answers first even though the mutation also breaks the joinSigs. The
        # rejected transaction spends nothing, so the registration below still funds from
        # the same coin.
        unsubmitted = node.protxsharedregister(
            shares, operator, voting, 0, early_period, early_penalty, fund_addr, False)
        evo_tx = from_hex(CTransaction(), unsubmitted)
        payload = bytearray(evo_tx.vExtraPayload)
        # the offsets are asserted, not assumed: if the payload layout ever moves, this
        # fails here rather than mutating some other field and passing for a wrong reason
        assert_equal(int.from_bytes(payload[0:2], "little"), 4)  # the multi-payout version
        assert_equal(int.from_bytes(payload[2:4], "little"), 0)  # regular, as the RPC built it
        payload[2:4] = (1).to_bytes(2, "little")                 # the evolution type
        # the platform node id sits AFTER the inputs hash but BEFORE the payload's
        # trailing signature field, which a shared registration leaves empty because its
        # collateral is internal and needs no ownership proof
        assert_equal(payload[-1], 0)                             # that empty signature
        payload[-1:-1] = b"\x11" * 20                            # platformNodeID
        evo_tx.vExtraPayload = bytes(payload)
        evo_tx.rehash()
        assert_raises_rpc_error(None, "bad-protx-shared-type",
                                node.sendrawtransaction, evo_tx.serialize().hex())

        self.log.info("registration consent binds the funding input sequences")
        # The consent digest hashes every input's nSequence alongside the prevouts. Without
        # that, a funding signer could rewrite a sequence after the participants had signed,
        # and their consents would stay valid over the altered transaction. Sequences carry
        # BIP68 relative timelocks on version 2 and later transactions, so the rewrite can
        # delay a fully consented registration by months with nobody having agreed to it.
        #
        # The mutation is exactly one field, on an otherwise valid signed registration.
        # Rewriting the sequence also breaks the funding input's own script signature, but
        # special-transaction checks run in PreChecks, ahead of PolicyScriptChecks, so the
        # consent failure is what answers. That ordering is the whole point of asserting the
        # SPECIFIC refusal here: before the sequences entered the digest, this transaction
        # was refused for a script signature instead, so a digest that stopped covering them
        # would change this message rather than merely still failing.
        unsubmitted_seq = node.protxsharedregister(
            shares, operator, voting, 0, early_period, early_penalty, fund_addr, False)
        seq_tx = from_hex(CTransaction(), unsubmitted_seq)
        assert_greater_than(len(seq_tx.vin), 0)
        original_sequence = seq_tx.vin[0].nSequence
        # A BIP68-meaningful value that is necessarily DIFFERENT from whatever the wallet
        # set. Choosing a constant would pass vacuously on the day the wallet happens to
        # use that same constant: the mutation would be a no-op and the transaction would
        # be refused for some unrelated reason, or not refused at all.
        seq_tx.vin[0].nSequence = 0xfffffffd if original_sequence != 0xfffffffd else 0xfffffffe
        assert seq_tx.vin[0].nSequence != original_sequence
        seq_tx.rehash()
        assert_raises_rpc_error(None, "bad-protx-joinsig",
                                node.sendrawtransaction, seq_tx.serialize().hex())

        self.log.info("register a shared masternode")
        txid = node.protxsharedregister(shares, operator, voting, 0, early_period, early_penalty, fund_addr)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        raw = node.getrawtransaction(txid, 1)
        preg = raw["proRegTx"]
        assert_equal(len(preg["shares"]), 2)
        assert_equal(preg["earlyPenalty"], early_penalty * COIN)
        # the deterministic-list state (protx info) now carries the share table too, so a
        # shared masternode is fully inspectable without fetching its registration tx
        info = node.protx("info", txid)
        assert_equal(info["proTxHash"], txid)
        state = info["state"]
        assert_equal(len(state["shares"]), 2)
        assert_equal(state["earlyPenalty"], early_penalty * COIN)
        assert_equal(state["earlyPeriodBlocks"], early_period)
        assert_equal([s["amount"] for s in state["shares"]], [500 * COIN, 500 * COIN])
        # the recorded refund addresses match what was registered, in share order
        assert_equal([s["refundAddress"] for s in state["shares"]], [refund0, refund1])

        # locate the template collateral output
        coll_vout = next(i for i, o in enumerate(raw["vout"])
                         if o["scriptPubKey"]["hex"] == "04445348437551")
        assert_equal(int(round(raw["vout"][coll_vout]["value"])), 1000)

        self.log.info("a normal transaction cannot spend the template collateral (the covenant)")
        steal = node.createrawtransaction(
            [{"txid": txid, "vout": coll_vout}], {node.getnewaddress(): 999.9})
        # template is anyone-can-spend at the script layer, so no signature is needed; consensus
        # rejects the spend because it is not a ProDisTx.
        assert_raises_rpc_error(-26, "bad-txns-template-spend", node.sendrawtransaction, steal)

        self.log.info("the dissolution fee is capped at MAX_DIS_FEE")
        # Value conservation means every duff not paid to a refund output comes out of the
        # ACTOR's share, so an uncapped fee is a route for the actor's whole principal to
        # leave to miners. MAX_DIS_FEE is 1,000,000 duffs; ask for twice that.
        assert_raises_rpc_error(None, "bad-prodistx-fee-ceiling", node.protxshareddissolve,
                                txid, 0, "unilateral", 2 * 1000000)
        # and the ceiling is a ceiling, not a fixed value: the default fee still works, which
        # is what the successful dissolution at the end of this test relies on
        assert_raises_rpc_error(None, "bad-prodistx-fee-ceiling", node.protxshareddissolve,
                                txid, 0, "unilateral", 1000001)

        self.log.info("a unilateral dissolution may not overpay the penalty beyond earlyPenalty")
        # The other route by which value leaves the actor's share is voluntary penalty
        # overpayment, concentrated onto a non-actor output. The ceiling is the CONFIGURED
        # earlyPenalty (height-independent), not the height-dependent requiredPenalty, which
        # is what keeps a standby dissolution valid forever once it is valid.
        #
        # Build a valid unilateral dissolution, then move one DASH from the actor output to
        # the non-actor output. The sum is preserved, so the fee is untouched and the fee
        # ceiling cannot be what answers; only the bonus ceiling can.
        unsubmitted_dis = node.protxshareddissolve(txid, 0, "unilateral", 100000, False)
        bonus_tx = from_hex(CTransaction(), unsubmitted_dis)
        assert_equal(len(bonus_tx.vout), 2)  # one non-actor refund, one actor output
        # vout[0] is the non-actor share (500 DASH) plus the whole 5 DASH penalty bonus
        assert_equal(bonus_tx.vout[0].nValue, (500 + early_penalty) * COIN)
        before_sum = bonus_tx.vout[0].nValue + bonus_tx.vout[1].nValue
        bonus_tx.vout[0].nValue += COIN
        bonus_tx.vout[1].nValue -= COIN
        assert_equal(bonus_tx.vout[0].nValue + bonus_tx.vout[1].nValue, before_sum)
        bonus_tx.rehash()
        assert_raises_rpc_error(None, "bad-prodistx-bonus-ceiling",
                                node.sendrawtransaction, bonus_tx.serialize().hex())

        self.log.info("participant 0 dissolves unilaterally during the early period")
        bal1_before = node.getreceivedbyaddress(refund1, 0)
        dis_txid = node.protxshareddissolve(txid, 0, "unilateral")
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        # the masternode is gone from the list (removed via the collateral spend)
        assert txid not in [d["proTxHash"] for d in node.protx("list", "registered", True)]

        # participant 1, who took no action, received their full principal at their immutable
        # refund address; participant 0 (the actor) received their share minus the penalty and fee.
        dis = node.getrawtransaction(dis_txid, 1)
        pays = {o["scriptPubKey"]["address"]: o["value"] for o in dis["vout"]
                if "address" in o["scriptPubKey"]}
        # non-actor gets amount + the whole penalty bonus (single non-actor share)
        assert_equal(int(round(pays[refund1])), 500 + early_penalty)
        # actor gets amount - penalty - fee (just under 495)
        assert_greater_than(pays[refund0], 494)
        assert_greater_than(495, pays[refund0])
        bal1_after = node.getreceivedbyaddress(refund1, 0)
        assert_greater_than(bal1_after, bal1_before)

        self.log.info("Malleability closed: principal exited to immutable refund scripts via the covenant, "
                      "keyed by proTxHash, with nothing pre-signed against a malleable txid")


if __name__ == "__main__":
    TegaraSharedCollateralTest().main()

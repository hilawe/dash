#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The co-signer re-signing mutation, run against a dips#187 shared registration.

A pre-signed multi-party refund is broken by first-party transaction-identifier
malleability, because Dash has no SegWit: a co-funder who contributed an input can re-sign that
input with a different signature hash before confirmation, which changes the funding
transaction's identifier while leaving its inputs and outputs identical. Anything pre-signed
against the original identifier is then dead.

This test runs that same mutation against a shared registration and shows the covenant does not
care, which is the property the pre-signed construction could not provide:

  - the registration is funded from TWO separate coins, so it carries two independently signed
    inputs, standing in for two co-funders;
  - it is signed but NOT submitted, then EXACTLY ONE input is re-signed under a different
    signature hash while the other input keeps its original signature untouched. That is the
    mechanism: one participant acting alone, with no cooperation from the other. The second
    signature stays valid because a legacy signature hash blanks the other inputs' scripts, which
    is the very reason identifier malleability exists without SegWit;
  - the VARIANT is submitted and accepted, so the joinSigs still verify: the consent digest
    binds prevouts and outputs, not the identifier;
  - the masternode registers under the variant's identifier, and the internal collateral outpoint
    follows it, because a shared registration records a null collateral hash meaning "this
    transaction";
  - a participant still exits unilaterally to their immutable refund script afterwards, with no
    counterparty cooperation.

The original identifier is confirmed absent from the chain, which is exactly what would have
broken a pre-signed refund bound to it. Nothing in the covenant is bound to it, so nothing breaks.
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
DISSOLVE_FEE = 100000  # the dissolution builder's flat default, paid from the actor's share


class TegaraFundingMalleabilityTest(DashTestFramework):
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

    def run_test(self):
        node = self.nodes[0]
        self.activate_v24()
        self.generate(node, 120, sync_fun=self.no_op)

        refund0, refund1 = node.getnewaddress(), node.getnewaddress()
        owner0, owner1 = node.getnewaddress(), node.getnewaddress()
        voting = node.getnewaddress()
        operator = node.bls("generate")["public"]
        fund_addr = node.getnewaddress()
        # TWO separate coins at the funding address, each too small to cover the 1000 DASH
        # collateral alone, so the registration must spend both and carries two independently
        # signed inputs. Those two inputs stand in for two co-funders.
        node.sendtoaddress(fund_addr, 600)
        node.sendtoaddress(fund_addr, 501)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        shares = [
            {"amount": 500, "refund": refund0, "owner": owner0},
            {"amount": 500, "refund": refund1, "owner": owner1},
        ]
        early_penalty = 5
        early_period = 100

        self.log.info("build and sign a shared registration WITHOUT submitting it")
        signed_hex = node.protxsharedregister(
            shares, operator, voting, 0, early_period, early_penalty, fund_addr, False)
        original = from_hex(CTransaction(), signed_hex)
        original.rehash()
        original_txid = original.hash
        # nothing is on chain or in the mempool yet
        assert_raises_rpc_error(-5, "No such mempool or blockchain transaction",
                                node.getrawtransaction, original_txid)
        # the two funding coins really did become two separately signed inputs, which is what
        # makes the single-participant mutation below meaningful rather than a whole-transaction
        # re-sign
        assert_greater_than(len(original.vin), 1)
        assert all(len(txin.scriptSig) > 0 for txin in original.vin)

        self.log.info("ONE participant re-signs ONLY their own input (the co-signer mutation)")
        # Re-sign everything under a different signature hash type, then keep only input 0's new
        # script and restore every other input's ORIGINAL signature. The result is what one
        # co-funder acting alone can produce: their own input re-signed, nobody else's touched,
        # no cooperation required.
        stripped = from_hex(CTransaction(), signed_hex)
        for txin in stripped.vin:
            txin.scriptSig = b""
        resigned = node.signrawtransactionwithwallet(
            stripped.serialize().hex(), [], "ALL|ANYONECANPAY")
        assert_equal(resigned["complete"], True)
        all_resigned = from_hex(CTransaction(), resigned["hex"])

        variant = from_hex(CTransaction(), signed_hex)
        variant.vin[0].scriptSig = all_resigned.vin[0].scriptSig
        variant.rehash()
        variant_txid = variant.hash

        # exactly one input moved, and every other participant's signature is byte-identical to
        # what they signed. Their signatures stay VALID because a legacy signature hash blanks
        # the other inputs' scripts, which is precisely why the identifier is malleable here.
        assert variant.vin[0].scriptSig != original.vin[0].scriptSig
        for i in range(1, len(original.vin)):
            assert_equal(variant.vin[i].scriptSig, original.vin[i].scriptSig)

        # the mutation is real: a different identifier over identical prevouts and outputs
        assert variant_txid != original_txid, "re-signing did not change the identifier"
        assert_equal([(i.prevout.hash, i.prevout.n) for i in variant.vin],
                     [(i.prevout.hash, i.prevout.n) for i in original.vin])
        assert_equal([(o.nValue, o.scriptPubKey) for o in variant.vout],
                     [(o.nValue, o.scriptPubKey) for o in original.vout])
        # the registration payload itself is byte-identical, joinSigs included: the consent
        # digest commits to prevouts and outputs, and the input hash commits to prevouts only,
        # so neither moved when the input scripts did
        assert_equal(variant.vExtraPayload, original.vExtraPayload)
        self.log.info(f"  identifier moved {original_txid[:12]}.. -> {variant_txid[:12]}..")

        self.log.info("the variant is accepted and registers the masternode under ITS identifier")
        sent = node.sendrawtransaction(variant.serialize().hex())
        assert_equal(sent, variant_txid)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        # the original identifier never existed on chain. A refund pre-signed against it, which
        # is what W1 required, would be unspendable here. The covenant pre-signs nothing.
        assert_raises_rpc_error(-5, "No such mempool or blockchain transaction",
                                node.getrawtransaction, original_txid)

        registered = [d["proTxHash"] for d in node.protx("list", "registered", True)]
        assert variant_txid in registered, "the variant did not register"
        assert original_txid not in registered

        info = node.protx("info", variant_txid)
        state = info["state"]
        assert_equal(len(state["shares"]), 2)
        assert_equal([s["amount"] for s in state["shares"]], [500 * COIN, 500 * COIN])
        # the refund rights survived the mutation intact, keyed by the variant's proTxHash
        assert_equal([s["refundAddress"] for s in state["shares"]], [refund0, refund1])

        # the internal collateral outpoint followed the new identifier automatically, because a
        # shared registration records a null collateral hash meaning "an output of this tx"
        raw = node.getrawtransaction(variant_txid, 1)
        coll_vout = next(i for i, o in enumerate(raw["vout"])
                         if o["scriptPubKey"]["hex"] == "04445348437551")
        assert_equal(info["collateralHash"], variant_txid)
        assert_equal(info["collateralIndex"], coll_vout)

        self.log.info("a participant still exits unilaterally after the mutation")
        dis_txid = node.protxshareddissolve(variant_txid, 0, "unilateral")
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        assert variant_txid not in [d["proTxHash"] for d in node.protx("list", "registered", True)]
        dis = node.getrawtransaction(dis_txid, 1)
        # exact duffs, not rounded DASH: valueSat is the integer the node recorded
        pays = {o["scriptPubKey"]["address"]: o["valueSat"] for o in dis["vout"]
                if "address" in o["scriptPubKey"]}
        # the passive participant's principal landed at the refund script recorded before the
        # mutation, in full, plus the whole early-period penalty as the single non-actor
        assert_equal(pays[refund1], (500 + early_penalty) * COIN)
        # the actor is short exactly the penalty and the builder's flat fee, to the duff
        assert_equal(pays[refund0], (500 - early_penalty) * COIN - DISSOLVE_FEE)

        self.log.info("Co-signer mutation applied to a shared registration: the identifier changed "
                      "before confirmation and the covenant was unaffected, because refund "
                      "rights live in consensus state keyed by proTxHash with nothing pre-signed")


if __name__ == "__main__":
    TegaraFundingMalleabilityTest().main()

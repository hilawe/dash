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
from test_framework.test_framework import DashTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error, softfork_active

V24_ACTIVATION_THRESHOLD = 100
COIN = 100000000


class TegaraSharedCollateralTest(DashTestFramework):
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
        # mature coinbases so the wallet can fund a 1000 DASH collateral
        self.generate(node, 120, sync_fun=self.no_op)

        # two participants, 500 DASH each, distinct refund and owner keys
        refund0, refund1 = node.getnewaddress(), node.getnewaddress()
        owner0, owner1 = node.getnewaddress(), node.getnewaddress()
        voting = node.getnewaddress()
        operator = node.bls("generate")["public"]
        fund_addr = node.getnewaddress()
        node.sendtoaddress(fund_addr, 1001)
        self.generate(node, 1, sync_fun=self.no_op)

        shares = [
            {"amount": 500, "refund": refund0, "owner": owner0},
            {"amount": 500, "refund": refund1, "owner": owner1},
        ]
        early_penalty = 5  # DASH, < min share (100)
        early_period = 100

        self.log.info("register a shared masternode")
        txid = node.protxsharedregister(shares, operator, voting, 0, early_period, early_penalty, fund_addr)
        self.generate(node, 1, sync_fun=self.no_op)

        raw = node.getrawtransaction(txid, 1)
        preg = raw["proRegTx"]
        assert_equal(len(preg["shares"]), 2)
        assert_equal(preg["earlyPenalty"], early_penalty * COIN)
        # the masternode is in the list, with a null owner key (share keys carry ownership)
        info = node.protx("info", txid)
        assert_equal(len(info["state"]["shares"]), 2)

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

        self.log.info("participant 0 dissolves unilaterally during the early period")
        bal1_before = node.getreceivedbyaddress(refund1, 0)
        dis_txid = node.protxshareddissolve(txid, 0, "unilateral")
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

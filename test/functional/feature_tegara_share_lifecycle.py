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

        self.log.info("malformed rotations are refused")
        # an index outside the share table
        assert_raises_rpc_error(-8, "shareIndex out of range",
                                node.protxupdateshare, txid, 3, node.getnewaddress(), fund_addr)
        # the reward script may not reuse a share owner key, which would collapse two roles
        assert_raises_rpc_error(None, "bad-proupsharetx-key-reuse",
                                node.protxupdateshare, txid, 0, owners[2], fund_addr)
        # nor the voting key
        assert_raises_rpc_error(None, "bad-proupsharetx-key-reuse",
                                node.protxupdateshare, txid, 0, voting, fund_addr)
        # a refused rotation changes nothing
        assert_equal(node.protx("info", txid)["state"]["shares"], after)

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

        pays = {o["scriptPubKey"]["address"]: o["value"] for o in dis["vout"]
                if "address" in o["scriptPubKey"]}
        # THE POINT OF THE UNANIMOUS MODE. No penalty applies even inside the early period, so
        # the two non-actors are paid exactly their share, with none of the bonus a unilateral
        # exit would have handed them, and the actor is short only the flat fee.
        assert_equal(int(round(pays[refunds[1]] * COIN)), 300 * COIN)
        assert_equal(int(round(pays[refunds[2]] * COIN)), 300 * COIN)
        assert_equal(int(round(pays[refunds[0]] * COIN)), 400 * COIN - DISSOLVE_FEE)
        # every participant's principal actually arrived at its own immutable refund address
        received_after = [node.getreceivedbyaddress(r, 0) for r in refunds]
        for i in range(3):
            assert_greater_than(received_after[i], received_before[i])

        self.log.info("ProUpShareTx rotates one reward script under one owner signature, and a "
                      "unanimous dissolution refunds every share in full with no penalty")


if __name__ == "__main__":
    TegaraShareLifecycleTest().main()

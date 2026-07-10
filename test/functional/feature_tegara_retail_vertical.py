#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tegara Track C, the L1 half of the retail vertical (dips#187 + DIP-0026).

One slot of a shared masternode represents a retail sub-funder group. This test drives
that slot through a full reward epoch and a full principal exit on regtest:

  1. registers a two-slot shared masternode (slot 0 = the retail group, 600 DASH, with a
     designated reward address distinct from its refund address; slot 1 = a direct
     co-owner, 400 DASH, reward defaulting to its refund address),
  2. revives it from the registered-without-service PoSe ban via protx update_service,
  3. mines a block and confirms the coinbase pays the share-derived owner rewards,
     amount-weighted with DIP-0026 rounding, to each slot's reward script,
  4. exports the observed epoch (proTxHash, block, coinbase txid/vout, amount) as JSON;
     the Platform credit-rail consumes this observation as its inflow (the Track C
     bridge; the two chains are separate in the prototype, one chain in production),
  5. resilience: the OTHER slot dissolves unilaterally, with one signature and no
     cooperation from the group, its coordinator, or any Layer 2, and the passive group
     slot's full principal (plus the penalty bonus) lands on its immutable refund
     address. The group's principal never depended on anyone being alive.

The intra-group split of the refunded principal behind the group's refund address is a
product-layer question, documented in tegara/docs (it is not claimed solved here).
"""
import json
import os

from test_framework.test_framework import DashTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    p2p_port,
    softfork_active,
)

V24_ACTIVATION_THRESHOLD = 100
COIN = 100000000
# regtest nMasternodePaymentsStartBlock; be past it before expecting coinbase payouts
MN_PAYMENTS_START = 240


class TegaraRetailVerticalTest(DashTestFramework):
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

    def mine_past(self, height):
        node = self.nodes[0]
        while node.getblockcount() < height:
            n = min(50, height - node.getblockcount())
            self.bump_mocktime(n)
            self.generate(node, n, sync_fun=self.no_op)

    def coinbase_payouts(self, block_hash):
        """Map address -> (vout index, duffs) for the coinbase of the given block."""
        coinbase = self.nodes[0].getblock(block_hash, 2)["tx"][0]
        by_addr = {}
        for i, o in enumerate(coinbase["vout"]):
            addr = o["scriptPubKey"].get("address")
            if addr is not None:
                by_addr[addr] = (i, int(o["value"] * COIN))
        return coinbase, by_addr

    def run_test(self):
        node = self.nodes[0]
        self.activate_v24()
        self.mine_past(MN_PAYMENTS_START + 20)

        # slot 0, the retail group: reward address deliberately distinct from the refund
        # address (the group's reward flow and its principal exit are different scripts).
        # slot 1, a direct co-owner: reward defaults to the refund script.
        group_refund, group_reward = node.getnewaddress(), node.getnewaddress()
        coowner_refund = node.getnewaddress()
        owner0, owner1 = node.getnewaddress(), node.getnewaddress()
        voting = node.getnewaddress()
        operator = node.bls("generate")
        fund_addr = node.getnewaddress()
        node.sendtoaddress(fund_addr, 1002)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        shares = [
            {"amount": 600, "refund": group_refund, "owner": owner0, "reward": group_reward},
            {"amount": 400, "refund": coowner_refund, "owner": owner1},
        ]
        early_penalty = 5   # DASH, < min share
        early_period = 1000  # longer than this test, so the dissolution below is early-period

        self.log.info("register the shared masternode (slot 0 = retail group 600, slot 1 = co-owner 400)")
        protx_hash = node.protxsharedregister(shares, operator["public"], voting, 0,
                                              early_period, early_penalty, fund_addr)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)
        reg_height = node.getblockcount()

        preg = node.getrawtransaction(protx_hash, 1)["proRegTx"]
        assert_equal(len(preg["shares"]), 2)

        self.log.info("revive from the no-service PoSe ban via protx update_service")
        node.protx("update_service", protx_hash, [f"127.0.0.1:{p2p_port(1)}"],
                   operator["secret"], "", fund_addr, True)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)
        valid = [d["proTxHash"] for d in node.protx("list", "valid", True)]
        assert protx_hash in valid, "shared masternode not valid after update_service revive"

        self.log.info("mine one block; the coinbase pays the share-derived owner rewards")
        self.bump_mocktime(1)
        pay_hash = self.generate(node, 1, sync_fun=self.no_op)[0]
        coinbase, by_addr = self.coinbase_payouts(pay_hash)
        assert group_reward in by_addr, "group slot's reward output missing from the coinbase"
        assert coowner_refund in by_addr, "co-owner's reward output missing from the coinbase"
        # the reward goes to the designated reward script, not the refund script
        assert group_refund not in by_addr

        g_idx, g_amt = by_addr[group_reward]
        c_idx, c_amt = by_addr[coowner_refund]
        mn_reward = g_amt + c_amt
        assert_greater_than(mn_reward, 0)
        # amount-weighted split, DIP-0026 rounding: floor for the first share, the
        # remainder to the last
        assert_equal(g_amt, mn_reward * 600 // 1000)
        assert_equal(c_amt, mn_reward - g_amt)
        pay_height = node.getblockcount()
        self.log.info(f"slot 0 (group) earned {g_amt} duffs, slot 1 earned {c_amt} duffs "
                      f"at height {pay_height}")

        self.log.info("export the epoch observation for the Platform credit-rail")
        out_path = os.environ.get(
            "TEGARA_EPOCH_OUT",
            os.path.join(self.options.tmpdir, "tegara_epoch_observation.json"))
        observation = {
            "version": 1,
            "network": "fork-regtest",
            "source": "feature_tegara_retail_vertical.py",
            "proTxHash": protx_hash,
            "slotIndex": 0,
            "shareAmountDuffs": 600 * COIN,
            "collateralDuffs": 1000 * COIN,
            "registeredHeight": reg_height,
            "height": pay_height,
            "blockHash": pay_hash,
            "coinbaseTxid": coinbase["txid"],
            "rewardVout": g_idx,
            "rewardAddress": group_reward,
            "rewardScriptHex": coinbase["vout"][g_idx]["scriptPubKey"]["hex"],
            "amountDuffs": g_amt,
            "mnRewardDuffs": mn_reward,
            "operatorRewardBps": 0,
        }
        with open(out_path, "w", encoding="utf8") as f:
            json.dump(observation, f, indent=2, sort_keys=True)
        self.log.info(f"epoch observation written to {out_path}")

        self.log.info("rewards recur: two more blocks pay the same reward scripts")
        for _ in range(2):
            self.bump_mocktime(1)
            bh = self.generate(node, 1, sync_fun=self.no_op)[0]
            _, more = self.coinbase_payouts(bh)
            assert group_reward in more and coowner_refund in more

        self.log.info("resilience: slot 1 dissolves unilaterally; the group and its "
                      "coordinator take no action and no Layer 2 exists on this chain")
        dis_txid = node.protxshareddissolve(protx_hash, 1, "unilateral")
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        dis = node.getrawtransaction(dis_txid, 1)
        assert_equal(dis["proDisTx"]["mode"], "unilateral")
        assert_equal(dis["proDisTx"]["sigCount"], 1)
        assert_equal(dis["proDisTx"]["actorIndex"], 1)

        assert protx_hash not in [d["proTxHash"] for d in node.protx("list", "registered", True)]

        pays = {o["scriptPubKey"]["address"]: int(o["value"] * COIN) for o in dis["vout"]
                if "address" in o["scriptPubKey"]}
        # the passive group slot: full principal plus the whole penalty bonus (single
        # non-actor), at its immutable refund address, exact to the duff
        assert_equal(pays[group_refund], (600 + early_penalty) * COIN)
        # the actor: principal minus the penalty and the flat dissolution fee (the RPC
        # default, 100000 duffs), exact to the duff
        assert_equal(pays[coowner_refund], 400 * COIN - early_penalty * COIN - 100000)

        self.log.info("retail vertical, L1 half, demonstrated: the group slot earned "
                      "consensus-paid rewards to its designated reward address, and its "
                      "principal exited in full to its immutable refund address with no "
                      "action from the group, its coordinator, or any Layer 2")


if __name__ == "__main__":
    TegaraRetailVerticalTest().main()

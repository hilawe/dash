#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Negative cases for the dips#187 dissolution covenant (ProDisTx).

The happy-path dissolution is covered in feature_tegara_shared_collateral.py. This test
pins the REJECTION side: consensus must refuse a dissolution that violates any one output
rule, so a dishonest member cannot redirect or underpay another participant's principal,
and cannot get a malformed exit accepted.

Approach. protxshareddissolve with submit=false returns a valid, signed dissolution hex
against a live shared masternode without spending the collateral. Each case deserializes
that hex, mutates exactly one field, and submits it raw, asserting the specific consensus
rejection. Because CheckProDisTx validates the outputs before the signature, an output
mutation is rejected on its own rule even though the mutation also invalidates the
signature; the signature case keeps the outputs valid and corrupts the signature instead.
A rejected transaction spends nothing, so every case runs against the same masternode.
"""
from test_framework.messages import COIN, CTransaction, from_hex
from test_framework.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, hash160
from test_framework.test_framework import DashTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    softfork_active,
)

V24_ACTIVATION_THRESHOLD = 100


def p2pkh_script(dummy_seed: bytes) -> CScript:
    """A well-formed P2PKH script for an address the covenant did not record."""
    return CScript([OP_DUP, OP_HASH160, hash160(dummy_seed), OP_EQUALVERIFY, OP_CHECKSIG])


class TegaraDissolveNegativesTest(DashTestFramework):
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

    def submit_mutated(self, valid_hex, mutate):
        """Deserialize a valid dissolution, apply mutate(tx), return the serialized hex."""
        tx = from_hex(CTransaction(), valid_hex)
        mutate(tx)
        tx.rehash()
        return tx.serialize().hex()

    def run_test(self):
        node = self.nodes[0]
        self.activate_v24()
        self.generate(node, 120, sync_fun=self.no_op)

        # a three-participant shared node so a non-actor output is unambiguous and the
        # penalty splits across more than one non-actor share
        refunds = [node.getnewaddress() for _ in range(3)]
        owners = [node.getnewaddress() for _ in range(3)]
        voting = node.getnewaddress()
        operator = node.bls("generate")["public"]
        fund_addr = node.getnewaddress()
        node.sendtoaddress(fund_addr, 1001)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        shares = [{"amount": 400, "refund": refunds[0], "owner": owners[0]},
                  {"amount": 300, "refund": refunds[1], "owner": owners[1]},
                  {"amount": 300, "refund": refunds[2], "owner": owners[2]}]
        early_penalty, early_period = 5, 1000

        self.log.info("register a three-participant shared masternode")
        protx_hash = node.protxsharedregister(shares, operator, voting, 0,
                                              early_period, early_penalty, fund_addr)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)

        # a valid unilateral dissolution by participant 0, built but NOT submitted
        actor = 0
        valid_hex = node.protxshareddissolve(protx_hash, actor, "unilateral", 100000, False)
        # sanity: the unmutated hex IS accepted (then we work only against the mutated copies;
        # this one is left in the mempool and never mined, so the collateral stays unspent for
        # the negative cases below)... instead, confirm acceptance via testmempoolaccept so
        # nothing is actually spent.
        accept = node.testmempoolaccept([valid_hex])[0]
        assert_equal(accept["allowed"], True)

        base = from_hex(CTransaction(), valid_hex)
        assert_equal(len(base.vin), 1)
        # non-actor outputs are shares 1 and 2 (in share order), then the optional actor output
        assert 2 <= len(base.vout) <= 3

        self.log.info("a non-actor output paying a script the covenant did not record is rejected")
        def redirect_nonactor(tx):
            tx.vout[0].scriptPubKey = p2pkh_script(b"attacker-address")
        assert_raises_rpc_error(-26, "bad-prodistx-refund-script", node.sendrawtransaction,
                                self.submit_mutated(valid_hex, redirect_nonactor))

        self.log.info("underpaying a non-actor share (below its minimum) is rejected")
        def underpay_nonactor(tx):
            tx.vout[0].nValue -= 10 * COIN  # well under share 1's 300 DASH minimum
        assert_raises_rpc_error(-26, "bad-prodistx-refund-min", node.sendrawtransaction,
                                self.submit_mutated(valid_hex, underpay_nonactor))

        self.log.info("dropping a required non-actor output (wrong output count) is rejected")
        def drop_output(tx):
            # remove the last output; with two non-actors + actor that leaves one non-actor
            # missing, so the count is below the required non-actor count
            del tx.vout[-1]
            if len(tx.vout) > 1:
                del tx.vout[-1]
        assert_raises_rpc_error(-26, "bad-prodistx-outcount", node.sendrawtransaction,
                                self.submit_mutated(valid_hex, drop_output))

        self.log.info("an actor output paying the wrong script is rejected")
        has_actor_output = len(base.vout) == 3
        if has_actor_output:
            def redirect_actor(tx):
                tx.vout[-1].scriptPubKey = p2pkh_script(b"actor-elsewhere")
            assert_raises_rpc_error(-26, "bad-prodistx-actor-script", node.sendrawtransaction,
                                    self.submit_mutated(valid_hex, redirect_actor))
        else:
            self.log.info("  (no actor output in this dissolution; skipping)")

        self.log.info("a corrupted signature (valid outputs) is rejected")
        def corrupt_sig(tx):
            # the compact signature is the tail of the payload; flipping its last byte
            # leaves every output rule satisfied so the failure is the signature check
            payload = bytearray(tx.vExtraPayload)
            payload[-1] ^= 0x01
            tx.vExtraPayload = bytes(payload)
        assert_raises_rpc_error(-26, "bad-prodistx-sig", node.sendrawtransaction,
                                self.submit_mutated(valid_hex, corrupt_sig))

        self.log.info("after all rejections the masternode is untouched and still dissolvable")
        assert protx_hash in [d["proTxHash"] for d in node.protx("list", "registered", True)]
        # the collateral was never spent, so a real dissolution still succeeds
        node.sendrawtransaction(valid_hex)
        self.bump_mocktime(10 * 60 + 1)
        self.generate(node, 1, sync_fun=self.no_op)
        assert protx_hash not in [d["proTxHash"] for d in node.protx("list", "registered", True)]
        # participant 1 (a non-actor) received its full 300 DASH principal plus a penalty
        # bonus at its immutable refund address (the exact split is pinned elsewhere)
        assert_greater_than(node.getreceivedbyaddress(refunds[1], 0), 300)

        self.log.info("ProDisTx negative cases all rejected on their specific consensus rule")


if __name__ == "__main__":
    TegaraDissolveNegativesTest().main()

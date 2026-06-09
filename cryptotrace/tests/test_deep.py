"""Deep tests for CRYPTOTRACE.

Covers: OFAC screening, hop-distance exposure, value-weighted taint
propagation, common-input + change-address clustering, cluster risk
scoring, known-actor attribution, peeling-chain detection, and the CLI
(screen / cluster / taint / peel / check / sdn) including exit codes.

No network. Run with: python -m pytest  (or python -m unittest).
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    actor_tag,
    analyze,
    cluster_addresses,
    detect_peel_chains,
    is_sanctioned,
    ofac_entries,
    parse_txs,
    propagate_taint,
)
from cryptotrace.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "02-deep", "tx_graph.json",
)

# A real OFAC SDN address (SUEX OTC) used throughout the demo graph.
SDN_BTC = "1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f"


def _load_demo():
    with open(DEMO, encoding="utf-8") as fh:
        return parse_txs(fh.read())


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "cryptotrace")
        self.assertTrue(TOOL_VERSION)

    def test_sdn_list_nonempty_and_real(self):
        entries = ofac_entries()
        self.assertGreaterEqual(len(entries), 18)
        addrs = {e["address"].lower() for e in entries}
        self.assertIn(SDN_BTC.lower(), addrs)
        self.assertIn("0x8589427373d6d84e98730d7795d8f6f8731fda16", addrs)
        entities = {e["entity"] for e in entries}
        self.assertIn("Lazarus Group (DPRK)", entities)
        self.assertIn("Tornado Cash", entities)
        # every entry carries an actor category
        self.assertTrue(all("category" in e for e in entries))
        cats = {e["category"] for e in entries}
        self.assertTrue({"mixer", "exchange", "threat_actor"} <= cats)


class TestSanctionsMatch(unittest.TestCase):
    def test_direct_hit(self):
        hit = is_sanctioned(SDN_BTC)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["entity"], "SUEX OTC")

    def test_eth_case_insensitive(self):
        upper = "0x8589427373D6D84E98730D7795D8F6F8731FDA16"
        self.assertIsNotNone(is_sanctioned(upper))

    def test_clean_address(self):
        self.assertIsNone(is_sanctioned("1SomeRandomCleanAddress0000000000"))

    def test_actor_tag(self):
        tag = actor_tag("1MerchantPayDemo000000000000eeee")
        self.assertIsNotNone(tag)
        self.assertEqual(tag["category"], "merchant")
        self.assertIsNone(actor_tag(SDN_BTC))  # sanctioned != actor tag


class TestParsing(unittest.TestCase):
    def test_parse_demo(self):
        self.assertEqual(len(_load_demo()), 8)

    def test_parse_account_style(self):
        txs = parse_txs('[{"hash":"x","from":"0xabc","to":"0xdef","asset":"ETH"}]')
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0].inputs, ["0xabc"])
        self.assertEqual(txs[0].outputs, ["0xdef"])

    def test_parse_explorer_objects(self):
        txs = parse_txs(
            '[{"txid":"a","inputs":[{"address":"1AAA"}],'
            '"outputs":[{"scriptpubkey_address":"1BBB"}]}]')
        self.assertEqual(txs[0].inputs, ["1AAA"])
        self.assertEqual(txs[0].outputs, ["1BBB"])

    def test_parse_jsonl(self):
        jsonl = '{"txid":"a","inputs":["1X"],"outputs":["1Y"]}\n' \
                '{"txid":"b","inputs":["1Y"],"outputs":["1Z"]}'
        self.assertEqual(len(parse_txs(jsonl)), 2)

    def test_parse_empty(self):
        self.assertEqual(parse_txs("   "), [])


class TestAnalysis(unittest.TestCase):
    def setUp(self):
        self.res = analyze(_load_demo(), max_hops=2)

    def test_direct_hit_finding(self):
        direct = [f for f in self.res.findings if f.kind == "ofac_direct_hit"]
        self.assertEqual(len(direct), 1)
        self.assertEqual(direct[0].address, SDN_BTC)
        self.assertEqual(direct[0].severity, "critical")
        self.assertEqual(direct[0].entity, "SUEX OTC")

    def test_one_hop_exposure(self):
        one = {f.address for f in self.res.findings
               if f.kind == "ofac_indirect_exposure" and f.hops == 1}
        self.assertIn("1Layer1Recv00000000000000000000aaaa", one)

    def test_two_hop_exposure(self):
        two = {f.address for f in self.res.findings
               if f.kind == "ofac_indirect_exposure" and f.hops == 2}
        self.assertIn("1Peel1Small000000000000000000pp01", two)

    def test_max_severity(self):
        self.assertEqual(self.res.max_severity, "critical")

    def test_max_hops_limits_exposure(self):
        narrow = analyze(_load_demo(), max_hops=1)
        twohop = [f for f in narrow.findings
                  if f.kind == "ofac_indirect_exposure" and f.hops >= 2]
        self.assertEqual(twohop, [])

    def test_clean_graph_no_findings(self):
        clean = parse_txs(
            '[{"txid":"c1","inputs":["1Clean1","1Clean2"],'
            '"outputs":["1Clean3"]}]')
        res = analyze(clean)
        self.assertEqual(
            [f for f in res.findings if f.kind.startswith("ofac")], [])
        self.assertEqual(res.max_severity, "info")

    def test_json_serializable(self):
        d = self.res.to_dict()
        json.dumps(d)  # must not raise
        self.assertEqual(d["tool"], "cryptotrace")
        self.assertTrue(d["findings"])
        self.assertTrue(d["clusters"])
        self.assertIn("dirty_value_total", d)
        self.assertGreater(d["dirty_value_total"], 0.0)

    def test_taint_threshold_suppresses(self):
        strict = analyze(_load_demo(), max_hops=2, taint_threshold=0.9)
        # the ~53% tainted addresses must be filtered out (unless they are
        # reported solely on a hop basis — none here are 1-hop & < 0.9)
        for f in strict.findings:
            if f.kind == "ofac_indirect_exposure" and f.hops == 0:
                self.assertGreaterEqual(f.taint, 0.9)


class TestTaintPropagation(unittest.TestCase):
    def setUp(self):
        self.txs = _load_demo()
        self.taint = propagate_taint(self.txs, {SDN_BTC})

    def test_direct_recipients_fully_tainted(self):
        a = self.taint["1Layer1Recv00000000000000000000aaaa"]
        self.assertAlmostEqual(a["taint"], 1.0, places=6)
        self.assertGreater(a["dirty"], 0.0)

    def test_taint_fraction_bounded(self):
        for v in self.taint.values():
            self.assertGreaterEqual(v["taint"], 0.0)
            self.assertLessEqual(v["taint"], 1.0 + 1e-9)

    def test_clean_recipient_untainted(self):
        # the all-clean tx (t8) recipients must never appear as tainted
        self.assertNotIn("1CleanRecipient000000000000000jjjj", self.taint)

    def test_mixing_dilutes_taint(self):
        # WalletA mixes 3.0 clean BTC with 1.7 dirty (from peel chain) into
        # 1Layer2Hop; the resulting taint must be a partial fraction < 1.0.
        hop = self.taint.get("1Layer2Hop000000000000000000000cccc")
        self.assertIsNotNone(hop)
        self.assertLess(hop["taint"], 1.0)
        self.assertGreater(hop["taint"], 0.0)

    def test_no_sources_no_taint(self):
        self.assertEqual(propagate_taint(self.txs, set()), {})


class TestPeelChains(unittest.TestCase):
    def test_demo_peel_chain_detected(self):
        chains = detect_peel_chains(_load_demo(), min_length=3)
        self.assertTrue(chains)
        # the SUEX-seeded layering chain begins at t1
        self.assertEqual(chains[0][0], "t1")
        self.assertGreaterEqual(len(chains[0]), 4)

    def test_min_length_filters(self):
        self.assertEqual(detect_peel_chains(_load_demo(), min_length=99), [])

    def test_no_chain_in_flat_graph(self):
        txs = parse_txs('[{"txid":"a","inputs":["1A","1B"],"outputs":["1C"]}]')
        self.assertEqual(detect_peel_chains(txs), [])


class TestClustering(unittest.TestCase):
    def setUp(self):
        self.clusters = cluster_addresses(_load_demo())

    def _cluster_with(self, addr):
        for c in self.clusters:
            if addr in c.addresses:
                return c
        return None

    def test_common_input_cluster(self):
        c = self._cluster_with("1WalletA-in1000000000000000000ddd1")
        self.assertIsNotNone(c)
        self.assertIn("1WalletA-in2000000000000000000ddd2", c.addresses)
        self.assertIn("common_input", c.heuristics)

    def test_change_address_folded(self):
        c = self._cluster_with("1WalletA-in1000000000000000000ddd1")
        self.assertIn("1WalletA-chg000000000000000000ddd3", c.addresses)
        self.assertIn("change_address", c.heuristics)

    def test_clean_wallets_clustered_separately(self):
        c = self._cluster_with("1CleanWalletX00000000000000000hhhh")
        self.assertIsNotNone(c)
        self.assertIn("1CleanWalletY00000000000000000iiii", c.addresses)
        self.assertNotIn("1WalletA-in1000000000000000000ddd1", c.addresses)

    def test_singletons_not_emitted(self):
        for c in self.clusters:
            self.assertGreaterEqual(len(c.addresses), 2)

    def test_unrelated_inputs_not_merged(self):
        txs = parse_txs(
            '[{"txid":"a","inputs":["1P","1Q"],"outputs":["1R"]},'
            ' {"txid":"b","inputs":["1S","1T"],"outputs":["1U"]}]')
        clusters = cluster_addresses(txs)
        for c in clusters:
            self.assertFalse({"1P", "1S"} <= set(c.addresses))

    def test_risk_score_present(self):
        for c in self.clusters:
            self.assertGreaterEqual(c.risk_score, 0)
            self.assertLessEqual(c.risk_score, 100)

    def test_sanctioned_cluster_high_risk(self):
        # build a graph where two inputs (one SDN) are co-spent -> the cluster
        # inherits the sanction and a high risk score.
        txs = parse_txs(json.dumps([{
            "txid": "s", "inputs": [SDN_BTC, "1CoOwned000000000000000000000xx"],
            "outputs": ["1Out0000000000000000000000000yy"]}]))
        clusters = cluster_addresses(txs)
        sanctioned = [c for c in clusters if c.sanctioned_member]
        self.assertEqual(len(sanctioned), 1)
        self.assertEqual(sanctioned[0].sanctioned_entity, "SUEX OTC")
        self.assertGreaterEqual(sanctioned[0].risk_score, 80)


class TestCLI(unittest.TestCase):
    def test_screen_exit_nonzero_on_findings(self):
        self.assertEqual(main(["screen", DEMO, "--format", "json"]), 1)

    def test_screen_json_has_taint_field(self):
        # smoke: the JSON path must produce parseable output with taint info.
        clean = '[{"txid":"c1","inputs":["1Clean1","1Clean2"],"outputs":["1C3"]}]'
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8") as tf:
            tf.write(clean)
            path = tf.name
        out = os.path.join(tempfile.gettempdir(), "ct_out.json")
        try:
            self.assertEqual(
                main(["screen", path, "--format", "json", "-o", out]), 0)
            with open(out, encoding="utf-8") as fh:
                d = json.load(fh)
            self.assertIn("dirty_value_total", d)
        finally:
            for p in (path, out):
                if os.path.exists(p):
                    os.unlink(p)

    def test_taint_subcommand_nonzero(self):
        self.assertEqual(main(["taint", DEMO, "--format", "json"]), 1)

    def test_peel_subcommand_nonzero(self):
        self.assertEqual(main(["peel", DEMO, "--format", "json"]), 1)

    def test_cluster_subcommand_exit_zero_when_clean(self):
        # the demo has no sanctioned *cluster* member, so cluster exits 0
        self.assertEqual(main(["cluster", DEMO, "--format", "json"]), 0)

    def test_check_sdn_exit_nonzero(self):
        self.assertEqual(main(["check", SDN_BTC]), 1)

    def test_check_clean_exit_zero(self):
        self.assertEqual(main(["check", "1TotallyCleanAddress00000000000000"]), 0)

    def test_check_actor_exit_zero(self):
        # known actor but not sanctioned -> exit 0
        self.assertEqual(main(["check", "1MerchantPayDemo000000000000eeee"]), 0)

    def test_screen_clean_exit_zero(self):
        clean = '[{"txid":"c1","inputs":["1Clean1","1Clean2"],"outputs":["1Clean3"]}]'
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8") as tf:
            tf.write(clean)
            path = tf.name
        try:
            self.assertEqual(main(["screen", path, "--format", "table"]), 0)
        finally:
            os.unlink(path)

    def test_sdn_subcommand(self):
        self.assertEqual(main(["sdn", "--format", "json"]), 0)

    def test_bad_path(self):
        self.assertEqual(main(["screen", "/no/such/file.json"]), 2)


if __name__ == "__main__":
    unittest.main()

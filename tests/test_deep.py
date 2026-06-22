"""Deep tests for CRYPTOTRACE: OFAC screening + address clustering.

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
    analyze,
    cluster_addresses,
    is_sanctioned,
    ofac_entries,
    parse_txs,
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
        self.assertGreaterEqual(len(entries), 15)
        addrs = {e["address"].lower() for e in entries}
        self.assertIn(SDN_BTC.lower(), addrs)
        # known Tornado Cash router address must be present
        self.assertIn("0x8589427373d6d84e98730d7795d8f6f8731fda16", addrs)
        entities = {e["entity"] for e in entries}
        self.assertIn("Lazarus Group (DPRK)", entities)
        self.assertIn("Tornado Cash", entities)


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


class TestParsing(unittest.TestCase):
    def test_parse_demo(self):
        txs = _load_demo()
        self.assertEqual(len(txs), 6)

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
        self.assertIn("1Layer2Hop000000000000000000000cccc", two)

    def test_hop_severity_grading(self):
        # v3 grading: a 1-hop counterparty is always "high"; deeper hops are
        # "medium" UNLESS value-weighted taint is heavy (>=50%), in which case
        # the finding is escalated to "high".
        for f in self.res.findings:
            if f.kind != "ofac_indirect_exposure":
                continue
            if f.hops == 1:
                self.assertEqual(f.severity, "high")
            elif f.taint >= 0.5:
                self.assertEqual(f.severity, "high")
            else:
                self.assertEqual(f.severity, "medium")

    def test_max_severity(self):
        self.assertEqual(self.res.max_severity, "critical")

    def test_max_hops_limits_exposure(self):
        narrow = analyze(_load_demo(), max_hops=1)
        # with only 1 hop, the 2-hop addresses must not be flagged
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
        # must NOT be merged with WalletA
        self.assertNotIn("1WalletA-in1000000000000000000ddd1", c.addresses)

    def test_singletons_not_emitted(self):
        for c in self.clusters:
            self.assertGreaterEqual(len(c.addresses), 2)

    def test_unrelated_inputs_not_merged(self):
        # two txs that never share inputs must not be one cluster
        txs = parse_txs(
            '[{"txid":"a","inputs":["1P","1Q"],"outputs":["1R"]},'
            ' {"txid":"b","inputs":["1S","1T"],"outputs":["1U"]}]')
        clusters = cluster_addresses(txs)
        for c in clusters:
            self.assertFalse({"1P", "1S"} <= set(c.addresses))


class TestCLI(unittest.TestCase):
    def test_screen_exit_nonzero_on_findings(self):
        rc = main(["screen", DEMO, "--format", "json"])
        self.assertEqual(rc, 1)

    def test_check_sdn_exit_nonzero(self):
        rc = main(["check", SDN_BTC])
        self.assertEqual(rc, 1)

    def test_check_clean_exit_zero(self):
        rc = main(["check", "1TotallyCleanAddress00000000000000"])
        self.assertEqual(rc, 0)

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

    def test_cluster_subcommand_exit_zero(self):
        self.assertEqual(main(["cluster", DEMO, "--format", "json"]), 0)

    def test_sdn_subcommand(self):
        self.assertEqual(main(["sdn", "--format", "json"]), 0)

    def test_bad_path(self):
        self.assertEqual(main(["screen", "/no/such/file.json"]), 2)


if __name__ == "__main__":
    unittest.main()

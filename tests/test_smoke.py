"""Smoke tests for CRYPTOTRACE. No network. Run: python -m pytest or unittest."""
import json
import os
import sys
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

# A real OFAC SDN address (SUEX OTC) used in the demo graph.
SDN_BTC = "1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f"


class TestMetadata(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(TOOL_NAME, "cryptotrace")
        self.assertTrue(TOOL_VERSION)

    def test_sdn_bundle(self):
        self.assertGreaterEqual(len(ofac_entries()), 18)


class TestSanctions(unittest.TestCase):
    def test_hit(self):
        hit = is_sanctioned(SDN_BTC)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["entity"], "SUEX OTC")

    def test_eth_case_insensitive(self):
        self.assertIsNotNone(
            is_sanctioned("0x8589427373D6D84E98730D7795D8F6F8731FDA16"))

    def test_no_hit(self):
        self.assertIsNone(is_sanctioned("1SomeRandomCleanAddress0000000000"))


class TestParsing(unittest.TestCase):
    def test_account_style(self):
        txs = parse_txs('[{"hash":"x","from":"0xabc","to":"0xdef","asset":"ETH"}]')
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0].inputs, ["0xabc"])
        self.assertEqual(txs[0].outputs, ["0xdef"])

    def test_utxo_style(self):
        txs = parse_txs('[{"txid":"a","inputs":["1AAA","1BBB"],"outputs":["1CCC"]}]')
        self.assertEqual(txs[0].inputs, ["1AAA", "1BBB"])


class TestClustering(unittest.TestCase):
    def test_cospend_merges(self):
        txs = parse_txs('[{"txid":"a","inputs":["1AAA","1BBB"],"outputs":["1CCC"]}]')
        clusters = cluster_addresses(txs)
        merged = [c for c in clusters
                  if "1AAA" in c.addresses and "1BBB" in c.addresses]
        self.assertEqual(len(merged), 1)
        self.assertNotIn("1CCC", merged[0].addresses)


class TestAnalyze(unittest.TestCase):
    def test_clean_graph(self):
        txs = parse_txs('[{"txid":"c1","inputs":["1Clean1"],"outputs":["1Clean2"]}]')
        res = analyze(txs)
        self.assertEqual(
            [f for f in res.findings if f.kind.startswith("ofac")], [])
        self.assertEqual(res.max_severity, "info")

    def test_demo_graph_serializable(self):
        with open(DEMO, encoding="utf-8") as fh:
            res = analyze(parse_txs(fh.read()))
        json.dumps(res.to_dict())  # must not raise
        self.assertEqual(res.max_severity, "critical")


class TestCLI(unittest.TestCase):
    def test_check_sdn_exit_1(self):
        self.assertEqual(main(["check", SDN_BTC]), 1)

    def test_check_clean_exit_0(self):
        self.assertEqual(main(["check", "1TotallyCleanAddress00000000000000"]), 0)

    def test_screen_demo_json_exit_1(self):
        self.assertEqual(main(["screen", DEMO, "--format", "json"]), 1)

    def test_sdn_listing_exit_0(self):
        self.assertEqual(main(["sdn", "--format", "json"]), 0)

    def test_bad_path_exit_2(self):
        self.assertEqual(main(["screen", "/no/such/file.json"]), 2)


if __name__ == "__main__":
    unittest.main()

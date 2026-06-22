"""Smoke tests for CRYPTOTRACE (current API). No network.

Run: python -m pytest  (or python -m unittest).
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
    Transaction,
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

# A real OFAC SDN address (Tornado Cash router) used as a known-good probe.
SDN_ETH = "0x722122df12d4e14e13ac3b6895a86e84145b6967"


class TestMetadata(unittest.TestCase):
    def test_name_and_version(self):
        self.assertEqual(TOOL_NAME, "cryptotrace")
        self.assertTrue(TOOL_VERSION)

    def test_sdn_list_nonempty(self):
        entries = ofac_entries()
        self.assertGreater(len(entries), 5)
        for e in entries:
            self.assertIn("address", e)
            self.assertIn("entity", e)
            self.assertIn("program", e)


class TestSanctions(unittest.TestCase):
    def test_direct_hit(self):
        hit = is_sanctioned(SDN_ETH)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["entity"], "Tornado Cash")

    def test_case_insensitive_eth(self):
        self.assertIsNotNone(is_sanctioned(SDN_ETH.upper()))

    def test_clean(self):
        self.assertIsNone(is_sanctioned("0x" + "f" * 40))


class TestClustering(unittest.TestCase):
    def test_common_input_merges(self):
        a, b, c = "0x" + "a" * 40, "0x" + "b" * 40, "0x" + "c" * 40
        txs = [Transaction(txid="t1", inputs=[a, b], outputs=[c], asset="ETH")]
        clusters = cluster_addresses(txs)
        self.assertEqual(len(clusters), 1)
        members = set(clusters[0].addresses)
        self.assertIn(a, members)
        self.assertIn(b, members)
        self.assertNotIn(c, members)


class TestAnalyze(unittest.TestCase):
    def test_direct_hit_is_critical(self):
        txs = [Transaction(txid="t1", inputs=["0x" + "1" * 40],
                           outputs=[SDN_ETH], value=5.0, asset="ETH")]
        res = analyze(txs, max_hops=1)
        self.assertEqual(res.max_severity, "critical")
        kinds = {f.kind for f in res.findings}
        self.assertIn("ofac_direct_hit", kinds)
        self.assertIn("ofac_indirect_exposure", kinds)

    def test_json_serializable(self):
        txs = parse_txs('[{"txid":"t","inputs":["0x' + "1" * 40
                        + '"],"outputs":["0x' + "2" * 40
                        + '"],"asset":"ETH","value":1.0}]')
        json.dumps(analyze(txs).to_dict())  # must not raise

    def test_clean_graph_is_info(self):
        txs = [Transaction(txid="t1", inputs=["0x" + "1" * 40],
                           outputs=["0x" + "2" * 40], asset="ETH")]
        res = analyze(txs)
        self.assertEqual(res.max_severity, "info")


class TestCLI(unittest.TestCase):
    def test_screen_demo_flags(self):
        # The deep demo contains an SDN address, so screen must exit non-zero.
        self.assertEqual(main(["screen", DEMO]), 1)

    def test_screen_json(self):
        # JSON path must run without raising; exit non-zero (SDN present).
        self.assertEqual(main(["screen", "--format", "json", DEMO]), 1)

    def test_check_hit_exit_1(self):
        self.assertEqual(main(["check", SDN_ETH]), 1)

    def test_check_clean_exit_0(self):
        self.assertEqual(main(["check", "0x" + "e" * 40]), 0)

    def test_sdn_lists(self):
        self.assertEqual(main(["sdn"]), 0)

    def test_bad_file_exit_2(self):
        self.assertEqual(main(["screen", "/no/such/file.json"]), 2)

    def test_empty_input_clean(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("[]")
            path = f.name
        try:
            self.assertEqual(main(["screen", path]), 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

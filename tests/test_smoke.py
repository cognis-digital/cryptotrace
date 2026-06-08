"""Smoke tests for CRYPTOTRACE. No network. Run: python -m pytest or unittest."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace import (  # noqa: E402
    TOOL_NAME, TOOL_VERSION, classify_address, cluster_addresses,
    sanctions_xref, investigate, Transfer,
)
from cryptotrace.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "demos", "01-basic", "transfers.json")


class TestClassify(unittest.TestCase):
    def test_eth(self):
        self.assertEqual(classify_address("0x" + "a" * 40), "eth")

    def test_btc_legacy(self):
        self.assertEqual(classify_address("1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s"), "btc-legacy")

    def test_bech32(self):
        self.assertEqual(classify_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "btc-bech32")

    def test_invalid(self):
        self.assertEqual(classify_address("not-an-address"), "invalid")
        self.assertEqual(classify_address("0x123"), "invalid")


class TestClustering(unittest.TestCase):
    def test_cospend_merges(self):
        a, b, c = "0x" + "a" * 40, "0x" + "b" * 40, "0x" + "c" * 40
        ts = [Transfer(src=a, dst=c, inputs=[a, b])]
        cl = cluster_addresses(ts)
        self.assertEqual(cl[a], cl[b])  # co-spent -> same cluster
        self.assertNotEqual(cl[a], cl[c])  # destination separate


class TestSanctions(unittest.TestCase):
    def test_hit(self):
        hits = sanctions_xref(["0x722122df12d4e14e13ac3b6895a86e84145b6967"])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["category"], "sanctioned")

    def test_no_hit(self):
        self.assertEqual(sanctions_xref(["0x" + "f" * 40]), [])

    def test_case_insensitive(self):
        upper = "0x722122DF12D4E14E13AC3B6895A86E84145B6967"
        self.assertEqual(len(sanctions_xref([upper])), 1)


class TestInvestigate(unittest.TestCase):
    def test_demo_report(self):
        with open(DEMO, encoding="utf-8") as fh:
            rows = json.load(fh)
        ts = [Transfer(src=r["src"], dst=r["dst"], value=r.get("value", 0),
                       inputs=r.get("inputs", [])) for r in rows]
        rep = investigate(ts)
        self.assertGreaterEqual(rep["summary"]["sanctioned_clusters"], 1)
        self.assertGreaterEqual(rep["summary"]["flagged_addresses"], 1)
        # co-spent aaa/bbb share a cluster
        prof = {a["address"]: a for a in rep["addresses"]}
        self.assertEqual(prof["0x" + "a" * 40]["cluster_id"],
                         prof["0x" + "b" * 40]["cluster_id"])

    def test_json_serializable(self):
        rep = investigate([Transfer(src="0x" + "1" * 40, dst="0x" + "2" * 40, value=1.0)])
        json.dumps(rep)  # must not raise


class TestCLI(unittest.TestCase):
    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "cryptotrace")
        self.assertTrue(TOOL_VERSION)

    def test_investigate_json(self):
        self.assertEqual(main(["--format", "json", "investigate", DEMO]), 0)

    def test_xref_hit_exit_2(self):
        self.assertEqual(main(["xref", "0x722122df12d4e14e13ac3b6895a86e84145b6967"]), 2)

    def test_xref_clean_exit_0(self):
        self.assertEqual(main(["xref", "0x" + "e" * 40]), 0)

    def test_classify_invalid_exit_1(self):
        self.assertEqual(main(["classify", "garbage"]), 1)

    def test_bad_file_exit_1(self):
        self.assertEqual(main(["investigate", "/no/such/file.json"]), 1)

    def test_bad_json_exit_1(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{not json")
            path = f.name
        try:
            self.assertEqual(main(["investigate", path]), 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

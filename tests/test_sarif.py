"""Tests for the SARIF 2.1.0 export (`cryptotrace screen --format sarif`).

No network. Run with: python -m pytest  (or python -m unittest).
"""
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace import (  # noqa: E402
    SARIF_SCHEMA,
    Transaction,
    analyze,
    to_sarif,
)
from cryptotrace.cli import main  # noqa: E402

SDN_ETH = "0x722122df12d4e14e13ac3b6895a86e84145b6967"  # Tornado Cash router


def _sanctioned_result():
    txs = [
        Transaction(txid="t1", inputs=["0x" + "1" * 40], outputs=[SDN_ETH],
                    value=10.0, asset="ETH"),
        Transaction(txid="t2", inputs=[SDN_ETH], outputs=["0x" + "2" * 40],
                    value=9.5, asset="ETH"),
    ]
    return analyze(txs, max_hops=2)


class TestSarifStructure(unittest.TestCase):
    def setUp(self):
        self.sarif = to_sarif(_sanctioned_result())

    def test_top_level(self):
        self.assertEqual(self.sarif["version"], "2.1.0")
        self.assertEqual(self.sarif["$schema"], SARIF_SCHEMA)
        self.assertIn("runs", self.sarif)
        self.assertEqual(len(self.sarif["runs"]), 1)

    def test_serializable(self):
        # SARIF must be valid JSON.
        json.dumps(self.sarif)

    def test_driver(self):
        driver = self.sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "cryptotrace")
        self.assertTrue(driver["version"])
        self.assertTrue(driver["informationUri"].startswith("https://"))

    def test_rules_match_results(self):
        run = self.sarif["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        result_rule_ids = {res["ruleId"] for res in run["results"]}
        # Every result references a declared rule.
        self.assertTrue(result_rule_ids.issubset(rule_ids))
        # ruleIndex must point at the matching rule.
        rules = run["tool"]["driver"]["rules"]
        for res in run["results"]:
            self.assertEqual(rules[res["ruleIndex"]]["id"], res["ruleId"])

    def test_result_fields(self):
        run = self.sarif["runs"][0]
        self.assertTrue(run["results"])  # sanctioned graph => >=1 result
        direct = [r for r in run["results"]
                  if r["ruleId"] == "ofac_direct_hit"]
        self.assertEqual(len(direct), 1)
        r = direct[0]
        self.assertEqual(r["level"], "error")
        self.assertEqual(r["properties"]["security-severity"], "9.5")
        self.assertEqual(r["properties"]["address"], SDN_ETH)
        loc = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertIn(SDN_ETH, loc)
        self.assertIn("partialFingerprints", r)

    def test_severity_levels(self):
        # SARIF level must be one of the four legal values.
        legal = {"error", "warning", "note", "none"}
        for res in self.sarif["runs"][0]["results"]:
            self.assertIn(res["level"], legal)


class TestSarifEmptyGraph(unittest.TestCase):
    def test_clean_graph_has_no_results(self):
        txs = [Transaction(txid="t1", inputs=["0x" + "1" * 40],
                           outputs=["0x" + "2" * 40], asset="ETH")]
        sarif = to_sarif(analyze(txs))
        run = sarif["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["tool"]["driver"]["rules"], [])
        json.dumps(sarif)  # still valid


class TestSarifCLI(unittest.TestCase):
    DEMO = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "demos", "01-tornado-cash-deposit", "tx_graph.json",
    )

    def test_cli_sarif_exit_and_output(self):
        # Capture stdout.
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = main(["screen", "--format", "sarif", self.DEMO])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 1)  # SDN present => non-zero
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])

    def test_cli_sarif_to_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sarif",
                                         delete=False) as f:
            path = f.name
        try:
            rc = main(["screen", "--format", "sarif", "-o", path, self.DEMO])
            self.assertEqual(rc, 1)
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["version"], "2.1.0")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

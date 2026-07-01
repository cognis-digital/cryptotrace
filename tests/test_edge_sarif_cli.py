"""SARIF-export edge tests + CLI error-path / exit-code tests. No network.

Run: python -m pytest  (or python -m unittest).
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace.cli import main  # noqa: E402
from cryptotrace.core import (  # noqa: E402
    SARIF_SCHEMA,
    Transaction,
    analyze,
    to_sarif,
)

SDN_ETH = "0x722122df12d4e14e13ac3b6895a86e84145b6967"   # Tornado Cash router
SDN_BTC = "1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f"           # SUEX OTC


def tx(txid, ins, outs, asset="ETH", value=0.0):
    return Transaction(txid, list(ins), list(outs), asset, value)


def _run(argv):
    """Run the CLI, capturing (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as e:  # argparse errors
            rc = e.code if isinstance(e.code, int) else 2
    return rc, out.getvalue(), err.getvalue()


def _write(text):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# --------------------------------------------------------------------------- #
# SARIF edge cases
# --------------------------------------------------------------------------- #
class TestSarifEdges(unittest.TestCase):
    def test_empty_result_valid_sarif(self):
        s = to_sarif(analyze([]))
        self.assertEqual(s["version"], "2.1.0")
        self.assertEqual(s["$schema"], SARIF_SCHEMA)
        self.assertEqual(s["runs"][0]["results"], [])
        self.assertEqual(s["runs"][0]["tool"]["driver"]["rules"], [])

    def test_rules_deduped_by_kind(self):
        # Multiple direct hits -> one 'ofac_direct_hit' rule.
        txs = [tx("t0", [SDN_ETH], ["B"], value=1.0),
               tx("t1", [SDN_BTC], ["C"], "BTC", value=1.0)]
        s = to_sarif(analyze(txs))
        rule_ids = [r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertIn("ofac_direct_hit", rule_ids)

    def test_rule_index_matches(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0),
               tx("t1", ["B"], ["C"], value=10.0)]
        s = to_sarif(analyze(txs, max_hops=2))
        rules = s["runs"][0]["tool"]["driver"]["rules"]
        for res in s["runs"][0]["results"]:
            self.assertEqual(rules[res["ruleIndex"]]["id"], res["ruleId"])

    def test_result_levels_mapped(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0)]
        s = to_sarif(analyze(txs))
        levels = {r["level"] for r in s["runs"][0]["results"]}
        self.assertTrue(levels <= {"error", "warning", "note", "none"})

    def test_security_severity_present(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0)]
        s = to_sarif(analyze(txs))
        for r in s["runs"][0]["results"]:
            self.assertIn("security-severity", r["properties"])

    def test_locations_encode_address(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0)]
        s = to_sarif(analyze(txs))
        r = s["runs"][0]["results"][0]
        uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertTrue(uri.startswith("chain/ETH/"))

    def test_partial_fingerprints_present(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0)]
        s = to_sarif(analyze(txs))
        for r in s["runs"][0]["results"]:
            self.assertIn("cryptotrace/v1", r["partialFingerprints"])

    def test_serializable(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0)]
        # Must round-trip cleanly through json.
        s = to_sarif(analyze(txs))
        json.loads(json.dumps(s))


# --------------------------------------------------------------------------- #
# CLI exit codes & error paths
# --------------------------------------------------------------------------- #
class TestCliErrorPaths(unittest.TestCase):
    def test_screen_missing_file_exit_2(self):
        rc, _, err = _run(["screen", os.path.join(tempfile.gettempdir(),
                                                   "no_such_cryptotrace_file.json")])
        self.assertEqual(rc, 2)
        self.assertIn("cannot read", err)

    def test_cluster_missing_file_exit_2(self):
        rc, _, err = _run(["cluster", "/does/not/exist.json"])
        self.assertEqual(rc, 2)

    def test_taint_missing_file_exit_2(self):
        rc, _, _ = _run(["taint", "/does/not/exist.json"])
        self.assertEqual(rc, 2)

    def test_peel_missing_file_exit_2(self):
        rc, _, _ = _run(["peel", "/does/not/exist.json"])
        self.assertEqual(rc, 2)

    def test_screen_bad_taint_threshold_exit_2(self):
        path = _write('[{"inputs":["A"],"outputs":["B"]}]')
        try:
            rc, _, err = _run(["screen", path, "--min-taint", "2.0"])
        finally:
            os.remove(path)
        self.assertEqual(rc, 2)
        self.assertIn("taint_threshold", err)

    def test_taint_bad_min_taint_exit_2(self):
        path = _write('[{"inputs":["A"],"outputs":["B"]}]')
        try:
            rc, _, err = _run(["taint", path, "--min-taint", "-0.5"])
        finally:
            os.remove(path)
        self.assertEqual(rc, 2)
        self.assertIn("min-taint", err)


class TestCliExitCodes(unittest.TestCase):
    def test_clean_screen_exit_0(self):
        path = _write('[{"inputs":["CLEAN1"],"outputs":["CLEAN2"],"value":1}]')
        try:
            rc, _, _ = _run(["screen", path])
        finally:
            os.remove(path)
        self.assertEqual(rc, 0)

    def test_flagged_screen_exit_1(self):
        path = _write('[{"inputs":["%s"],"outputs":["B"],"value":10,"asset":"ETH"}]'
                      % SDN_ETH)
        try:
            rc, _, _ = _run(["screen", path])
        finally:
            os.remove(path)
        self.assertEqual(rc, 1)

    def test_check_sanctioned_exit_1(self):
        rc, out, _ = _run(["check", SDN_BTC])
        self.assertEqual(rc, 1)
        self.assertIn("SANCTIONED", out)

    def test_check_clean_exit_0(self):
        rc, out, _ = _run(["check", "1CleanAddressNotOnAnyList0000000000"])
        self.assertEqual(rc, 0)
        self.assertIn("clean", out)

    def test_check_json_shape(self):
        rc, out, _ = _run(["check", SDN_BTC, "--format", "json"])
        data = json.loads(out)
        self.assertTrue(data["sanctioned"])
        self.assertEqual(data["address"], SDN_BTC)

    def test_sdn_lists_entries(self):
        rc, out, _ = _run(["sdn"])
        self.assertEqual(rc, 0)
        self.assertIn("SUEX OTC", out)

    def test_sdn_json(self):
        rc, out, _ = _run(["sdn", "--format", "json"])
        data = json.loads(out)
        self.assertGreaterEqual(len(data), 15)

    def test_screen_json_output_to_file(self):
        src = _write('[{"inputs":["%s"],"outputs":["B"],"value":10,"asset":"ETH"}]'
                     % SDN_ETH)
        fd, dst = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            rc, _, err = _run(["screen", src, "--format", "json", "-o", dst])
            with open(dst, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["tool"], "cryptotrace")
            self.assertIn("wrote", err)
        finally:
            os.remove(src)
            os.remove(dst)

    def test_screen_sarif_output(self):
        src = _write('[{"inputs":["%s"],"outputs":["B"],"value":10,"asset":"ETH"}]'
                     % SDN_ETH)
        try:
            rc, out, _ = _run(["screen", src, "--format", "sarif"])
            data = json.loads(out)
            self.assertEqual(data["version"], "2.1.0")
        finally:
            os.remove(src)

    def test_peel_json_shape(self):
        # Build a peel chain fixture on disk.
        txs = []
        prev = "SRC"
        for i in range(3):
            change = f"hop{i+1}"
            txs.append({"txid": f"p{i}", "inputs": [prev],
                        "outputs": [f"peel{i}", change], "value": 10 - i})
            prev = change
        path = _write(json.dumps(txs))
        try:
            rc, out, _ = _run(["peel", path, "--format", "json"])
            data = json.loads(out)
            self.assertIn("peel_chains", data)
            self.assertEqual(rc, 1)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()

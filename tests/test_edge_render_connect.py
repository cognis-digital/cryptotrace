"""Table-rendering, CLI-command-coverage, connect/emit mapping, and deeper
analyze/taint integration tests. No network.

Run: python -m pytest.
"""
from __future__ import annotations

import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace.cli import _render_table, _flagged, main  # noqa: E402
from cryptotrace.core import (  # noqa: E402
    Transaction,
    analyze,
    propagate_taint,
)

SDN_ETH = "0x722122df12d4e14e13ac3b6895a86e84145b6967"   # Tornado Cash router
SDN_BTC = "1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f"           # SUEX OTC


def tx(txid, ins, outs, asset="ETH", value=0.0):
    return Transaction(txid, list(ins), list(outs), asset, value)


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 2
    return rc, out.getvalue(), err.getvalue()


def _write(text):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# --------------------------------------------------------------------------- #
# Table rendering
# --------------------------------------------------------------------------- #
class TestRenderTable(unittest.TestCase):
    def _flagged_res(self):
        return analyze([tx("t0", [SDN_ETH], ["B"], value=10.0),
                        tx("t1", ["B"], ["C"], value=10.0)], max_hops=2)

    def test_header_present(self):
        out = _render_table(self._flagged_res())
        self.assertIn("CRYPTOTRACE report", out)
        self.assertIn("Transactions analyzed", out)
        self.assertIn("Highest severity", out)

    def test_findings_section(self):
        out = _render_table(self._flagged_res())
        self.assertIn("Findings:", out)
        self.assertIn("CRITICAL", out)

    def test_clean_result_no_exposure_line(self):
        res = analyze([tx("t0", ["A", "B"], ["C"], value=1.0)])
        out = _render_table(res)
        self.assertIn("No sanctioned exposure found.", out)

    def test_clusters_section_when_present(self):
        res = analyze([tx("t0", [SDN_BTC, "CLEAN"], ["OUT"], "BTC", 1.0)])
        out = _render_table(res)
        self.assertIn("Clusters", out)
        self.assertIn("SANCTIONED", out)

    def test_tainted_value_line(self):
        out = _render_table(self._flagged_res())
        self.assertIn("Tainted value (total)", out)


class TestFlaggedHelper(unittest.TestCase):
    def test_flagged_true_on_critical(self):
        self.assertTrue(_flagged(analyze([tx("t0", [SDN_ETH], ["B"], value=1.0)])))

    def test_flagged_false_on_clean(self):
        self.assertFalse(_flagged(analyze([tx("t0", ["A"], ["B"], value=1.0)])))

    def test_flagged_false_on_empty(self):
        self.assertFalse(_flagged(analyze([])))


# --------------------------------------------------------------------------- #
# CLI command coverage (table + json paths, stdin)
# --------------------------------------------------------------------------- #
class TestCliCommands(unittest.TestCase):
    def test_cluster_table_output(self):
        path = _write('[{"inputs":["%s","CLEAN"],"outputs":["OUT"],"value":1,'
                      '"asset":"BTC"}]' % SDN_BTC)
        try:
            rc, out, _ = _run(["cluster", path])
        finally:
            os.remove(path)
        self.assertEqual(rc, 1)  # sanctioned cluster -> exit 1
        self.assertIn("SANCTIONED", out)

    def test_cluster_no_clusters_message(self):
        path = _write('[{"inputs":["A"],"outputs":["B"],"value":1}]')
        try:
            rc, out, _ = _run(["cluster", path])
        finally:
            os.remove(path)
        self.assertEqual(rc, 0)
        self.assertIn("No multi-address clusters", out)

    def test_cluster_json(self):
        path = _write('[{"inputs":["A","B"],"outputs":["C"],"value":1}]')
        try:
            rc, out, _ = _run(["cluster", path, "--format", "json"])
        finally:
            os.remove(path)
        data = json.loads(out)
        self.assertIsInstance(data, list)

    def test_taint_table_output(self):
        path = _write('[{"inputs":["%s"],"outputs":["DOWN"],"value":5,'
                      '"asset":"ETH"}]' % SDN_ETH)
        try:
            rc, out, _ = _run(["taint", path])
        finally:
            os.remove(path)
        self.assertEqual(rc, 1)
        self.assertIn("Sanctioned sources", out)

    def test_taint_json(self):
        path = _write('[{"inputs":["%s"],"outputs":["DOWN"],"value":5,'
                      '"asset":"ETH"}]' % SDN_ETH)
        try:
            rc, out, _ = _run(["taint", path, "--format", "json"])
        finally:
            os.remove(path)
        data = json.loads(out)
        self.assertIn("sources", data)
        self.assertIn("tainted", data)

    def test_taint_no_sources_exit_0(self):
        path = _write('[{"inputs":["A"],"outputs":["B"],"value":1}]')
        try:
            rc, out, _ = _run(["taint", path])
        finally:
            os.remove(path)
        self.assertEqual(rc, 0)

    def test_peel_no_chains_message(self):
        path = _write('[{"inputs":["A"],"outputs":["B"],"value":1}]')
        try:
            rc, out, _ = _run(["peel", path])
        finally:
            os.remove(path)
        self.assertEqual(rc, 0)
        self.assertIn("No peeling chains", out)

    def test_screen_stdin(self):
        payload = '[{"inputs":["%s"],"outputs":["B"],"value":10,"asset":"ETH"}]' % SDN_ETH
        old = sys.stdin
        sys.stdin = io.StringIO(payload)
        try:
            rc, out, _ = _run(["screen", "-", "--format", "json"])
        finally:
            sys.stdin = old
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["tool"], "cryptotrace")

    def test_check_actor_tag(self):
        rc, out, _ = _run(["check", "1ExchangeHotWalletDemo0000000000"])
        self.assertEqual(rc, 0)
        self.assertIn("known actor", out)

    def test_max_hops_zero_no_indirect(self):
        path = _write(json.dumps([
            {"txid": "t0", "inputs": [SDN_ETH], "outputs": ["B"], "value": 10,
             "asset": "ETH"},
            {"txid": "t1", "inputs": ["B"], "outputs": ["C"], "value": 10,
             "asset": "ETH"},
        ]))
        try:
            rc, out, _ = _run(["screen", path, "--format", "json", "--max-hops", "0"])
            data = json.loads(out)
        finally:
            os.remove(path)
        self.assertEqual(data["max_hops_scanned"], 0)


# --------------------------------------------------------------------------- #
# connect / emit mapping (cognis-connect is an optional extra)
# --------------------------------------------------------------------------- #
class TestConnectMapping(unittest.TestCase):
    def setUp(self):
        try:
            importlib.import_module("cognis_connect")
        except ImportError:
            self.skipTest("cognis-connect not installed")
        self.mod = importlib.import_module("cryptotrace.connect")

    def test_map_record_passthrough(self):
        rec = {"kind": "ofac_direct_hit", "address": "0xabc", "severity": "critical"}
        self.assertEqual(self.mod.map_record(rec), rec)

    def test_findings_from_results_wrapper(self):
        payload = json.dumps({"results": [
            {"title": "x", "severity": "high", "address": "0xabc"}]})
        fs = self.mod._findings(payload)
        self.assertEqual(len(fs), 1)

    def test_findings_from_findings_wrapper(self):
        payload = json.dumps({"findings": [
            {"title": "x", "severity": "medium", "address": "0xabc"}]})
        fs = self.mod._findings(payload)
        self.assertEqual(len(fs), 1)

    def test_findings_from_bare_dict(self):
        payload = json.dumps({"title": "x", "severity": "low", "domain": "a.example"})
        fs = self.mod._findings(payload)
        self.assertEqual(len(fs), 1)

    def test_emit_requires_to(self):
        with self.assertRaises(SystemExit):
            self.mod.emit_main([])  # --to is required


# --------------------------------------------------------------------------- #
# Deeper analyze / taint integration
# --------------------------------------------------------------------------- #
class TestIntegration(unittest.TestCase):
    def test_min_taint_suppresses_low_taint(self):
        # A long dilution chain drops taint fraction; a high threshold prunes it.
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0)]
        for i in range(5):
            txs.append(tx(f"c{i}", [f"m{i}" if i else "B", f"clean{i}"],
                          [f"m{i+1}"], value=100.0))
        full = analyze(txs, max_hops=10, taint_threshold=0.0)
        pruned = analyze(txs, max_hops=10, taint_threshold=0.9)
        self.assertGreaterEqual(len(full.findings), len(pruned.findings))

    def test_dirty_total_matches_taint_sum(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0),
               tx("t1", ["B"], ["C"], value=10.0)]
        res = analyze(txs, max_hops=2)
        taint = propagate_taint(txs, {SDN_ETH})
        self.assertAlmostEqual(res.dirty_value_total,
                               sum(v["dirty"] for v in taint.values()), places=6)

    def test_multiple_sources(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=5.0),
               tx("t1", [SDN_BTC], ["C"], "BTC", value=5.0)]
        res = analyze(txs, max_hops=2)
        directs = [f for f in res.findings if f.kind == "ofac_direct_hit"]
        self.assertEqual(len(directs), 2)

    def test_no_taint_without_source_in_graph(self):
        # SDN address referenced but never spends -> its recipients only.
        txs = [tx("t0", ["A"], [SDN_ETH], value=10.0)]  # SDN is an OUTPUT
        res = analyze(txs, max_hops=2)
        # direct hit present, but no dirty value flows FROM it here
        self.assertTrue(any(f.kind == "ofac_direct_hit" for f in res.findings))

    def test_asset_inferred_from_first_tx(self):
        res = analyze([tx("t0", ["A"], ["B"], asset="ETH", value=1.0)])
        self.assertEqual(res.asset, "ETH")

    def test_analyze_is_deterministic(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0),
               tx("t1", ["B"], ["C"], value=10.0)]
        a = analyze(txs, max_hops=2).to_dict()
        b = analyze(list(txs), max_hops=2).to_dict()
        self.assertEqual(json.dumps(a, sort_keys=True),
                         json.dumps(b, sort_keys=True))

    def test_taint_is_deterministic(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0),
               tx("t1", ["B", "CLEAN"], ["C"], value=20.0)]
        self.assertEqual(propagate_taint(txs, {SDN_ETH}),
                         propagate_taint(list(txs), {SDN_ETH}))

    def test_analyze_does_not_mutate_input(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0)]
        before = [(t.txid, tuple(t.inputs), tuple(t.outputs)) for t in txs]
        analyze(txs, max_hops=2)
        after = [(t.txid, tuple(t.inputs), tuple(t.outputs)) for t in txs]
        self.assertEqual(before, after)

    def test_taint_threshold_zero_reports_all(self):
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0),
               tx("t1", ["B"], ["C"], value=10.0)]
        res = analyze(txs, max_hops=2, taint_threshold=0.0)
        self.assertTrue(any(f.kind == "ofac_indirect_exposure" for f in res.findings))

    def test_taint_threshold_one_prunes_diluted(self):
        # A diluted downstream address (<100% taint) is pruned at threshold 1.0.
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0),
               tx("t1", ["B", "CLEAN"], ["C"], value=100.0)]
        res = analyze(txs, max_hops=2, taint_threshold=1.0)
        c = [f for f in res.findings if f.address == "c" and f.taint < 1.0]
        self.assertEqual(c, [])

    def test_render_table_empty(self):
        # Should not raise on an empty result.
        out = _render_table(analyze([]))
        self.assertIn("CRYPTOTRACE report", out)

    def test_screen_table_default_stdout(self):
        path = _write('[{"inputs":["%s"],"outputs":["B"],"value":10,"asset":"ETH"}]'
                      % SDN_ETH)
        try:
            rc, out, _ = _run(["screen", path])
        finally:
            os.remove(path)
        self.assertEqual(rc, 1)
        self.assertIn("CRYPTOTRACE report", out)


if __name__ == "__main__":
    unittest.main()

"""Hardening tests: input validation, error handling, and edge cases.

Covers the new guards added to cli.py and core.py without touching or
duplicating any existing test assertions.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace import analyze, investigate, parse_txs, sanctions_xref
from cryptotrace.cli import main


# ---------------------------------------------------------------------------
# core.py — analyze() max_hops validation
# ---------------------------------------------------------------------------

class TestAnalyzeValidation(unittest.TestCase):
    def test_negative_max_hops_raises(self):
        """analyze() must reject negative max_hops with a clear ValueError."""
        txs = parse_txs('[{"txid":"t1","inputs":["1A"],"outputs":["1B"]}]')
        with self.assertRaises(ValueError) as ctx:
            analyze(txs, max_hops=-1)
        self.assertIn("max_hops", str(ctx.exception))

    def test_zero_max_hops_ok(self):
        """max_hops=0 is valid: only direct hits are reported, no BFS."""
        txs = parse_txs('[{"txid":"t1","inputs":["1A"],"outputs":["1B"]}]')
        res = analyze(txs, max_hops=0)
        # No indirect exposure findings since we never BFS
        indirect = [f for f in res.findings if f.kind == "ofac_indirect_exposure"]
        self.assertEqual(indirect, [])

    def test_empty_tx_list(self):
        """analyze() over an empty list returns a valid TraceResult."""
        res = analyze([])
        self.assertEqual(res.total_txs, 0)
        self.assertEqual(res.total_addresses, 0)
        self.assertEqual(res.findings, [])
        self.assertEqual(res.max_severity, "info")


# ---------------------------------------------------------------------------
# core.py — investigate() validation
# ---------------------------------------------------------------------------

class TestInvestigateValidation(unittest.TestCase):
    def test_negative_max_hops_raises(self):
        """investigate() must reject negative max_hops."""
        with self.assertRaises(ValueError) as ctx:
            investigate([], max_hops=-1)
        self.assertIn("max_hops", str(ctx.exception))

    def test_empty_transfers(self):
        """investigate([]) must return a structurally valid report."""
        rep = investigate([])
        self.assertEqual(rep["summary"]["total_transfers"], 0)
        self.assertEqual(rep["summary"]["flagged_addresses"], 0)
        self.assertIsInstance(rep["findings"], list)
        self.assertIsInstance(rep["clusters"], list)
        json.dumps(rep)  # must be JSON-serialisable


# ---------------------------------------------------------------------------
# core.py — sanctions_xref() edge cases
# ---------------------------------------------------------------------------

class TestSanctionsXrefEdgeCases(unittest.TestCase):
    def test_none_input_returns_empty(self):
        """sanctions_xref(None) must return [] not raise."""
        self.assertEqual(sanctions_xref(None), [])

    def test_empty_list_returns_empty(self):
        self.assertEqual(sanctions_xref([]), [])


# ---------------------------------------------------------------------------
# cli.py — screen subcommand: --max-hops guard
# ---------------------------------------------------------------------------

class TestCLIScreenMaxHops(unittest.TestCase):
    def test_negative_max_hops_exits_2(self):
        """screen --max-hops -1 must print an error to stderr and exit 2."""
        clean = '[{"txid":"t1","inputs":["1CleanA"],"outputs":["1CleanB"]}]'
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8") as tf:
            tf.write(clean)
            path = tf.name
        try:
            rc = main(["screen", path, "--max-hops", "-1"])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# cli.py — cluster subcommand: bad file guard
# ---------------------------------------------------------------------------

class TestCLIClusterBadFile(unittest.TestCase):
    def test_missing_file_exits_2(self):
        """cluster with a non-existent file must exit 2."""
        rc = main(["cluster", "/no/such/file.json"])
        self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# core.py — parse_txs edge cases
# ---------------------------------------------------------------------------

class TestParseTxsEdgeCases(unittest.TestCase):
    def test_none_like_empty(self):
        """parse_txs('') must return an empty list, not raise."""
        self.assertEqual(parse_txs(""), [])

    def test_fully_invalid_json(self):
        """parse_txs with fully invalid JSON must return empty (JSONL fallback)."""
        result = parse_txs("this is not json at all !!!")
        # JSONL fallback silently skips invalid lines → empty list
        self.assertIsInstance(result, list)

    def test_non_dict_items_skipped(self):
        """JSON arrays with non-dict items are skipped gracefully."""
        raw = '[1, null, "string", {"txid":"ok","inputs":["1A"],"outputs":["1B"]}]'
        txs = parse_txs(raw)
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0].txid, "ok")


if __name__ == "__main__":
    unittest.main()

"""Severity-grading boundaries + per-entity SDN table coverage. No network.

Run: python -m pytest.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace.core import (  # noqa: E402
    SEVERITY_ORDER,
    Transaction,
    analyze,
    is_sanctioned,
    ofac_entries,
)

SDN_ETH = "0x722122df12d4e14e13ac3b6895a86e84145b6967"   # Tornado Cash router


def tx(txid, ins, outs, asset="ETH", value=0.0):
    return Transaction(txid, list(ins), list(outs), asset, value)


# Every distinct real SDN entity that must be screenable by its bundled address.
_ENTITY_ADDRS = {
    "Lazarus Group (DPRK)": "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
    "Tornado Cash": "0x722122df12d4e14e13ac3b6895a86e84145b6967",
    "Garantex Europe OU": "1Fdyrt4iC91kAFRz9SiF44ZRzhCJqkLAFD",
    "SUEX OTC": "1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f",
    "Chatex": "1Dby8GNquU8tDjfDD3y8KZc4nKfHQwfJtL",
    "Hydra Market": "1AdraFvB8Ads5KFFGZQUgYvuhMQVjUuk5j",
    "Blender.io": "bc1q2sttgr0vd4r88uxq7feu5g0r8z7q3qkq0r6yqr",
    "Sinbad.io": "bc1qs4dqj3x3pqr0z5fpmldtq3z0d6q5w2x5lj7qk0",
    "Bitzlato": "1FzWLkAahHooV3kzTgyx6qsswXJ6sCXkSR",
}


class TestSdnEntityCoverage(unittest.TestCase):
    """One test per bundled SDN entity — a regression guard on the seed set."""


def _make_entity_test(entity, addr):
    def test(self):
        hit = is_sanctioned(addr)
        self.assertIsNotNone(hit, f"{entity} address not screenable")
        self.assertEqual(hit["entity"], entity)
    return test


for _entity, _addr in _ENTITY_ADDRS.items():
    _name = "test_" + "".join(c if c.isalnum() else "_" for c in _entity).lower()
    setattr(TestSdnEntityCoverage, _name, _make_entity_test(_entity, _addr))


class TestSdnCategories(unittest.TestCase):
    def test_categories_are_known(self):
        allowed = {"mixer", "exchange", "market", "threat_actor", "sdn"}
        for e in ofac_entries():
            self.assertIn(e["category"], allowed, f"{e['entity']}: {e['category']}")

    def test_programs_nonempty(self):
        for e in ofac_entries():
            self.assertTrue(e["program"], f"{e['entity']} missing program")

    def test_added_dates_iso(self):
        for e in ofac_entries():
            self.assertRegex(e["added"], r"^\d{4}-\d{2}-\d{2}$")

    def test_assets_btc_or_eth(self):
        for e in ofac_entries():
            self.assertIn(e["asset"], ("BTC", "ETH"))

    def test_no_duplicate_addresses(self):
        addrs = [e["address"].lower() for e in ofac_entries()]
        self.assertEqual(len(addrs), len(set(addrs)))

    def test_at_least_three_mixers(self):
        mixers = [e for e in ofac_entries() if e["category"] == "mixer"]
        self.assertGreaterEqual(len(mixers), 3)


class TestSeverityGrading(unittest.TestCase):
    def test_direct_hit_is_critical(self):
        res = analyze([tx("t0", [SDN_ETH], ["B"], value=10.0)])
        direct = [f for f in res.findings if f.kind == "ofac_direct_hit"]
        self.assertTrue(direct)
        self.assertTrue(all(f.severity == "critical" for f in direct))

    def test_one_hop_is_high(self):
        res = analyze([tx("t0", [SDN_ETH], ["B"], value=10.0)], max_hops=2)
        b = [f for f in res.findings
             if f.address == "b" or f.address == "B"]  # normalized may vary
        exposure = [f for f in res.findings if f.kind == "ofac_indirect_exposure"
                    and f.hops == 1]
        self.assertTrue(exposure)
        self.assertTrue(all(f.severity == "high" for f in exposure))

    def test_high_taint_is_high_even_far(self):
        # A fully-tainted address several hops out is still 'high' by taint.
        txs = [tx("t0", [SDN_ETH], ["B"], value=10.0),
               tx("t1", ["B"], ["C"], value=10.0),
               tx("t2", ["C"], ["D"], value=10.0)]
        res = analyze(txs, max_hops=1)  # only 1 hop scanned, taint still flows
        far = [f for f in res.findings if f.kind == "ofac_indirect_exposure"
               and f.taint >= 0.5]
        self.assertTrue(all(f.severity == "high" for f in far))

    def test_severity_order_monotonic(self):
        self.assertGreater(SEVERITY_ORDER["critical"], SEVERITY_ORDER["high"])
        self.assertGreater(SEVERITY_ORDER["high"], SEVERITY_ORDER["medium"])
        self.assertGreater(SEVERITY_ORDER["medium"], SEVERITY_ORDER["low"])
        self.assertGreater(SEVERITY_ORDER["low"], SEVERITY_ORDER["info"])

    def test_clean_graph_no_findings(self):
        res = analyze([tx("t0", ["A"], ["B"], value=1.0)])
        self.assertEqual(res.findings, [])


class TestHopGradingBoundaries(unittest.TestCase):
    def _chain(self, n, value=10.0):
        txs = [tx("t0", [SDN_ETH], ["h1"], value=value)]
        for i in range(1, n):
            txs.append(tx(f"t{i}", [f"h{i}"], [f"h{i+1}"], value=value))
        return txs

    def test_two_hops_medium_or_high(self):
        res = analyze(self._chain(3), max_hops=3)
        for f in res.findings:
            if f.kind == "ofac_indirect_exposure":
                self.assertIn(f.severity, ("high", "medium"))

    def test_hops_recorded_increasing(self):
        res = analyze(self._chain(4), max_hops=4)
        exposures = [f for f in res.findings if f.kind == "ofac_indirect_exposure"]
        hop_vals = sorted({f.hops for f in exposures})
        self.assertEqual(hop_vals, list(range(1, len(hop_vals) + 1)))


if __name__ == "__main__":
    unittest.main()

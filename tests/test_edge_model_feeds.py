"""Model-serialization, feeds-parser corner, and end-to-end fixture tests.

No network: feeds tests point COGNIS_FEEDS_CACHE at the committed fixture and
read offline. Run: python -m pytest.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from cryptotrace.core import (  # noqa: E402
    SEVERITY_ORDER,
    Cluster,
    Finding,
    TraceResult,
    Transaction,
    actor_tag,
    analyze,
    is_sanctioned,
    ofac_entries,
    parse_txs,
)

REPO = Path(__file__).resolve().parent.parent
DEMOS = REPO / "demos"
SDN_ETH = "0x722122df12d4e14e13ac3b6895a86e84145b6967"   # Tornado Cash router
SDN_BTC = "1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f"           # SUEX OTC


# --------------------------------------------------------------------------- #
# Transaction model
# --------------------------------------------------------------------------- #
class TestTransactionModel(unittest.TestCase):
    def test_all_addresses_normalizes(self):
        t = Transaction("t", ["0xABC"], ["0xDEF"], "ETH")
        self.assertEqual(t.all_addresses(), {"0xabc", "0xdef"})

    def test_all_addresses_dedupes(self):
        t = Transaction("t", ["A", "A"], ["A", "B"], "BTC")
        self.assertEqual(t.all_addresses(), {"A", "B"})

    def test_all_addresses_drops_empty(self):
        t = Transaction("t", ["A", ""], [""], "BTC")
        self.assertEqual(t.all_addresses(), {"A"})

    def test_defaults(self):
        t = Transaction("t", [], [])
        self.assertEqual(t.asset, "BTC")
        self.assertEqual(t.value, 0.0)
        self.assertEqual(t.timestamp, "")


# --------------------------------------------------------------------------- #
# Finding serialization
# --------------------------------------------------------------------------- #
class TestFindingModel(unittest.TestCase):
    def test_to_dict_keys(self):
        f = Finding("high", "kind", "addr", "detail", entity="E", program="P",
                    hops=2, taint=0.3333333, dirty_value=1.23456789)
        d = f.to_dict()
        for k in ("severity", "kind", "address", "detail", "entity", "program",
                  "hops", "taint", "dirty_value"):
            self.assertIn(k, d)

    def test_taint_rounded_6dp(self):
        f = Finding("high", "k", "a", "d", taint=0.123456789)
        self.assertEqual(f.to_dict()["taint"], round(0.123456789, 6))

    def test_dirty_value_rounded_8dp(self):
        f = Finding("high", "k", "a", "d", dirty_value=1.123456789012)
        self.assertEqual(f.to_dict()["dirty_value"], round(1.123456789012, 8))


# --------------------------------------------------------------------------- #
# Cluster serialization
# --------------------------------------------------------------------------- #
class TestClusterModel(unittest.TestCase):
    def test_to_dict_size_matches(self):
        c = Cluster(1, ["A", "B", "C"])
        self.assertEqual(c.to_dict()["size"], 3)

    def test_heuristics_sorted_unique(self):
        c = Cluster(1, ["A", "B"], heuristics=["change_address", "common_input",
                                               "common_input"])
        self.assertEqual(c.to_dict()["heuristics"],
                         ["change_address", "common_input"])

    def test_defaults(self):
        c = Cluster(1, ["A", "B"])
        d = c.to_dict()
        self.assertEqual(d["sanctioned_member"], "")
        self.assertEqual(d["actor"], "")
        self.assertEqual(d["risk_score"], 0)


# --------------------------------------------------------------------------- #
# TraceResult
# --------------------------------------------------------------------------- #
class TestTraceResultModel(unittest.TestCase):
    def _res(self):
        txs = [Transaction("t0", [SDN_ETH], ["B"], "ETH", 10.0),
               Transaction("t1", ["B"], ["C"], "ETH", 10.0)]
        return analyze(txs, max_hops=2)

    def test_counts_sum_matches_findings(self):
        res = self._res()
        self.assertEqual(sum(res.counts().values()), len(res.findings))

    def test_counts_has_all_severities(self):
        res = self._res()
        self.assertEqual(set(res.counts()), set(SEVERITY_ORDER))

    def test_max_severity_is_critical_on_direct_hit(self):
        self.assertEqual(self._res().max_severity, "critical")

    def test_max_severity_info_when_empty(self):
        self.assertEqual(analyze([]).max_severity, "info")

    def test_to_dict_roundtrips_json(self):
        json.loads(json.dumps(self._res().to_dict()))

    def test_to_dict_tool_and_version(self):
        d = self._res().to_dict()
        self.assertEqual(d["tool"], "cryptotrace")
        self.assertTrue(d["version"])

    def test_sanctioned_clusters_property(self):
        txs = [Transaction("t0", [SDN_BTC, "CLEAN"], ["OUT"], "BTC", 1.0)]
        res = analyze(txs)
        self.assertTrue(all(c.sanctioned_member for c in res.sanctioned_clusters))

    def test_findings_sorted_worst_first(self):
        res = self._res()
        sevs = [SEVERITY_ORDER[f.severity] for f in res.findings]
        self.assertEqual(sevs, sorted(sevs, reverse=True))


# --------------------------------------------------------------------------- #
# SDN table + actor tags
# --------------------------------------------------------------------------- #
class TestSdnTable(unittest.TestCase):
    def test_ofac_entries_is_copy(self):
        a = ofac_entries()
        a[0]["entity"] = "MUTATED"
        self.assertNotEqual(ofac_entries()[0]["entity"], "MUTATED")

    def test_is_sanctioned_case_insensitive_eth(self):
        self.assertIsNotNone(is_sanctioned(SDN_ETH.upper()))

    def test_is_sanctioned_none_for_clean(self):
        self.assertIsNone(is_sanctioned("1SomeCleanAddress0000000000000000000"))

    def test_actor_tag_demo_exchange(self):
        tag = actor_tag("1ExchangeHotWalletDemo0000000000")
        self.assertIsNotNone(tag)
        self.assertEqual(tag["category"], "exchange")

    def test_actor_tag_none_for_unknown(self):
        self.assertIsNone(actor_tag("1TotallyUnknownAddress00000000000000"))

    def test_every_sdn_entry_has_required_fields(self):
        for e in ofac_entries():
            for k in ("address", "asset", "entity", "program", "added", "category"):
                self.assertIn(k, e)


# --------------------------------------------------------------------------- #
# End-to-end fixture screening (all bundled demo graphs)
# --------------------------------------------------------------------------- #
class TestFixtureScreening(unittest.TestCase):
    def _load(self, name):
        with open(DEMOS / name / "tx_graph.json", encoding="utf-8") as fh:
            return parse_txs(fh.read())

    def test_tornado_deposit_has_direct_hit(self):
        res = analyze(self._load("01-tornado-cash-deposit"), max_hops=2)
        self.assertTrue(any(f.kind == "ofac_direct_hit" for f in res.findings))

    def test_lazarus_bridge_exit_flags(self):
        res = analyze(self._load("03-lazarus-bridge-exit"), max_hops=2)
        self.assertEqual(res.max_severity, "critical")

    def test_peel_chain_fixture_detects_chain(self):
        from cryptotrace.core import detect_peel_chains
        chains = detect_peel_chains(self._load("04-peel-chain-laundering"),
                                    min_length=3)
        self.assertGreaterEqual(len(chains), 1)

    def test_clean_treasury_no_high_findings(self):
        res = analyze(self._load("05-clean-treasury-baseline"), max_hops=2)
        self.assertNotIn(res.max_severity, ("critical", "high"))

    def test_cospend_cluster_inherits(self):
        res = analyze(self._load("07-cospend-cluster-taint"), max_hops=2)
        self.assertTrue(any(f.kind == "cluster_sanctioned" for f in res.findings))

    def test_all_fixtures_parse_and_analyze(self):
        for d in sorted(DEMOS.iterdir()):
            g = d / "tx_graph.json"
            if not g.exists():
                continue
            txs = parse_txs(g.read_text(encoding="utf-8"))
            self.assertGreater(len(txs), 0, f"{d.name} parsed empty")
            res = analyze(txs, max_hops=2)  # must not raise
            self.assertGreaterEqual(res.total_txs, 1)


# --------------------------------------------------------------------------- #
# Feeds parser corners (offline, pytest-style for the monkeypatch fixture)
# --------------------------------------------------------------------------- #
FIX = Path(__file__).parent / "fixtures"
CACHE = FIX / "feeds-cache"


@pytest.fixture(autouse=True)
def _cache(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(CACHE))
    import importlib
    from cryptotrace import core, feeds
    importlib.reload(core)
    importlib.reload(feeds)
    yield


def test_parse_empty_csv_is_empty():
    from cryptotrace import feeds
    assert feeds.parse_sdn_addresses("") == []


def test_parse_rows_without_dca_ignored():
    from cryptotrace import feeds
    csv = '1,"Foo Corp","-0- ","CYBER2","-0- ",,,,,,,,"nothing here"'
    assert feeds.parse_sdn_addresses(csv) == []


def test_parse_short_row_skipped():
    from cryptotrace import feeds
    # Fewer than 4 fields but contains the DCA marker -> skipped gracefully.
    assert feeds.parse_sdn_addresses("Digital Currency Address - XBT abc") == []


def test_parse_eth_address_lowercased():
    from cryptotrace import feeds
    csv = ('1,"Cyber Co","-0- ","CYBER2","-0- ",,,,,,,,'
           '"Digital Currency Address - ETH 0xABCDEF0123456789"')
    entries = feeds.parse_sdn_addresses(csv)
    assert entries and entries[0]["address"] == "0xABCDEF0123456789"
    # de-dup key is normalized: a lowercased duplicate is not re-emitted
    dup = csv + "\n" + csv.replace("0xABCDEF0123456789", "0xabcdef0123456789")
    assert len(feeds.parse_sdn_addresses(dup)) == 1


def test_asset_map_unknown_code_passthrough():
    from cryptotrace import feeds
    csv = ('1,"Coin Co","-0- ","CYBER2","-0- ",,,,,,,,'
           '"Digital Currency Address - FOO Zabc123"')
    entries = feeds.parse_sdn_addresses(csv)
    assert entries and entries[0]["asset"] == "FOO"


def test_disallowed_feed_update_rejected():
    from cryptotrace import feeds
    with pytest.raises(ValueError):
        feeds.update_feed("not-a-real-feed")


def test_sdn_summary_empty():
    from cryptotrace import feeds
    assert feeds.sdn_summary([]) == {}


if __name__ == "__main__":
    unittest.main()

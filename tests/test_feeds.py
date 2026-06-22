"""Offline tests for the OFAC SDN data-feed ingestion layer.

These tests NEVER hit the network: COGNIS_FEEDS_CACHE is pointed at a committed,
trimmed SDN fixture and every read uses offline=True / cached data.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures"
CACHE = FIX / "feeds-cache"


@pytest.fixture(autouse=True)
def _point_cache_at_fixture(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(CACHE))
    # Reload core's index between tests so merges don't leak across cases.
    from cryptotrace import core, feeds
    import importlib
    importlib.reload(core)
    importlib.reload(feeds)
    yield


def _feeds():
    from cryptotrace import feeds
    return feeds


# --------------------------------------------------------------------------- #
# catalog / wiring
# --------------------------------------------------------------------------- #
def test_relevant_feeds_only_ofac():
    rows = _feeds().relevant_feeds()
    assert [r["id"] for r in rows] == ["ofac-sdn"]
    assert rows[0]["format"] == "csv"
    assert "treasury.gov" in rows[0]["url"]


def test_disallowed_feed_rejected():
    f = _feeds()
    with pytest.raises(ValueError):
        f.update_feed("cisa-kev")
    with pytest.raises(ValueError):
        f.get_feed("opensky-states", offline=True)


# --------------------------------------------------------------------------- #
# offline serve + parse
# --------------------------------------------------------------------------- #
def test_offline_get_serves_fixture():
    text = _feeds().get_feed("ofac-sdn", offline=True)
    assert isinstance(text, str)
    assert "Digital Currency Address" in text


def test_offline_get_without_cache_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    import importlib
    from cryptotrace import datafeeds, feeds
    importlib.reload(datafeeds)
    importlib.reload(feeds)
    with pytest.raises(FileNotFoundError):
        feeds.get_feed("ofac-sdn", offline=True)


def test_parse_extracts_all_addresses():
    f = _feeds()
    entries = f.parse_sdn_addresses(f.get_feed("ofac-sdn", offline=True))
    addrs = {e["address"] for e in entries}
    # multi-currency designee yields both an XBT/BTC and an XMR address
    assert "1NewSDNExampleAddr000000000000000aBcDeF" in addrs
    assert any(e["asset"] == "XMR" for e in entries)
    # XBT is normalized to the internal BTC hint
    assert all(e["asset"] != "XBT" for e in entries)
    # program + entity are carried through from the right CSV columns
    suex = [e for e in entries if e["entity"] == "SUEX OTC"]
    assert suex and all(e["program"] == "CYBER2" for e in suex)


def test_parse_ignores_non_crypto_rows():
    f = _feeds()
    entries = f.parse_sdn_addresses(f.get_feed("ofac-sdn", offline=True))
    # the vessel row carries no Digital Currency Address
    assert all(e["entity"] != "EXAMPLE VESSEL CO" for e in entries)


def test_parse_dedupes():
    f = _feeds()
    text = f.get_feed("ofac-sdn", offline=True)
    doubled = text + "\n" + text
    once = {e["address"] for e in f.parse_sdn_addresses(text)}
    twice = {e["address"] for e in f.parse_sdn_addresses(doubled)}
    assert once == twice


def test_summary_counts():
    f = _feeds()
    entries = f.parse_sdn_addresses(f.get_feed("ofac-sdn", offline=True))
    summary = f.sdn_summary(entries)
    assert summary["BTC"] >= 1 and summary["ETH"] >= 1 and summary["XMR"] == 1
    assert sum(summary.values()) == len(entries)


# --------------------------------------------------------------------------- #
# the real enrichment: live SDN merges into the screening index
# --------------------------------------------------------------------------- #
NEW_BTC = "1NewSDNExampleAddr000000000000000aBcDeF"
NEW_XMR = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3X"
           "jrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")


def test_enrichment_makes_new_sdn_address_screenable():
    from cryptotrace import core, feeds
    # not in the bundled seed
    assert core.is_sanctioned(NEW_XMR) is None
    assert core.is_sanctioned(NEW_BTC) is None
    merged = feeds.load_sdn_into_index(offline=True)
    assert merged >= 2
    # now screenable against the live SDN set
    hit = core.is_sanctioned(NEW_XMR)
    assert hit and hit["entity"] == "NEW SDN DESIGNEE EXAMPLE"
    assert core.is_sanctioned(NEW_BTC) is not None


def test_enrichment_idempotent():
    from cryptotrace import feeds
    first = feeds.load_sdn_into_index(offline=True)
    second = feeds.load_sdn_into_index(offline=True)
    assert first >= 2
    assert second == 0  # nothing new on the second pass


def test_enrichment_does_not_clobber_seed():
    from cryptotrace import core, feeds
    # a seed Lazarus address present before and after merge
    lazarus = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
    before = core.is_sanctioned(lazarus)
    assert before is not None
    feeds.load_sdn_into_index(offline=True)
    after = core.is_sanctioned(lazarus)
    # seed entry retained (richer 'category'/'added' than the SDN-derived one)
    assert after["entity"] == before["entity"]


def test_enriched_taint_propagation_flags_downstream():
    """End-to-end: a newly-merged SDN source taints downstream funds."""
    from cryptotrace import core, feeds
    feeds.load_sdn_into_index(offline=True)
    txs = core.parse_txs(json.dumps([
        {"txid": "t1", "inputs": [NEW_BTC], "outputs": ["1victimDownstreamAddr0000000000000xyz"],
         "asset": "BTC", "value": 1.0},
    ]))
    res = core.analyze(txs, max_hops=2)
    # the SDN source itself is a critical direct hit
    assert any(fd.severity == "critical" for fd in res.findings)
    assert res.dirty_value_total > 0

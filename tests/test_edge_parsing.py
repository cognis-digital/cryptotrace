"""Edge-case + error-path tests for parsing and value coercion.

Covers malformed tx graphs, mixed/dirty exports, and the value-coercion
hardening (negative / NaN / inf / string / null notionals). No network.

Run: python -m pytest  (or python -m unittest).
"""
from __future__ import annotations

import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace.core import (  # noqa: E402
    Transaction,
    _as_addr_list,
    _coerce_value,
    _norm_addr,
    analyze,
    parse_txs,
    propagate_taint,
)

SDN_ETH = "0x722122df12d4e14e13ac3b6895a86e84145b6967"  # Tornado Cash router


class TestParseEmptyAndGarbage(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(parse_txs(""), [])

    def test_whitespace_only(self):
        self.assertEqual(parse_txs("   \n\t  "), [])

    def test_none_input(self):
        self.assertEqual(parse_txs(None), [])  # type: ignore[arg-type]

    def test_pure_garbage_not_json(self):
        # Not JSON, not JSONL — every line fails to parse -> empty.
        self.assertEqual(parse_txs("this is not json at all !!!"), [])

    def test_json_scalar_not_list(self):
        # A bare number/string is valid JSON but not a tx list.
        self.assertEqual(parse_txs("42"), [])
        self.assertEqual(parse_txs('"hello"'), [])

    def test_json_object_without_tx_key(self):
        # dict lacking transactions/txs -> empty list, no crash.
        self.assertEqual(parse_txs('{"foo": "bar"}'), [])

    def test_list_of_non_dicts_skipped(self):
        txs = parse_txs('[1, 2, "three", null]')
        self.assertEqual(txs, [])

    def test_list_with_some_non_dicts(self):
        txs = parse_txs('[1, {"txid":"t","inputs":["a"],"outputs":["b"]}, "x"]')
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0].txid, "t")


class TestParseJsonl(unittest.TestCase):
    def test_jsonl_fallback(self):
        text = ('{"txid":"a","inputs":["x"],"outputs":["y"]}\n'
                '{"txid":"b","inputs":["y"],"outputs":["z"]}')
        txs = parse_txs(text)
        self.assertEqual([t.txid for t in txs], ["a", "b"])

    def test_jsonl_with_blank_lines(self):
        # Genuine multi-record JSONL (whole-text json.loads fails -> JSONL path),
        # with blank lines interspersed.
        text = ('\n{"txid":"a","inputs":["x"],"outputs":["y"]}\n\n'
                '{"txid":"b","inputs":["y"],"outputs":["z"]}\n')
        txs = parse_txs(text)
        self.assertEqual([t.txid for t in txs], ["a", "b"])

    def test_jsonl_skips_bad_lines(self):
        text = ('{"txid":"a","inputs":["x"],"outputs":["y"]}\n'
                'this line is broken\n'
                '{"txid":"b","inputs":["y"],"outputs":["z"]}')
        txs = parse_txs(text)
        self.assertEqual([t.txid for t in txs], ["a", "b"])


class TestParseFieldAliases(unittest.TestCase):
    def test_from_to_aliases(self):
        txs = parse_txs('[{"from":"A","to":"B","amount":5}]')
        self.assertEqual(txs[0].inputs, ["A"])
        self.assertEqual(txs[0].outputs, ["B"])
        self.assertEqual(txs[0].value, 5.0)

    def test_vin_vout_aliases(self):
        txs = parse_txs('[{"vin":["A"],"vout":["B"]}]')
        self.assertEqual(txs[0].inputs, ["A"])
        self.assertEqual(txs[0].outputs, ["B"])

    def test_hash_and_id_txid_aliases(self):
        self.assertEqual(parse_txs('[{"hash":"h1","inputs":[],"outputs":[]}]')[0].txid, "h1")
        self.assertEqual(parse_txs('[{"id":"i1","inputs":[],"outputs":[]}]')[0].txid, "i1")

    def test_synthetic_txid_when_missing(self):
        txs = parse_txs('[{"inputs":["A"],"outputs":["B"]},'
                        '{"inputs":["B"],"outputs":["C"]}]')
        self.assertEqual(txs[0].txid, "tx0")
        self.assertEqual(txs[1].txid, "tx1")

    def test_chain_alias_for_asset_uppercased(self):
        txs = parse_txs('[{"chain":"eth","inputs":["A"],"outputs":["B"]}]')
        self.assertEqual(txs[0].asset, "ETH")

    def test_timestamp_aliases(self):
        for key in ("timestamp", "time", "block_time"):
            txs = parse_txs('[{"%s":"2026-01-01","inputs":[],"outputs":[]}]' % key)
            self.assertEqual(txs[0].timestamp, "2026-01-01")


class TestAddrListCoercion(unittest.TestCase):
    def test_string_becomes_singleton(self):
        self.assertEqual(_as_addr_list("A"), ["A"])

    def test_none_becomes_empty(self):
        self.assertEqual(_as_addr_list(None), [])

    def test_explorer_object_forms(self):
        for key in ("address", "addr", "prev_addr", "scriptpubkey_address"):
            self.assertEqual(_as_addr_list([{key: "A"}]), ["A"])

    def test_object_first_matching_key_wins(self):
        # address takes precedence over addr in the key scan order.
        self.assertEqual(_as_addr_list([{"address": "A", "addr": "B"}]), ["A"])

    def test_empty_and_missing_keys_dropped(self):
        self.assertEqual(_as_addr_list([{"nope": "x"}, {"address": ""}, {"addr": "Y"}]),
                         ["Y"])

    def test_mixed_list(self):
        self.assertEqual(_as_addr_list(["A", {"address": "B"}, "", None]), ["A", "B"])

    def test_number_ignored(self):
        self.assertEqual(_as_addr_list([1, 2.5]), [])


class TestValueCoercion(unittest.TestCase):
    def test_none_zero(self):
        self.assertEqual(_coerce_value(None), 0.0)

    def test_plain_number(self):
        self.assertEqual(_coerce_value(3.5), 3.5)

    def test_numeric_string(self):
        self.assertEqual(_coerce_value("2.25"), 2.25)

    def test_garbage_string_zero(self):
        self.assertEqual(_coerce_value("not-a-number"), 0.0)

    def test_negative_becomes_magnitude(self):
        # BUGFIX: a negative export must not silently fall through to a 1.0
        # neutral weight; it becomes its magnitude.
        self.assertEqual(_coerce_value(-5.0), 5.0)
        self.assertEqual(_coerce_value("-7"), 7.0)

    def test_nan_rejected(self):
        self.assertEqual(_coerce_value(float("nan")), 0.0)
        self.assertEqual(_coerce_value("nan"), 0.0)

    def test_inf_rejected(self):
        self.assertEqual(_coerce_value(float("inf")), 0.0)
        self.assertEqual(_coerce_value(float("-inf")), 0.0)
        self.assertEqual(_coerce_value("inf"), 0.0)

    def test_bool_coerces(self):
        # True -> 1.0, False -> 0.0 (Python bool is an int subclass).
        self.assertEqual(_coerce_value(True), 1.0)
        self.assertEqual(_coerce_value(False), 0.0)


class TestParseValueHardening(unittest.TestCase):
    def test_parse_negative_value_clamped(self):
        txs = parse_txs('[{"inputs":["A"],"outputs":["B"],"value":-9}]')
        self.assertEqual(txs[0].value, 9.0)

    def test_parse_nan_value_zeroed(self):
        txs = parse_txs('[{"inputs":["A"],"outputs":["B"],"value":"NaN"}]')
        self.assertEqual(txs[0].value, 0.0)

    def test_parse_string_value(self):
        txs = parse_txs('[{"inputs":["A"],"outputs":["B"],"value":"1.5"}]')
        self.assertEqual(txs[0].value, 1.5)


class TestTaintValueHardening(unittest.TestCase):
    """Direct-API callers can bypass parse_txs; propagate_taint must still
    keep taint fractions in [0, 1] and dirty values finite & non-negative."""

    def test_negative_value_transaction(self):
        txs = [Transaction("t", [SDN_ETH], ["down"], "ETH", value=-10.0)]
        out = propagate_taint(txs, {SDN_ETH})
        self.assertIn("down", out)
        self.assertTrue(0.0 <= out["down"]["taint"] <= 1.0)
        self.assertGreaterEqual(out["down"]["dirty"], 0.0)

    def test_nan_value_transaction(self):
        txs = [Transaction("t", [SDN_ETH], ["down"], "ETH", value=float("nan"))]
        out = propagate_taint(txs, {SDN_ETH})
        # Falls back to unit weight -> finite dirty value.
        self.assertTrue(math.isfinite(out["down"]["dirty"]))
        self.assertTrue(0.0 <= out["down"]["taint"] <= 1.0)

    def test_inf_value_transaction(self):
        txs = [Transaction("t", [SDN_ETH], ["down"], "ETH", value=float("inf"))]
        out = propagate_taint(txs, {SDN_ETH})
        self.assertTrue(math.isfinite(out["down"]["dirty"]))

    def test_analyze_negative_value_finite_total(self):
        txs = [
            Transaction("t0", [SDN_ETH], ["mid"], "ETH", value=-10.0),
            Transaction("t1", ["mid"], ["end"], "ETH", value=-10.0),
        ]
        res = analyze(txs, max_hops=2)
        self.assertTrue(math.isfinite(res.dirty_value_total))
        self.assertGreaterEqual(res.dirty_value_total, 0.0)


class TestParseExplorerJson(unittest.TestCase):
    """Blockchain-explorer style nested input/output objects."""

    def test_esplora_style_vin_vout(self):
        payload = ('[{"txid":"t0",'
                   '"vin":[{"prev_addr":"A"}],'
                   '"vout":[{"scriptpubkey_address":"B"}],'
                   '"value":3}]')
        txs = parse_txs(payload)
        self.assertEqual(txs[0].inputs, ["A"])
        self.assertEqual(txs[0].outputs, ["B"])

    def test_address_object_form(self):
        payload = '[{"inputs":[{"address":"A"}],"outputs":[{"address":"B"}]}]'
        txs = parse_txs(payload)
        self.assertEqual(txs[0].inputs, ["A"])
        self.assertEqual(txs[0].outputs, ["B"])

    def test_transactions_wrapper_key(self):
        payload = '{"transactions":[{"inputs":["A"],"outputs":["B"]}]}'
        self.assertEqual(len(parse_txs(payload)), 1)

    def test_txs_wrapper_key(self):
        payload = '{"txs":[{"inputs":["A"],"outputs":["B"]}]}'
        self.assertEqual(len(parse_txs(payload)), 1)

    def test_multi_input_multi_output(self):
        payload = '[{"inputs":["A","B"],"outputs":["C","D"],"value":10}]'
        txs = parse_txs(payload)
        self.assertEqual(txs[0].inputs, ["A", "B"])
        self.assertEqual(txs[0].outputs, ["C", "D"])

    def test_missing_inputs_and_outputs(self):
        txs = parse_txs('[{"txid":"lonely"}]')
        self.assertEqual(txs[0].inputs, [])
        self.assertEqual(txs[0].outputs, [])

    def test_empty_string_addresses_dropped(self):
        txs = parse_txs('[{"inputs":["A",""],"outputs":["",""]}]')
        self.assertEqual(txs[0].inputs, ["A"])
        self.assertEqual(txs[0].outputs, [])


class TestParseValueAliases(unittest.TestCase):
    def test_amount_alias(self):
        self.assertEqual(parse_txs('[{"inputs":[],"outputs":[],"amount":7}]')[0].value, 7.0)

    def test_value_takes_precedence_over_amount(self):
        txs = parse_txs('[{"inputs":[],"outputs":[],"value":2,"amount":9}]')
        self.assertEqual(txs[0].value, 2.0)

    def test_missing_value_zero(self):
        self.assertEqual(parse_txs('[{"inputs":["A"],"outputs":["B"]}]')[0].value, 0.0)

    def test_null_value_zero(self):
        self.assertEqual(parse_txs('[{"inputs":["A"],"outputs":["B"],"value":null}]')[0].value, 0.0)


class TestNormAddr(unittest.TestCase):
    def test_eth_lowercased(self):
        self.assertEqual(_norm_addr("0xABCDEF"), "0xabcdef")

    def test_btc_case_preserved(self):
        self.assertEqual(_norm_addr("1AbCdEf"), "1AbCdEf")

    def test_trimmed(self):
        self.assertEqual(_norm_addr("  0xAB  "), "0xab")

    def test_empty_and_none(self):
        self.assertEqual(_norm_addr(""), "")
        self.assertEqual(_norm_addr(None), "")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

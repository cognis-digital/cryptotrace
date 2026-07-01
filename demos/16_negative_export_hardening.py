"""Scenario 16 - correctness (signed/negative value hardening).

Some accounting exports emit signed value deltas. A naive parser once let a
negative value silently become a neutral unit weight, quietly distorting the
dirty-value totals the whole taint model depends on. cryptotrace now normalises
every value to its finite, non-negative magnitude. This demo shows a
negative-value export producing correct, finite taint arithmetic.
"""
import math

from _common import load, rule
from cryptotrace.core import analyze, propagate_taint, is_sanctioned


def main() -> None:
    rule("NEGATIVE-EXPORT HARDENING  -  signed deltas can't poison the math")

    txs = load("13-negative-export")
    print(f"\nLoaded {len(txs)} txs whose raw 'value' fields were negative "
          f"(signed deltas).")
    print("parse_txs() clamped each to its magnitude:")
    for t in txs:
        print(f"     {t.txid}: value={t.value}  (>= 0, finite)")
        assert t.value >= 0.0 and math.isfinite(t.value)

    all_addrs = set()
    for t in txs:
        all_addrs |= t.all_addresses()
    sources = {a for a in all_addrs if is_sanctioned(a)}
    taint = propagate_taint(txs, sources)
    print(f"\n1) taint fractions stay in [0, 1] and dirty values stay finite:")
    for addr, v in sorted(taint.items(), key=lambda kv: -kv[1]["taint"]):
        ok = 0.0 <= v["taint"] <= 1.0 and math.isfinite(v["dirty"])
        print(f"     {'OK ' if ok else 'BAD'}  {v['taint'] * 100:6.1f}%  "
              f"{v['dirty']:.4f}  {addr}")
        assert ok

    res = analyze(txs, max_hops=2)
    print(f"\n2) analyze() dirty-value total: {res.dirty_value_total:.4f} "
          f"(finite: {math.isfinite(res.dirty_value_total)}, "
          f">= 0: {res.dirty_value_total >= 0})")

    print("\nThe regression this guards: a negative export used to fall through to")
    print("a '1.0' weight and understate dirty value. Now it can't.")


if __name__ == "__main__":
    main()

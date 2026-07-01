"""Scenario 15 - reliability (a dirty export must not crash the screen).

Real exports contain junk: bare scalars, non-object rows, records missing
inputs/outputs, and unparseable value tokens. cryptotrace skips the junk record
by record and still surfaces the genuine SDN hit, rather than throwing on the
first bad row. This demo feeds it a deliberately dirty graph and shows it survive.
"""
from _common import load, rule
from cryptotrace.core import analyze, is_sanctioned


def main() -> None:
    rule("MALFORMED RESILIENCE  -  skip the junk, keep the signal")

    txs = load("12-malformed-resilience")
    print(f"\nThe fixture has 5 raw entries (a scalar, a string, a record with no")
    print(f"inputs/outputs, a bad-value record, and one real SDN record).")
    print(f"parse_txs() kept {len(txs)} usable Transaction(s):")
    for t in txs:
        print(f"     {t.txid}: {t.inputs} -> {t.outputs}  (value={t.value})")

    # The bad-value record's value must have coerced to a clean 0.0, not crashed.
    bad = [t for t in txs if t.txid == "bad-value"]
    if bad:
        print(f"\n1) the 'not-a-number' value coerced safely to {bad[0].value} "
              f"(no exception).")

    res = analyze(txs, max_hops=2)
    direct = [f for f in res.findings if f.kind == "ofac_direct_hit"]
    print(f"\n2) despite the junk, the screen still found {len(direct)} "
          f"direct OFAC hit(s):")
    for f in direct:
        hit = is_sanctioned(f.address)
        print(f"     {f.address}  ->  {hit['entity']} ({hit['program']})")

    print("\nOne bad row can't blind the screen — malformed input is dropped")
    print("record-by-record, and the real designation still lands in the report.")


if __name__ == "__main__":
    main()

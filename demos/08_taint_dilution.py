"""Scenario 8 - AML analysts (the haircut model, made concrete).

Hop count tells you *how far* funds travelled; taint tells you *how much* of what
arrived is actually dirty. This demo walks a DPRK mixer chain and reads off the
value-weighted taint fraction and absolute dirty value at each downstream node,
showing how mixing dilutes taint below 100% while hop distance keeps climbing.
"""
from _common import load, rule
from cryptotrace.core import analyze, is_sanctioned, propagate_taint


def main() -> None:
    rule("TAINT DILUTION  -  hop distance vs. value-weighted taint")

    txs = load("08-dprk-mixer-chain")
    print(f"\nLoaded {len(txs)} transactions from a DPRK-linked mixer chain.\n")

    all_addrs = set()
    for t in txs:
        all_addrs |= t.all_addresses()
    sources = {a for a in all_addrs if is_sanctioned(a)}
    print(f"1) {len(sources)} sanctioned source(s) seed the taint:")
    for s in sorted(sources):
        print(f"     {s}  <{is_sanctioned(s)['entity']}>")

    taint = propagate_taint(txs, sources)
    print(f"\n2) propagate_taint() -> {len(taint)} tainted downstream address(es), "
          f"worst first:")
    for addr, v in sorted(taint.items(), key=lambda kv: -kv[1]["taint"]):
        print(f"     {v['taint'] * 100:6.1f}% tainted  "
              f"{v['dirty']:9.4f} dirty  {addr}")

    res = analyze(txs, max_hops=4)
    print(f"\n3) analyze(max_hops=4) grades each node — note taint can stay high "
          f"even as hops grow:")
    for f in res.findings:
        if f.kind == "ofac_indirect_exposure":
            print(f"     [{f.severity:6}] hop {f.hops}  "
                  f"{f.taint * 100:5.1f}% taint  {f.address}")

    print(f"\n   Total dirty value in scope: {res.dirty_value_total:.4f}.")
    print("   Dilution is the point: a 3%-tainted wallet 5 hops out is a very")
    print("   different report line than a 100%-tainted direct recipient.")


if __name__ == "__main__":
    main()

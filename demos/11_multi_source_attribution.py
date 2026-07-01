"""Scenario 11 - threat intel / attribution.

Real consolidation wallets often collect from more than one sanctioned program
at once. This demo screens a wallet fed by BOTH Tornado Cash and a Lazarus Group
address, and shows cryptotrace attributing each flow to its own SDN entity while
tainting the shared consolidation node from multiple sources.
"""
from _common import load, rule
from cryptotrace.core import analyze, is_sanctioned, propagate_taint


def main() -> None:
    rule("MULTI-SOURCE ATTRIBUTION  -  one wallet, two sanctioned programs")

    txs = load("14-multi-source")
    res = analyze(txs, max_hops=2)
    print(f"\nLoaded {len(txs)} txs, {res.total_addresses} addresses.\n")

    direct = [f for f in res.findings if f.kind == "ofac_direct_hit"]
    print(f"1) {len(direct)} distinct sanctioned source(s), each attributed:")
    entities = set()
    for f in direct:
        hit = is_sanctioned(f.address)
        entities.add(hit["entity"])
        print(f"     {f.address}")
        print(f"        -> {hit['entity']} ({hit['category']}, {hit['program']})")
    print(f"   programs implicated: {sorted(entities)}")

    sources = {f.address for f in direct}
    taint = propagate_taint(txs, sources)
    print(f"\n2) taint from BOTH sources converges on the consolidation node:")
    for addr, v in sorted(taint.items(), key=lambda kv: -kv[1]["dirty"]):
        print(f"     {v['taint'] * 100:6.1f}% tainted  {v['dirty']:8.4f} dirty  {addr}")

    print(f"\n3) total dirty value across both programs: "
          f"{res.dirty_value_total:.4f}")
    print("\nAttribution stays per-entity even when flows merge — the case file")
    print("names Tornado Cash AND Lazarus, not one blurred 'sanctioned' blob.")


if __name__ == "__main__":
    main()

"""Scenario 3 - investigative journalists.

A reporter has a wallet they believe belongs to a DPRK hacking crew and wants a
defensible, reproducible attribution — not a vibe. This demo walks the Lazarus
bridge-exit graph: it names the on-chain entity from the bundled OFAC table,
traces the stolen funds fanning out, and quantifies how much tainted value
landed on each downstream wallet. Every number is reproducible from the fixture.
"""
from _common import load, rule
from cryptotrace.core import analyze, is_sanctioned, propagate_taint


def main() -> None:
    rule("JOURNALIST ATTRIBUTION  -  name the entity, show your work")

    txs = load("03-lazarus-bridge-exit")
    print(f"\nLoaded {len(txs)} transactions tracing a bridge-drain consolidation.\n")

    # 1) Name the entity straight from the OFAC SDN table.
    addrs = set()
    for t in txs:
        addrs |= t.all_addresses()
    sdn = [(a, is_sanctioned(a)) for a in sorted(addrs) if is_sanctioned(a)]
    print("1) Sanctioned address in the flow (from the bundled OFAC SDN table):")
    for a, hit in sdn:
        print(f"     {a}")
        print(f"       -> {hit['entity']}  (program {hit['program']}, "
              f"{hit['category']}, OFAC-listed {hit['added']})")

    # 2) Quantify the fan-out with value-weighted taint.
    sources = {a for a, _ in sdn}
    taint = propagate_taint(txs, sources)
    print("\n2) Where the funds went — value-weighted taint from that wallet:")
    for addr, info in sorted(taint.items(), key=lambda kv: -kv[1]["dirty"]):
        print(f"     {info['taint'] * 100:5.1f}% tainted  "
              f"{info['dirty']:.4f} {txs[0].asset}  ->  {addr}")

    # 3) The full screen, for the sidebar / methodology box.
    res = analyze(txs, max_hops=3)
    print(f"\n3) Full screen: {len(res.findings)} finding(s), "
          f"highest severity {res.max_severity.upper()}.")
    print("   Every figure above is reproduced by:")
    print("     python -m cryptotrace screen demos/03-lazarus-bridge-exit/tx_graph.json")

    print("\nThe attribution rests on a published OFAC designation plus arithmetic")
    print("anyone can re-run — the standard for a story that has to hold up.")


if __name__ == "__main__":
    main()

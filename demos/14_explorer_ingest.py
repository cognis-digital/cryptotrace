"""Scenario 14 - integrators (ingest raw block-explorer JSON).

Block explorers (Esplora/Blockstream-style) return inputs/outputs as nested
OBJECTS keyed by ``prev_addr`` / ``scriptpubkey_address``, and call the id
``hash``. cryptotrace coerces those shapes directly, so you can pipe an explorer
response into the screen without writing a normalizer first. This demo proves it.
"""
from _common import load, rule
from cryptotrace.core import analyze, is_sanctioned


def main() -> None:
    rule("EXPLORER INGEST  -  screen raw Esplora-style JSON, no normalizer")

    txs = load("11-explorer-json")
    print(f"\nParsed {len(txs)} tx(s) from explorer-shaped JSON "
          f"(objects, 'hash' ids, 'chain' asset):")
    for t in txs:
        print(f"     {t.txid}: {t.inputs} -> {t.outputs}  ({t.value} {t.asset})")

    res = analyze(txs, max_hops=2)
    direct = [f for f in res.findings if f.kind == "ofac_direct_hit"]
    print(f"\n1) {len(direct)} direct OFAC hit(s) extracted from the nested inputs:")
    for f in direct:
        hit = is_sanctioned(f.address)
        print(f"     {f.address}  ->  {hit['entity']} ({hit['program']})")

    print(f"\n2) full screen: {len(res.findings)} finding(s), highest "
          f"{res.max_severity.upper()}, {res.dirty_value_total:.4f} dirty value.")

    print("\nThe parser meets the data where it is — explorer JSON goes straight")
    print("into the same analyze() call as any hand-built graph.")


if __name__ == "__main__":
    main()

"""Scenario 5 - AML / forensic analysts (clustering deep-dive).

The most powerful — and most defensible — move in chain analysis: prove two
wallets are *one entity* from their on-chain behavior, then inherit a sanctions
tag across the whole cluster. This demo runs the real common-input-ownership
clustering over a co-spend graph and shows a clean wallet being pulled into a
SUEX-controlled cluster because it was spent together with an SDN address.
"""
from _common import load, rule
from cryptotrace.core import analyze, cluster_addresses, is_sanctioned


def main() -> None:
    rule("CLUSTER INHERITANCE  -  co-spend proves common ownership")

    txs = load("07-cospend-cluster-taint")
    print(f"\nLoaded {len(txs)} transactions containing a multi-input co-spend.\n")

    clusters = cluster_addresses(txs)
    print(f"1) cluster_addresses() -> {len(clusters)} multi-address entity(ies):")
    for c in clusters:
        flag = (f"  !! SANCTIONED: {c.sanctioned_entity}"
                if c.sanctioned_member else "")
        print(f"     cluster #{c.cluster_id}  size={len(c.addresses)}  "
              f"txs={c.tx_count}  risk={c.risk_score}/100  "
              f"heuristics={c.heuristics or ['-']}{flag}")
        for a in c.addresses:
            mark = " (OFAC SDN)" if is_sanctioned(a) else ""
            print(f"        {a}{mark}")

    sanctioned = [c for c in clusters if c.sanctioned_member]
    print(f"\n2) {len(sanctioned)} cluster(s) inherit a sanctions tag.")
    for c in sanctioned:
        clean = [a for a in c.addresses if not is_sanctioned(a)]
        print(f"   Cluster #{c.cluster_id} is controlled by "
              f"{c.sanctioned_entity}; {len(clean)} co-owned wallet(s) that are "
              f"NOT individually on the SDN list now inherit the exposure:")
        for a in clean:
            print(f"        {a}")

    # The screen folds this into a finding analysts can action.
    res = analyze(txs)
    inherited = [f for f in res.findings if f.kind == "cluster_sanctioned"]
    print(f"\n3) analyze() surfaces {len(inherited)} 'cluster_sanctioned' "
          f"finding(s) — the actionable output.")

    print("\nClustering turns one SDN hit into exposure across every wallet the")
    print("entity controls — the multiplier that makes chain analysis worth doing.")


if __name__ == "__main__":
    main()

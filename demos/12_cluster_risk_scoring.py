"""Scenario 12 - forensic analysts (read the cluster risk score).

Clustering doesn't just group addresses — it assigns each entity a 0-100 risk
score from sanctions inheritance, mixer membership, heuristics used, and size.
This demo runs clustering over the co-spend graph and walks the components of
each cluster's score so an analyst can defend the number in a report.
"""
from _common import load, rule
from cryptotrace.core import _cluster_risk, actor_tag, cluster_addresses, is_sanctioned


def main() -> None:
    rule("CLUSTER RISK SCORING  -  where the 0-100 number comes from")

    txs = load("07-cospend-cluster-taint")
    clusters = cluster_addresses(txs)
    print(f"\nLoaded {len(txs)} txs -> {len(clusters)} multi-address entity(ies).\n")

    for c in clusters:
        print(f"Cluster #{c.cluster_id}  size={len(c.addresses)}  "
              f"txs={c.tx_count}  heuristics={c.heuristics or ['-']}")
        # Decompose the score the way _cluster_risk builds it.
        parts = []
        if c.sanctioned_member:
            parts.append(f"+80 sanctioned member ({c.sanctioned_entity})")
        mixers = [a for a in c.addresses
                  if (actor_tag(a) or {}).get("category") == "mixer"]
        if mixers:
            parts.append(f"+{25 * len(mixers)} mixer member(s)")
        if "change_address" in c.heuristics:
            parts.append("+5 change-address heuristic")
        if len(c.addresses) >= 5:
            parts.append("+5 large cluster (>=5)")
        recomputed = _cluster_risk(c)
        print(f"   risk = {c.risk_score}/100  (recompute {recomputed}, capped at 100)")
        for p in parts or ["+0 (clean)"]:
            print(f"        {p}")
        for a in c.addresses:
            mark = " (OFAC SDN)" if is_sanctioned(a) else ""
            print(f"        - {a}{mark}")
        print()

    print("Every point is explainable — that's what lets an analyst put the")
    print("risk score in front of a reviewer and defend it.")


if __name__ == "__main__":
    main()

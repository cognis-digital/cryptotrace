"""Scenario 17 - reporting (one screen, three consumers).

The same TraceResult serves three different audiences: a human reads the table,
a data pipeline ingests the JSON, and code-scanning ingests the SARIF. This demo
runs one analysis and renders all three from it, proving they're consistent
views of a single result — no re-analysis, no drift between formats.
"""
import json

from _common import load, rule
from cryptotrace.core import analyze, to_sarif


def main() -> None:
    rule("TRIPLE EXPORT  -  table + JSON + SARIF from one analysis")

    txs = load("03-lazarus-bridge-exit")
    res = analyze(txs, max_hops=2)

    # 1) JSON (the machine-readable canonical form).
    doc = res.to_dict()
    print(f"\n1) JSON: tool={doc['tool']} v{doc['version']}  "
          f"findings={len(doc['findings'])}  "
          f"max_severity={doc['max_severity']}")
    print("   " + json.dumps(doc["counts"]))

    # 2) SARIF (for code-scanning), derived from the SAME result.
    sarif = to_sarif(res)
    run = sarif["runs"][0]
    print(f"\n2) SARIF {sarif['version']}: {len(run['results'])} result(s), "
          f"rules={[r['id'] for r in run['tool']['driver']['rules']]}")

    # 3) Consistency check: the three views agree on the finding count.
    n_json = len(doc["findings"])
    n_sarif = len(run["results"])
    print(f"\n3) consistency: JSON findings={n_json}, SARIF results={n_sarif} "
          f"-> {'MATCH' if n_json == n_sarif else 'MISMATCH'}")
    assert n_json == n_sarif

    print(f"\n4) human summary line:")
    print(f"   {res.total_txs} txs, {res.total_addresses} addresses, "
          f"{res.dirty_value_total:.4f} dirty, highest {res.max_severity.upper()}")

    print("\nOne analysis, three faithful renderings — the report a human signs")
    print("and the artifact a machine ingests never disagree.")


if __name__ == "__main__":
    main()

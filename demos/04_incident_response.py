"""Scenario 4 - incident response / SOC.

After a breach, IR needs to (a) recognize the laundering pattern in the
attacker's cash-out and (b) hand the finding to the security pipeline in a
format the tooling already ingests. This demo detects the peeling chain out of
a sanctioned market, then emits the whole screen as SARIF 2.1.0 — the exact
artifact you upload to GitHub/GitLab code-scanning or DefectDojo.
"""
from _common import load, rule
from cryptotrace.core import analyze, detect_peel_chains, to_sarif


def main() -> None:
    rule("INCIDENT RESPONSE  -  spot the laundering pattern, emit SARIF")

    txs = load("04-peel-chain-laundering")
    print(f"\nLoaded {len(txs)} transactions from the post-incident tx export.\n")

    # 1) Pattern detection: the peeling chain the attacker used to cash out.
    chains = detect_peel_chains(txs, min_length=3)
    print(f"1) detect_peel_chains() -> {len(chains)} laundering chain(s):")
    for i, ch in enumerate(chains, 1):
        print(f"     chain #{i} (len {len(ch)}): {' -> '.join(ch)}")
    print("   Each hop sheds a small 'peel' and forwards the change — classic"
          " layering.")

    # 2) Full screen, then hand it to the pipeline as SARIF 2.1.0.
    res = analyze(txs, max_hops=2)
    sarif = to_sarif(res)
    run = sarif["runs"][0]
    print(f"\n2) to_sarif() -> SARIF {sarif['version']} log")
    print(f"     tool.driver.name : {run['tool']['driver']['name']} "
          f"v{run['tool']['driver']['version']}")
    print(f"     rules            : "
          f"{[r['id'] for r in run['tool']['driver']['rules']]}")
    print(f"     results          : {len(run['results'])} "
          f"(levels: {sorted({r['level'] for r in run['results']})})")

    print("\n3) Pipeline wiring (no new tooling needed):")
    print("     cryptotrace screen tx_graph.json --format sarif -o cryptotrace.sarif")
    print("     # upload with github/codeql-action/upload-sarif@v3")

    print("\nIR gets the named pattern AND a code-scanning artifact in one pass —")
    print("the finding shows up next to the team's existing security alerts.")


if __name__ == "__main__":
    main()

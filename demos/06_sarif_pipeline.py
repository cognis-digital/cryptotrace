"""Scenario 6 - security engineering / DevSecOps.

The whole value of SARIF is that a chain-forensics finding lands in the *same*
inbox as the team's SAST/dependency alerts. This demo turns a real screen into a
SARIF 2.1.0 log and inspects the exact fields a code-scanning UI keys on: rule
descriptors, result levels, security-severity, and a stable partial fingerprint
so re-scans dedupe instead of re-alerting.
"""
from _common import load, rule
from cryptotrace.core import analyze, to_sarif


def main() -> None:
    rule("SARIF PIPELINE  -  a chain finding that lands next to your SAST alerts")

    txs = load("04-peel-chain-laundering")
    res = analyze(txs, max_hops=2)
    sarif = to_sarif(res)
    run = sarif["runs"][0]

    print(f"\n1) to_sarif() -> SARIF {sarif['version']} (schema present: "
          f"{'$schema' in sarif})")
    print(f"   driver: {run['tool']['driver']['name']} "
          f"v{run['tool']['driver']['version']}")

    print("\n2) reusable rule descriptors (one per finding kind):")
    for r in run["tool"]["driver"]["rules"]:
        print(f"     {r['id']:24} default={r['defaultConfiguration']['level']:7} "
              f"- {r['shortDescription']['text'][:52]}...")

    print("\n3) results, with the fields code-scanning grades on:")
    for res_obj in run["results"][:6]:
        p = res_obj["properties"]
        print(f"     [{res_obj['level']:7}] sec-sev={p['security-severity']:>3}  "
              f"{res_obj['ruleId']:22} {p['address']}")

    fps = {r["partialFingerprints"]["cryptotrace/v1"] for r in run["results"]}
    print(f"\n4) {len(fps)} stable partial-fingerprint(s) -> re-scans dedupe, "
          f"they don't re-alert.")

    print("\n   Ship it:  cryptotrace screen tx.json --format sarif -o out.sarif")
    print("   then github/codeql-action/upload-sarif@v3. One artifact, no new UI.")


if __name__ == "__main__":
    main()

"""Scenario 10 - compliance QA (the negative control matters most).

A screen that flags everything is useless — the number that keeps a desk usable
is the false-positive rate. This demo runs the full analysis over a perfectly
clean DAO treasury graph and asserts, out loud, that NOTHING is flagged: no
direct hit, no taint, no sanctioned cluster. The tool has to be quiet when it
should be quiet.
"""
from _common import load, rule, severity_line
from cryptotrace.core import analyze


def main() -> None:
    rule("FALSE-POSITIVE AUDIT  -  prove the screen stays quiet on clean data")

    txs = load("05-clean-treasury-baseline")
    res = analyze(txs, max_hops=3, taint_threshold=0.0)
    print(f"\nLoaded {len(txs)} clean-treasury txs, {res.total_addresses} "
          f"addresses  [{severity_line(res)}]\n")

    checks = {
        "direct OFAC hits":      sum(1 for f in res.findings
                                     if f.kind == "ofac_direct_hit"),
        "indirect exposures":    sum(1 for f in res.findings
                                     if f.kind == "ofac_indirect_exposure"),
        "sanctioned clusters":   len(res.sanctioned_clusters),
        "critical/high findings": sum(1 for f in res.findings
                                      if f.severity in ("critical", "high")),
        "dirty value (total)":   res.dirty_value_total,
    }
    all_clean = True
    print("1) audit checks (every count must be zero):")
    for name, n in checks.items():
        ok = (n == 0)
        all_clean &= ok
        print(f"     {'PASS' if ok else 'FAIL'}  {name:24} = {n}")

    print(f"\n2) verdict: {'CLEAN — no over-flagging' if all_clean else 'FAILED'}")
    print(f"   highest severity observed: {res.max_severity.upper()}")

    print("\nBenign clustering (multi-address entities) can still appear — that's")
    print("attribution context, not an alert. What matters: zero sanctions noise.")
    if not all_clean:  # pragma: no cover - guards the negative control
        raise SystemExit("negative control failed: clean graph produced alerts")


if __name__ == "__main__":
    main()

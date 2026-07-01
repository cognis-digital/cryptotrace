"""Scenario 9 - sanctions desk (name the destination, not just the source).

Most screening asks "did funds come FROM a sanctioned wallet?" This one asks the
other, equally-reportable question: are funds heading INTO a sanctioned exchange?
This demo screens a Garantex cash-out flow and shows the direct hit on the
sanctioned destination plus the upstream wallets now exposed for feeding it.
"""
from _common import load, rule, severity_line, show_findings
from cryptotrace.core import analyze, is_sanctioned


def main() -> None:
    rule("GARANTEX CASH-OUT  -  screening the destination, not just the source")

    txs = load("06-garantex-cashout")
    res = analyze(txs, max_hops=2)
    print(f"\nLoaded {len(txs)} txs, {res.total_addresses} addresses  "
          f"[{severity_line(res)}]\n")

    direct = [f for f in res.findings if f.kind == "ofac_direct_hit"]
    print(f"1) {len(direct)} direct OFAC hit(s) — the sanctioned destination:")
    for f in direct:
        hit = is_sanctioned(f.address)
        print(f"     {f.address}  ->  {hit['entity']} "
              f"({hit['category']}, {hit['program']})")

    exposure = [f for f in res.findings if f.kind == "ofac_indirect_exposure"]
    print(f"\n2) {len(exposure)} upstream/counterparty address(es) exposed by "
          f"feeding the sanctioned exchange:")
    show_findings(res, limit=6)

    flagged = any(f.severity in ("critical", "high", "medium") for f in res.findings)
    print(f"\n3) deposit-gate decision: "
          f"{'HOLD / FILE (exit 1)' if flagged else 'CLEAR (exit 0)'}")
    print("\nCashing OUT to a sanctioned venue is a reportable event too — the")
    print("screen catches the destination and everyone who routed funds to it.")


if __name__ == "__main__":
    main()

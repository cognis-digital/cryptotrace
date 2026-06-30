"""Scenario 1 - crypto investigators / AML analysts.

The investigator's first move on a fresh tx export: *screen it*. Who's a direct
OFAC hit, who's downstream and how far, how much dirty value reached them, and
which wallets actually belong to the sanctioned entity? This demo runs the real
`analyze()` over the bundled Tornado Cash deposit graph and reads off exactly
what an analyst would put in the case file.
"""
from _common import load, rule, severity_line, show_findings
from cryptotrace.core import analyze, is_sanctioned


def main() -> None:
    rule("INVESTIGATOR TRIAGE  -  screen a fresh tx export end to end")

    txs = load("01-tornado-cash-deposit")
    print(f"\nLoaded {len(txs)} transactions from the case fixture (ETH).")
    print("Task: a customer routed ETH somewhere — is there sanctions exposure?\n")

    res = analyze(txs, max_hops=2)
    print(f"1) analyze(max_hops=2) -> {res.total_addresses} distinct addresses, "
          f"{len(res.findings)} finding(s)  [{severity_line(res)}]")
    print(f"   highest severity: {res.max_severity.upper()}, "
          f"{res.dirty_value_total:.4f} {res.asset} of tainted value in scope\n")

    print("2) findings, worst first — this is the triage queue:")
    show_findings(res)

    # The single fact that drives the SAR: which exact address is the SDN hit.
    direct = [f for f in res.findings if f.kind == "ofac_direct_hit"]
    print(f"\n3) {len(direct)} direct OFAC hit(s) — the reportable anchor:")
    for f in direct:
        hit = is_sanctioned(f.address)
        print(f"     {f.address}  ->  {hit['entity']} "
              f"(program {hit['program']}, listed {hit['added']})")

    print("\nThe analyst now has the SDN anchor, the tainted downstream wallets,")
    print("and the dirty-value figure — everything a SAR narrative needs.")


if __name__ == "__main__":
    main()

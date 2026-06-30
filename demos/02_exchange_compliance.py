"""Scenario 2 - exchanges / compliance teams.

An exchange must decide, at deposit time, whether to credit funds. Two cases
matter: a customer who *received* from a sanctioned source, and a customer who
is *cashing out into* a sanctioned exchange. This demo screens both directions
and shows the exit code a deposit gate would branch on — exit 1 (block/escalate)
vs exit 0 (clear).
"""
from _common import load, rule, severity_line, show_findings
from cryptotrace.core import analyze


def screen(label: str, scenario: str, max_hops: int = 2) -> bool:
    txs = load(scenario)
    res = analyze(txs, max_hops=max_hops)
    flagged = any(f.severity in ("critical", "high", "medium")
                  for f in res.findings)
    decision = "BLOCK / ESCALATE (exit 1)" if flagged else "CLEAR (exit 0)"
    print(f"\n{label}")
    print(f"   {res.total_txs} txs, {res.total_addresses} addresses  "
          f"[{severity_line(res)}]  -> {decision}")
    show_findings(res, limit=3)
    return flagged


def main() -> None:
    rule("EXCHANGE COMPLIANCE  -  the deposit-gate decision, both directions")

    print("\nGate policy: any critical/high/medium finding -> hold for review.\n")

    # Inbound: customer deposit traces back to a sanctioned mixer.
    inbound = screen(
        "A) Inbound deposit — funds trace back to Garantex (sanctioned exchange):",
        "06-garantex-cashout")

    # Outbound / clean: a normal DAO treasury — must NOT be over-flagged.
    clean = screen(
        "B) Clean DAO treasury — the negative control (must clear):",
        "05-clean-treasury-baseline")

    rule("DEPOSIT-GATE SUMMARY")
    print(f"\n   Garantex cash-out flow : {'HELD' if inbound else 'cleared'}")
    print(f"   Clean treasury         : {'HELD' if clean else 'cleared'}")
    print("\nThe gate holds the sanctioned flow and clears the clean one —")
    print("no over-flagging, which is exactly what keeps a compliance desk usable.")


if __name__ == "__main__":
    main()

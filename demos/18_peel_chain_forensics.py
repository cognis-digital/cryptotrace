"""Scenario 18 - forensic deep-dive on the peeling chain.

The incident-response demo detects the chain; this one dissects it. For each hop
it reads the peel payment vs. the forwarded change, shows the value decaying down
the chain, and confirms the change output of each tx is the input of the next —
the structural fingerprint of layering.
"""
from _common import load, rule
from cryptotrace.core import detect_peel_chains, is_sanctioned


def main() -> None:
    rule("PEEL-CHAIN FORENSICS  -  dissect the layering hop by hop")

    txs = load("04-peel-chain-laundering")
    by_id = {t.txid: t for t in txs}

    chains = detect_peel_chains(txs, min_length=3)
    print(f"\ndetect_peel_chains() -> {len(chains)} chain(s).\n")

    for ci, chain in enumerate(chains, 1):
        print(f"Chain #{ci}  ({len(chain)} hops): {' -> '.join(chain)}")
        prev_change = None
        for txid in chain:
            t = by_id[txid]
            src = t.inputs[0] if t.inputs else "?"
            sdn = is_sanctioned(src)
            tag = f"  <SDN: {sdn['entity']}>" if sdn else ""
            outs = t.outputs
            print(f"   {txid}: spend {src}{tag}  value={t.value}")
            if len(outs) == 2:
                print(f"        peel   -> {outs[0]}")
                print(f"        change -> {outs[1]}  (becomes next hop's input)")
            # structural check: this tx's input is the previous tx's change
            if prev_change is not None:
                linked = (src == prev_change)
                print(f"        link OK: input == prior change? {linked}")
            prev_change = outs[1] if len(outs) == 2 else None
        print()

    print("The decaying value + change-chaining is what separates layering from")
    print("ordinary spends — and it starts at a real sanctioned market address.")


if __name__ == "__main__":
    main()

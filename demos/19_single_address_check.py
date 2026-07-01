"""Scenario 19 - the fast path: screen one address.

Not every question needs a graph. The most common compliance query is "is THIS
address sanctioned?" This demo exercises the single-address path — direct SDN
lookup, actor-tag attribution, and the clean case — the same logic behind the
`cryptotrace check` CLI subcommand, across every bundled entity.
"""
from _common import rule
from cryptotrace.core import actor_tag, is_sanctioned, ofac_entries


def main() -> None:
    rule("SINGLE-ADDRESS CHECK  -  the fast compliance query")

    # 1) One representative address per bundled SDN entity.
    seen_entities = {}
    for e in ofac_entries():
        seen_entities.setdefault(e["entity"], e["address"])
    print(f"\n1) is_sanctioned() across {len(seen_entities)} bundled entities:")
    for entity, addr in seen_entities.items():
        hit = is_sanctioned(addr)
        assert hit is not None
        print(f"     HIT  {addr:46} {hit['entity']} ({hit['program']})")

    # 2) A known-actor (non-sanctioned) attribution.
    demo = "1ExchangeHotWalletDemo0000000000"
    tag = actor_tag(demo)
    print(f"\n2) actor_tag() attribution (not sanctioned): {demo}")
    print(f"     -> {tag['actor']} ({tag['category']})")

    # 3) A clean address.
    clean = "1DefinitelyCleanAddress00000000000000"
    print(f"\n3) clean address: {clean}")
    print(f"     sanctioned={is_sanctioned(clean) is not None}  "
          f"actor={actor_tag(clean)}")

    print("\nThree outcomes — SANCTIONED / known-actor / clean — from one lookup,")
    print("case-insensitive on ETH addresses. This is the `check` subcommand.")


if __name__ == "__main__":
    main()

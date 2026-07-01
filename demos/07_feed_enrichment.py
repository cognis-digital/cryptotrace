"""Scenario 7 - compliance / data engineering (keep the screen current).

The bundled SDN seed is small on purpose. The real screen becomes *current* by
ingesting the authoritative US Treasury OFAC SDN list and merging every
``Digital Currency Address`` into the live index. This demo does exactly that,
fully OFFLINE, by pointing the datafeeds cache at the committed test fixture — so
an address that is NOT in the seed becomes screenable after enrichment.
"""
import importlib
import os

from _common import rule

# Point the feeds cache at the committed offline SDN fixture (no network).
FIXTURE_CACHE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tests", "fixtures", "feeds-cache")

NEW_BTC = "1NewSDNExampleAddr000000000000000aBcDeF"


def main() -> None:
    rule("FEED ENRICHMENT  -  make the screen current from the live OFAC SDN list")

    prior = os.environ.get("COGNIS_FEEDS_CACHE")
    os.environ["COGNIS_FEEDS_CACHE"] = FIXTURE_CACHE
    # reload so core/feeds pick up the cache env for a clean, isolated run
    from cryptotrace import core, feeds
    importlib.reload(core)
    importlib.reload(feeds)

    print(f"\nFeeds cache (offline fixture): {FIXTURE_CACHE}")
    print("Feeds wired into cryptotrace:", [f["id"] for f in feeds.relevant_feeds()])

    print(f"\n1) before enrichment: is {NEW_BTC[:18]}... sanctioned? "
          f"-> {core.is_sanctioned(NEW_BTC) is not None}")

    merged = feeds.load_sdn_into_index(offline=True)
    print(f"2) feeds.load_sdn_into_index(offline=True) merged {merged} "
          f"SDN address(es) into the live index.")

    hit = core.is_sanctioned(NEW_BTC)
    print(f"3) after enrichment: is {NEW_BTC[:18]}... sanctioned? "
          f"-> {hit is not None}  ({hit['entity'] if hit else '-'})")

    # The enrichment is real: analysis built on is_sanctioned now sees it.
    txs = core.parse_txs(
        '[{"txid":"e0","asset":"BTC","value":1.0,"inputs":["%s"],'
        '"outputs":["1victimDownstream00000000000000xyz"]}]' % NEW_BTC)
    res = core.analyze(txs, max_hops=2)
    crit = [f for f in res.findings if f.severity == "critical"]
    print(f"4) analyze() now raises {len(crit)} critical finding on the "
          f"newly-merged SDN source; dirty value = {res.dirty_value_total:.4f}.")

    print("\nSame code path an air-gapped enclave uses: fetch+cache online once,")
    print("sneakernet the cache in, then screen offline against the full SDN set.")

    # Restore process state so this scenario stays isolated when run in a batch.
    if prior is None:
        os.environ.pop("COGNIS_FEEDS_CACHE", None)
    else:
        os.environ["COGNIS_FEEDS_CACHE"] = prior
    importlib.reload(core)
    importlib.reload(feeds)


if __name__ == "__main__":
    main()

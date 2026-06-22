# Demo 09 — Live OFAC SDN feed enrichment (edge / air-gap)

CRYPTOTRACE ships a curated seed of OFAC-sanctioned crypto wallets. This demo
shows the **real enrichment**: ingesting the authoritative US Treasury OFAC SDN
list (catalog feed `ofac-sdn`) and merging every published *Digital Currency
Address* into the live screening index — so an address that is **not** in the
bundled seed becomes screenable.

Everything here runs **offline** against a trimmed, committed SDN fixture; no
network is touched.

## Run it (offline)

```sh
# point the feed cache at the committed fixture (no network)
export COGNIS_FEEDS_CACHE="$PWD/tests/fixtures/feeds-cache"

# what feeds are wired in?
python -m cryptotrace feeds list

# parse the live SDN crypto addresses straight from the cached feed
python -m cryptotrace feeds get ofac-sdn --offline

# an address only present in the live SDN list (not the seed):
ADDR=44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A

python -m cryptotrace check "$ADDR"                  # -> clean (seed only)
python -m cryptotrace check "$ADDR" --feed --offline # -> SANCTIONED (after merge)
```

## Air-gap workflow

1. On a connected host: `python -m cryptotrace.datafeeds update ofac-sdn`
2. Snapshot the cache: `python -m cryptotrace.datafeeds snapshot-export sdn.tar.gz`
3. Sneakernet `sdn.tar.gz` into the enclave.
4. Inside the enclave: `python -m cryptotrace.datafeeds snapshot-import sdn.tar.gz`
5. Screen with `--feed --offline` — the enclave never reaches the network.

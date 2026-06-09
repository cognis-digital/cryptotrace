# Demo 02-deep — OFAC screening, taint tracking, clustering + laundering patterns

This scenario screens a small BTC transaction graph that launders funds out of
a **real OFAC SDN address** — `1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f`
(SUEX OTC, the first crypto exchange OFAC ever designated, Sep 2021).
Every other address is fictional.

The graph is built so that one run exercises every engine capability:

| Capability | How the graph triggers it |
|---|---|
| **Direct OFAC hit** | `t1` spends from the SUEX SDN address. |
| **Indirect exposure (hop distance)** | `1Layer1Recv…` (1 hop), `1Peel1…` (2 hops), and on outward. |
| **Value-weighted taint** | Dirty value is propagated forward; `t5` mixes 3.0 clean BTC with 1.7 dirty BTC, so `1Layer2Hop…` comes out only ~53% tainted (haircut model). |
| **Common-input-ownership cluster** | `t5` spends `1WalletA-in1` + `1WalletA-in2` together → one entity. |
| **Change-address cluster** | `t5`/`t6` fold `1WalletA-chg…` into WalletA. |
| **Peeling-chain laundering** | `t1→t2→t3→t4→t7` each shed a small "peel" payment while forwarding the change — the classic layering pattern. |
| **Known-actor attribution** | `1MerchantPayDemo…` is tagged as a merchant in the bundled actor table. |

## Run it

```bash
# Full screen (table) — direct hits, taint, clusters, peel chains
python -m cryptotrace screen demos/02-deep/tx_graph.json

# Machine-readable, for a CI compliance gate
python -m cryptotrace screen --format json demos/02-deep/tx_graph.json

# Only report downstream addresses that are >= 50% tainted
python -m cryptotrace screen --min-taint 0.5 demos/02-deep/tx_graph.json

# Value-weighted taint propagation on its own
python -m cryptotrace taint demos/02-deep/tx_graph.json --min-taint 0.5

# Peeling-chain laundering detection
python -m cryptotrace peel demos/02-deep/tx_graph.json

# Wallet clustering with risk scores
python -m cryptotrace cluster demos/02-deep/tx_graph.json

# Screen a single address (SDN, known-actor, or clean)
python -m cryptotrace check 1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f
python -m cryptotrace check 1MerchantPayDemo000000000000eeee

# Show the bundled OFAC SDN crypto address list
python -m cryptotrace sdn
```

## Expected

- Exit code **1** (sanctioned exposure found) for `screen`, `taint`, `peel`,
  and `check` on the SDN address.
- One `ofac_direct_hit` (CRITICAL) on the SUEX address.
- A spread of `ofac_indirect_exposure` findings carrying both hop distance and
  a taint fraction; addresses fed by the mixed WalletA come out partially
  tainted (~53%) rather than 100%.
- A `peel_chain` finding spanning `t1 → t2 → t3 → t4 → t7`.
- A WalletA cluster of 3 addresses tagged with both `common_input` and
  `change_address` heuristics, plus an aggregate `risk_score`.

This is defensive/compliance tooling: it operates only on a tx export you
already hold and makes **no network calls**. The bundled SDN list is
representative, not exhaustive — OFAC publishes the authoritative list, and you
can supply your own actor-tag/SDN data in production.

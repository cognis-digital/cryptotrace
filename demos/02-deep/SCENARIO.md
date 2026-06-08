# Demo 02-deep — OFAC screening + clustering over a tx graph

This scenario screens a small BTC transaction graph that launders funds out of
a **real OFAC SDN address** — `1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f`
(SUEX OTC, the first crypto exchange OFAC ever designated, Sep 2021).
Every other address is fictional.

The graph is built so that one run exercises all four engine capabilities:

| Capability | How the graph triggers it |
|---|---|
| **Direct OFAC hit** | `t1` spends from the SUEX SDN address. |
| **Indirect exposure (1 hop)** | `1Layer1Recv…` / `1Layer1Chng…` receive directly from SUEX. |
| **Indirect exposure (2 hops)** | `1Layer2Hop…`, `1WalletA-in1/in2` sit two hops out. |
| **Common-input-ownership cluster** | `t3` spends `1WalletA-in1` + `1WalletA-in2` together → one entity. |
| **Change-address cluster** | `t3`/`t4` fold `1WalletA-chg…` into WalletA. |

## Run it

```bash
# Full screen (table)
python -m cryptotrace screen demos/02-deep/tx_graph.json

# Machine-readable, for a CI compliance gate
python -m cryptotrace screen --format json demos/02-deep/tx_graph.json

# Trace exposure further out
python -m cryptotrace screen --max-hops 3 demos/02-deep/tx_graph.json

# Just the wallet clustering
python -m cryptotrace cluster demos/02-deep/tx_graph.json

# Screen a single address
python -m cryptotrace check 1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f

# Show the bundled OFAC SDN crypto address list
python -m cryptotrace sdn
```

## Expected

- Exit code **1** (sanctioned exposure found) for `screen` and `check` on the SDN address.
- One `ofac_direct_hit` (CRITICAL) on the SUEX address.
- Two `ofac_indirect_exposure` HIGH findings (1 hop) and three MEDIUM (2 hops).
- A WalletA cluster of 3 addresses tagged with both
  `common_input` and `change_address` heuristics.

This is defensive/compliance tooling: it operates only on a tx export you
already hold and makes no network calls.

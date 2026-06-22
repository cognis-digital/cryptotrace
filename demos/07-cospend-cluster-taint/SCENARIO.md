# Demo 07 — Common-input clustering with sanctions inheritance (BTC)

**Use case:** prove that two "unknown" wallets are actually controlled by a
sanctioned entity. The transaction `cospend1` spends the **real OFAC SDN SUEX
OTC** address (`12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h`, designated 2021-09-21 under
CYBER2) **together** with two other wallets in a single multi-input
transaction. By the common-input-ownership heuristic (the foundational
GraphSense / WalletExplorer rule), inputs co-spent in one tx share an owner — so
both unknown wallets are now attributable to SUEX and the whole cluster inherits
the taint.

## Where the data comes from

A three-transaction BTC graph (`tx_graph.json`) built around one multi-input
co-spend. Only the SUEX address is a real SDN entry; the co-spend wallets,
consolidation, and downstream addresses are fictional placeholders.

## Run

```bash
python -m cryptotrace cluster demos/07-cospend-cluster-taint/tx_graph.json
python -m cryptotrace screen demos/07-cospend-cluster-taint/tx_graph.json
python -m cryptotrace screen --format json demos/07-cospend-cluster-taint/tx_graph.json
```

## What to expect

- `cluster` returns exit **1** and one **3-address cluster** tagged
  `!! SANCTIONED: SUEX OTC`, `risk=80/100`, heuristic `common_input`.
- `screen` adds a **CRITICAL** direct hit on the SUEX address plus a
  **`cluster_sanctioned` HIGH** finding noting the co-owned addresses that
  inherit the taint.

## How to act

Add the two co-spend wallets (`…aaaa1`, `…bbbb2`) to your sanctioned-entity
watchlist — the clustering is your evidence that they are the same operator as
the SDN address. Treat any future activity from them as sanctioned exposure.

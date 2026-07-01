# Demo 11 — Raw block-explorer JSON ingest (BTC)

**Use case:** ingest a response straight from a block explorer
(Esplora/Blockstream-style) with **no normalizer**. Explorers return
inputs/outputs as nested **objects** keyed by `prev_addr` /
`scriptpubkey_address`, name the id `hash`, and carry the asset as `chain`.
`cryptotrace`'s parser coerces all of those shapes into its `Transaction` model.

## Where the data comes from

`tx_graph.json`: two BTC transactions in explorer shape. The first spends the
real OFAC **Hydra Market** address (`1AdraFvB8Ads5KFFGZQUgYvuhMQVjUuk5j`,
RUSSIA-EO14024); the rest are fictional placeholders.

## Run

```bash
python -m cryptotrace screen demos/11-explorer-json/tx_graph.json
python demos/14_explorer_ingest.py
```

## What to expect

- Exit code **1** with a **CRITICAL** direct hit on the Hydra Market address,
  extracted from the nested `prev_addr` object.
- The `hash` id and `chain: "btc"` asset hint are honored automatically.

## How to act

Pipe explorer JSON directly into `analyze()` / `screen` — the parser meets the
data where it is.

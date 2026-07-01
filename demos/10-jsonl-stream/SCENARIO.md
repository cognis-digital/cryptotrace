# Demo 10 — JSONL streaming input (ETH)

**Use case:** large chain exports are delivered as **JSONL** — one JSON
transaction per line — because it streams without loading the whole file into
memory. `cryptotrace` accepts JSONL transparently: when the whole blob is not a
single JSON document, the parser falls back to line-by-line parsing.

## Where the data comes from

`tx_graph.jsonl`: three ETH transactions, one per line. The first spends the
real OFAC Tornado Cash router address
(`0x722122df12d4e14e13ac3b6895a86e84145b6967`, CYBER2); the rest are fictional
downstream hops.

## Run

```bash
python -m cryptotrace screen demos/10-jsonl-stream/tx_graph.jsonl
python demos/13_jsonl_streaming.py
```

## What to expect

- Exit code **1** with a **CRITICAL** direct hit on the Tornado Cash router.
- Downstream hops surface as tainted exposure — the JSONL is treated identically
  to a JSON array, with no reshaping step in the pipeline.

## How to act

Point your existing streaming export straight at `screen` — there is no
normalizer to write and one fewer place for bugs to hide.

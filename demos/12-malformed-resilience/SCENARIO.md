# Demo 12 — Malformed-export resilience (ETH)

**Use case:** real exports contain junk. `cryptotrace` must skip bad rows
**record by record** and still surface the genuine SDN hit, rather than throwing
on the first malformed entry.

## Where the data comes from

`tx_graph.json`: five raw entries — a bare scalar (`42`), a non-object string, a
record with no inputs/outputs, a record with an unparseable `"value"` token, and
one genuine ETH record spending the real OFAC Tornado Cash router
(`0x722122df12d4e14e13ac3b6895a86e84145b6967`, CYBER2).

## Run

```bash
python -m cryptotrace screen demos/12-malformed-resilience/tx_graph.json
python demos/15_malformed_resilience.py
```

## What to expect

- The parser keeps only the usable records; the junk is dropped silently.
- The bad `"value"` token coerces to a clean `0.0` (no exception).
- Exit code **1** with a **CRITICAL** direct hit on the Tornado Cash router —
  the signal survives the noise.

## How to act

Feed cryptotrace whatever your upstream produces; one bad row can't blind the
screen.

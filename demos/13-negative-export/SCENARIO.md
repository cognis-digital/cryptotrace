# Demo 13 — Signed / negative value hardening (ETH)

**Use case:** some accounting exports emit **signed value deltas**. A naive
parser once let a negative value silently fall through to a neutral `1.0` unit
weight, quietly **understating the dirty-value totals** the taint model depends
on. `cryptotrace` now normalises every value to its finite, non-negative
magnitude.

## Where the data comes from

`tx_graph.json`: two ETH transactions with negative `"value"` fields. The first
spends the real OFAC **Lazarus Group (DPRK)** address
(`0x098b716b8aaf21512996dc57eb0615e2383e2f96`, DPRK3); the rest are fictional
placeholders.

## Run

```bash
python -m cryptotrace screen demos/13-negative-export/tx_graph.json
python demos/16_negative_export_hardening.py
```

## What to expect

- Each negative value is clamped to its magnitude (e.g. `-20.0 → 20.0`).
- Taint fractions stay in `[0, 1]`; dirty values stay finite and non-negative.
- Exit code **1** with a **CRITICAL** direct hit on the Lazarus address and a
  correct, finite dirty-value total.

## How to act

This is a regression guard: the fix ensures signed exports can't understate
exposure. If your source emits signed deltas, screening still reports the true
tainted magnitude.

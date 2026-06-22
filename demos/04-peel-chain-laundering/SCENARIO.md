# Demo 04 — Peeling-chain laundering from a sanctioned market (BTC)

**Use case:** funds leave the **real OFAC SDN Hydra Market** address
(`1AdraFvB8Ads5KFFGZQUgYvuhMQVjUuk5j`, designated 2022-04-05 under
RUSSIA-EO14024) and are walked down a textbook **peeling chain**: each
transaction sheds a small "peel" to a fresh deposit address and forwards the
larger change to the next hop. This is the layering pattern mixers and OTC
launderers use to break a large balance into many small, hard-to-trace payouts.

## Where the data comes from

A five-transaction BTC graph (`tx_graph.json`) of single-input / two-output
transactions chained through their change outputs. Only the Hydra Market
address is a real SDN entry; the peel/change addresses are fictional
placeholders.

## Run

```bash
# Detect the laundering pattern explicitly
python -m cryptotrace peel demos/04-peel-chain-laundering/tx_graph.json

# Full screen also surfaces the peel_chain finding alongside taint
python -m cryptotrace screen --max-hops 5 demos/04-peel-chain-laundering/tx_graph.json

# Require a longer chain before flagging
python -m cryptotrace peel demos/04-peel-chain-laundering/tx_graph.json --min-length 4
```

## What to expect

- `peel` reports **one chain of 5 txs**: `peel0 -> peel1 -> peel2 -> peel3 -> peel4`.
- `screen` returns exit code **1** with a **CRITICAL** Hydra Market direct hit,
  a `peel_chain` finding, and value-weighted taint following every change hop.

## How to act

Each "peel" deposit address (`1Peel0Deposit…` … `1Peel4Deposit…`) is a likely
cash-out point — these are the addresses to forward to exchanges for freezing.
The chain length and the steadily shrinking change output are the laundering
signature; document them in the SAR narrative.

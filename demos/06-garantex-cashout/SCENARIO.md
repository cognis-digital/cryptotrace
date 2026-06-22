# Demo 06 — Cash-out INTO a sanctioned exchange (Garantex, BTC)

**Use case:** the opposite direction from the mixer demos. Here the sanctioned
address is the **destination**, not the source. Fraud proceeds pool in a
collector wallet, take one hop, and land in the **real OFAC SDN Garantex Europe
OU** deposit address (`1Fdyrt4iC91kAFRz9SiF44ZRzhCJqkLAFD`, designated
2022-04-05 under RUSSIA-EO14024). This is the classic "off-ramp at a sanctioned
exchange" pattern.

## Where the data comes from

A four-transaction BTC graph (`tx_graph.json`): two victim payments into a scam
collector, one intermediate hop, then the cash-out to Garantex. Only the
Garantex address is a real SDN entry; all others are fictional placeholders.

## Run

```bash
python -m cryptotrace screen --max-hops 3 demos/06-garantex-cashout/tx_graph.json
python -m cryptotrace check 1Fdyrt4iC91kAFRz9SiF44ZRzhCJqkLAFD
```

## What to expect

- Exit code **1** with a **CRITICAL** Garantex direct hit.
- **HIGH** exposure on the intermediate wallet (1 hop) and **MEDIUM** exposure
  on the collector and the two victim wallets (2–3 hops).
- `Tainted value (total): 0` — note this. Taint propagates *forward from*
  sanctioned **sources**; here the SDN address is the **sink**, so the value
  signal is the **hop-distance** exposure, not forward taint. Use `--max-hops`
  (not `taint`) for sink-side cash-out detection.

## How to act

Sending value to a sanctioned exchange is itself a violation. The two
2–3-hop "victim" wallets are likely genuine victims (run the upstream trace to
confirm), while the collector and intermediate are the operator's wallets — the
priority targets for the report.

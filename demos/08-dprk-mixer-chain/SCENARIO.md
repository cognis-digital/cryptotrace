# Demo 08 — Chained DPRK mixers: Blender.io → Sinbad.io (BTC)

**Use case:** track funds through **two** OFAC-sanctioned, DPRK-linked mixers in
sequence. Value exits **Blender.io** (`bc1q2sttgr0vd4r88uxq7feu5g0r8z7q3qkq0r6yqr`,
designated 2022-05-06 under DPRK3), takes an intermediate hop, enters
**Sinbad.io** — Blender.io's successor mixer (`bc1qs4dqj3x3pqr0z5fpmldtq3z0d6q5w2x5lj7qk0`,
designated 2023-11-29 under DPRK3) — and finally splits to two payout wallets.

## Where the data comes from

A four-transaction BTC graph (`tx_graph.json`). Both mixer addresses are real
SDN entries; the intermediate hop and the two payout wallets are fictional
placeholders.

## Run

```bash
python -m cryptotrace screen --max-hops 3 demos/08-dprk-mixer-chain/tx_graph.json
python -m cryptotrace taint demos/08-dprk-mixer-chain/tx_graph.json
python -m cryptotrace taint demos/08-dprk-mixer-chain/tx_graph.json --min-taint 0.9
```

## What to expect

- Exit code **1** with **two CRITICAL** direct hits (Blender.io and Sinbad.io).
- `taint` reports **two sanctioned sources** and **three 100%-tainted**
  downstream addresses — the intermediate hop and both payout wallets, with
  exact dirty-value amounts in BTC.

## How to act

A two-mixer chain with two distinct DPRK designations is strong evidence of
deliberate, sophisticated laundering. The two 100%-tainted payout wallets
(`…bbbb2`, `…cccc3`) are the off-ramp targets — escalate them and use the
`--min-taint` filter to keep only the high-confidence, fully-dirty endpoints in
your report.

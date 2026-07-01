# Demo 14 — Multi-source attribution: Tornado Cash + Lazarus (ETH)

**Use case:** a consolidation wallet that collects from **more than one**
sanctioned program at once. `cryptotrace` attributes each flow to its own SDN
entity and taints the shared consolidation node from multiple sources.

## Where the data comes from

`tx_graph.json`: three ETH transactions. A consolidation wallet receives from
**both** the real OFAC Tornado Cash router
(`0x722122df12d4e14e13ac3b6895a86e84145b6967`, CYBER2) and a real Lazarus Group
address (`0x098b716b8aaf21512996dc57eb0615e2383e2f96`, DPRK3), then fans out to
two payout wallets. Non-SDN addresses are fictional placeholders.

## Run

```bash
python -m cryptotrace screen demos/14-multi-source/tx_graph.json
python -m cryptotrace taint demos/14-multi-source/tx_graph.json
python demos/11_multi_source_attribution.py
```

## What to expect

- Exit code **1** with **two CRITICAL** direct hits attributed to distinct
  programs (CYBER2 and DPRK3).
- Taint from both sources converges on the consolidation node; the payout
  wallets inherit the combined dirty value.

## How to act

The case file names **both** Tornado Cash and Lazarus, not one blurred
"sanctioned" blob — attribution stays per-entity even when flows merge.

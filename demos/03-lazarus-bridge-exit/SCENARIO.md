# Demo 03 — Lazarus Group (DPRK) bridge-drain exit (ETH)

**Use case:** an incident-response / threat-intel analyst reconstructs where the
proceeds of a cross-chain bridge exploit went. Two drain wallets consolidate
into one wallet, which forwards everything to a **real OFAC SDN Lazarus Group
(DPRK) address** (`0xa0e1c89ef1a489c9c7de96311ed5ce5d32c20e4b`, designated
2022-08-08 under DPRK3) before fanning the funds out to fresh laundering wallets.

## Where the data comes from

A five-transaction ETH graph (`tx_graph.json`) reconstructed from on-chain
forensics. The Lazarus address is the only real SDN entry; the drain,
consolidation, and laundering wallets are fictional placeholders for the
addresses you would pull from your own investigation.

## Run

```bash
python -m cryptotrace screen --max-hops 3 demos/03-lazarus-bridge-exit/tx_graph.json
python -m cryptotrace taint demos/03-lazarus-bridge-exit/tx_graph.json --min-taint 0.5
python -m cryptotrace check 0xa0e1c89ef1a489c9c7de96311ed5ce5d32c20e4b
```

## What to expect

- Exit code **1** (sanctioned exposure found).
- One **CRITICAL** `ofac_direct_hit` attributed to *Lazarus Group (DPRK)*,
  category `threat_actor`.
- Two **HIGH** fan-out wallets that each receive 100%-tainted value directly
  from the SDN address — these are the live laundering endpoints.
- The consolidation wallet plus the two drain wallets appear as further
  exposure (HIGH / MEDIUM by hop distance).

## How to act

DPRK attribution makes this a national-security matter, not just AML. Preserve
the graph, report the SDN nexus, and prioritise the two 100%-tainted fan-out
wallets (`…a1`, `…b2`) for real-time watchlisting before the funds reach an
off-ramp.

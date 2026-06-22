# Demo 01 — Tornado Cash deposit screening (ETH)

**Use case:** a centralized exchange's compliance team screens a customer's
on-chain history before approving a large fiat withdrawal. The export shows the
customer routed ETH through the **OFAC-sanctioned Tornado Cash router**
(`0x722122df12d4e14e13ac3b6895a86e84145b6967`, designated 2022-08-08 under
program CYBER2), then pulled it back out two hops later.

## Where the data comes from

A four-transaction ETH graph exported from your own block explorer / indexer
(`tx_graph.json`). The only real address is the Tornado Cash router — every
`0x1111…`–`0x4444…` address is a fictional placeholder standing in for the
customer wallets you would substitute from your case.

## Run

```bash
python -m cryptotrace screen demos/01-tornado-cash-deposit/tx_graph.json
python -m cryptotrace screen --format json demos/01-tornado-cash-deposit/tx_graph.json
python -m cryptotrace taint demos/01-tornado-cash-deposit/tx_graph.json
```

## What to expect

- Exit code **1** (sanctioned exposure found).
- One `ofac_direct_hit` **CRITICAL** on the Tornado Cash router.
- Three **HIGH** `ofac_indirect_exposure` findings — the immediate deposit
  source, the withdrawal address (100% tainted), and the cash-out wallet
  (2 hops but heavily tainted, so escalated to HIGH).
- One **MEDIUM** exposure on the original funding wallet.

## How to act

A direct Tornado Cash interaction is an OFAC nexus and is reportable. Freeze the
withdrawal, file the SAR/blocking report, and pivot on the 100%-tainted
withdrawal address (`0x3333…`) — that is where the laundered value re-entered
the clear-net flow.

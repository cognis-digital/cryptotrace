# Demo 05 — Clean treasury baseline (negative control)

**Use case:** a periodic compliance audit of a DAO / company treasury multisig.
Nothing here touches a sanctioned address, so a correct run produces **zero
sanctions findings and exits 0**. This is the negative-control demo — it proves
CRYPTOTRACE does not over-flag ordinary payroll, grant, top-up, and vendor
activity, which is exactly what you want when you gate CI on the exit code.

## Where the data comes from

A four-transaction ETH treasury graph (`tx_graph.json`): a payroll payment with
change back to the treasury, a grant, a signer top-up, and a vendor payment.
All addresses are fictional placeholders.

## Run

```bash
python -m cryptotrace screen demos/05-clean-treasury-baseline/tx_graph.json
python -m cryptotrace screen --format json demos/05-clean-treasury-baseline/tx_graph.json
python -m cryptotrace cluster demos/05-clean-treasury-baseline/tx_graph.json
```

## What to expect

- Exit code **0** — no sanctioned exposure.
- `Findings: 0 (none)`, highest severity `INFO`.
- Clustering still runs: the change output back to the treasury folds the
  contributor address into the treasury's entity cluster (`change_address`
  heuristic), with a low `risk=5/100` score. This is useful audit context, not
  a flag.

## How to act

A clean exit-0 is your green light. Keep this file as a regression fixture: if a
future SDN-list update ever flags it, you know your treasury counterparties
changed — investigate the new hit.

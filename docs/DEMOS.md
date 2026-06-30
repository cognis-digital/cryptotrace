# Demos

Two layers of demos ship with `cryptotrace`:

1. **Scenario folders** — `demos/NN-name/` each hold a real-format `tx_graph.json`
   plus a `SCENARIO.md` explaining the data, the exact command, and what to
   expect. Run them straight through the CLI.
2. **Runnable Python scenarios** — `demos/NN_name.py` drive the **real**
   cryptotrace API over those same bundled fixtures, with narrated output, one
   per audience. They run **offline** (no live chain calls) and exit 0.

```bash
python demos/run_all.py                 # all five Python scenarios, end to end
python demos/03_journalist_attribution.py   # or just one
PYTHONUTF8=1 python demos/run_all.py    # on Windows, force UTF-8 output
```

## Runnable scenarios by audience

| # | Scenario | Audience | Fixture | Exercises |
|---|----------|----------|---------|-----------|
| 1 | [`01_investigator_triage.py`](../demos/01_investigator_triage.py) | Crypto investigators / AML analysts | `01-tornado-cash-deposit` | `analyze` · direct hit · hop grading · taint · dirty-value |
| 2 | [`02_exchange_compliance.py`](../demos/02_exchange_compliance.py) | Exchanges / compliance desks | `06-garantex-cashout` + `05-clean-treasury-baseline` | deposit-gate decision · exit codes · no over-flagging |
| 3 | [`03_journalist_attribution.py`](../demos/03_journalist_attribution.py) | Investigative journalists | `03-lazarus-bridge-exit` | `is_sanctioned` attribution · `propagate_taint` · reproducibility |
| 4 | [`04_incident_response.py`](../demos/04_incident_response.py) | Incident response / SOC | `04-peel-chain-laundering` | `detect_peel_chains` · `to_sarif` (SARIF 2.1.0) · pipeline wiring |
| 5 | [`05_cluster_inheritance.py`](../demos/05_cluster_inheritance.py) | AML / forensic analysts | `07-cospend-cluster-taint` | `cluster_addresses` · common-input ownership · sanctions inheritance |

### 1. Investigator triage — *screen a fresh tx export*
The analyst's first move: run `analyze()` and read off the triage queue —
the SDN anchor, the tainted downstream wallets, and the dirty-value figure that
a SAR narrative needs.

### 2. Exchange compliance — *the deposit-gate decision*
Screens a sanctioned cash-out flow **and** a clean DAO treasury, and shows the
exit code a deposit gate branches on: hold the Garantex flow, clear the clean
one. The negative control proves it does not over-flag.

### 3. Journalist attribution — *name the entity, show your work*
Names the on-chain entity straight from the bundled OFAC designation, then
quantifies the fan-out with value-weighted taint. Every figure is reproducible
from the fixture with one CLI command — the bar for a story that has to hold up.

### 4. Incident response — *spot the pattern, emit SARIF*
Detects the attacker's peeling-chain cash-out and emits the whole screen as
SARIF 2.1.0 — the exact artifact you upload to GitHub/GitLab code-scanning, so
the finding lands next to the team's existing security alerts.

### 5. Cluster inheritance — *co-spend proves common ownership*
Runs common-input-ownership clustering over a co-spend graph and shows clean
wallets being pulled into a SUEX-controlled cluster — turning one SDN hit into
exposure across every wallet the entity controls.

---

Each scenario prints clear, narrated output and exits 0, so they double as smoke
tests — `tests/test_demos.py` runs all five under `pytest` with the network
unused.

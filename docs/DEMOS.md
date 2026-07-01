# Demos

Two layers of demos ship with `cryptotrace`:

1. **Scenario folders** — `demos/NN-name/` each hold a real-format `tx_graph.json`
   plus a `SCENARIO.md` explaining the data, the exact command, and what to
   expect. Run them straight through the CLI.
2. **Runnable Python scenarios** — `demos/NN_name.py` drive the **real**
   cryptotrace API over those same bundled fixtures, with narrated output, one
   per audience. They run **offline** (no live chain calls) and exit 0.

```bash
python demos/run_all.py                 # all 20 Python scenarios, end to end
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
| 6 | [`06_sarif_pipeline.py`](../demos/06_sarif_pipeline.py) | Security engineering / DevSecOps | `04-peel-chain-laundering` | `to_sarif` rule descriptors · levels · security-severity · fingerprints |
| 7 | [`07_feed_enrichment.py`](../demos/07_feed_enrichment.py) | Compliance / data engineering | `tests/fixtures/feeds-cache` (offline) | `feeds.load_sdn_into_index` · live-SDN merge · offline enclave path |
| 8 | [`08_taint_dilution.py`](../demos/08_taint_dilution.py) | AML analysts | `08-dprk-mixer-chain` | `propagate_taint` haircut model · hop vs. taint |
| 9 | [`09_garantex_cashout.py`](../demos/09_garantex_cashout.py) | Sanctions desk | `06-garantex-cashout` | destination screening · direct hit on the sink |
| 10 | [`10_false_positive_audit.py`](../demos/10_false_positive_audit.py) | Compliance QA | `05-clean-treasury-baseline` | negative control · zero sanctions noise |
| 11 | [`11_multi_source_attribution.py`](../demos/11_multi_source_attribution.py) | Threat intel / attribution | `14-multi-source` | multi-source taint · per-entity attribution |
| 12 | [`12_cluster_risk_scoring.py`](../demos/12_cluster_risk_scoring.py) | Forensic analysts | `07-cospend-cluster-taint` | `_cluster_risk` decomposition · defensible score |
| 13 | [`13_jsonl_streaming.py`](../demos/13_jsonl_streaming.py) | Data engineering | `10-jsonl-stream` | JSONL parsing path · streaming input |
| 14 | [`14_explorer_ingest.py`](../demos/14_explorer_ingest.py) | Integrators | `11-explorer-json` | explorer-shaped JSON (`prev_addr`/`hash`/`chain`) ingest |
| 15 | [`15_malformed_resilience.py`](../demos/15_malformed_resilience.py) | Reliability | `12-malformed-resilience` | junk-row skipping · value coercion · no crash |
| 16 | [`16_negative_export_hardening.py`](../demos/16_negative_export_hardening.py) | Correctness | `13-negative-export` | signed/negative value clamping · finite taint math |
| 17 | [`17_triple_export.py`](../demos/17_triple_export.py) | Reporting | `03-lazarus-bridge-exit` | table + JSON + SARIF from one result · consistency |
| 18 | [`18_peel_chain_forensics.py`](../demos/18_peel_chain_forensics.py) | Forensic analysts | `04-peel-chain-laundering` | per-hop peel/change dissection · change-chaining |
| 19 | [`19_single_address_check.py`](../demos/19_single_address_check.py) | Compliance (fast path) | bundled SDN table | `is_sanctioned` · `actor_tag` · clean case |
| 20 | [`20_connect_emit.py`](../demos/20_connect_emit.py) | Interoperability | `03-lazarus-bridge-exit` | `cryptotrace.connect` → STIX / Sigma (graceful without extra) |

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

### 6. SARIF pipeline — *a chain finding next to your SAST alerts*
Turns a screen into a SARIF 2.1.0 log and inspects the exact fields a
code-scanning UI keys on: rule descriptors, result levels, security-severity,
and the stable partial fingerprint that makes re-scans dedupe instead of
re-alerting.

### 7. Feed enrichment — *keep the screen current, offline*
Ingests the authoritative OFAC SDN list (offline, from the committed fixture
cache) and merges every crypto address into the live index, so an address that
was NOT in the bundled seed becomes screenable — the same code path an air-gapped
enclave uses.

### 8. Taint dilution — *hop distance vs. value-weighted taint*
Walks a DPRK mixer chain and reads off the taint fraction and dirty value at each
node, showing how mixing dilutes taint below 100% while hop distance keeps
climbing — the haircut model made concrete.

### 9. Garantex cash-out — *screen the destination, not just the source*
Screens funds heading **into** a sanctioned exchange, surfacing the direct hit on
the destination plus the upstream wallets exposed for feeding it.

### 10. False-positive audit — *prove the screen stays quiet*
Runs the full analysis over a clean DAO treasury and asserts every sanctions
count is zero — the negative control that keeps a compliance desk usable.

### 11. Multi-source attribution — *one wallet, two programs*
Screens a consolidation wallet fed by both Tornado Cash and Lazarus, attributing
each flow to its own SDN entity while taint converges on the shared node.

### 12. Cluster risk scoring — *where the 0-100 number comes from*
Decomposes each cluster's risk score (sanctions inheritance, mixer membership,
heuristics, size) so an analyst can defend the number in a report.

### 13. JSONL streaming — *screen a line-delimited export unchanged*
Screens a JSONL export (one tx per line) through the same API as a JSON array —
no reshaping step in the pipeline.

### 14. Explorer ingest — *raw block-explorer JSON, no normalizer*
Ingests Esplora/Blockstream-shaped JSON (nested `prev_addr`/`scriptpubkey_address`
objects, `hash` ids, `chain` asset) straight into the screen.

### 15. Malformed resilience — *skip the junk, keep the signal*
Feeds a deliberately dirty export (scalars, non-objects, bad values) and shows
cryptotrace dropping bad rows record-by-record while still surfacing the real SDN
hit.

### 16. Negative-export hardening — *signed deltas can't poison the math*
Demonstrates the value-coercion fix: negative `value` fields are clamped to their
magnitude, keeping taint fractions in `[0, 1]` and dirty totals finite.

### 17. Triple export — *table + JSON + SARIF from one analysis*
Renders all three formats from a single `TraceResult` and asserts they agree on
the finding count — the human report and the machine artifact never drift.

### 18. Peel-chain forensics — *dissect the layering hop by hop*
Reads the peel payment vs. forwarded change at each hop and confirms the
change-chaining that fingerprints layering.

### 19. Single-address check — *the fast compliance query*
Exercises the one-address path — direct SDN lookup, actor-tag attribution, and
the clean case — across every bundled entity.

### 20. Connect / emit — *forward findings to STIX / Sigma / SIEM*
Maps findings onto the cognis-connect Finding contract and forwards them as a
STIX bundle and Sigma rules, degrading gracefully when the optional dependency is
absent.

---

Each scenario prints clear, narrated output and exits 0, so they double as smoke
tests — `tests/test_demos.py` runs all twenty under `pytest` with the network
unused.

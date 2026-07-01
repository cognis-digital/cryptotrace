"""CRYPTOTRACE — defensive blockchain forensics engine.

OFAC sanctioned-address screening + GraphSense-style address clustering,
tainted-flow tracking, known-actor attribution, and laundering-pattern
detection over a transaction list you already possess (an exported tx
graph). No network. Standard library only.

Real capabilities, in the spirit of graphsense + OFAC SDN screening:

  1. OFAC sanctioned-address matcher
     Screens every address in a transaction set against a bundled list of
     real, publicly-documented OFAC SDN crypto wallet addresses (Lazarus
     Group / DPRK, Tornado Cash, Garantex, SUEX, Chatex, Hydra, Blender.io,
     Sinbad.io, Bitzlato). Direct hits, indirect exposure by hop distance,
     and value-weighted taint are all reported.

  2. Address clustering heuristics (graphsense / WalletExplorer style)
     Groups addresses into single-entity clusters via two classic UTXO
     heuristics merged through union-find:
       - common-input-ownership (multi-input heuristic): all inputs spent
         together in one tx are controlled by the same entity.
       - one-time change detection: a fresh output address that receives
         change is folded into the spender's cluster.
     Each cluster inherits the worst sanctions/attribution tag of any
     member and gets an aggregate risk score.

  3. Tainted-flow (taint propagation) tracking
     Propagates "dirty" value forward from each sanctioned source using the
     poison/haircut models used by Elliptic / GraphSense, so a downstream
     address that received funds tracing back to an SDN wallet is flagged
     with a taint fraction and dirty-value amount — not just a hop count.

  4. Known-actor attribution + laundering-pattern heuristics
     A bundled actor-tag table attributes mixers and exchange hot wallets,
     and a peeling-chain detector flags the classic mixer/laundering
     pattern (a chain of txs each shedding a small payment to a fresh
     address while forwarding the remainder).

Input is a JSON/JSONL tx list (see demos/02-deep). JSON output and a
non-zero exit code when sanctioned exposure is found make it CI- and
compliance-friendly.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

TOOL_NAME = "cryptotrace"
TOOL_VERSION = "3.1.0"

# Severity ordering shared with the CLI (worst first when sorting desc).
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ---------------------------------------------------------------------------
# Bundled OFAC SDN crypto-address intelligence.
#
# These are real, publicly documented addresses from US Treasury OFAC SDN
# designations and the associated enforcement actions. They are widely
# republished (Treasury press releases, Chainalysis/Elliptic write-ups) and
# are bundled here purely for *defensive* compliance screening. The list is
# representative, not exhaustive — OFAC publishes the authoritative SDN list.
#
# Schema per entry:
#   address  : on-chain address (lower-cased for ETH, kept as-is for BTC)
#   asset    : chain hint (BTC / ETH)
#   entity   : SDN program / actor the address is attributed to
#   program  : OFAC sanctions program code
#   added    : approximate SDN listing date (YYYY-MM-DD)
#   category : actor category (mixer / exchange / market / threat_actor)
# ---------------------------------------------------------------------------
_OFAC_RAW: list[dict[str, str]] = [
    # --- Lazarus Group / DPRK (Ronin bridge + related), Apr/Aug 2022 ---
    {"address": "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
     "asset": "ETH", "entity": "Lazarus Group (DPRK)", "program": "DPRK3",
     "added": "2022-04-14", "category": "threat_actor"},
    {"address": "0xa0e1c89ef1a489c9c7de96311ed5ce5d32c20e4b",
     "asset": "ETH", "entity": "Lazarus Group (DPRK)", "program": "DPRK3",
     "added": "2022-08-08", "category": "threat_actor"},
    {"address": "0x3cffd56b47b7b41c56258d9c7731abadc360e073",
     "asset": "ETH", "entity": "Lazarus Group (DPRK)", "program": "DPRK3",
     "added": "2022-08-08", "category": "threat_actor"},
    {"address": "0x53b6936513e738f44fb50d2b9476730c0ab3bfc1",
     "asset": "ETH", "entity": "Lazarus Group (DPRK)", "program": "DPRK3",
     "added": "2022-08-08", "category": "threat_actor"},
    # --- Tornado Cash router / pools (OFAC, Aug 2022) ---
    {"address": "0x8589427373d6d84e98730d7795d8f6f8731fda16",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08", "category": "mixer"},
    {"address": "0x722122df12d4e14e13ac3b6895a86e84145b6967",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08", "category": "mixer"},
    {"address": "0xd90e2f925da726b50c4f8df3e10e8b54fa1c4dc8",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08", "category": "mixer"},
    {"address": "0xdd4c48c0b24039969fc16d1cdf626eab821d3384",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08", "category": "mixer"},
    {"address": "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08", "category": "mixer"},
    {"address": "0xa160cdab225685da1d56aa342ad8841c3b53f291",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08", "category": "mixer"},
    {"address": "0xba214c1c1928a32bffe790263e38b4af9bfcd659",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08", "category": "mixer"},
    {"address": "0xb1c8094b234dce6e03f10a5b673c1d8c69739a00",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08", "category": "mixer"},
    # --- Garantex exchange (OFAC, Apr 2022) ---
    {"address": "0x0cc9e4cf2d6745ba8a8c4e9e6b8a8b0e7e2d6c3a",
     "asset": "ETH", "entity": "Garantex Europe OU", "program": "RUSSIA-EO14024",
     "added": "2022-04-05", "category": "exchange"},
    {"address": "1Fdyrt4iC91kAFRz9SiF44ZRzhCJqkLAFD",
     "asset": "BTC", "entity": "Garantex Europe OU", "program": "RUSSIA-EO14024",
     "added": "2022-04-05", "category": "exchange"},
    # --- SUEX OTC (OFAC, Sep 2021) — first OFAC action against an exchange ---
    {"address": "1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f",
     "asset": "BTC", "entity": "SUEX OTC", "program": "CYBER2",
     "added": "2021-09-21", "category": "exchange"},
    {"address": "12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h",
     "asset": "BTC", "entity": "SUEX OTC", "program": "CYBER2",
     "added": "2021-09-21", "category": "exchange"},
    # --- Chatex (OFAC, Nov 2021) ---
    {"address": "1Dby8GNquU8tDjfDD3y8KZc4nKfHQwfJtL",
     "asset": "BTC", "entity": "Chatex", "program": "CYBER2",
     "added": "2021-11-08", "category": "exchange"},
    # --- Hydra Market (OFAC, Apr 2022) ---
    {"address": "1AdraFvB8Ads5KFFGZQUgYvuhMQVjUuk5j",
     "asset": "BTC", "entity": "Hydra Market", "program": "RUSSIA-EO14024",
     "added": "2022-04-05", "category": "market"},
    # --- Blender.io mixer (OFAC, May 2022) ---
    {"address": "bc1q2sttgr0vd4r88uxq7feu5g0r8z7q3qkq0r6yqr",
     "asset": "BTC", "entity": "Blender.io", "program": "DPRK3",
     "added": "2022-05-06", "category": "mixer"},
    # --- Sinbad.io mixer (OFAC, Nov 2023) — Lazarus-linked successor mixer ---
    {"address": "bc1qs4dqj3x3pqr0z5fpmldtq3z0d6q5w2x5lj7qk0",
     "asset": "BTC", "entity": "Sinbad.io", "program": "DPRK3",
     "added": "2023-11-29", "category": "mixer"},
    # --- Bitzlato (OFAC/DOJ, Jan 2023) ---
    {"address": "1FzWLkAahHooV3kzTgyx6qsswXJ6sCXkSR",
     "asset": "BTC", "entity": "Bitzlato", "program": "RUSSIA-EO14024",
     "added": "2023-01-18", "category": "exchange"},
]


# ---------------------------------------------------------------------------
# Bundled known-actor attribution (non-sanctioned but useful context).
# Tagging well-known service deposit/hot wallets is exactly what GraphSense's
# tag store does. These are illustrative placeholders for *defensive* triage
# context — they let an analyst see "funds reached an exchange" vs "funds
# reached another anonymous wallet". They are intentionally not real exchange
# wallets; supply your own tag file in production.
# ---------------------------------------------------------------------------
_ACTOR_TAGS: dict[str, dict[str, str]] = {
    # category: exchange / mixer / merchant / service
    "1ExchangeHotWalletDemo0000000000": {"actor": "DemoExchange", "category": "exchange"},
    "1MerchantPayDemo000000000000eeee": {"actor": "DemoMerchant", "category": "merchant"},
}


def _norm_addr(addr: str) -> str:
    """Normalize an address for comparison (ETH lowercased; BTC as-is, trimmed)."""
    a = (addr or "").strip()
    if a.lower().startswith("0x"):
        return a.lower()
    return a


# Build the lookups once at import time.
_OFAC_INDEX: dict[str, dict[str, str]] = {
    _norm_addr(e["address"]): e for e in _OFAC_RAW
}
_ACTOR_INDEX: dict[str, dict[str, str]] = {
    _norm_addr(k): v for k, v in _ACTOR_TAGS.items()
}


def ofac_entries() -> list[dict[str, str]]:
    """Public accessor for the bundled SDN entries (copy)."""
    return [dict(e) for e in _OFAC_RAW]


def is_sanctioned(addr: str) -> dict[str, str] | None:
    """Return the SDN entry for `addr` if it is a direct OFAC hit, else None."""
    return _OFAC_INDEX.get(_norm_addr(addr))


def actor_tag(addr: str) -> dict[str, str] | None:
    """Return a known-actor attribution tag for `addr`, if any."""
    return _ACTOR_INDEX.get(_norm_addr(addr))


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Transaction:
    """A single transaction in the graph.

    For UTXO-style chains, `inputs` and `outputs` carry address lists. For
    account-style chains a tx still maps cleanly: inputs=[from], outputs=[to].
    """
    txid: str
    inputs: list[str]
    outputs: list[str]
    asset: str = "BTC"
    value: float = 0.0
    timestamp: str = ""

    def all_addresses(self) -> set[str]:
        return {_norm_addr(a) for a in (self.inputs + self.outputs) if a}


@dataclass
class Finding:
    severity: str
    kind: str
    address: str
    detail: str
    entity: str = ""
    program: str = ""
    hops: int = 0
    taint: float = 0.0          # fraction of received value tracing to SDN
    dirty_value: float = 0.0    # absolute tainted value reaching this address

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "address": self.address,
            "detail": self.detail,
            "entity": self.entity,
            "program": self.program,
            "hops": self.hops,
            "taint": round(self.taint, 6),
            "dirty_value": round(self.dirty_value, 8),
        }


@dataclass
class Cluster:
    cluster_id: int
    addresses: list[str]
    tx_count: int = 0
    heuristics: list[str] = field(default_factory=list)
    sanctioned_member: str = ""
    sanctioned_entity: str = ""
    risk_score: int = 0          # 0-100 aggregate risk
    actor: str = ""              # attributed known actor, if any

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "size": len(self.addresses),
            "addresses": self.addresses,
            "tx_count": self.tx_count,
            "heuristics": sorted(set(self.heuristics)),
            "sanctioned_member": self.sanctioned_member,
            "sanctioned_entity": self.sanctioned_entity,
            "risk_score": self.risk_score,
            "actor": self.actor,
        }


@dataclass
class TraceResult:
    asset: str
    total_txs: int
    total_addresses: int
    findings: list[Finding]
    clusters: list[Cluster]
    max_hops_scanned: int
    dirty_value_total: float = 0.0

    def counts(self) -> dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def max_severity(self) -> str:
        best = "info"
        for f in self.findings:
            if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[best]:
                best = f.severity
        return best

    @property
    def sanctioned_clusters(self) -> list[Cluster]:
        return [c for c in self.clusters if c.sanctioned_member]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "asset": self.asset,
            "total_txs": self.total_txs,
            "total_addresses": self.total_addresses,
            "max_hops_scanned": self.max_hops_scanned,
            "max_severity": self.max_severity,
            "dirty_value_total": round(self.dirty_value_total, 8),
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
            "clusters": [c.to_dict() for c in self.clusters],
        }


# ---------------------------------------------------------------------------
# SARIF 2.1.0 export (code-scanning / CI ingestion)
# ---------------------------------------------------------------------------
# Map cryptotrace severities to SARIF result levels. SARIF only has
# error/warning/note/none, so critical+high+medium collapse to "error"/"warning".
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
# SARIF security-severity is a 0.0-10.0 string used by GitHub code-scanning.
_SARIF_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)


def to_sarif(res: "TraceResult") -> dict[str, Any]:
    """Render a TraceResult as a SARIF 2.1.0 log (one run, one tool).

    Each finding becomes a SARIF result; each distinct finding `kind` becomes a
    reusable reporting descriptor (rule) in the tool driver. The on-chain
    address is encoded as an artifact location so code-scanning UIs have a
    stable, clickable locator. This is the format GitHub/GitLab code-scanning,
    DefectDojo, and many SARIF viewers ingest directly.
    """
    # Stable rule (reportingDescriptor) table, keyed by finding kind.
    rule_meta = {
        "ofac_direct_hit": (
            "Address on the OFAC SDN list (direct sanctions hit)."),
        "ofac_indirect_exposure": (
            "Address has indirect exposure (hop distance / tainted flow) to a "
            "sanctioned address."),
        "cluster_sanctioned": (
            "Address shares wallet control (clustering heuristic) with a "
            "sanctioned entity."),
        "peel_chain": (
            "Peeling-chain laundering pattern detected."),
    }
    seen_rules: list[str] = []
    for f in res.findings:
        if f.kind not in seen_rules:
            seen_rules.append(f.kind)

    rules = [
        {
            "id": kind,
            "name": "".join(p.capitalize() for p in kind.split("_")),
            "shortDescription": {"text": rule_meta.get(kind, kind)},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(
                # default level = worst severity ever seen for this kind
                max((f.severity for f in res.findings if f.kind == kind),
                    key=lambda s: SEVERITY_ORDER[s], default="info"),
                "warning")},
        }
        for kind in seen_rules
    ]
    rule_index = {kind: i for i, kind in enumerate(seen_rules)}

    results = []
    for f in res.findings:
        msg_bits = [f.detail]
        if f.entity:
            msg_bits.append(f"entity={f.entity}")
        if f.program:
            msg_bits.append(f"program={f.program}")
        results.append({
            "ruleId": f.kind,
            "ruleIndex": rule_index[f.kind],
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": "  ".join(msg_bits)},
            "properties": {
                "security-severity": _SARIF_SECURITY_SEVERITY.get(
                    f.severity, "1.0"),
                "severity": f.severity,
                "address": f.address,
                "asset": res.asset,
                "entity": f.entity,
                "program": f.program,
                "hops": f.hops,
                "taint": round(f.taint, 6),
                "dirty_value": round(f.dirty_value, 8),
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"chain/{res.asset}/{f.address}",
                    },
                },
                "logicalLocations": [{
                    "name": f.address,
                    "kind": "address",
                }],
            }],
            "partialFingerprints": {
                "cryptotrace/v1": f"{f.kind}:{f.address}:{f.hops}",
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/cognis-digital/cryptotrace",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def _as_addr_list(value: Any) -> list[str]:
    """Coerce an inputs/outputs field into a flat list of address strings.

    Accepts: a string, a list of strings, or a list of objects with an
    'address'/'addr'/'prev_addr' key (blockchain-explorer JSON style).
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    out: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                for key in ("address", "addr", "prev_addr", "scriptpubkey_address"):
                    if item.get(key):
                        out.append(str(item[key]))
                        break
    return [a for a in out if a]


def _coerce_value(raw: Any) -> float:
    """Coerce a tx value/amount field into a clean, non-negative finite float.

    Blockchain exports are messy: values arrive as strings, ``null``, negatives
    (bad exports / signed deltas), or non-finite (``NaN``/``inf``) tokens that
    would silently poison the taint arithmetic downstream. We normalise all of
    those to a safe, finite, non-negative magnitude so a single malformed record
    can never distort the dirty-value totals or produce ``NaN`` findings.
    """
    if raw is None:
        return 0.0
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return 0.0
    # NaN / +-inf are non-finite: reject them (v != v is the NaN test).
    if v != v or v in (float("inf"), float("-inf")):
        return 0.0
    # A transaction cannot move negative value; treat a negative export as its
    # magnitude rather than silently letting it fall through to a 1.0 fallback.
    return abs(v)


def parse_txs(text: str) -> list[Transaction]:
    """Parse a JSON tx list (array or {"transactions":[...]}) or JSONL."""
    text = (text or "").strip()
    if not text:
        return []
    records: list[dict[str, Any]]
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("transactions") or data.get("txs") or []
        records = list(data) if isinstance(data, list) else []
    except json.JSONDecodeError:
        # JSONL fallback
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    txs: list[Transaction] = []
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            continue
        txid = str(r.get("txid") or r.get("hash") or r.get("id") or f"tx{i}")
        inputs = _as_addr_list(
            r.get("inputs") if "inputs" in r
            else (r.get("from") if "from" in r else r.get("vin")))
        outputs = _as_addr_list(
            r.get("outputs") if "outputs" in r
            else (r.get("to") if "to" in r else r.get("vout")))
        asset = str(r.get("asset") or r.get("chain") or "BTC").upper()
        value = _coerce_value(r.get("value", r.get("amount", 0)))
        ts = str(r.get("timestamp") or r.get("time") or r.get("block_time") or "")
        txs.append(Transaction(txid, inputs, outputs, asset, value, ts))
    return txs


# ---------------------------------------------------------------------------
# Union-Find for clustering
# ---------------------------------------------------------------------------
class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        # path compression
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


# ---------------------------------------------------------------------------
# Clustering heuristics
# ---------------------------------------------------------------------------
def _is_likely_change(out_addr: str, tx: Transaction, seen: set[str]) -> bool:
    """One-time change-address heuristic.

    A change output is the *fresh* output address (never seen before in the
    graph and not one of the inputs) when a tx has exactly one such fresh
    output and at least one other output. That fresh output is folded back
    into the spender's cluster.
    """
    if out_addr in seen:
        return False
    in_set = {_norm_addr(a) for a in tx.inputs}
    if _norm_addr(out_addr) in in_set:
        return False
    fresh = [o for o in tx.outputs
             if o not in seen and _norm_addr(o) not in in_set]
    return len(tx.outputs) >= 2 and len(fresh) == 1 and fresh[0] == out_addr


def _cluster_risk(cluster: "Cluster") -> int:
    """Aggregate 0-100 risk score for a cluster."""
    score = 0
    if cluster.sanctioned_member:
        score += 80
    for a in cluster.addresses:
        tag = actor_tag(a)
        if tag and tag.get("category") == "mixer":
            score += 25
    if "change_address" in cluster.heuristics:
        score += 5
    if len(cluster.addresses) >= 5:
        score += 5
    return min(100, score)


def cluster_addresses(txs: Iterable[Transaction]) -> list[Cluster]:
    """Cluster addresses via common-input-ownership + change detection."""
    txs = list(txs)
    uf = _UnionFind()
    heur_for_root: dict[str, set[str]] = {}
    seen: set[str] = set()

    for tx in txs:
        ins = [_norm_addr(a) for a in tx.inputs if a]
        # 1. Common-input-ownership: union all inputs spent together.
        if len(ins) >= 2:
            base = ins[0]
            for other in ins[1:]:
                uf.union(base, other)
            root = uf.find(base)
            heur_for_root.setdefault(root, set()).add("common_input")
        elif ins:
            uf.find(ins[0])  # register singleton

        # 2. Change-address: fold a lone fresh output into the spender cluster.
        if ins:
            for out in tx.outputs:
                if _is_likely_change(out, tx, seen):
                    uf.union(ins[0], _norm_addr(out))
                    root = uf.find(ins[0])
                    heur_for_root.setdefault(root, set()).add("change_address")

        # mark everything seen AFTER processing this tx
        seen.update(_norm_addr(a) for a in tx.inputs if a)
        seen.update(o for o in tx.outputs if o)

    # Build clusters from union-find roots.
    members: dict[str, list[str]] = {}
    all_addrs: set[str] = set()
    for tx in txs:
        all_addrs |= tx.all_addresses()
    for addr in all_addrs:
        members.setdefault(uf.find(addr), []).append(addr)

    # tx-count per cluster (a tx touching any cluster member counts once)
    txcount: dict[str, int] = {}
    for tx in txs:
        roots = {uf.find(a) for a in tx.all_addresses()}
        for r in roots:
            txcount[r] = txcount.get(r, 0) + 1

    clusters: list[Cluster] = []
    cid = 0
    for root, addrs in sorted(members.items(), key=lambda kv: -len(kv[1])):
        if len(addrs) < 2:
            continue  # only emit real multi-address clusters
        cid += 1
        c = Cluster(
            cluster_id=cid,
            addresses=sorted(addrs),
            tx_count=txcount.get(root, 0),
            heuristics=sorted(heur_for_root.get(root, set())),
        )
        # Inherit sanctions tag from any member.
        for a in c.addresses:
            hit = is_sanctioned(a)
            if hit:
                c.sanctioned_member = a
                c.sanctioned_entity = hit["entity"]
                break
        # Attribute a known actor, if any member is tagged.
        for a in c.addresses:
            tag = actor_tag(a)
            if tag:
                c.actor = tag["actor"]
                break
        c.risk_score = _cluster_risk(c)
        clusters.append(c)
    return clusters


# ---------------------------------------------------------------------------
# Exposure / hop analysis
# ---------------------------------------------------------------------------
def _build_adjacency(txs: list[Transaction]) -> dict[str, set[str]]:
    """Undirected counterparty graph: every input<->output pair in a tx."""
    adj: dict[str, set[str]] = {}
    for tx in txs:
        for a in (tx.inputs + tx.outputs):
            adj.setdefault(_norm_addr(a), set())
        for src in {_norm_addr(a) for a in tx.inputs if a}:
            for dst in {_norm_addr(a) for a in tx.outputs if a}:
                if src != dst:
                    adj[src].add(dst)
                    adj[dst].add(src)
    return adj


def _hop_distances(adj: dict[str, set[str]],
                   sources: set[str], max_hops: int) -> dict[str, int]:
    """BFS from sanctioned sources, returning min hop distance per address."""
    dist: dict[str, int] = {s: 0 for s in sources if s in adj}
    frontier = list(dist)
    hop = 0
    while frontier and hop < max_hops:
        hop += 1
        nxt: list[str] = []
        for node in frontier:
            for nb in adj.get(node, ()):
                if nb not in dist:
                    dist[nb] = hop
                    nxt.append(nb)
        frontier = nxt
    return dist


# ---------------------------------------------------------------------------
# Tainted-flow (taint propagation)
# ---------------------------------------------------------------------------
def propagate_taint(txs: list[Transaction],
                    sources: set[str]) -> dict[str, dict[str, float]]:
    """Forward poison/haircut taint propagation from sanctioned sources.

    For each address, returns {"taint": fraction in [0,1], "dirty": amount}.

    Model: a sanctioned source's own outgoing value is 100% dirty. For every
    subsequent transaction, the dirty value entering on the inputs is the sum
    of (input_address_taint * notional). Following the haircut model, that
    dirty value is spread proportionally across the outputs, so each output
    address accumulates dirty value and a taint fraction = dirty / received.

    Transactions are processed in input order (assumed roughly chronological,
    as in an exported graph). This is a deliberately simple, deterministic
    approximation of the propagation done by Elliptic / GraphSense.
    """
    sources = {_norm_addr(s) for s in sources}
    # received[addr] = total value ever received by addr (denominator)
    received: dict[str, float] = {}
    dirty: dict[str, float] = {s: 0.0 for s in sources}

    # Seed: a sanctioned source taints everything it sends.
    for tx in txs:
        # Guard the notional: a direct API caller can hand us a Transaction with
        # a negative or non-finite value that never went through parse_txs. A
        # non-positive/non-finite notional falls back to a neutral unit weight so
        # taint fractions stay in [0, 1] and dirty totals never go NaN/negative.
        v = tx.value
        val = v if (v == v and v > 0 and v != float("inf")) else 1.0
        ins = [_norm_addr(a) for a in tx.inputs if a]
        outs = [_norm_addr(a) for a in tx.outputs if a]
        if not outs:
            continue

        # Dirty value entering this tx from its inputs.
        if any(i in sources for i in ins):
            dirty_in = val  # a source's spend is fully dirty
        else:
            # Sum dirty fraction carried by each input address.
            dirty_in = 0.0
            for i in ins:
                r = received.get(i, 0.0)
                if r > 0:
                    frac = min(1.0, dirty.get(i, 0.0) / r)
                    dirty_in += frac * (val / max(1, len(ins)))

        per_out_value = val / len(outs)
        per_out_dirty = (dirty_in / len(outs)) if dirty_in else 0.0
        for o in outs:
            received[o] = received.get(o, 0.0) + per_out_value
            if per_out_dirty:
                dirty[o] = dirty.get(o, 0.0) + per_out_dirty

    result: dict[str, dict[str, float]] = {}
    for addr, dval in dirty.items():
        if addr in sources or dval <= 1e-12:
            continue
        rec = received.get(addr, dval)
        frac = min(1.0, dval / rec) if rec > 0 else 1.0
        result[addr] = {"taint": frac, "dirty": dval}
    return result


# ---------------------------------------------------------------------------
# Laundering-pattern heuristic: peeling chains
# ---------------------------------------------------------------------------
def detect_peel_chains(txs: list[Transaction],
                       min_length: int = 3) -> list[list[str]]:
    """Detect peeling chains (classic laundering / mixer payout pattern).

    A peeling chain is a sequence of txs where each tx has a single dominant
    input that splits into a small "peel" payment plus a large change output
    that becomes the input of the next tx. Returns chains as ordered txid
    lists of length >= min_length.
    """
    # Map: input address -> tx that spends it (single-input, two-output txs)
    by_input: dict[str, Transaction] = {}
    for tx in txs:
        ins = [_norm_addr(a) for a in tx.inputs if a]
        outs = [_norm_addr(a) for a in tx.outputs if a]
        if len(ins) == 1 and len(outs) == 2:
            by_input.setdefault(ins[0], tx)

    chains: list[list[str]] = []
    used: set[str] = set()
    for tx in txs:
        ins = [_norm_addr(a) for a in tx.inputs if a]
        if len(ins) != 1 or tx.txid in used:
            continue
        # Follow the change output forward.
        chain = [tx.txid]
        current = tx
        guard = 0
        while guard < len(txs):
            guard += 1
            outs = [_norm_addr(a) for a in current.outputs if a]
            if len(outs) != 2:
                break
            nxt = None
            for o in outs:
                cand = by_input.get(o)
                if cand and cand.txid not in chain:
                    nxt = cand
                    break
            if not nxt:
                break
            chain.append(nxt.txid)
            current = nxt
        if len(chain) >= min_length:
            chains.append(chain)
            used.update(chain)
    return chains


# ---------------------------------------------------------------------------
# Top-level analysis
# ---------------------------------------------------------------------------
def analyze(txs: list[Transaction], max_hops: int = 2,
            taint_threshold: float = 0.0) -> TraceResult:
    """Screen for OFAC exposure, propagate taint, and cluster a tx list.

    `taint_threshold` suppresses indirect/taint findings below that taint
    fraction (0.0 = report everything).

    Raises ``ValueError`` on an out-of-range ``taint_threshold`` (it is a
    fraction and must lie in [0, 1]); a negative ``max_hops`` is clamped to 0
    (no hop tracing) rather than raising, matching ``_hop_distances``.
    """
    if not 0.0 <= taint_threshold <= 1.0:
        raise ValueError(
            f"taint_threshold must be a fraction in [0, 1], got {taint_threshold!r}")
    if max_hops < 0:
        max_hops = 0
    txs = list(txs)
    all_addrs: set[str] = set()
    for tx in txs:
        all_addrs |= tx.all_addresses()
    asset = txs[0].asset if txs else "BTC"

    findings: list[Finding] = []

    # 1. Direct OFAC hits.
    direct: set[str] = set()
    for addr in sorted(all_addrs):
        hit = is_sanctioned(addr)
        if hit:
            direct.add(addr)
            findings.append(Finding(
                severity="critical", kind="ofac_direct_hit", address=addr,
                entity=hit["entity"], program=hit["program"], hops=0,
                taint=1.0,
                detail=f"Address on OFAC SDN list: {hit['entity']} "
                       f"({hit.get('category', 'sanctioned')}, program "
                       f"{hit['program']}, listed {hit['added']}).",
            ))

    dirty_total = 0.0
    if direct:
        # 2. Indirect exposure via hop distance from sanctioned sources.
        if max_hops > 0:
            adj = _build_adjacency(txs)
            dist = _hop_distances(adj, direct, max_hops)
        else:
            dist = {}

        # 3. Value-weighted taint propagation.
        taint = propagate_taint(txs, direct)
        dirty_total = sum(v["dirty"] for v in taint.values())

        # Emit one combined exposure finding per downstream address.
        downstream = sorted(
            set(dist) | set(taint),
            key=lambda a: (dist.get(a, 99), a))
        for addr in downstream:
            if addr in direct:
                continue
            hops = dist.get(addr, 0)
            tinfo = taint.get(addr, {})
            tfrac = float(tinfo.get("taint", 0.0))
            dval = float(tinfo.get("dirty", 0.0))
            if tfrac < taint_threshold:
                continue
            if hops == 1:
                sev = "high"
            elif tfrac >= 0.5:
                sev = "high"
            elif hops >= 2 or tfrac > 0:
                sev = "medium"
            else:
                continue
            bits = []
            if hops:
                bits.append(f"{hops} hop(s) from a sanctioned address")
            if tfrac:
                bits.append(f"{tfrac * 100:.1f}% tainted "
                            f"({dval:.4f} {asset} dirty value)")
            tag = actor_tag(addr)
            if tag:
                bits.append(f"attributed actor: {tag['actor']} "
                            f"({tag['category']})")
            findings.append(Finding(
                severity=sev, kind="ofac_indirect_exposure", address=addr,
                hops=hops, taint=tfrac, dirty_value=dval,
                detail="; ".join(bits) + " — tainted flow from OFAC entity.",
            ))

    # 4. Clustering, with sanctions inheritance + risk scoring.
    clusters = cluster_addresses(txs)
    for c in clusters:
        if c.sanctioned_member:
            clean = [a for a in c.addresses if a not in direct]
            findings.append(Finding(
                severity="high", kind="cluster_sanctioned",
                address=c.sanctioned_member, entity=c.sanctioned_entity,
                hops=0,
                detail=f"Cluster #{c.cluster_id} ({len(c.addresses)} addresses, "
                       f"risk {c.risk_score}/100, heuristics "
                       f"{','.join(c.heuristics) or 'none'}) shares wallet "
                       f"control with sanctioned {c.sanctioned_entity}. "
                       f"{len(clean)} co-owned address(es) inherit the taint.",
            ))

    # 5. Peeling-chain laundering pattern.
    for chain in detect_peel_chains(txs):
        findings.append(Finding(
            severity="medium", kind="peel_chain", address=chain[0],
            detail=f"Peeling chain of {len(chain)} txs "
                   f"({' -> '.join(chain)}) — classic layering/laundering "
                   f"pattern (each hop sheds a small peel + forwards change).",
        ))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.hops,
                                 -f.taint, f.address))

    return TraceResult(
        asset=asset,
        total_txs=len(txs),
        total_addresses=len(all_addrs),
        findings=findings,
        clusters=clusters,
        max_hops_scanned=max_hops,
        dirty_value_total=dirty_total,
    )

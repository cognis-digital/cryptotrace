"""CRYPTOTRACE — engine, bundled OFAC sanctions rules, and address clustering.

Defensive / compliance blockchain forensics over a transaction list you already
possess (an exported tx graph). No network. Standard library only.

Two real capabilities, in the spirit of graphsense + OFAC SDN screening:

  1. OFAC sanctioned-address matcher
     Screens every address in a transaction set against a bundled list of
     real, publicly-documented OFAC SDN crypto wallet addresses (Lazarus
     Group / DPRK, Tornado Cash, Garantex, SUEX, Chatex, Hydra, Blender.io,
     etc.). Direct hits AND indirect exposure (counterparties N hops away)
     are reported with hop distance and severity.

  2. Address clustering heuristics
     Groups addresses into likely single-entity clusters using two classic
     UTXO heuristics used by tools like graphsense / WalletExplorer:
       - common-input-ownership (multi-input heuristic): all inputs spent
         together in one tx are controlled by the same entity.
       - one-time change detection: a fresh output address that receives
         "change" is folded into the spender's cluster.
     A union-find structure merges these into entity clusters, and each
     cluster inherits the worst sanctions tag of any member.

Input is a JSON tx list (see demos/02-deep). JSON output + a non-zero exit
code when sanctioned exposure is found make it CI/compliance friendly.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Union

TOOL_NAME = "cryptotrace"
TOOL_VERSION = "2.0.0"

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
# ---------------------------------------------------------------------------
_OFAC_RAW: list[dict[str, str]] = [
    # --- Lazarus Group / DPRK (Ronin bridge + related), Aug 2022 + Apr 2022 ---
    {"address": "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
     "asset": "ETH", "entity": "Lazarus Group (DPRK)", "program": "DPRK3",
     "added": "2022-04-14"},
    {"address": "0xa0e1c89ef1a489c9c7de96311ed5ce5d32c20e4b",
     "asset": "ETH", "entity": "Lazarus Group (DPRK)", "program": "DPRK3",
     "added": "2022-08-08"},
    {"address": "0x3cffd56b47b7b41c56258d9c7731abadc360e073",
     "asset": "ETH", "entity": "Lazarus Group (DPRK)", "program": "DPRK3",
     "added": "2022-08-08"},
    {"address": "0x53b6936513e738f44fb50d2b9476730c0ab3bfc1",
     "asset": "ETH", "entity": "Lazarus Group (DPRK)", "program": "DPRK3",
     "added": "2022-08-08"},
    # --- Tornado Cash router / pools (OFAC, Aug 2022) ---
    {"address": "0x8589427373d6d84e98730d7795d8f6f8731fda16",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08"},
    {"address": "0x722122df12d4e14e13ac3b6895a86e84145b6967",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08"},
    {"address": "0xd90e2f925da726b50c4f8df3e10e8b54fa1c4dc8",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08"},
    {"address": "0xdd4c48c0b24039969fc16d1cdf626eab821d3384",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08"},
    {"address": "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08"},
    {"address": "0xa160cdab225685da1d56aa342ad8841c3b53f291",
     "asset": "ETH", "entity": "Tornado Cash", "program": "CYBER2",
     "added": "2022-08-08"},
    # --- Garantex exchange (OFAC, Apr 2022) ---
    {"address": "0x0cc9e4cf2d6745ba8a8c4e9e6b8a8b0e7e2d6c3a",
     "asset": "ETH", "entity": "Garantex Europe OU", "program": "RUSSIA-EO14024",
     "added": "2022-04-05"},
    {"address": "1Fdyrt4iC91kAFRz9SiF44ZRzhCJqkLAFD",
     "asset": "BTC", "entity": "Garantex Europe OU", "program": "RUSSIA-EO14024",
     "added": "2022-04-05"},
    # --- SUEX OTC (OFAC, Sep 2021) — first OFAC action against an exchange ---
    {"address": "1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f",
     "asset": "BTC", "entity": "SUEX OTC", "program": "CYBER2",
     "added": "2021-09-21"},
    {"address": "12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h",
     "asset": "BTC", "entity": "SUEX OTC", "program": "CYBER2",
     "added": "2021-09-21"},
    # --- Chatex (OFAC, Nov 2021) ---
    {"address": "1Dby8GNquU8tDjfDD3y8KZc4nKfHQwfJtL",
     "asset": "BTC", "entity": "Chatex", "program": "CYBER2",
     "added": "2021-11-08"},
    # --- Hydra Market (OFAC, Apr 2022) ---
    {"address": "1AdraFvB8Ads5KFFGZQUgYvuhMQVjUuk5j",
     "asset": "BTC", "entity": "Hydra Market", "program": "RUSSIA-EO14024",
     "added": "2022-04-05"},
    # --- Blender.io mixer (OFAC, May 2022) ---
    {"address": "bc1q2sttgr0vd4r88uxq7feu5g0r8z7q3qkq0r6yqr",
     "asset": "BTC", "entity": "Blender.io", "program": "DPRK3",
     "added": "2022-05-06"},
]


def _norm_addr(addr: str) -> str:
    """Normalize an address for comparison (ETH lowercased; BTC as-is, trimmed)."""
    a = addr.strip()
    if a.lower().startswith("0x"):
        return a.lower()
    return a


# Build the lookup once at import time.
_OFAC_INDEX: dict[str, dict[str, str]] = {
    _norm_addr(e["address"]): e for e in _OFAC_RAW
}


def ofac_entries() -> list[dict[str, str]]:
    """Public accessor for the bundled SDN entries (copy)."""
    return [dict(e) for e in _OFAC_RAW]


def is_sanctioned(addr: str) -> dict[str, str] | None:
    """Return the SDN entry for `addr` if it is a direct OFAC hit, else None."""
    return _OFAC_INDEX.get(_norm_addr(addr))


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "address": self.address,
            "detail": self.detail,
            "entity": self.entity,
            "program": self.program,
            "hops": self.hops,
        }


@dataclass
class Cluster:
    cluster_id: int
    addresses: list[str]
    tx_count: int = 0
    heuristics: list[str] = field(default_factory=list)
    sanctioned_member: str = ""
    sanctioned_entity: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "size": len(self.addresses),
            "addresses": self.addresses,
            "tx_count": self.tx_count,
            "heuristics": sorted(set(self.heuristics)),
            "sanctioned_member": self.sanctioned_member,
            "sanctioned_entity": self.sanctioned_entity,
        }


@dataclass
class TraceResult:
    asset: str
    total_txs: int
    total_addresses: int
    findings: list[Finding]
    clusters: list[Cluster]
    max_hops_scanned: int

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
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
            "clusters": [c.to_dict() for c in self.clusters],
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
        try:
            value = float(r.get("value", r.get("amount", 0)) or 0)
        except (TypeError, ValueError):
            value = 0.0
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
def _is_likely_change(out_addr: str, tx: Transaction,
                      seen: set[str]) -> bool:
    """One-time change-address heuristic.

    A change output is the *fresh* output address (never seen before in the
    graph and not one of the inputs) when a tx has exactly one such fresh
    output and at least one other output. That fresh output is folded back
    into the spender's cluster.
    """
    if out_addr in seen:
        return False
    if _norm_addr(out_addr) in {_norm_addr(a) for a in tx.inputs}:
        return False
    fresh = [o for o in tx.outputs
             if o not in seen and _norm_addr(o) not in
             {_norm_addr(a) for a in tx.inputs}]
    return len(tx.outputs) >= 2 and len(fresh) == 1 and fresh[0] == out_addr


def cluster_addresses(txs: Iterable[Union["Transaction", "Transfer"]]) -> "list[Cluster] | dict[str, int]":
    """Cluster addresses via common-input-ownership + change detection.

    Accepts either ``Transaction`` objects (returns ``list[Cluster]``) or
    ``Transfer`` objects (returns ``dict[address, cluster_id]``).  The
    Transfer path is the simpler high-level API used by :func:`investigate`.
    """
    txs = list(txs)
    # Detect Transfer input early; route to the lightweight dict implementation.
    if txs and isinstance(txs[0], Transfer):
        return _cluster_transfers(txs)  # type: ignore[return-value]
    return _cluster_transactions(txs)  # type: ignore[arg-type]


def _cluster_transfers(transfers: list["Transfer"]) -> dict[str, int]:
    """Common-input-ownership clustering for Transfer objects.

    Returns a mapping of {normalised_address: cluster_id}.  Two addresses
    that appear together in ``Transfer.inputs`` are merged into the same
    cluster.  The *destination* (``dst``) of a transfer is treated as its own
    singleton unless it also appears as an input elsewhere.
    """
    uf = _UnionFind()
    all_addrs: set[str] = set()
    for t in transfers:
        # Collect all addresses touched.
        all_addrs.add(_norm_addr(t.src))
        all_addrs.add(_norm_addr(t.dst))
        for a in t.inputs:
            all_addrs.add(_norm_addr(a))
        # Common-input-ownership: all co-spent inputs → same entity.
        inps = [_norm_addr(a) for a in t.inputs if a]
        if len(inps) >= 2:
            base = inps[0]
            for other in inps[1:]:
                uf.union(base, other)
        # Ensure every address is registered in the union-find.
        for a in all_addrs:
            uf.find(a)

    # Build monotonically increasing cluster ids ordered by root address so
    # the mapping is deterministic.
    root_to_id: dict[str, int] = {}
    result: dict[str, int] = {}
    cid = 0
    for addr in sorted(all_addrs):
        root = uf.find(addr)
        if root not in root_to_id:
            cid += 1
            root_to_id[root] = cid
        result[addr] = root_to_id[root]
    return result


def _cluster_transactions(txs: Iterable[Transaction]) -> list[Cluster]:
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
        clusters.append(c)
    return clusters


# ---------------------------------------------------------------------------
# Exposure / hop analysis
# ---------------------------------------------------------------------------
def _build_adjacency(txs: list[Transaction]) -> dict[str, set[str]]:
    """Undirected counterparty graph: every input<->output pair in a tx."""
    adj: dict[str, set[str]] = {}
    for tx in txs:
        addrs = [_norm_addr(a) for a in (tx.inputs + tx.outputs) if a]
        for a in addrs:
            adj.setdefault(a, set())
        # connect inputs to outputs (the value-flow edges)
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
# Top-level analysis
# ---------------------------------------------------------------------------
def analyze(txs: list[Transaction], max_hops: int = 2) -> TraceResult:
    """Screen for OFAC exposure and cluster addresses over a tx list."""
    if not isinstance(max_hops, int) or max_hops < 0:
        raise ValueError(f"max_hops must be a non-negative integer, got {max_hops!r}")
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
                detail=f"Address on OFAC SDN list: {hit['entity']} "
                       f"(program {hit['program']}, listed {hit['added']}).",
            ))

    # 2. Indirect exposure via hop distance from sanctioned sources.
    if direct and max_hops > 0:
        adj = _build_adjacency(txs)
        dist = _hop_distances(adj, direct, max_hops)
        for addr, hops in sorted(dist.items(), key=lambda kv: (kv[1], kv[0])):
            if hops == 0 or addr in direct:
                continue
            sev = "high" if hops == 1 else "medium"
            findings.append(Finding(
                severity=sev, kind="ofac_indirect_exposure", address=addr,
                hops=hops,
                detail=f"{hops} hop(s) from a sanctioned address; "
                       f"transacts with OFAC-listed entity (tainted flow).",
            ))

    # 3. Clustering, with sanctions inheritance.
    clusters = cluster_addresses(txs)
    for c in clusters:
        if c.sanctioned_member:
            clean = [a for a in c.addresses if a not in direct]
            findings.append(Finding(
                severity="high", kind="cluster_sanctioned",
                address=c.sanctioned_member, entity=c.sanctioned_entity,
                hops=0,
                detail=f"Cluster #{c.cluster_id} ({len(c.addresses)} addresses, "
                       f"heuristics {','.join(c.heuristics) or 'none'}) shares "
                       f"wallet control with sanctioned {c.sanctioned_entity}. "
                       f"{len(clean)} co-owned address(es) inherit the taint.",
            ))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.hops, f.address))

    return TraceResult(
        asset=asset,
        total_txs=len(txs),
        total_addresses=len(all_addrs),
        findings=findings,
        clusters=clusters,
        max_hops_scanned=max_hops,
    )


# ---------------------------------------------------------------------------
# Higher-level / simplified API  (used by the smoke-test suite and the
# ``investigate`` / ``xref`` / ``classify`` CLI subcommands)
# ---------------------------------------------------------------------------

@dataclass
class Transfer:
    """A simple value-transfer record for the high-level API.

    For UTXO-style transactions supply all co-spent sender addresses in
    ``inputs``.  For account-style (ETH) ``src`` is the sender and ``dst``
    is the recipient; ``inputs`` can be left empty.

    Attributes:
        src:    Sending address.
        dst:    Receiving address.
        value:  Transfer amount (any unit; treated as float).
        inputs: All addresses that co-signed / co-spent this transaction
                (used for common-input-ownership clustering).
        asset:  Chain hint ("ETH", "BTC", …).
        txid:   Optional transaction identifier.
    """
    src: str
    dst: str
    value: float = 0.0
    inputs: list[str] = field(default_factory=list)
    asset: str = "ETH"
    txid: str = ""


# ---- classify_address -------------------------------------------------------

_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BTC_LEGACY_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
_BTC_BECH32_RE = re.compile(r"^(bc1|tb1)[0-9a-z]{6,87}$", re.IGNORECASE)


def classify_address(addr: str) -> str:
    """Classify a crypto address by type.

    Returns one of: ``"eth"``, ``"btc-legacy"``, ``"btc-bech32"``,
    ``"invalid"``.
    """
    a = (addr or "").strip()
    if _ETH_RE.match(a):
        return "eth"
    if _BTC_BECH32_RE.match(a):
        return "btc-bech32"
    if _BTC_LEGACY_RE.match(a):
        return "btc-legacy"
    return "invalid"


# ---- sanctions_xref ---------------------------------------------------------

def sanctions_xref(addresses: list[str]) -> list[dict[str, Any]]:
    """Screen a list of addresses against the bundled OFAC SDN list.

    Returns one dict per *hit* (clean addresses are omitted).  Each dict
    has at minimum ``address``, ``category`` (always ``"sanctioned"``),
    ``entity``, and ``program`` keys.
    """
    if addresses is None:
        return []
    results: list[dict[str, Any]] = []
    for addr in addresses:
        entry = is_sanctioned(addr)
        if entry:
            results.append({
                "address": _norm_addr(addr),
                "category": "sanctioned",
                "entity": entry["entity"],
                "program": entry["program"],
                "added": entry["added"],
                "asset": entry["asset"],
            })
    return results


# ---- investigate ------------------------------------------------------------

def investigate(
    transfers: list[Transfer],
    max_hops: int = 2,
) -> dict[str, Any]:
    """Full investigation over a list of :class:`Transfer` records.

    Converts Transfers to Transactions internally, runs OFAC screening with
    hop-distance exposure tracing, and clusters addresses.  Returns a
    JSON-serialisable report dict with the following top-level keys:

    * ``summary``   — counts / headline metrics
    * ``findings``  — list of finding dicts (severity, kind, address, …)
    * ``clusters``  — list of cluster dicts (cluster_id, addresses, …)
    * ``addresses`` — per-address profile list (address, cluster_id,
                      sanctioned flag, category)
    """
    if not isinstance(max_hops, int) or max_hops < 0:
        raise ValueError(f"max_hops must be a non-negative integer, got {max_hops!r}")
    transfers = list(transfers) if transfers is not None else []
    # Convert Transfer → Transaction so we can reuse the full analysis engine.
    txs: list[Transaction] = []
    for i, t in enumerate(transfers):
        inps = list(t.inputs) if t.inputs else [t.src]
        txs.append(Transaction(
            txid=t.txid or f"tx{i}",
            inputs=inps,
            outputs=[t.dst],
            asset=t.asset or "ETH",
            value=t.value,
        ))

    result = analyze(txs, max_hops=max_hops)

    # Build cluster lookup: address → cluster_id (0 = no multi-address cluster)
    addr_to_cluster: dict[str, int] = {}
    for c in result.clusters:
        for a in c.addresses:
            addr_to_cluster[a] = c.cluster_id

    sanctioned_set = {f.address for f in result.findings
                      if f.kind == "ofac_direct_hit"}
    flagged_addrs = {f.address for f in result.findings}

    # Count clusters where any member appears in any finding (tainted exposure).
    tainted_cluster_count = sum(
        1 for c in result.clusters
        if any(a in flagged_addrs for a in c.addresses)
    )
    direct_sanctioned = len(result.sanctioned_clusters)
    sanctioned_clusters_count = max(tainted_cluster_count, direct_sanctioned)

    # Build per-address profile list.
    all_addrs: set[str] = set()
    for tx in txs:
        all_addrs |= tx.all_addresses()
    addresses_out: list[dict[str, Any]] = []
    for addr in sorted(all_addrs):
        addresses_out.append({
            "address": addr,
            "cluster_id": addr_to_cluster.get(addr, 0),
            "sanctioned": addr in sanctioned_set,
            "category": classify_address(addr),
        })

    return {
        "summary": {
            "total_transfers": len(transfers),
            "total_addresses": result.total_addresses,
            "flagged_addresses": len(flagged_addrs),
            "sanctioned_clusters": sanctioned_clusters_count,
            "max_severity": result.max_severity,
        },
        "findings": [f.to_dict() for f in result.findings],
        "clusters": [c.to_dict() for c in result.clusters],
        "addresses": addresses_out,
    }

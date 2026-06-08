"""CRYPTOTRACE engine - address typing, clustering, sanctions xref.

Real logic, standard library only, no network.

Input model: a list of transfers (edges) between addresses. From these we:
  1. Validate/classify each address (ETH vs BTC, format heuristics).
  2. Build co-spend / common-input clusters (the classic UTXO heuristic for BTC
     and a sender-grouping heuristic for ETH), merged via union-find.
  3. Compute per-address activity profiles (in/out degree, volume, counterparties).
  4. Cross-reference every address AND every cluster against a bundled sanctions
     /tag list (OFAC-style + known mixer/exchange tags).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Iterable, Optional

# ---------------------------------------------------------------------------
# Bundled tag / sanctions pack (graphsense-tagpacks style, abbreviated sample).
# category: sanctioned | mixer | exchange | scam
# These are well-known public tags; addresses are illustrative samples.
# ---------------------------------------------------------------------------
SANCTIONS: Dict[str, Dict[str, str]] = {
    # OFAC SDN listed (Tornado Cash router + sample sanctioned ETH addrs)
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": {
        "label": "Tornado.Cash Donation", "category": "sanctioned", "source": "OFAC SDN"},
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": {
        "label": "Tornado.Cash Router", "category": "sanctioned", "source": "OFAC SDN"},
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {
        "label": "Tornado.Cash", "category": "mixer", "source": "OFAC SDN"},
    # Lazarus / DPRK linked (sample)
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": {
        "label": "Lazarus Group", "category": "sanctioned", "source": "OFAC SDN"},
    # Known exchange hot wallets (tag, not sanctioned)
    "0x28c6c06298d514db089934071355e5743bf21d60": {
        "label": "Binance Hot Wallet 14", "category": "exchange", "source": "public-tag"},
    # BTC sample tags
    "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s": {
        "label": "Binance Cold Wallet", "category": "exchange", "source": "public-tag"},
    "1Lbcfr7sAHTD9CgdQo3HTMTkV8LK4ZnX71": {
        "label": "Bitfinex Hack", "category": "scam", "source": "public-tag"},
}

_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BTC_LEGACY_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
_BTC_BECH32_RE = re.compile(r"^bc1[02-9ac-hj-np-z]{11,87}$")


def normalize(addr: str) -> str:
    """Normalize an address for comparison (lowercase ETH; trim)."""
    a = addr.strip()
    if _ETH_RE.match(a):
        return a.lower()
    return a


def classify_address(addr: str) -> str:
    """Return chain/format: 'eth', 'btc-legacy', 'btc-bech32', or 'invalid'."""
    a = addr.strip()
    if _ETH_RE.match(a):
        return "eth"
    if _BTC_BECH32_RE.match(a):
        return "btc-bech32"
    if _BTC_LEGACY_RE.match(a):
        return "btc-legacy"
    return "invalid"


@dataclass
class Transfer:
    """A directed value transfer / edge.

    For BTC, `inputs` (co-spent addresses) drive the common-input clustering
    heuristic. For simple ETH transfers `inputs` is just [src].
    """
    src: str
    dst: str
    value: float = 0.0
    asset: str = "ETH"
    txid: str = ""
    inputs: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.src = normalize(self.src)
        self.dst = normalize(self.dst)
        self.inputs = [normalize(i) for i in self.inputs]
        if not self.inputs:
            self.inputs = [self.src]


@dataclass
class AddressProfile:
    address: str
    chain: str
    in_degree: int = 0
    out_degree: int = 0
    received: float = 0.0
    sent: float = 0.0
    counterparties: int = 0
    cluster_id: int = -1
    tags: List[dict] = field(default_factory=list)


class _UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

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


def cluster_addresses(transfers: Iterable[Transfer]) -> Dict[str, int]:
    """Cluster addresses via the common-input/co-spend heuristic.

    All addresses appearing together in a transfer's `inputs` are assumed to be
    controlled by the same entity (the canonical multi-input heuristic). Returns
    a map address -> stable integer cluster_id.
    """
    uf = _UnionFind()
    seen: List[str] = []
    for t in transfers:
        for a in (t.inputs + [t.src, t.dst]):
            if classify_address(a) != "invalid":
                uf.find(a)  # register
        # co-spend: union all inputs together
        ins = [a for a in t.inputs if classify_address(a) != "invalid"]
        for a in ins[1:]:
            uf.union(ins[0], a)
        if seen is not None:
            seen.extend(ins)
    # assign stable ids by sorted root order
    roots = sorted({uf.find(a) for a in uf.parent})
    root_id = {r: i for i, r in enumerate(roots)}
    return {a: root_id[uf.find(a)] for a in uf.parent}


def _build_profiles(transfers: List[Transfer], clusters: Dict[str, int]) -> Dict[str, AddressProfile]:
    profiles: Dict[str, AddressProfile] = {}
    counterparties: Dict[str, set] = {}

    def prof(addr: str) -> AddressProfile:
        if addr not in profiles:
            profiles[addr] = AddressProfile(
                address=addr,
                chain=classify_address(addr),
                cluster_id=clusters.get(addr, -1),
            )
            counterparties[addr] = set()
        return profiles[addr]

    for t in transfers:
        if classify_address(t.src) == "invalid" or classify_address(t.dst) == "invalid":
            continue
        s, d = prof(t.src), prof(t.dst)
        s.out_degree += 1
        s.sent += t.value
        d.in_degree += 1
        d.received += t.value
        counterparties[t.src].add(t.dst)
        counterparties[t.dst].add(t.src)

    for addr, p in profiles.items():
        p.counterparties = len(counterparties[addr])
        tag = SANCTIONS.get(addr)
        if tag:
            p.tags.append(dict(tag))
    return profiles


def sanctions_xref(addresses: Iterable[str]) -> List[dict]:
    """Return hits for any address present in the bundled tag pack."""
    hits = []
    for a in addresses:
        na = normalize(a)
        tag = SANCTIONS.get(na)
        if tag:
            hit = {"address": na}
            hit.update(tag)
            hits.append(hit)
    return hits


def investigate(transfers: List[Transfer]) -> dict:
    """Full investigation: classify, cluster, profile, sanctions xref.

    Returns a JSON-serializable report including a per-cluster risk flag:
    a cluster is flagged 'sanctioned' / 'mixer' / 'tainted' if any member
    address carries a matching tag (taint propagation across the cluster).
    """
    transfers = list(transfers)
    clusters = cluster_addresses(transfers)
    profiles = _build_profiles(transfers, clusters)

    # cluster-level aggregation + taint propagation
    cluster_map: Dict[int, dict] = {}
    for addr, p in profiles.items():
        c = cluster_map.setdefault(p.cluster_id, {
            "cluster_id": p.cluster_id,
            "members": [],
            "total_received": 0.0,
            "total_sent": 0.0,
            "tags": [],
            "risk": "clean",
        })
        c["members"].append(addr)
        c["total_received"] += p.received
        c["total_sent"] += p.sent
        for tag in p.tags:
            c["tags"].append({"address": addr, **tag})

    risk_rank = {"clean": 0, "exchange": 1, "scam": 2, "mixer": 3, "tainted": 3, "sanctioned": 4}
    for c in cluster_map.values():
        c["members"].sort()
        for tag in c["tags"]:
            cat = tag.get("category", "clean")
            if cat == "sanctioned":
                c["risk"] = "sanctioned"
            elif risk_rank.get(cat, 0) > risk_rank.get(c["risk"], 0):
                c["risk"] = cat
        # taint propagation: any member tag taints whole multi-member cluster
        if c["tags"] and len(c["members"]) > 1 and c["risk"] == "clean":
            c["risk"] = "tainted"

    all_addrs = sorted(profiles)
    report = {
        "summary": {
            "transfers": len(transfers),
            "addresses": len(all_addrs),
            "clusters": len(cluster_map),
            "sanctioned_clusters": sum(1 for c in cluster_map.values() if c["risk"] == "sanctioned"),
            "flagged_addresses": sum(1 for p in profiles.values() if p.tags),
        },
        "addresses": [asdict(profiles[a]) for a in all_addrs],
        "clusters": sorted(cluster_map.values(), key=lambda c: c["cluster_id"]),
        "sanctions_hits": sanctions_xref(all_addrs),
    }
    return report

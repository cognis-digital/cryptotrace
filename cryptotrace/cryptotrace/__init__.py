"""CRYPTOTRACE — OFAC sanctions screening + GraphSense-style forensics.

Defensive blockchain forensics over a transaction list you already possess.
Screens addresses against bundled OFAC SDN crypto wallets (Lazarus/DPRK,
Tornado Cash, Garantex, SUEX, Chatex, Hydra, Blender.io, Sinbad.io,
Bitzlato), traces indirect exposure by hop distance AND value-weighted
taint propagation, clusters addresses into single-entity wallets using
common-input-ownership + change-address heuristics, attributes known
actors, and flags peeling-chain laundering patterns. No network. Standard
library only.
"""
from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    SEVERITY_ORDER,
    Transaction,
    Finding,
    Cluster,
    TraceResult,
    Transfer,
    parse_txs,
    analyze,
    cluster_addresses,
    propagate_taint,
    detect_peel_chains,
    is_sanctioned,
    actor_tag,
    ofac_entries,
    classify_address,
    sanctions_xref,
    investigate,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "SEVERITY_ORDER",
    "Transaction",
    "Finding",
    "Cluster",
    "TraceResult",
    "Transfer",
    "parse_txs",
    "analyze",
    "cluster_addresses",
    "propagate_taint",
    "detect_peel_chains",
    "is_sanctioned",
    "actor_tag",
    "ofac_entries",
    "classify_address",
    "sanctions_xref",
    "investigate",
]

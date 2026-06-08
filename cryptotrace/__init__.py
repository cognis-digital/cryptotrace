"""CRYPTOTRACE — OFAC sanctions screening + address clustering for tx graphs.

Defensive blockchain forensics over a transaction list you already possess.
Screens addresses against bundled OFAC SDN crypto wallets (Lazarus/DPRK,
Tornado Cash, Garantex, SUEX, Chatex, Hydra, Blender.io), traces indirect
exposure by hop distance, and clusters addresses into single-entity wallets
using common-input-ownership + change-address heuristics (graphsense-style).
No network. Standard library only.
"""
from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    SEVERITY_ORDER,
    Transaction,
    Finding,
    Cluster,
    TraceResult,
    parse_txs,
    analyze,
    cluster_addresses,
    is_sanctioned,
    ofac_entries,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "SEVERITY_ORDER",
    "Transaction",
    "Finding",
    "Cluster",
    "TraceResult",
    "parse_txs",
    "analyze",
    "cluster_addresses",
    "is_sanctioned",
    "ofac_entries",
]

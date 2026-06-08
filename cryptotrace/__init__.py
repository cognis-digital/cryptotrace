"""CRYPTOTRACE - Free-tier blockchain investigator.

ETH/BTC address clustering + sanctions cross-reference, stdlib only.
Inspired by graphsense/graphsense-tagpacks.
"""
from .core import (
    classify_address,
    cluster_addresses,
    sanctions_xref,
    investigate,
    Transfer,
    AddressProfile,
    SANCTIONS,
)

TOOL_NAME = "cryptotrace"
TOOL_VERSION = "1.0.0"

__all__ = [
    "classify_address",
    "cluster_addresses",
    "sanctions_xref",
    "investigate",
    "Transfer",
    "AddressProfile",
    "SANCTIONS",
    "TOOL_NAME",
    "TOOL_VERSION",
]

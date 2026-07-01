"""Shared helpers for the runnable demo scenarios.

Every scenario loads a bundled transaction-graph fixture (the same
`tx_graph.json` files used by the `SCENARIO.md` walkthroughs) and drives the
REAL cryptotrace API over it. No network, no live chain calls, standard
library only — the fixtures ship with the repo.
"""
from __future__ import annotations

import json
import os
import sys

# allow `python demos/NN_name.py` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace.core import (  # noqa: E402
    Transaction,
    TraceResult,
    parse_txs,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS_DIR = os.path.join(REPO_ROOT, "demos")


def fixture(scenario: str) -> str:
    """Absolute path to a bundled scenario fixture.

    Prefers ``tx_graph.json`` but falls back to ``tx_graph.jsonl`` so JSONL
    streaming scenarios work through the same helper.
    """
    base = os.path.join(DEMOS_DIR, scenario)
    for name in ("tx_graph.json", "tx_graph.jsonl"):
        path = os.path.join(base, name)
        if os.path.exists(path):
            return path
    # default to the .json path (open() will raise a clear FileNotFoundError)
    return os.path.join(base, "tx_graph.json")


def load(scenario: str) -> list[Transaction]:
    """Parse a bundled scenario fixture into Transactions via the real parser."""
    with open(fixture(scenario), "r", encoding="utf-8") as fh:
        return parse_txs(fh.read())


def rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def severity_line(res: TraceResult) -> str:
    counts = res.counts()
    parts = [f"{k}={counts[k]}" for k in
             ("critical", "high", "medium", "low", "info") if counts.get(k)]
    return ", ".join(parts) or "none"


def show_findings(res: TraceResult, limit: int = 8) -> None:
    """Print the top findings of a TraceResult in a compact, narrated form."""
    for f in res.findings[:limit]:
        tag = f.entity or (f"{f.hops} hop(s)" if f.hops else "")
        head = f"   [{f.severity.upper():8}] {f.kind:22} {f.address}"
        if tag:
            head += f"  <{tag}>"
        print(head)
        print(f"              {f.detail}")
    extra = len(res.findings) - limit
    if extra > 0:
        print(f"   ... and {extra} more finding(s)")


def pretty_json(obj) -> str:
    return json.dumps(obj, indent=2)

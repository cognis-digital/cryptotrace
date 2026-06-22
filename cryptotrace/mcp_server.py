"""CRYPTOTRACE MCP server — exposes screening as an MCP tool for Cognis.Studio.

Requires the optional `cognis_core` dependency (the shared MCP scaffold). The
exposed tool screens a transaction-list file path (or raw JSON string) for OFAC
exposure, taint, and clustering and returns the JSON report.
"""
from cognis_core.mcp import build_mcp_server  # optional dependency

from cryptotrace.core import TOOL_NAME, analyze, parse_txs


def scan(target: str) -> dict:
    """Screen a tx-list (file path or raw JSON/JSONL string) and return JSON.

    `target` may be a path to a tx-graph file or the JSON text itself.
    """
    try:
        with open(target, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        text = target  # treat the argument as raw JSON/JSONL
    return analyze(parse_txs(text)).to_dict()


run_mcp_server = build_mcp_server(
    tool_name=TOOL_NAME,
    description="Free-tier blockchain investigator — ETH/BTC clustering + sanctions xref",
    scan_fn=scan,
)

if __name__ == "__main__":
    run_mcp_server()

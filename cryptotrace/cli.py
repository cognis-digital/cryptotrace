"""CRYPTOTRACE command-line interface.

Subcommands:
  investigate <file>   Run full investigation on a transfers JSON file.
  xref <addr...>       Cross-reference addresses against the bundled tag pack.
  classify <addr...>   Identify chain/format of one or more addresses.

Input JSON for `investigate`: a list of transfer objects, e.g.
  [{"src": "0x..", "dst": "0x..", "value": 1.5, "asset": "ETH",
    "txid": "0x..", "inputs": ["0x..", "0x.."]}, ...]
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Transfer, investigate, sanctions_xref, classify_address


def _load_transfers(path: str) -> List[Transfer]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "transfers" in data:
        data = data["transfers"]
    if not isinstance(data, list):
        raise ValueError("input must be a JSON list of transfers")
    out: List[Transfer] = []
    for i, row in enumerate(data):
        if not isinstance(row, dict) or "src" not in row or "dst" not in row:
            raise ValueError(f"transfer #{i} missing required 'src'/'dst'")
        out.append(Transfer(
            src=row["src"],
            dst=row["dst"],
            value=float(row.get("value", 0.0)),
            asset=row.get("asset", "ETH"),
            txid=row.get("txid", ""),
            inputs=list(row.get("inputs", []) or []),
        ))
    return out


def _print_table(report: dict) -> None:
    s = report["summary"]
    print("== CRYPTOTRACE investigation ==")
    print(f"transfers={s['transfers']} addresses={s['addresses']} "
          f"clusters={s['clusters']} sanctioned_clusters={s['sanctioned_clusters']} "
          f"flagged={s['flagged_addresses']}")
    print()
    print("-- addresses --")
    print(f"{'address':<44} {'chain':<11} {'cl':>3} {'in':>4} {'out':>4} {'recv':>10} {'tags'}")
    for a in report["addresses"]:
        tagstr = ",".join(t.get("label", "?") for t in a["tags"]) or "-"
        print(f"{a['address']:<44} {a['chain']:<11} {a['cluster_id']:>3} "
              f"{a['in_degree']:>4} {a['out_degree']:>4} {a['received']:>10.4f} {tagstr}")
    print()
    print("-- clusters --")
    for c in report["clusters"]:
        print(f"cluster {c['cluster_id']:>3}  risk={c['risk']:<10} members={len(c['members'])} "
              f"recv={c['total_received']:.4f} sent={c['total_sent']:.4f}")
    if report["sanctions_hits"]:
        print()
        print("-- sanctions / tag hits --")
        for h in report["sanctions_hits"]:
            print(f"  [{h['category'].upper()}] {h['address']}  {h['label']} ({h['source']})")


def _emit(obj: dict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, sort_keys=True))
    else:
        _print_table(obj)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Free-tier blockchain investigator (ETH/BTC clustering + sanctions xref).")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("investigate", help="run full investigation on a transfers JSON file")
    pi.add_argument("file", help="path to transfers JSON file")

    px = sub.add_parser("xref", help="cross-reference addresses against the tag pack")
    px.add_argument("addresses", nargs="+")

    pc = sub.add_parser("classify", help="identify chain/format of addresses")
    pc.add_argument("addresses", nargs="+")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fmt = args.format
    try:
        if args.cmd == "investigate":
            transfers = _load_transfers(args.file)
            report = investigate(transfers)
            _emit(report, fmt)
            return 0
        if args.cmd == "xref":
            hits = sanctions_xref(args.addresses)
            if fmt == "json":
                print(json.dumps({"hits": hits}, indent=2, sort_keys=True))
            else:
                if not hits:
                    print("no tag/sanctions hits")
                for h in hits:
                    print(f"[{h['category'].upper()}] {h['address']}  {h['label']} ({h['source']})")
            return 0 if not hits else 2  # exit 2 signals a positive hit
        if args.cmd == "classify":
            result = {a: classify_address(a) for a in args.addresses}
            if fmt == "json":
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                for a, c in result.items():
                    print(f"{c:<11} {a}")
            return 0 if all(v != "invalid" for v in result.values()) else 1
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())

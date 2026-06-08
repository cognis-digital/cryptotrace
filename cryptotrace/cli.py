"""Command-line interface for CRYPTOTRACE."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    SEVERITY_ORDER,
    TraceResult,
    analyze,
    cluster_addresses,
    is_sanctioned,
    ofac_entries,
    parse_txs,
)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _render_table(res: TraceResult) -> str:
    lines: list[str] = []
    lines.append(f"CRYPTOTRACE report  ({res.asset})")
    lines.append("=" * 60)
    lines.append(f"Transactions analyzed : {res.total_txs}")
    lines.append(f"Distinct addresses    : {res.total_addresses}")
    lines.append(f"Entity clusters       : {len(res.clusters)}")
    lines.append(f"Sanctioned clusters   : {len(res.sanctioned_clusters)}")
    lines.append(f"Hops scanned          : {res.max_hops_scanned}")
    counts = res.counts()
    sev_line = ", ".join(
        f"{k}={counts[k]}" for k in ("critical", "high", "medium", "low", "info")
        if counts.get(k)
    ) or "none"
    lines.append(f"Findings              : {len(res.findings)} ({sev_line})")
    lines.append(f"Highest severity      : {res.max_severity.upper()}")
    lines.append("")

    if res.findings:
        lines.append("Findings:")
        for f in res.findings:
            tag = f.entity or (f"{f.hops} hop(s)" if f.hops else "")
            head = f"  [{f.severity.upper():8}] {f.kind:24} {f.address}"
            if tag:
                head += f"  <{tag}>"
            lines.append(head)
            lines.append(f"             {f.detail}")
    else:
        lines.append("No sanctioned exposure found.")
    lines.append("")

    multi = [c for c in res.clusters]
    if multi:
        lines.append("Clusters (multi-address entities):")
        for c in multi:
            flag = f"  !! SANCTIONED: {c.sanctioned_entity}" if c.sanctioned_member else ""
            lines.append(
                f"  #{c.cluster_id}  size={len(c.addresses)}  txs={c.tx_count}  "
                f"heuristics=[{','.join(c.heuristics) or '-'}]{flag}")
            for a in c.addresses:
                mark = " (SDN)" if is_sanctioned(a) else ""
                lines.append(f"        {a}{mark}")
    return "\n".join(lines)


def _cmd_screen(args: argparse.Namespace) -> int:
    try:
        text = _read(args.txfile)
    except OSError as exc:
        print(f"error: cannot read tx file: {exc}", file=sys.stderr)
        return 2
    txs = parse_txs(text)
    res = analyze(txs, max_hops=args.max_hops)

    if args.format == "json":
        out = json.dumps(res.to_dict(), indent=2)
    else:
        out = _render_table(res)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
        except OSError as exc:
            print(f"error: cannot write output: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(out)

    # Non-zero exit when any sanctioned exposure (direct/indirect/cluster) exists.
    flagged = [f for f in res.findings if f.severity in ("critical", "high", "medium")]
    return 1 if flagged else 0


def _cmd_cluster(args: argparse.Namespace) -> int:
    try:
        text = _read(args.txfile)
    except OSError as exc:
        print(f"error: cannot read tx file: {exc}", file=sys.stderr)
        return 2
    clusters = cluster_addresses(parse_txs(text))
    if args.format == "json":
        print(json.dumps([c.to_dict() for c in clusters], indent=2))
    else:
        if not clusters:
            print("No multi-address clusters detected.")
        for c in clusters:
            flag = f"  !! SANCTIONED: {c.sanctioned_entity}" if c.sanctioned_member else ""
            print(f"#{c.cluster_id}  size={len(c.addresses)}  txs={c.tx_count}  "
                  f"heuristics=[{','.join(c.heuristics) or '-'}]{flag}")
            for a in c.addresses:
                print(f"    {a}")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    hit = is_sanctioned(args.address)
    if args.format == "json":
        print(json.dumps({"address": args.address,
                          "sanctioned": bool(hit),
                          "entry": hit}, indent=2))
    else:
        if hit:
            print(f"SANCTIONED: {args.address}")
            print(f"  entity  : {hit['entity']}")
            print(f"  program : {hit['program']}")
            print(f"  listed  : {hit['added']}")
        else:
            print(f"clean: {args.address} is not on the bundled OFAC SDN list")
    return 1 if hit else 0


def _cmd_sdn(args: argparse.Namespace) -> int:
    entries = ofac_entries()
    if args.format == "json":
        print(json.dumps(entries, indent=2))
    else:
        print(f"Bundled OFAC SDN crypto addresses: {len(entries)}")
        for e in entries:
            print(f"  [{e['asset']:3}] {e['address']:44} {e['entity']} "
                  f"({e['program']}, {e['added']})")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="OFAC sanctions screening + address clustering over a "
                    "transaction list (defensive blockchain forensics).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")

    # Shared parent so every subcommand accepts --format {table,json}.
    fmt = argparse.ArgumentParser(add_help=False)
    fmt.add_argument("--format", choices=("table", "json"), default="table",
                     help="output format")

    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("screen", parents=[fmt],
                       help="full screen: OFAC hits, indirect exposure, clusters")
    s.add_argument("txfile", help="tx list JSON/JSONL, or '-' for stdin")
    s.add_argument("--max-hops", type=int, default=2,
                   help="how many hops out to trace indirect exposure (default 2)")
    s.add_argument("-o", "--output", help="write report to this file")
    s.set_defaults(func=_cmd_screen)

    c = sub.add_parser("cluster", parents=[fmt],
                       help="cluster addresses into single-entity wallets")
    c.add_argument("txfile", help="tx list JSON/JSONL, or '-' for stdin")
    c.set_defaults(func=_cmd_cluster)

    k = sub.add_parser("check", parents=[fmt],
                       help="check a single address against the SDN list")
    k.add_argument("address", help="address to screen")
    k.set_defaults(func=_cmd_check)

    sdn = sub.add_parser("sdn", parents=[fmt],
                         help="list the bundled OFAC SDN crypto addresses")
    sdn.set_defaults(func=_cmd_sdn)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

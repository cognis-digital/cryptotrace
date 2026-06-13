"""Command-line interface for CRYPTOTRACE."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    TraceResult,
    Transfer,
    actor_tag,
    analyze,
    classify_address,
    cluster_addresses,
    detect_peel_chains,
    investigate,
    is_sanctioned,
    ofac_entries,
    parse_txs,
    propagate_taint,
    sanctions_xref,
)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _render_table(res: TraceResult) -> str:
    lines: list[str] = []
    lines.append(f"CRYPTOTRACE report  ({res.asset})")
    lines.append("=" * 64)
    lines.append(f"Transactions analyzed : {res.total_txs}")
    lines.append(f"Distinct addresses    : {res.total_addresses}")
    lines.append(f"Entity clusters       : {len(res.clusters)}")
    lines.append(f"Sanctioned clusters   : {len(res.sanctioned_clusters)}")
    lines.append(f"Hops scanned          : {res.max_hops_scanned}")
    lines.append(f"Tainted value (total) : {res.dirty_value_total:.6f} {res.asset}")
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
            head = f"  [{f.severity.upper():8}] {f.kind:22} {f.address}"
            if tag:
                head += f"  <{tag}>"
            lines.append(head)
            lines.append(f"             {f.detail}")
    else:
        lines.append("No sanctioned exposure found.")
    lines.append("")

    if res.clusters:
        lines.append("Clusters (multi-address entities):")
        for c in res.clusters:
            flag = (f"  !! SANCTIONED: {c.sanctioned_entity}"
                    if c.sanctioned_member else "")
            actor = f"  actor={c.actor}" if c.actor else ""
            lines.append(
                f"  #{c.cluster_id}  size={len(c.addresses)}  txs={c.tx_count}  "
                f"risk={c.risk_score}/100  "
                f"heuristics=[{','.join(c.heuristics) or '-'}]{actor}{flag}")
            for a in c.addresses:
                mark = " (SDN)" if is_sanctioned(a) else ""
                lines.append(f"        {a}{mark}")
    return "\n".join(lines)


def _flagged(res: TraceResult) -> bool:
    return any(f.severity in ("critical", "high", "medium")
               for f in res.findings)


def _cmd_screen(args: argparse.Namespace) -> int:
    try:
        text = _read(args.txfile)
    except OSError as exc:
        print(f"error: cannot read tx file: {exc}", file=sys.stderr)
        return 2
    res = analyze(parse_txs(text), max_hops=args.max_hops,
                  taint_threshold=args.min_taint)

    out = (json.dumps(res.to_dict(), indent=2)
           if args.format == "json" else _render_table(res))

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

    return 1 if _flagged(res) else 0


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
            flag = (f"  !! SANCTIONED: {c.sanctioned_entity}"
                    if c.sanctioned_member else "")
            print(f"#{c.cluster_id}  size={len(c.addresses)}  txs={c.tx_count}  "
                  f"risk={c.risk_score}/100  "
                  f"heuristics=[{','.join(c.heuristics) or '-'}]{flag}")
            for a in c.addresses:
                print(f"    {a}")
    # Non-zero if any cluster is sanctioned.
    return 1 if any(c.sanctioned_member for c in clusters) else 0


def _cmd_taint(args: argparse.Namespace) -> int:
    try:
        text = _read(args.txfile)
    except OSError as exc:
        print(f"error: cannot read tx file: {exc}", file=sys.stderr)
        return 2
    txs = parse_txs(text)
    all_addrs: set[str] = set()
    for t in txs:
        all_addrs |= t.all_addresses()
    sources = {a for a in all_addrs if is_sanctioned(a)}
    taint = propagate_taint(txs, sources)
    rows = sorted(taint.items(), key=lambda kv: -kv[1]["taint"])
    rows = [(a, v) for a, v in rows if v["taint"] >= args.min_taint]

    if args.format == "json":
        print(json.dumps({
            "sources": sorted(sources),
            "tainted": [{"address": a, "taint": round(v["taint"], 6),
                         "dirty_value": round(v["dirty"], 8)}
                        for a, v in rows],
        }, indent=2))
    else:
        print(f"Sanctioned sources : {len(sources)}")
        for s in sorted(sources):
            print(f"  source {s}  <{is_sanctioned(s)['entity']}>")
        print(f"Tainted downstream addresses (>= {args.min_taint:.0%}):")
        if not rows:
            print("  none")
        for a, v in rows:
            print(f"  {v['taint'] * 100:6.1f}%  {v['dirty']:.6f}  {a}")
    return 1 if rows else 0


def _cmd_peel(args: argparse.Namespace) -> int:
    try:
        text = _read(args.txfile)
    except OSError as exc:
        print(f"error: cannot read tx file: {exc}", file=sys.stderr)
        return 2
    chains = detect_peel_chains(parse_txs(text), min_length=args.min_length)
    if args.format == "json":
        print(json.dumps({"peel_chains": chains}, indent=2))
    else:
        if not chains:
            print("No peeling chains detected.")
        for i, ch in enumerate(chains, 1):
            print(f"chain #{i} (len {len(ch)}): {' -> '.join(ch)}")
    return 1 if chains else 0


def _cmd_check(args: argparse.Namespace) -> int:
    hit = is_sanctioned(args.address)
    tag = actor_tag(args.address)
    if args.format == "json":
        print(json.dumps({"address": args.address,
                          "sanctioned": bool(hit),
                          "entry": hit,
                          "actor": tag}, indent=2))
    else:
        if hit:
            print(f"SANCTIONED: {args.address}")
            print(f"  entity   : {hit['entity']}")
            print(f"  category : {hit.get('category', '-')}")
            print(f"  program  : {hit['program']}")
            print(f"  listed   : {hit['added']}")
        elif tag:
            print(f"known actor: {args.address} -> {tag['actor']} "
                  f"({tag['category']}) [not sanctioned]")
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
                  f"({e.get('category', '-')}/{e['program']}, {e['added']})")
    return 0


def _cmd_investigate(args: argparse.Namespace) -> int:
    """``investigate`` subcommand — high-level Transfer-based investigation."""
    path = args.txfile
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"error: cannot read file: {exc}", file=sys.stderr)
        return 1
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(rows, list):
        print("error: expected a JSON array of transfer records", file=sys.stderr)
        return 1
    transfers = [
        Transfer(
            src=r.get("src", r.get("from", "")),
            dst=r.get("dst", r.get("to", "")),
            value=float(r.get("value", 0) or 0),
            inputs=r.get("inputs", []),
            asset=str(r.get("asset", "ETH")),
            txid=str(r.get("txid", "")),
        )
        for r in rows if isinstance(r, dict)
    ]
    report = investigate(transfers)
    fmt = getattr(args, "format", "table")
    if fmt == "json":
        print(json.dumps(report, indent=2))
    else:
        s = report["summary"]
        print(f"CRYPTOTRACE investigate report")
        print(f"  Transfers          : {s['total_transfers']}")
        print(f"  Addresses          : {s['total_addresses']}")
        print(f"  Flagged            : {s['flagged_addresses']}")
        print(f"  Sanctioned clusters: {s['sanctioned_clusters']}")
        print(f"  Highest severity   : {s['max_severity'].upper()}")
        for f in report["findings"]:
            print(f"  [{f['severity'].upper():8}] {f['kind']:24} {f['address']}")
    return 0


def _cmd_xref(args: argparse.Namespace) -> int:
    """``xref`` subcommand — OFAC xref for a single address; exit 2 on hit."""
    hits = sanctions_xref([args.address])
    fmt = getattr(args, "format", "table")
    if fmt == "json":
        print(json.dumps(hits, indent=2))
    else:
        if hits:
            h = hits[0]
            print(f"SANCTIONED: {h['address']}")
            print(f"  entity  : {h['entity']}")
            print(f"  program : {h['program']}")
            print(f"  listed  : {h['added']}")
        else:
            print(f"clean: {args.address} is not on the bundled OFAC SDN list")
    return 2 if hits else 0


def _cmd_classify(args: argparse.Namespace) -> int:
    """``classify`` subcommand — classify an address type; exit 1 if invalid."""
    kind = classify_address(args.address)
    fmt = getattr(args, "format", "table")
    if fmt == "json":
        print(json.dumps({"address": args.address, "type": kind}, indent=2))
    else:
        print(f"{args.address}  ->  {kind}")
    return 1 if kind == "invalid" else 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="OFAC sanctions screening, address clustering, tainted-flow "
                    "tracking + laundering-pattern detection over a transaction "
                    "list (defensive blockchain forensics).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    # Global --format so callers can place it before OR after the subcommand.
    p.add_argument("--format", choices=("table", "json"), default="table",
                   help="output format (default: table)")

    fmt = argparse.ArgumentParser(add_help=False)
    fmt.add_argument("--format", choices=("table", "json"), default="table",
                     help="output format")

    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("screen", parents=[fmt],
                       help="full screen: OFAC hits, taint, clusters, patterns")
    s.add_argument("txfile", help="tx list JSON/JSONL, or '-' for stdin")
    s.add_argument("--max-hops", type=int, default=2,
                   help="how many hops out to trace indirect exposure (default 2)")
    s.add_argument("--min-taint", type=float, default=0.0,
                   help="suppress indirect findings below this taint fraction")
    s.add_argument("-o", "--output", help="write report to this file")
    s.set_defaults(func=_cmd_screen)

    c = sub.add_parser("cluster", parents=[fmt],
                       help="cluster addresses into single-entity wallets")
    c.add_argument("txfile", help="tx list JSON/JSONL, or '-' for stdin")
    c.set_defaults(func=_cmd_cluster)

    t = sub.add_parser("taint", parents=[fmt],
                       help="propagate value-weighted taint from SDN sources")
    t.add_argument("txfile", help="tx list JSON/JSONL, or '-' for stdin")
    t.add_argument("--min-taint", type=float, default=0.0,
                   help="only report addresses at/above this taint fraction")
    t.set_defaults(func=_cmd_taint)

    pe = sub.add_parser("peel", parents=[fmt],
                        help="detect peeling-chain laundering patterns")
    pe.add_argument("txfile", help="tx list JSON/JSONL, or '-' for stdin")
    pe.add_argument("--min-length", type=int, default=3,
                    help="minimum chain length to report (default 3)")
    pe.set_defaults(func=_cmd_peel)

    k = sub.add_parser("check", parents=[fmt],
                       help="check a single address against the SDN/actor tables")
    k.add_argument("address", help="address to screen")
    k.set_defaults(func=_cmd_check)

    sdn = sub.add_parser("sdn", parents=[fmt],
                         help="list the bundled OFAC SDN crypto addresses")
    sdn.set_defaults(func=_cmd_sdn)

    inv = sub.add_parser("investigate", parents=[fmt],
                         help="full investigation over a Transfer JSON list")
    inv.add_argument("txfile", help="JSON file with transfer records")
    inv.set_defaults(func=_cmd_investigate)

    xr = sub.add_parser("xref", parents=[fmt],
                        help="OFAC xref for a single address (exit 2 on hit)")
    xr.add_argument("address", help="address to xref")
    xr.set_defaults(func=_cmd_xref)

    cl = sub.add_parser("classify", parents=[fmt],
                        help="classify an address type (exit 1 if invalid)")
    cl.add_argument("address", help="address to classify")
    cl.set_defaults(func=_cmd_classify)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

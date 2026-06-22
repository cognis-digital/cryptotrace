"""Command-line interface for CRYPTOTRACE."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from . import datafeeds
from .core import (
    SEVERITY_ORDER,
    TraceResult,
    actor_tag,
    analyze,
    cluster_addresses,
    detect_peel_chains,
    is_sanctioned,
    ofac_entries,
    parse_txs,
    propagate_taint,
    to_sarif,
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


def _enrich_from_feed(args: argparse.Namespace) -> None:
    """Optionally merge the live OFAC SDN feed into the screening index so the
    screen covers the full designation set, not just the bundled seed."""
    if not getattr(args, "feed", False):
        return
    from . import feeds as _feeds
    try:
        n = _feeds.load_sdn_into_index(offline=getattr(args, "offline", False))
        print(f"[feeds] merged {n} live OFAC SDN address(es) into the index",
              file=sys.stderr)
    except (ValueError, KeyError, FileNotFoundError, ConnectionError) as exc:
        print(f"[feeds] warning: could not load OFAC SDN feed: {exc}",
              file=sys.stderr)


def _cmd_screen(args: argparse.Namespace) -> int:
    try:
        text = _read(args.txfile)
    except OSError as exc:
        print(f"error: cannot read tx file: {exc}", file=sys.stderr)
        return 2
    _enrich_from_feed(args)
    res = analyze(parse_txs(text), max_hops=args.max_hops,
                  taint_threshold=args.min_taint)

    if args.format == "json":
        out = json.dumps(res.to_dict(), indent=2)
    elif args.format == "sarif":
        out = json.dumps(to_sarif(res), indent=2)
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
    _enrich_from_feed(args)
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


def _cmd_feeds(args: argparse.Namespace) -> int:
    from . import feeds as _feeds

    if args.feeds_cmd == "list":
        rows = _feeds.relevant_feeds()
        if args.format == "json":
            print(json.dumps(rows, indent=2))
        else:
            print(f"Feeds wired into {TOOL_NAME}: {len(rows)}")
            for f in rows:
                age = datafeeds.cached_age_hours(f["id"])
                fresh = "uncached" if age is None else f"{age:.1f}h old"
                print(f"  {f['id']:12} [{fresh:9}] {f['name']}")
                print(f"               {f['url']}")
        return 0

    if args.feeds_cmd == "update":
        try:
            path = _feeds.update_feed(args.id)
        except (ValueError, KeyError, ConnectionError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"updated {args.id} -> {path}")
        return 0

    if args.feeds_cmd == "get":
        try:
            csv_text = _feeds.get_feed(args.id, offline=args.offline)
            entries = _feeds.parse_sdn_addresses(
                csv_text if isinstance(csv_text, str)
                else csv_text.decode("utf-8", "replace"))
        except (ValueError, KeyError, FileNotFoundError, ConnectionError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps({"feed": args.id,
                              "addresses": entries,
                              "summary": _feeds.sdn_summary(entries)}, indent=2))
        else:
            print(f"OFAC SDN crypto addresses in feed: {len(entries)}")
            for e in entries:
                print(f"  [{e['asset']:4}] {e['address']:46} {e['entity']} "
                      f"({e['program']})")
            print(f"  summary: {_feeds.sdn_summary(entries)}")
        return 0

    return 2


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


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="OFAC sanctions screening, address clustering, tainted-flow "
                    "tracking + laundering-pattern detection over a transaction "
                    "list (defensive blockchain forensics).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")

    fmt = argparse.ArgumentParser(add_help=False)
    fmt.add_argument("--format", choices=("table", "json"), default="table",
                     help="output format")

    sub = p.add_subparsers(dest="command", required=True)

    # `screen` supports an extra SARIF 2.1.0 output for code-scanning / CI.
    s = sub.add_parser("screen",
                       help="full screen: OFAC hits, taint, clusters, patterns")
    s.add_argument("--format", choices=("table", "json", "sarif"),
                   default="table",
                   help="output format (sarif = SARIF 2.1.0 for code-scanning)")
    s.add_argument("txfile", help="tx list JSON/JSONL, or '-' for stdin")
    s.add_argument("--max-hops", type=int, default=2,
                   help="how many hops out to trace indirect exposure (default 2)")
    s.add_argument("--min-taint", type=float, default=0.0,
                   help="suppress indirect findings below this taint fraction")
    s.add_argument("-o", "--output", help="write report to this file")
    s.add_argument("--feed", action="store_true",
                   help="enrich screening with the live OFAC SDN feed before "
                        "analysis (datafeeds-backed)")
    s.add_argument("--offline", action="store_true",
                   help="with --feed, serve the SDN feed from cache only")
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
    k.add_argument("--feed", action="store_true",
                   help="enrich with the live OFAC SDN feed before checking")
    k.add_argument("--offline", action="store_true",
                   help="with --feed, serve the SDN feed from cache only")
    k.set_defaults(func=_cmd_check)

    sdn = sub.add_parser("sdn", parents=[fmt],
                         help="list the bundled OFAC SDN crypto addresses")
    sdn.set_defaults(func=_cmd_sdn)

    # `feeds` — edge/air-gap live OFAC SDN ingestion (datafeeds-backed).
    fe = sub.add_parser(
        "feeds",
        help="ingest the live OFAC SDN list (catalog feed 'ofac-sdn')")
    fe.set_defaults(func=_cmd_feeds)
    fesub = fe.add_subparsers(dest="feeds_cmd", required=True)
    fl = fesub.add_parser("list", parents=[fmt],
                          help="list the feeds wired into cryptotrace")
    fl.set_defaults(func=_cmd_feeds)
    fu = fesub.add_parser("update", help="fetch + cache a feed (online)")
    fu.add_argument("id", nargs="?", default="ofac-sdn")
    fu.set_defaults(func=_cmd_feeds)
    fg = fesub.add_parser("get", parents=[fmt],
                          help="parse SDN crypto addresses from the feed")
    fg.add_argument("id", nargs="?", default="ofac-sdn")
    fg.add_argument("--offline", action="store_true",
                    help="serve from cache only; never touch the network")
    fg.set_defaults(func=_cmd_feeds)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""Scenario 13 - data engineering (JSONL streaming input).

Large chain exports are usually delivered as JSONL — one JSON transaction per
line — because it streams. cryptotrace's parser accepts JSONL transparently
(it falls back to line-by-line parsing when the whole blob isn't a single JSON
document). This demo screens a JSONL export end to end through the same API.
"""
from _common import fixture, load, rule, severity_line
from cryptotrace.core import analyze


def main() -> None:
    rule("JSONL STREAMING  -  screen a line-delimited export unchanged")

    path = fixture("10-jsonl-stream")
    print(f"\nFixture: {path}")
    print("Format: one JSON transaction per line (JSONL) — the streaming default.\n")

    txs = load("10-jsonl-stream")
    print(f"1) parse_txs() consumed the JSONL and produced {len(txs)} "
          f"Transaction object(s):")
    for t in txs:
        print(f"     {t.txid}: {t.inputs} -> {t.outputs}  ({t.value} {t.asset})")

    res = analyze(txs, max_hops=2)
    print(f"\n2) analyze() -> {len(res.findings)} finding(s)  "
          f"[{severity_line(res)}], highest {res.max_severity.upper()}")
    for f in res.findings[:5]:
        print(f"     [{f.severity:8}] {f.kind:22} {f.address}")

    print("\nSame API, whether the export is a JSON array or JSONL — no reshaping")
    print("step in the pipeline, which is one fewer place for bugs to hide.")


if __name__ == "__main__":
    main()

"""Run every runnable demo scenario end to end.

    python demos/run_all.py

Each scenario loads a bundled tx-graph fixture and drives the real cryptotrace
API offline, so they can be run in any order or on their own. Exit code is 0
when all scenarios complete.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_investigator_triage",
    "02_exchange_compliance",
    "03_journalist_attribution",
    "04_incident_response",
    "05_cluster_inheritance",
]


def main() -> int:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 70)
    print(f"  All {len(SCENARIOS)} demo scenarios completed.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

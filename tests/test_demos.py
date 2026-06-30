"""Tests for the runnable demo scenarios in demos/.

Each scenario must import, run its main() offline without raising, and the
run_all driver must return exit code 0. These double as smoke tests over the
real cryptotrace API paths the demos exercise. No network.
"""
import importlib
import io
import os
import sys
import unittest
from contextlib import redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(REPO_ROOT, "demos")
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, DEMOS)

SCENARIOS = [
    "01_investigator_triage",
    "02_exchange_compliance",
    "03_journalist_attribution",
    "04_incident_response",
    "05_cluster_inheritance",
]


class TestDemoScenarios(unittest.TestCase):
    def test_each_scenario_runs_and_prints(self):
        for name in SCENARIOS:
            with self.subTest(scenario=name):
                mod = importlib.import_module(name)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    mod.main()
                out = buf.getvalue()
                self.assertTrue(out.strip(),
                                f"{name} produced no output")
                # every scenario narrates a titled rule line
                self.assertIn("=" * 70, out)

    def test_run_all_exits_zero(self):
        run_all = importlib.import_module("run_all")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = run_all.main()
        self.assertEqual(rc, 0)
        self.assertIn("All 5 demo scenarios completed.", buf.getvalue())


class TestDemoFixtures(unittest.TestCase):
    def test_fixtures_present_and_parse(self):
        from _common import load
        for name in ("01-tornado-cash-deposit", "03-lazarus-bridge-exit",
                     "04-peel-chain-laundering", "05-clean-treasury-baseline",
                     "06-garantex-cashout", "07-cospend-cluster-taint"):
            with self.subTest(fixture=name):
                txs = load(name)
                self.assertGreater(len(txs), 0, f"{name} parsed empty")


if __name__ == "__main__":
    unittest.main()

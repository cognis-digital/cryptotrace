"""Edge/corner tests for clustering, taint propagation, hop analysis, peel-chain
detection, sanctions inheritance, and the analyze() error paths. No network.

Run: python -m pytest  (or python -m unittest).
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptotrace.core import (  # noqa: E402
    Cluster,
    Transaction,
    _build_adjacency,
    _hop_distances,
    _is_likely_change,
    analyze,
    cluster_addresses,
    detect_peel_chains,
    propagate_taint,
)

SDN_ETH = "0x722122df12d4e14e13ac3b6895a86e84145b6967"   # Tornado Cash router
SDN_BTC = "1J7uHGYDhd4LwwTgkUCTCgnPmExgzqUw1f"           # SUEX OTC


def tx(txid, ins, outs, asset="BTC", value=0.0):
    return Transaction(txid, list(ins), list(outs), asset, value)


# --------------------------------------------------------------------------- #
# analyze() validation / empty / degenerate inputs
# --------------------------------------------------------------------------- #
class TestAnalyzeValidation(unittest.TestCase):
    def test_taint_threshold_below_range_raises(self):
        with self.assertRaises(ValueError):
            analyze([], taint_threshold=-0.1)

    def test_taint_threshold_above_range_raises(self):
        with self.assertRaises(ValueError):
            analyze([], taint_threshold=1.5)

    def test_taint_threshold_bounds_ok(self):
        analyze([], taint_threshold=0.0)
        analyze([], taint_threshold=1.0)  # no raise at the edges

    def test_negative_max_hops_clamped_not_raised(self):
        res = analyze([tx("t", [SDN_BTC], ["down"], value=1.0)], max_hops=-3)
        self.assertEqual(res.max_hops_scanned, 0)

    def test_empty_result_shape(self):
        res = analyze([])
        self.assertEqual(res.total_txs, 0)
        self.assertEqual(res.total_addresses, 0)
        self.assertEqual(res.findings, [])
        self.assertEqual(res.clusters, [])
        self.assertEqual(res.max_severity, "info")
        self.assertEqual(res.dirty_value_total, 0.0)

    def test_accepts_generator(self):
        gen = (tx(f"t{i}", ["A"], ["B"]) for i in range(3))
        res = analyze(gen)
        self.assertEqual(res.total_txs, 3)


# --------------------------------------------------------------------------- #
# Clustering corners
# --------------------------------------------------------------------------- #
class TestClusteringCorners(unittest.TestCase):
    def test_no_clusters_when_all_singletons(self):
        # single-input single-output txs never co-spend -> no multi-addr cluster
        txs = [tx("t0", ["A"], ["B"]), tx("t1", ["C"], ["D"])]
        self.assertEqual(cluster_addresses(txs), [])

    def test_common_input_unions_all_inputs(self):
        txs = [tx("t0", ["A", "B", "C"], ["OUT"])]
        clusters = cluster_addresses(txs)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(set(clusters[0].addresses) & {"A", "B", "C"}, {"A", "B", "C"})
        self.assertIn("common_input", clusters[0].heuristics)

    def test_duplicate_inputs_deduped(self):
        # Repeated input addresses must not create phantom members.
        txs = [tx("t0", ["A", "A", "B"], ["OUT"])]
        clusters = cluster_addresses(txs)
        self.assertEqual(sorted(clusters[0].addresses), sorted({"A", "B", "OUT"}
                                                                & set(clusters[0].addresses)) or clusters[0].addresses)
        # A and B are in one cluster; A appears once.
        self.assertEqual(clusters[0].addresses.count("A"), 1)

    def test_self_loop_input_equals_output(self):
        # A tx that sends to itself should not crash or self-cluster to size>=2.
        clusters = cluster_addresses([tx("t0", ["X"], ["X"])])
        self.assertEqual(clusters, [])

    def test_change_address_folds_into_spender(self):
        # tx with 2 outputs, one fresh (change) -> folded into input cluster.
        # MERCHANT must already be 'seen' so CHANGE1 is the *lone* fresh output.
        txs = [
            tx("t0", ["A", "B"], ["MERCHANT"]),        # A,B cluster; MERCHANT seen
            tx("t1", ["A"], ["MERCHANT", "CHANGE1"]),  # CHANGE1 is the fresh change
        ]
        clusters = cluster_addresses(txs)
        big = max(clusters, key=lambda c: len(c.addresses))
        self.assertIn("CHANGE1", big.addresses)
        self.assertIn("change_address", big.heuristics)

    def test_change_heuristic_needs_two_outputs(self):
        seen = set()
        t = tx("t0", ["A"], ["ONLY"])
        self.assertFalse(_is_likely_change("ONLY", t, seen))

    def test_change_heuristic_rejects_seen_output(self):
        seen = {"KNOWN"}
        t = tx("t0", ["A"], ["PAY", "KNOWN"])
        self.assertFalse(_is_likely_change("KNOWN", t, seen))

    def test_change_heuristic_rejects_input_as_output(self):
        seen = set()
        t = tx("t0", ["A"], ["PAY", "A"])
        self.assertFalse(_is_likely_change("A", t, seen))

    def test_change_heuristic_two_fresh_outputs_ambiguous(self):
        seen = set()
        t = tx("t0", ["A"], ["FRESH1", "FRESH2"])
        # exactly one fresh output required; two fresh -> ambiguous -> False
        self.assertFalse(_is_likely_change("FRESH1", t, seen))

    def test_clusters_sorted_largest_first(self):
        txs = [
            tx("t0", ["A", "B", "C", "D"], ["Z"]),  # big cluster
            tx("t1", ["E", "F"], ["Y"]),            # small cluster
        ]
        clusters = cluster_addresses(txs)
        sizes = [len(c.addresses) for c in clusters]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_cluster_ids_are_sequential(self):
        txs = [tx("t0", ["A", "B"], ["Z"]), tx("t1", ["C", "D"], ["Y"])]
        clusters = cluster_addresses(txs)
        self.assertEqual([c.cluster_id for c in clusters], [1, 2])

    def test_tx_count_per_cluster(self):
        txs = [tx("t0", ["A", "B"], ["Z"]), tx("t1", ["A"], ["W"])]
        clusters = cluster_addresses(txs)
        # both txs touch the A/B cluster
        self.assertGreaterEqual(clusters[0].tx_count, 2)

    def test_empty_input_list(self):
        self.assertEqual(cluster_addresses([]), [])


# --------------------------------------------------------------------------- #
# Sanctions inheritance
# --------------------------------------------------------------------------- #
class TestSanctionsInheritance(unittest.TestCase):
    def test_cluster_inherits_from_sanctioned_member(self):
        txs = [tx("t0", [SDN_BTC, "CLEAN1"], ["OUT"])]
        clusters = cluster_addresses(txs)
        c = clusters[0]
        self.assertEqual(c.sanctioned_member, SDN_BTC)
        self.assertEqual(c.sanctioned_entity, "SUEX OTC")
        self.assertGreaterEqual(c.risk_score, 80)

    def test_clean_cluster_has_no_sanctions(self):
        txs = [tx("t0", ["CLEAN1", "CLEAN2"], ["OUT"])]
        c = cluster_addresses(txs)[0]
        self.assertEqual(c.sanctioned_member, "")
        self.assertLess(c.risk_score, 80)

    def test_analyze_emits_cluster_sanctioned_finding(self):
        txs = [tx("t0", [SDN_BTC, "CLEAN1"], ["OUT"], value=1.0)]
        res = analyze(txs)
        kinds = [f.kind for f in res.findings]
        self.assertIn("cluster_sanctioned", kinds)

    def test_risk_capped_at_100(self):
        # A big sanctioned cluster with a mixer tag would sum > 100.
        c = Cluster(cluster_id=1, addresses=[SDN_BTC] + [f"a{i}" for i in range(6)],
                    heuristics=["change_address"], sanctioned_member=SDN_BTC)
        from cryptotrace.core import _cluster_risk
        self.assertLessEqual(_cluster_risk(c), 100)


# --------------------------------------------------------------------------- #
# Hop distance / adjacency
# --------------------------------------------------------------------------- #
class TestHopAnalysis(unittest.TestCase):
    def test_adjacency_is_undirected(self):
        adj = _build_adjacency([tx("t0", ["A"], ["B"])])
        self.assertIn("B", adj["A"])
        self.assertIn("A", adj["B"])

    def test_adjacency_no_self_edges(self):
        adj = _build_adjacency([tx("t0", ["A"], ["A"])])
        self.assertNotIn("A", adj["A"])

    def test_hop_distance_bfs(self):
        adj = {"A": {"B"}, "B": {"A", "C"}, "C": {"B"}}
        dist = _hop_distances(adj, {"A"}, max_hops=5)
        self.assertEqual(dist["A"], 0)
        self.assertEqual(dist["B"], 1)
        self.assertEqual(dist["C"], 2)

    def test_hop_distance_respects_max_hops(self):
        adj = {"A": {"B"}, "B": {"A", "C"}, "C": {"B"}}
        dist = _hop_distances(adj, {"A"}, max_hops=1)
        self.assertIn("B", dist)
        self.assertNotIn("C", dist)

    def test_hop_distance_zero_max_hops(self):
        adj = {"A": {"B"}, "B": {"A"}}
        dist = _hop_distances(adj, {"A"}, max_hops=0)
        self.assertEqual(dist, {"A": 0})

    def test_hop_distance_negative_max_hops(self):
        adj = {"A": {"B"}, "B": {"A"}}
        dist = _hop_distances(adj, {"A"}, max_hops=-2)
        self.assertEqual(dist, {"A": 0})

    def test_source_not_in_graph(self):
        adj = {"A": {"B"}, "B": {"A"}}
        dist = _hop_distances(adj, {"Z"}, max_hops=3)
        self.assertEqual(dist, {})


# --------------------------------------------------------------------------- #
# Taint propagation corners
# --------------------------------------------------------------------------- #
class TestTaintCorners(unittest.TestCase):
    def test_no_sources_no_taint(self):
        txs = [tx("t0", ["A"], ["B"], value=1.0)]
        self.assertEqual(propagate_taint(txs, set()), {})

    def test_source_excluded_from_result(self):
        txs = [tx("t0", [SDN_ETH], ["B"], "ETH", value=1.0)]
        out = propagate_taint(txs, {SDN_ETH})
        self.assertNotIn(SDN_ETH, out)
        self.assertIn("B", out)

    def test_direct_recipient_fully_dirty(self):
        txs = [tx("t0", [SDN_ETH], ["B"], "ETH", value=10.0)]
        out = propagate_taint(txs, {SDN_ETH})
        self.assertAlmostEqual(out["B"]["taint"], 1.0, places=6)
        self.assertAlmostEqual(out["B"]["dirty"], 10.0, places=6)

    def test_haircut_dilution_downstream(self):
        # B receives 10 dirty; then B + CLEAN co-fund C -> C partially tainted.
        txs = [
            tx("t0", [SDN_ETH], ["B"], "ETH", value=10.0),
            tx("t1", ["B", "CLEAN"], ["C"], "ETH", value=20.0),
        ]
        out = propagate_taint(txs, {SDN_ETH})
        self.assertIn("C", out)
        self.assertLess(out["C"]["taint"], 1.0)
        self.assertGreater(out["C"]["taint"], 0.0)

    def test_taint_never_exceeds_one(self):
        txs = [
            tx("t0", [SDN_ETH], ["B"], "ETH", value=10.0),
            tx("t1", ["B"], ["C"], "ETH", value=10.0),
            tx("t2", ["C"], ["D"], "ETH", value=10.0),
        ]
        out = propagate_taint(txs, {SDN_ETH})
        for v in out.values():
            self.assertLessEqual(v["taint"], 1.0)

    def test_tx_with_no_outputs_skipped(self):
        txs = [tx("t0", [SDN_ETH], [], "ETH", value=5.0)]
        out = propagate_taint(txs, {SDN_ETH})
        self.assertEqual(out, {})

    def test_zero_value_uses_unit_weight(self):
        txs = [tx("t0", [SDN_ETH], ["B"], "ETH", value=0.0)]
        out = propagate_taint(txs, {SDN_ETH})
        # zero -> unit weight fallback; B is fully tainted
        self.assertAlmostEqual(out["B"]["taint"], 1.0, places=6)


# --------------------------------------------------------------------------- #
# Peel-chain detection corners
# --------------------------------------------------------------------------- #
class TestPeelChainCorners(unittest.TestCase):
    def _chain(self, n):
        txs = []
        prev = "SRC"
        for i in range(n):
            change = f"hop{i+1}"
            txs.append(tx(f"p{i}", [prev], [f"peel{i}", change], value=10 - i))
            prev = change
        return txs

    def test_basic_chain_detected(self):
        chains = detect_peel_chains(self._chain(5), min_length=3)
        self.assertEqual(len(chains), 1)
        self.assertEqual(len(chains[0]), 5)

    def test_min_length_filter(self):
        self.assertEqual(detect_peel_chains(self._chain(2), min_length=3), [])
        self.assertEqual(len(detect_peel_chains(self._chain(2), min_length=2)), 1)

    def test_no_chains_on_empty(self):
        self.assertEqual(detect_peel_chains([], min_length=3), [])

    def test_ignores_multi_input_txs(self):
        txs = [tx("t0", ["A", "B"], ["C", "D"]), tx("t1", ["C"], ["E", "F"])]
        self.assertEqual(detect_peel_chains(txs, min_length=2), [])

    def test_ignores_non_two_output_txs(self):
        txs = [tx("t0", ["A"], ["B"]), tx("t1", ["B"], ["C"])]
        self.assertEqual(detect_peel_chains(txs, min_length=2), [])

    def test_cycle_does_not_loop_forever(self):
        # change output of last tx points back to the head input.
        txs = [
            tx("p0", ["A"], ["peelA", "B"]),
            tx("p1", ["B"], ["peelB", "C"]),
            tx("p2", ["C"], ["peelC", "A"]),  # back to A (already spent by p0)
        ]
        chains = detect_peel_chains(txs, min_length=3)
        # Terminates; the one chain is length 3 (A->B->C).
        self.assertEqual(len(chains), 1)
        self.assertEqual(len(chains[0]), 3)

    def test_used_txs_not_reused_in_second_chain(self):
        # Two independent chains -> both found, disjoint txids.
        c1 = self._chain(3)
        c2 = [
            tx("q0", ["Z"], ["peelZ", "z1"]),
            tx("q1", ["z1"], ["peelz1", "z2"]),
            tx("q2", ["z2"], ["peelz2", "z3"]),
        ]
        chains = detect_peel_chains(c1 + c2, min_length=3)
        flat = [t for ch in chains for t in ch]
        self.assertEqual(len(flat), len(set(flat)))  # no txid reused

    def test_min_length_one(self):
        # single peel tx qualifies at min_length=1
        chains = detect_peel_chains(self._chain(1), min_length=1)
        self.assertEqual(len(chains), 1)


if __name__ == "__main__":
    unittest.main()

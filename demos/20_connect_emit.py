"""Scenario 20 - interoperability (forward findings to your stack).

A finding is only useful where your team already works. cryptotrace maps its
JSON findings onto the canonical cognis-connect Finding contract and forwards
them to STIX, MISP, Sigma, Splunk/Elastic, Slack/Discord, or a webhook. This
demo builds a real screen, then emits it as a STIX bundle and Sigma rules —
degrading gracefully to a dry description if cognis-connect isn't installed.
"""
import json

from _common import load, rule
from cryptotrace.core import analyze


def main() -> None:
    rule("CONNECT / EMIT  -  forward findings to STIX / Sigma / SIEM")

    txs = load("03-lazarus-bridge-exit")
    res = analyze(txs, max_hops=2)
    payload = json.dumps(res.to_dict())
    print(f"\nScreen produced {len(res.findings)} finding(s) to forward.\n")

    try:
        import importlib
        connect = importlib.import_module("cryptotrace.connect")
        import cognis_connect as cc
    except ImportError:
        print("cognis-connect not installed — this is a soft dependency.")
        print("Install it to forward findings:")
        print("  pip install "
              "'git+https://github.com/cognis-digital/cognis-connect.git'")
        print("\nWiring (once installed):")
        print("  cryptotrace screen tx.json --format json | cryptotrace-emit --to stix")
        print("  cryptotrace screen tx.json --format json | cryptotrace-emit --to sigma")
        return

    findings = connect._findings(payload)
    print(f"1) normalized {len(findings)} finding(s) onto the Finding contract.")

    bundle = cc.stix.to_bundle(findings)
    print(f"2) STIX bundle: type={bundle['type']}, "
          f"{len(bundle['objects'])} object(s).")

    rules = cc.sigma.to_rules(findings)
    n_rules = rules.count("title:")
    print(f"3) Sigma: emitted {n_rules} detection rule(s).")

    print("\nSame findings, delivered where the team already triages — STIX for")
    print("intel platforms, Sigma for detections, and more via --to.")


if __name__ == "__main__":
    main()

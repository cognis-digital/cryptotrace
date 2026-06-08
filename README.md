# CRYPTOTRACE — Free-tier blockchain investigator — ETH/BTC clustering + sanctions xref

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `osint`

[![PyPI](https://img.shields.io/pypi/v/cognis-cryptotrace.svg)](https://pypi.org/project/cognis-cryptotrace/)
[![CI](https://github.com/cognis-digital/cryptotrace/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/cryptotrace/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Free-tier blockchain investigator — ETH/BTC clustering + sanctions xref.

## Install

```bash
pip install cognis-cryptotrace
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
cryptotrace --version
cryptotrace scan demos/                          # run against bundled demo
cryptotrace scan demos/ --format sarif --out r.sarif --fail-on high
cryptotrace mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-ransom-payment-trace/` — see [`SCENARIO.md`](demos/01-ransom-payment-trace/SCENARIO.md)
- `demos/02-dao-treasury-analysis/` — see [`SCENARIO.md`](demos/02-dao-treasury-analysis/SCENARIO.md)
- `demos/03-suspect-ofac-probe/` — see [`SCENARIO.md`](demos/03-suspect-ofac-probe/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*

# Demo 01 - Tracing a Tornado Cash exit

A classic OSINT scenario: funds move from a known exchange hot wallet, get
mixed through a sanctioned Tornado Cash contract, and a co-spend (common-input)
links several otherwise-unrelated addresses into one entity.

## Input

`transfers.json` contains 6 directed transfers. Note that transfer `tx3`
lists two `inputs` (`0xaaa...` and `0xbbb...`) spent together in the same
transaction - the common-input heuristic will merge them into one cluster.
One of the destinations is the OFAC-listed Tornado.Cash router
(`0x722122df12d4e14e13ac3b6895a86e84145b6967`).

## Run

```bash
python -m cryptotrace investigate demos/01-basic/transfers.json
python -m cryptotrace --format json investigate demos/01-basic/transfers.json
python -m cryptotrace xref 0x722122df12d4e14e13ac3b6895a86e84145b6967
```

## What to look for

- The two co-spent addresses land in the **same cluster_id**.
- The cluster that touches the Tornado.Cash router is flagged
  `risk=sanctioned` and the `sanctions_hits` section lists the OFAC source.
- `xref` on a sanctioned address exits with code **2** (positive hit) so it can
  gate a shell pipeline.

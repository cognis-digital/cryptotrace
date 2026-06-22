"""feeds — live OFAC SDN ingestion wired into CRYPTOTRACE screening.

CRYPTOTRACE ships a small, hand-curated table of OFAC-sanctioned crypto wallets
(``core._OFAC_RAW``). This module makes the screen **current** by ingesting the
authoritative US Treasury OFAC SDN list (catalog feed ``ofac-sdn``) via the
bundled, stdlib-only :mod:`cryptotrace.datafeeds` engine and extracting every
``Digital Currency Address`` token OFAC publishes.

Real enrichment (not cosmetic): the parsed SDN crypto addresses are merged into
the live screening index, so :func:`cryptotrace.core.is_sanctioned` — and every
analysis built on it (taint propagation, clustering, peel-chain detection) —
reflects the full, up-to-date SDN designation set rather than only the bundled
seed.

Edge / air-gap:
  * keyless HTTPS fetch -> disk cache -> ``offline=True`` re-serve, all stdlib;
  * ``COGNIS_FEEDS_CACHE`` points the cache anywhere (e.g. a committed fixture);
  * snapshot export/import (see datafeeds) sneakernets the cache into an enclave.

Defensive / authorized-use sanctions screening only.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from . import datafeeds
from . import core

# Only the feed ids this tool is authorized to consume from the catalog.
RELEVANT_FEEDS = ["ofac-sdn"]

# OFAC writes crypto addresses in the SDN "remarks" field as, e.g.:
#   "Digital Currency Address - XBT 12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h; ..."
# One designee can carry many addresses across several currencies.
_DCA_RE = re.compile(
    r"Digital Currency Address\s*-\s*([A-Za-z0-9]+)\s+([A-Za-z0-9]+)"
)

# OFAC currency codes -> the asset hints CRYPTOTRACE uses internally.
_ASSET_MAP = {
    "XBT": "BTC", "BTC": "BTC", "ETH": "ETH", "USDT": "ETH", "USDC": "ETH",
    "XMR": "XMR", "LTC": "LTC", "BCH": "BCH", "BSV": "BSV", "DASH": "DASH",
    "ZEC": "ZEC", "XVG": "XVG", "ETC": "ETC", "TRX": "TRX", "BTG": "BTG",
    "ARB": "ETH", "BSC": "ETH", "XRP": "XRP",
}


def _require_relevant(feed_id: str) -> None:
    if feed_id not in RELEVANT_FEEDS:
        raise ValueError(
            f"feed {feed_id!r} is not wired into cryptotrace; "
            f"allowed: {RELEVANT_FEEDS}"
        )


def relevant_feeds() -> list[dict]:
    """Catalog entries this tool is allowed to consume."""
    catalog = datafeeds.load_catalog()
    by_id = {f["id"]: f for f in catalog.get("feeds", [])}
    return [by_id[i] for i in RELEVANT_FEEDS if i in by_id]


def update_feed(feed_id: str = "ofac-sdn") -> str:
    """Fetch + cache a relevant feed. Returns the cache path as a string."""
    _require_relevant(feed_id)
    return str(datafeeds.update(feed_id))


def get_feed(feed_id: str = "ofac-sdn", *, offline: bool = False) -> Any:
    """Return raw cached/fetched feed content (SDN CSV text)."""
    _require_relevant(feed_id)
    return datafeeds.get(feed_id, offline=offline)


# --------------------------------------------------------------------------- #
# SDN crypto-address extraction
# --------------------------------------------------------------------------- #
def _split_csv_line(line: str) -> list[str]:
    """Parse one OFAC SDN CSV record. OFAC quotes every field with '"' and uses
    ``"" `` for an embedded quote; commas live inside quoted fields, so a naive
    split breaks. Use the stdlib csv reader semantics on a single record."""
    import csv
    import io
    # OFAC puts a space after each comma, so the opening quote is not at the
    # raw field boundary -> skipinitialspace lets csv honor the quoting.
    return next(csv.reader(io.StringIO(line), skipinitialspace=True), [])


def parse_sdn_addresses(csv_text: str) -> list[dict[str, str]]:
    """Extract every ``Digital Currency Address`` from OFAC SDN CSV text.

    The SDN CSV columns are: ent_num, SDN_Name, SDN_Type, Program, Title,
    Call_Sign, Vess_type, Tonnage, GRT, Vess_flag, Vess_owner, Remarks.
    Crypto addresses are embedded in the final ``Remarks`` field.

    Returns a list of entries in the same schema as ``core._OFAC_RAW``:
    ``{address, asset, entity, program, added, category}``.
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in csv_text.splitlines():
        if "Digital Currency Address" not in raw:
            continue
        fields = _split_csv_line(raw)
        if len(fields) < 4:
            continue
        name = (fields[1] or "").strip().strip('"')
        program = (fields[3] or "").strip().strip('"')
        # Remarks is the last field; addresses can technically appear anywhere,
        # but scanning the whole record is robust to column drift.
        for m in _DCA_RE.finditer(raw):
            code, addr = m.group(1).upper(), m.group(2)
            asset = _ASSET_MAP.get(code, code)
            norm = addr.lower() if addr.lower().startswith("0x") else addr
            key = norm
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "address": addr,
                "asset": asset,
                "entity": name or "OFAC SDN designee",
                "program": program or "SDN",
                "added": "",  # SDN CSV does not carry a per-address listing date
                "category": "sdn",
            })
    return out


def load_sdn_into_index(*, offline: bool = False) -> int:
    """Ingest the live OFAC SDN list and merge its crypto addresses into the
    in-process screening index. Returns the number of addresses merged.

    This is the real enrichment: after calling it, ``core.is_sanctioned`` /
    ``analyze`` / ``propagate_taint`` screen against the full SDN designation
    set, not just the bundled seed.
    """
    csv_text = get_feed("ofac-sdn", offline=offline)
    if not isinstance(csv_text, str):
        csv_text = csv_text.decode("utf-8", "replace")
    entries = parse_sdn_addresses(csv_text)
    return merge_entries(entries)


def merge_entries(entries: list[dict[str, str]]) -> int:
    """Merge SDN entries into core's OFAC index in place (idempotent)."""
    merged = 0
    for e in entries:
        norm = core._norm_addr(e["address"])
        if norm in core._OFAC_INDEX:
            continue
        core._OFAC_INDEX[norm] = e
        merged += 1
    return merged


def sdn_summary(entries: list[dict[str, str]]) -> dict[str, int]:
    """Per-asset counts for a parsed SDN address set (for reporting)."""
    summary: dict[str, int] = {}
    for e in entries:
        summary[e["asset"]] = summary.get(e["asset"], 0) + 1
    return summary

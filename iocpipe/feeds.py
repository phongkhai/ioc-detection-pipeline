# Threat-intel feed ingestion.
# Pulls indicators from abuse.ch ThreatFox and normalizes them
# into Indicator objects. Includes an offline sample mode so the tool runs end to
# end without network access or an API key — for testing and demos.

# Note: abuse.ch now requires a free Auth-Key for API access. Sign up at
# https://auth.abuse.ch/ and set it as the THREATFOX_API_KEY environment variable.
 
# Add another feed later (URLhaus, OTX, MISP), write a new fetch_* function
# that returns list[Indicator]. The rest of the pipeline doesnt change.


from __future__ import annotations

import json
import os
from pathlib import Path

import requests

from .models import Indicator

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Map ThreatFox's ioc_type labels onto our normalized IOC_TYPES.
_THREATFOX_TYPE_MAP = {
    "domain": "domain",
    "url": "url",
    "ip:port": "ip_port",
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
}


def _normalize_threatfox(raw: dict) -> Indicator:
    # Turn one raw ThreatFox record into a normalized Indicator
    ioc_type = _THREATFOX_TYPE_MAP.get(raw.get("ioc_type", ""), raw.get("ioc_type", ""))
    return Indicator(
        value=raw.get("ioc", ""),
        ioc_type=ioc_type,
        malware=raw.get("malware_printable") or raw.get("malware"),
        threat_type=raw.get("threat_type"),
        confidence=raw.get("confidence_level"),
        first_seen=raw.get("first_seen"),
        source="threatfox",
        reference=raw.get("reference"),
        tags=list(raw.get("tags") or []),
    )


def fetch_threatfox(days: int = 1, limit: int | None = None) -> list[Indicator]:
    # Fetch recent IOCs from the live ThreatFox API.
    # Requires THREATFOX_API_KEY in the environment.
    
    api_key = os.environ.get("THREATFOX_API_KEY")
    if not api_key:
        raise RuntimeError(
            "THREATFOX_API_KEY is not set. Get a free key at https://auth.abuse.ch/ "
            "or run with --use-sample to test offline."
        )

    resp = requests.post(
        THREATFOX_URL,
        headers={"Auth-Key": api_key},
        json={"query": "get_iocs", "days": days},
        timeout=30,
    )
    resp.raise_for_status()
    payload = resp.json()

    if payload.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox returned: {payload.get('query_status')}")

    records = payload.get("data", [])
    if limit:
        records = records[:limit]
    return [_normalize_threatfox(r) for r in records]


def load_sample(path: str | Path | None = None, limit: int | None = None) -> list[Indicator]:
    """Load bundled sample data so the pipeline runs without network/API key."""
    if path is None:
        path = Path(__file__).resolve().parent.parent / "data" / "sample_threatfox.json"
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    records = payload.get("data", [])
    if limit:
        records = records[:limit]
    return [_normalize_threatfox(r) for r in records]

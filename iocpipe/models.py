# Core data model for threat indicators.

# Everything in the pipeline flows through the Indicator dataclass: feeds produce
# them, enrichment decorates them, ATT&CK mapping tags them, and the Sigma module
# turns them into detection rules. Keeping one normalized shape is what lets the
# tool ingest multiple feeds later without rewriting the rest of the pipeline.


from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional


# IOC types we normalize to. Different feeds use different labels for the same
# thing (e.g. "md5_hash" vs "file-md5"); normalize at the feed layer to these.
IOC_TYPES = {"domain", "url", "ip", "ip_port", "md5", "sha1", "sha256", "email"}


@dataclass
class Indicator:
    #A single normalized threat indicator

    value: str                         # the IOC (the domain, hash, etc.)
    ioc_type: str                      # one of IOC_TYPES
    malware: Optional[str] = None      # readable malware family, if known
    threat_type: Optional[str] = None  # e.g. botnet_cc, payload_delivery
    confidence: Optional[int] = None   # 0-100 if the feed provides it
    first_seen: Optional[str] = None   # ISO timestamp from feed
    source: Optional[str] = None       # which feed it came from
    reference: Optional[str] = None    # link back to the feed entry
    tags: list[str] = field(default_factory=list)

    # Populated later in the pipeline:
    attack_techniques: list[str] = field(default_factory=list)  # ATT&CK IDs
    enrichment: dict = field(default_factory=dict)              # VT/Shodan data

    def __post_init__(self) -> None:
        if self.ioc_type not in IOC_TYPES:
            # Dont crash the whole run on one odd record - flag it instead
            self.tags.append(f"unrecognized_ioc_type:{self.ioc_type}")

    def to_dict(self) -> dict:
        return asdict(self)

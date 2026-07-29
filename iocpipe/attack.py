# Map indicators to MITRE ATT&CK techniques.

# Note: A seed mapping is provided so the pipeline produces output
# Expand it and decide on a mapping strategy. Two approaches to consider:
# 1. By malware family (what's seeded below) — coarse but easy.
# 2. By threat_type + ioc_type — e.g. a botnet_cc domain implies T1071.001
# (Application Layer Protocol: Web Protocols) regardless of family.

# The ATT&CK technique list: https://attack.mitre.org/techniques/enterprise/


from __future__ import annotations

from .models import Indicator

# Seed: malware family -> ATT&CK technique IDs. EXPAND THIS.
# (Techniques shown are illustrative starting points, not an authoritative map —
# verify each against the ATT&CK site and the actual malware behavior.)
_FAMILY_TO_ATTACK: dict[str, list[str]] = {
    "Cobalt Strike": ["T1071.001", "T1059.003", "T1055"],
    "QakBot": ["T1566.001", "T1059.003", "T1071.001"],
    "IcedID": ["T1071.001", "T1055", "T1547.001"],
    "Emotet": ["T1566.001", "T1071.001", "T1547.001"],
    "LockBit": ["T1486", "T1490", "T1027"],
}

# TODO: add a threat_type -> technique fallback so indicators with an
# unknown family still get mapped from their behavior. Example to start from:
_THREAT_TYPE_TO_ATTACK: dict[str, list[str]] = {
    "botnet_cc": ["T1071.001"],   # C2 over web protocols
    # "payload_delivery": [...],
    # "payload": [...],
}


def map_to_attack(indicator: Indicator) -> Indicator:
    "Attach ATT&CK technique IDs to an indicator (mutates and returns it)."
    techniques: list[str] = []

    if indicator.malware and indicator.malware in _FAMILY_TO_ATTACK:
        techniques.extend(_FAMILY_TO_ATTACK[indicator.malware])

    # TODO: fall back to threat_type mapping when family is unknown,
    # and de-duplicate while preserving order.
    if indicator.threat_type in _THREAT_TYPE_TO_ATTACK:
        techniques.extend(_THREAT_TYPE_TO_ATTACK[indicator.threat_type])

    indicator.attack_techniques = list(dict.fromkeys(techniques))  # deduplication
    return indicator

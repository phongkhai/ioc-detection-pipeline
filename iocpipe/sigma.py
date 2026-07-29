# Generates Sigma detection rules from Indicator objects. Dispatches by
# ioc_type to type-specific rule builders (network, hash, IP), all sharing
# a common skeleton via _base_rule.


#Sigma spec reference: https://github.com/SigmaHQ/sigma


from __future__ import annotations

import re
from typing import Optional

import yaml
from .models import Indicator


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _base_rule(indicator: Indicator, title: str, logsource: dict, detection: dict) -> dict:
    # Assemble the common Sigma skeleton shared by all rule types
    tags = [f"attack.{t.lower()}" for t in indicator.attack_techniques]  # ATT&CK tags
    rule = {
        "title": title,
        "status": "experimental",
        "description": f"Detects activity associated with {indicator.malware or 'a known threat'} "
                       f"(source: {indicator.source}).",
        "references": [indicator.reference] if indicator.reference else [],
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "level": "high",
    }
    return rule


def _network_rule(indicator: Indicator) -> Optional[dict]:
    # Sigma rule for domain/url indicators (proxy/dns telemetry)
    if indicator.ioc_type == "domain":
        detection = {
            "selection": {"query": indicator.value},
            "condition": "selection",
        }
        logsource = {"category": "dns_query"}
    elif indicator.ioc_type == "url":
        detection = {
            "selection": {"c-uri|contains": indicator.value},
            "condition": "selection",
        }
        logsource = {"category": "proxy"}
    else:
        return None

    title = f"{indicator.malware or 'Threat'} network IOC: {indicator.value}"
    return _base_rule(indicator, title, logsource, detection)


def _hash_rule(indicator: Indicator) -> Optional[dict]:
    # Sigma rule for file-hash indicators (process-creation / file events).
    field = {"md5": "Hashes|contains", "sha1": "Hashes|contains",
             "sha256": "Hashes|contains"}.get(indicator.ioc_type)
    if not field:
        return None

    detection = {
        "selection": {field: indicator.value},
        "condition": "selection",
    }
    logsource = {"category": "process_creation", "product": "windows"}
    title = f"{indicator.malware or 'Threat'} file hash: {indicator.value[:16]}..."
    return _base_rule(indicator, title, logsource, detection)

def _ip_rule(indicator: Indicator) -> Optional[dict]:
    if indicator.ioc_type not in ("ip", "ip_port"):
        return None

    if indicator.ioc_type == "ip_port":
        try:
            ip, port = indicator.value.rsplit(":", 1)
            port = int(port)
        except ValueError:
            return None
        detection = {
            "selection": {"DestinationIp": ip, "DestinationPort": port},
            "condition": "selection",
        }
    else:
        detection = {
            "selection": {"DestinationIp": indicator.value},
            "condition": "selection",
        }

    logsource = {"category": "network_connection"}
    title = f"{indicator.malware or 'Threat'} IP: {indicator.value}"
    return _base_rule(indicator, title, logsource, detection)


def to_sigma(indicator: Indicator) -> Optional[str]:
    # Return a Sigma rule (YAML string) for an indicator, or None if unsupported.
    rule = _network_rule(indicator) or _hash_rule(indicator) or _ip_rule(indicator)
    if rule is None:
        return None
    return yaml.safe_dump(rule, sort_keys=False, default_flow_style=False)

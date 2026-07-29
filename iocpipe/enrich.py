# Indicator enrichment via third-party APIs

# VirusTotal (free tier, 4 requests/min).
# - Endpoint: https://www.virustotal.com/api/v3/<files|domains|ip_addresses>/<id>
# - Header:   x-apikey: <key>
# - Pull the malicious/suspicious vote counts and last_analysis_stats, store the useful bits in 
# indicator.enrichment, and dont let one failed lookup kill the whole run.

# A good stretch: add Shodan for ip/ip_port indicators (open ports, banners).


from __future__ import annotations

import os
import time

from .models import Indicator

VT_BASE = "https://www.virustotal.com/api/v3"


def enrich_virustotal(indicator: Indicator) -> Indicator:
  # Enrich an indicator with VirusTotal data.

  # TODO:  
  # 1. Read VT_API_KEY from the environment; if missing, return the indicator unchanged
  # 2. Pick the right VT endpoint based on indicator.ioc_type.
  # 3. requests.get(...) with the x-apikey header, handle non-200 gracefully.
  # 4. Store results in indicator.enrichment["virustotal"] = {...}
  # 5. Respect the free-tier rate limit (sleep between calls)

    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return indicator  # enrichment is optional; no key = skip cleanly

    # 4 req/min free-tier limit:
    # time.sleep(15)
    return indicator
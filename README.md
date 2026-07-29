# ioc-detection-pipeline

A Python CLI tool that turns raw threat intelligence into deployable detection rules.
Pulls IOCs from ThreatFox, normalizes them into a common Indicator dataclass, maps
them to MITRE ATT&CK techniques, and generates Sigma detection rules as YAML.
Sigma rules are vendor-neutral and can be converted to Splunk, Elastic, or Microsoft Sentinel queries.


## What it does

- Pulls indicators from ThreatFox (live API or a bundled sample file for offline).
- Normalizes each indicator into a common Indicator dataclass.
- Maps indicators to MITRE ATT&CK techniques based on malware family.
- Generates Sigma detection rules for supported indicator types:
    - Domains (dns_query logsource)
    - URLs (proxy logsource)
    - File hashes: MD5, SHA1, SHA256 (process_creation logsource)
    - IPs and IP:port pairs (network_connection logsource)
- Writes normalized indicators to JSON or CSV.
- VirusTotal enrichment (in progress).


## Setup

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    

## Usage

Run offline against the bundled sample data:

    python -m iocpipe --use-sample --sigma

This reads data/sample_threatfox.json, writes normalized indicators to
out/iocs.json, and writes generated Sigma rules to sigma/.

For live data, set THREATFOX_API_KEY in .env and run

    python -m iocpipe --days 1 --limit 50 --sigma


## Flags

    --use-sample      Use bundled sample data instead of live API.
    --days N          Days of IOCs to pull (live mode). Default: 1.
    --limit N         Cap number of indicators.
    --sigma           Also write Sigma rules to sigma/.
    --enrich          Run VirusTotal API. (in progress)
    --format FMT      json or csv. Default: json.
    --out PATH        Output file path. Default: out/iocs.json.


## Project structure 


```
  iocpipe/
    __init__.py
    __main__.py       Entry point for python -m iocpipe
    cli.py            Argument parsing and pipeline orchestration
    models.py         Indicator dataclass
    feeds.py          ThreatFox ingestion (live + sample)
    attack.py         MITRE ATT&CK mapping
    sigma.py          Sigma rule generation
    enrich.py         VirusTotal enrichment (optional)
  data/
    sample_threatfox.json   Bundled sample for offline dev
  requirements.txt
  README.md
```


## TODO

    - VirusTotal enrichment with rate limiting
    - Second feed (URLhaus)
    - Behavior-based ATT&CK fallback for unknown malware families
    - pySigma validation of generated rules
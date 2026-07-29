# Command-line interface for the IOC -> detection pipeline.
# Example: python -m iocpipe --use-sample --sigma

# Runs offline against bundled sample data and writes JSON + Sigma rules.



from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from . import feeds
from .attack import map_to_attack
from .enrich import enrich_virustotal
from .models import Indicator
from .sigma import to_sigma, _slug


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="iocpipe", description="Pull threat IOCs, "
                                "map to ATT&CK, and generate Sigma detection rules.")
    p.add_argument("--use-sample", action="store_true",
                   help="Use bundled offline sample data instead of the live API.")
    p.add_argument("--days", type=int, default=1, help="Days of IOCs to pull (live mode).")
    p.add_argument("--limit", type=int, default=None, help="Cap number of indicators.")
    p.add_argument("--enrich", action="store_true",
                   help="Run VirusTotal enrichment (needs VT_API_KEY). Phase 2.")
    p.add_argument("--sigma", action="store_true",
                   help="Also write generated Sigma rules to the sigma/ folder.")
    p.add_argument("--format", choices=["json", "csv"], default="json",
                   help="Output format for the indicator table.")
    p.add_argument("--out", default="out/iocs.json", help="Output file path.")
    return p.parse_args(argv)


def _write_json(indicators: list[Indicator], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([i.to_dict() for i in indicators], fh, indent=2)


def _write_csv(indicators: list[Indicator], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = ["value", "ioc_type", "malware", "threat_type", "confidence",
            "first_seen", "source", "attack_techniques"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for i in indicators:
            row = i.to_dict()
            row["attack_techniques"] = ";".join(row.get("attack_techniques") or [])
            w.writerow([row.get(c, "") for c in cols])


def _write_sigma(indicators: list[Indicator], out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for i in indicators:
        rule = to_sigma(i)
        if rule is None:
            continue
        fname = f"{_slug((i.malware or 'threat'))}_{_slug(i.value)[:24]}.yml"
        (out_dir / fname).write_text(rule, encoding="utf-8")
        count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    # 1. Ingest
    if args.use_sample:
        indicators = feeds.load_sample(limit=args.limit)
        print(f"- Loaded {len(indicators)} indicators from sample data.")
    else:
        try:
            indicators = feeds.fetch_threatfox(days=args.days, limit=args.limit)
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1
        print(f"- Pulled {len(indicators)} indicators from ThreatFox.")

    # 2. Map to ATT&CK
    indicators = [map_to_attack(i) for i in indicators]

    # 3. Enrich (optional, Phase 2)
    if args.enrich:
        indicators = [enrich_virustotal(i) for i in indicators]

    # 4. Output the indicator table
    out_path = Path(args.out)
    if args.format == "json":
        _write_json(indicators, out_path)
    else:
        _write_csv(indicators, out_path)
    print(f"- Wrote {len(indicators)} indicators to {out_path}")

    # 5. Generate Sigma rules (optional)
    if args.sigma:
        n = _write_sigma(indicators, Path("sigma"))
        print(f"- Generated {n} Sigma rules in ./sigma/")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

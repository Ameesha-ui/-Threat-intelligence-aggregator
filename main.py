"""
Threat Intelligence Aggregator (Non-AI)
Main Command Line Interface and Pipeline Orchestrator.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List

from threat_aggregator.models import FeedDefinition, Severity
from threat_aggregator.collector import FeedCollector
from threat_aggregator.normalizer import NormalizationEngine
from threat_aggregator.correlation import CorrelationEngine
from threat_aggregator.blocklist import BlocklistGenerator
from threat_aggregator.reporter import ThreatReporter

# Ensure console output safely handles Unicode characters on all platforms
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        print(f"[!] Warning: Config file '{config_path}' not found. Using defaults.")
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_pipeline(
    config_file: str = "config.json",
    filter_bogons: bool = False,
    min_severity: str = "LOW"
):
    print("=" * 70)
    print("   THREAT INTELLIGENCE AGGREGATOR (NON-AI)")
    print("   Automated Collection, Normalization, Correlation & Blocklists")
    print("=" * 70)

    cfg_path = Path(config_file)
    config = load_config(cfg_path)

    # 1. Prepare Feeds
    feed_defs_raw = config.get("feeds", [])
    feed_definitions: List[FeedDefinition] = []
    feed_weights = {}

    for f in feed_defs_raw:
        fdef = FeedDefinition(
            name=f.get("name", "UnnamedFeed"),
            format=f.get("format", "txt"),
            path_or_url=f.get("path_or_url", ""),
            enabled=f.get("enabled", True),
            weight=float(f.get("weight", 1.0)),
            category=f.get("category", "osint"),
            default_tags=f.get("default_tags", []),
            max_indicators=f.get("max_indicators")
        )
        feed_definitions.append(fdef)
        feed_weights[fdef.name] = fdef.weight

    print(f"\n[*] STEP 1: Ingesting feeds ({len(feed_definitions)} configured)...")
    collector = FeedCollector()
    raw_indicators, feed_audit = collector.collect(feed_definitions)
    print(f"[+] Ingested {len(raw_indicators)} raw indicator instances.")

    # 2. Normalize and Deduplicate
    print("\n[*] STEP 2 & 3: Parsing and Normalizing Indicators...")
    normalizer = NormalizationEngine(filter_bogons=filter_bogons)
    normalized_iocs = normalizer.normalize(raw_indicators)
    print(f"[+] Deduplicated & Normalized into {len(normalized_iocs)} unique canonical IOC records.")

    # 3. Correlation Engine
    print("\n[*] STEP 4: Executing Cross-Feed Correlation & Risk Scoring...")
    correlator = CorrelationEngine(feed_weights=feed_weights)
    correlated_iocs = correlator.correlate(normalized_iocs)
    correlation_stats = correlator.generate_correlation_matrix(correlated_iocs)
    print(f"[+] Correlation Complete: {correlation_stats['total_repeated_iocs']} multi-feed repeated threats identified.")

    # 4. Generate Defensive Blocklists
    print("\n[*] STEP 5: Generating Targeted Defensive Blocklists...")
    out_dirs = config.get("outputs", {})
    blocklists_dir = Path(out_dirs.get("blocklists_dir", "output/blocklists"))
    blocklist_gen = BlocklistGenerator(correlated_iocs)
    sev_map = {
        "LOW": Severity.LOW,
        "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH,
        "CRITICAL": Severity.CRITICAL,
    }
    target_sev = sev_map.get(min_severity.upper(), Severity.LOW)
    blocklist_counts = blocklist_gen.export_all(blocklists_dir, min_severity=target_sev)
    for b_name, count in blocklist_counts.items():
        print(f"    - {b_name:<24}: {count} indicators")

    # 5. Reporting
    print("\n[*] STEP 6: Generating Executive & Technical Reports...")
    reports_dir = Path(out_dirs.get("reports_dir", "output/reports"))
    db_dir = Path(out_dirs.get("database_dir", "output/database"))
    db_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    reporter = ThreatReporter(correlated_iocs, feed_audit, correlation_stats)
    
    # Export reports
    reporter.export_json(db_dir / "normalized_iocs.json")
    reporter.export_json(reports_dir / "threat_report.json")
    reporter.export_csv(reports_dir / "threat_report.csv")
    reporter.export_markdown(reports_dir / "threat_report.md")
    reporter.export_html(reports_dir / "threat_report.html")

    print("[+] Exported Artifacts:")
    print(f"    - Database  : {db_dir / 'normalized_iocs.json'}")
    print(f"    - Blocklists: {blocklists_dir}")
    print(f"    - HTML SOC  : {reports_dir / 'threat_report.html'}")
    print(f"    - Markdown  : {reports_dir / 'threat_report.md'}")

    # Print summary to console
    reporter.print_cli_summary()
    return correlated_iocs


def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator (Non-AI) - Collect, Normalize, Correlate, and Enforce IOCs."
    )
    parser.add_argument("--config", "-c", default="config.json", help="Path to configuration JSON file")
    parser.add_argument("--filter-bogons", action="store_true", help="Filter out RFC1918 and Bogon IP addresses")
    parser.add_argument("--min-severity", default="LOW", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Minimum severity filter")
    parser.add_argument("--serve", action="store_true", help="Launch interactive local web dashboard")
    parser.add_argument("--port", type=int, default=8080, help="Port for web dashboard (default: 8080)")
    parser.add_argument("--interval", "-i", type=int, default=None, help="Recurring execution interval in seconds for scheduled feed polling")

    args = parser.parse_args()

    if args.serve:
        import server
        server.start_server(port=args.port)
    elif args.interval and args.interval > 0:
        print(f"[*] Starting recurring threat aggregator service (polling every {args.interval}s)...")
        print("[*] Press Ctrl+C to terminate the scheduler.\n")
        cycle = 1
        try:
            while True:
                print(f"\n{'#' * 70}")
                print(f"   SCHEDULED RUN CYCLE #{cycle} - {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
                print(f"{'#' * 70}")
                run_pipeline(
                    config_file=args.config,
                    filter_bogons=args.filter_bogons,
                    min_severity=args.min_severity
                )
                print(f"\n[*] Cycle #{cycle} completed. Sleeping for {args.interval} seconds...")
                cycle += 1
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Scheduler stopped by user.")
    else:
        run_pipeline(
            config_file=args.config,
            filter_bogons=args.filter_bogons,
            min_severity=args.min_severity
        )


if __name__ == "__main__":
    main()

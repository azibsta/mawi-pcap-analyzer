#!/usr/bin/env python3
"""
analyze.py — CLI entry point for the MAWI PCAP Research Analyzer.

Examples
--------
# Single year
python analyze.py --year 2015

# Year range
python analyze.py --from 2006 --to 2025

# Force re-parse (ignore Parquet cache)
python analyze.py --from 2010 --to 2020 --no-cache

# Export results
python analyze.py --from 2006 --to 2025 --export csv
python analyze.py --from 2006 --to 2025 --export json
python analyze.py --from 2006 --to 2025 --export both

# Show milestone events
python analyze.py --from 2006 --to 2025 --milestones

# Use a different anomaly metric
python analyze.py --from 2006 --to 2025 --anomaly-metric udp_pkts

# Limit packets per PCAP (quick exploratory mode)
python analyze.py --year 2018 --max-packets 1000000
"""

import argparse
import sys
from pathlib import Path

# Allow running from the project root without installing
sys.path.insert(0, str(Path(__file__).parent))

import config  # noqa: E402  (patches DATA_DIR before anything imports it)
from pipeline import run_pipeline, export_csv, export_json, export_milestones


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="analyze.py",
        description="MAWI PCAP Research Analyzer — offline protocol trend analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Year selection (mutually exclusive: --year OR --from/--to)
    year_group = parser.add_mutually_exclusive_group(required=True)
    year_group.add_argument(
        "--year", type=int, metavar="YYYY",
        help="Analyze a single year",
    )
    year_group.add_argument(
        "--from", dest="year_from", type=int, metavar="YYYY",
        help="Start year (use with --to)",
    )

    parser.add_argument(
        "--to", dest="year_to", type=int, metavar="YYYY",
        default=config.YEAR_MAX,
        help=f"End year (default: {config.YEAR_MAX})",
    )

    # Engine
    parser.add_argument(
        "--build", action="store_true",
        help="(Re-)compile the C++ engine (mawi_engine.cpp) before running",
    )
    parser.add_argument(
        "--no-cpp", action="store_true",
        help="Disable C++ engine; always use Python dpkt parser",
    )

    # Cache
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Ignore existing Parquet cache and re-parse PCAPs",
    )

    # Output
    parser.add_argument(
        "--export", choices=["csv", "json", "both"], default=None,
        help="Export results to reports/ directory",
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Print cross-year summary table (always on by default)",
    )
    parser.add_argument(
        "--milestones", action="store_true",
        help="Print protocol transition milestone events",
    )

    # Analysis options
    parser.add_argument(
        "--anomaly-metric", default="total_packets",
        metavar="COLUMN",
        help="Column to use for cross-year anomaly Z-score (default: total_packets)",
    )
    parser.add_argument(
        "--max-packets", type=int, default=None, metavar="N",
        help="Stop parsing each PCAP after N packets (exploratory mode)",
    )

    # Data path override
    parser.add_argument(
        "--data-dir", type=Path, default=None,
        help="Override DATA_DIR (default: ./data/)",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Override config if requested
    if args.data_dir:
        config.DATA_DIR = args.data_dir.resolve()
        print(f"[config] DATA_DIR set to {config.DATA_DIR}")

    if args.max_packets:
        config.MAX_PACKETS_PER_FILE = args.max_packets
        print(f"[config] MAX_PACKETS_PER_FILE set to {args.max_packets:,}")

    # Resolve year range
    if args.year:
        years = [args.year]
    else:
        if args.year_to < args.year_from:
            print(f"[error] --to ({args.year_to}) must be >= --from ({args.year_from})")
            sys.exit(1)
        years = list(range(args.year_from, args.year_to + 1))

    # ── Engine setup ──────────────────────────────────────────────────────────
    use_cpp = not args.no_cpp
    if args.build:
        try:
            from cpp_bridge import build_engine
            build_engine(force=True)
        except Exception as e:
            print(f"[build error] {e}")
            sys.exit(1)

    # ── Run pipeline ──────────────────────────────────────────────────────────
    summary = run_pipeline(
        years=years,
        use_cache=not args.no_cache,
        use_cpp=use_cpp,
        anomaly_metric=args.anomaly_metric,
        verbose=True,
    )

    if summary.empty:
        print("[error] Pipeline produced no results. Exiting.")
        sys.exit(1)

    # ── Optional outputs ──────────────────────────────────────────────────────
    if args.milestones:
        export_milestones(summary)

    if args.export in ("csv", "both"):
        export_csv(summary)

    if args.export in ("json", "both"):
        export_json(summary)

    print("[done]")


if __name__ == "__main__":
    main()

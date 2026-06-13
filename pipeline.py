"""
pipeline.py

Orchestrates the full research pipeline:
  1. Discover PCAP files per year under DATA_DIR/<year>/
  2. Load from Parquet cache if available; otherwise parse + cache
  3. Parse via C++ engine (mawi_engine) if compiled, else Python dpkt
  4. Run Python analyzers (encryption, anomaly, cross-year derived metrics)
  5. Assemble per-year summary rows
  6. Compute cross-year derived metrics and anomaly scores
  7. Export results

Engine selection (automatic):
    C++ engine available → used for raw PCAP parsing (much faster)
    C++ engine missing   → falls back to Python dpkt parser transparently

Usage (programmatic):
    from pipeline import run_pipeline
    summary_df = run_pipeline(years=range(2010, 2020), use_cache=True)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable

import pandas as pd

from config import DATA_DIR, CACHE_DIR, REPORT_DIR, MAX_PACKETS_PER_FILE
from analyzers.transport   import parse_year, transport_stats
from analyzers.application import classify_dataframe, application_stats
from analyzers.encryption  import encryption_stats
from analyzers.anomaly     import daily_burst_stats, scan_signatures, add_anomaly_scores
from analyzers.summary     import compute_derived_metrics, milestone_report, print_summary_table

# C++ engine bridge (optional — falls back to Python if not compiled)
try:
    from cpp_bridge import (
        run_engine_year, engine_available,
        build_engine, print_engine_status, CppEngineNotFound,
    )
    _CPP_AVAILABLE = engine_available()
except ImportError:
    _CPP_AVAILABLE = False
    def run_engine_year(*a, **kw): return None       # type: ignore
    def engine_available(): return False             # type: ignore
    def build_engine(**kw): pass                     # type: ignore
    def print_engine_status(): pass                  # type: ignore


# ── Cache helpers ───────────────────────────────────────────────────────────────

def _cache_path(year: int) -> Path:
    return CACHE_DIR / f"{year}.parquet"


def _load_cache(year: int) -> pd.DataFrame | None:
    p = _cache_path(year)
    if p.exists():
        print(f"  [cache] Loading {year} from {p.name}")
        return pd.read_parquet(p)
    return None


def _save_cache(year: int, df: pd.DataFrame) -> None:
    p = _cache_path(year)
    df.to_parquet(p, index=False, compression="snappy")
    size_mb = p.stat().st_size / 1e6
    print(f"  [cache] Saved {p.name} ({size_mb:.1f} MB)")


# ── Per-year processing ─────────────────────────────────────────────────────────

def process_year(
    year: int,
    use_cache: bool = True,
    use_cpp: bool = True,
) -> dict | None:
    """
    Parse (or load from cache) one year's PCAP data and run all analyzers.

    Engine selection (automatic):
      1. Parquet cache hit           → skip parsing entirely
      2. C++ engine available        → fast native PCAP parse → JSON row
      3. Fallback                    → Python dpkt parse → DataFrame

    After parsing, Python-only analyzers (encryption payload heuristics,
    burst detection, scan signatures) augment the row regardless of engine.

    Returns a flat dict representing one row in the cross-year summary,
    or None if no data found for the year.
    """
    year_dir = DATA_DIR / str(year)
    if not year_dir.exists():
        print(f"  [skip] {year} — no directory at {year_dir}")
        return None

    # ── 1. Parquet cache ───────────────────────────────────────────────────────
    # Cache stores the raw packet DataFrame (Python path) OR a sentinel
    # parquet with a 'cpp_row' column (C++ path).
    cache_hit = _load_cache(year) if use_cache else None

    # C++ path: cache stores a single-row DataFrame tagged with source='cpp'
    if cache_hit is not None and "cpp_source" in cache_hit.columns:
        print(f"  [cache] {year} — loading C++ summary from cache")
        row = cache_hit.iloc[0].to_dict()
        row["year"] = year
        # Still run Python-only extras that don't need the full packet DF
        row.update(_python_extras_no_df(row))
        return row

    # Python path: cache stores full packet DataFrame
    if cache_hit is not None and not cache_hit.empty and "cpp_source" not in cache_hit.columns:
        print(f"  [cache] {year} — loading packet DataFrame from cache")
        df = cache_hit
        df = classify_dataframe(df)
        row: dict = {"year": year}
        row.update(transport_stats(df))
        row.update(application_stats(df))
        row.update(encryption_stats(df))
        row.update(daily_burst_stats(df))
        row.update(scan_signatures(df))
        return row

    # ── 2. C++ engine path ────────────────────────────────────────────────────
    if use_cpp and _CPP_AVAILABLE:
        print(f"  [C++] {year} — parsing via mawi_engine …")
        cpp_row = run_engine_year(year_dir, max_packets=MAX_PACKETS_PER_FILE)
        if cpp_row:
            cpp_row["year"] = year
            cpp_row.update(_python_extras_no_df(cpp_row))
            # Cache as a single-row DataFrame tagged so we know it came from C++
            cache_df = pd.DataFrame([cpp_row])
            cache_df["cpp_source"] = True
            _save_cache(year, cache_df)
            return cpp_row

        print(f"  [warn] {year} — C++ engine returned nothing; falling back to Python")

    # ── 3. Python dpkt fallback ───────────────────────────────────────────────
    print(f"  [Python] {year} — parsing via dpkt …")
    t0 = time.time()
    try:
        df = parse_year(year_dir, max_packets=MAX_PACKETS_PER_FILE)
    except FileNotFoundError as e:
        print(f"  [error] {e}")
        return None

    if df.empty:
        print(f"  [warn] {year} — parsed 0 packets")
        return None

    elapsed = time.time() - t0
    print(f"  [Python] {year} — {len(df):,} packets in {elapsed:.1f}s")
    _save_cache(year, df)

    df = classify_dataframe(df)
    row = {"year": year}
    row.update(transport_stats(df))
    row.update(application_stats(df))
    row.update(encryption_stats(df))
    row.update(daily_burst_stats(df))
    row.update(scan_signatures(df))
    return row


def _python_extras_no_df(row: dict) -> dict:
    """
    Python-only derived fields that don't need the full packet DataFrame.
    Applied to C++ engine output to augment it with fields the C++ binary
    doesn't compute (e.g. entropy-based encryption estimate).
    """
    extras: dict = {}

    total = row.get("total_packets", 1) or 1

    # Burst ratio from capture timestamps (C++ provides first_ts / last_ts)
    dur = row.get("capture_duration_sec", 0) or \
          (row.get("last_ts", 0) - row.get("first_ts", 0))
    extras["capture_duration_sec"] = dur

    # Simple SYN flood ratio
    syn  = row.get("tcp_syn", 0)
    ack  = row.get("tcp_ack", 0)
    extras["syn_ack_ratio"] = round(syn / ack, 4) if ack else 0.0

    # RST/FIN ratio (port scan indicator from your original heuristics)
    rst = row.get("tcp_rst", 0)
    fin = row.get("tcp_fin", 0)
    extras["rst_fin_ratio"] = round(rst / fin, 4) if fin else 0.0

    # Anomaly rate
    extras["anomaly_rate_pct"] = round(
        row.get("anomaly_pkts", 0) / total * 100, 4)

    return extras


# ── Full pipeline ───────────────────────────────────────────────────────────────

def run_pipeline(
    years: Iterable[int],
    use_cache: bool = True,
    use_cpp: bool = True,
    anomaly_metric: str = "total_packets",
    verbose: bool = True,
) -> pd.DataFrame:
    """
    Run the full research pipeline for the given years.

    Parameters
    ----------
    years         : Iterable of integer years to process.
    use_cache     : If True, load cached Parquet instead of re-parsing.
    use_cpp       : If True (default), use the compiled C++ engine for PCAP
                    parsing. Falls back to Python dpkt if binary not found.
    anomaly_metric: Column used for cross-year Z-score anomaly detection.
    verbose       : Print progress to stdout.

    Returns
    -------
    pd.DataFrame  : One row per year with all analysis columns + derived metrics.
    """
    year_list = sorted(set(years))

    print(f"\n{'='*60}")
    print(f"  MAWI Pipeline  |  {len(year_list)} years: {year_list[0]}–{year_list[-1]}")
    if use_cpp:
        print_engine_status()
    else:
        print("  [engine] C++ engine disabled — using Python dpkt parser")
    print(f"{'='*60}")

    rows: list[dict] = []

    for year in year_list:
        print(f"\n[{year}]")
        row = process_year(year, use_cache=use_cache, use_cpp=use_cpp)
        if row:
            rows.append(row)

    if not rows:
        print("\n[pipeline] No data produced. Check DATA_DIR and PCAP paths.")
        return pd.DataFrame()

    summary = pd.DataFrame(rows).sort_values("year").reset_index(drop=True)

    # ── Cross-year derived metrics ─────────────────────────────────────────────
    summary = compute_derived_metrics(summary)

    # ── Anomaly scoring ────────────────────────────────────────────────────────
    if anomaly_metric in summary.columns:
        summary = add_anomaly_scores(summary, metric=anomaly_metric)
    else:
        print(f"  [warn] anomaly_metric '{anomaly_metric}' not in columns; skipping Z-score.")

    if verbose:
        print_summary_table(summary)

    return summary


# ── Export helpers ──────────────────────────────────────────────────────────────

def export_csv(summary: pd.DataFrame, label: str = "") -> Path:
    years = summary["year"].agg(["min", "max"])
    fname = f"trends_{int(years['min'])}_{int(years['max'])}"
    if label:
        fname += f"_{label}"
    fname += ".csv"
    out = REPORT_DIR / fname
    summary.to_csv(out, index=False)
    print(f"\n[export] CSV  -> {out}")
    return out


def export_json(summary: pd.DataFrame, label: str = "") -> Path:
    years = summary["year"].agg(["min", "max"])
    fname = f"trends_{int(years['min'])}_{int(years['max'])}"
    if label:
        fname += f"_{label}"
    fname += ".json"
    out = REPORT_DIR / fname

    milestones = milestone_report(summary)
    summary = summary.fillna(0)  # Convert NaN to 0 for JSON serialization 
    payload = {
        "years":      summary["year"].tolist(),
        "milestones": milestones,
        "data":       summary.to_dict(orient="records"),
    }
    with open(out, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    print(f"[export] JSON -> {out}")
    return out


def export_milestones(summary: pd.DataFrame) -> None:
    """Print milestone events to stdout."""
    milestones = milestone_report(summary)
    if not milestones:
        print("\n[milestones] No milestones detected in the selected year range.")
        return
    print("\n" + "="*60)
    print("  Protocol Transition Milestones")
    print("="*60)
    for m in milestones:
        print(f"  {m['year']}  {m['event']}")
        print(f"         {m['detail']}")
    print("="*60 + "\n")

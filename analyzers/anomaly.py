"""
analyzers/anomaly.py

Cross-year anomaly detection for MAWI traffic research.

Two modes:
  1. Within-year  — detects burst days inside a single year's packet stream
                    (requires timestamp column, groups by calendar day).
  2. Cross-year   — Z-score of annual summary metric vs. the full year
                    series (called after all years are collected in pipeline).

Output is attached as extra columns to the annual summary DataFrame.
"""

from __future__ import annotations

import math
from typing import Sequence

import numpy as np
import pandas as pd

from config import ANOMALY_WINDOW, ANOMALY_THRESHOLD


# ── Within-year burst detection ─────────────────────────────────────────────────

def daily_burst_stats(df: pd.DataFrame) -> dict:
    """
    Group packets by calendar day, compute per-day packet/byte counts,
    and flag days that exceed mean + 2σ as burst days.

    Requires df to have a 'ts' column (Unix float timestamp).
    Returns a dict with burst statistics for the annual summary.
    """
    if df.empty or "ts" not in df.columns:
        return {"burst_days": 0, "burst_ratio": 0.0, "peak_day_bytes": 0}

    df = df.copy()
    df["date"] = pd.to_datetime(df["ts"], unit="s").dt.date

    daily = df.groupby("date").agg(
        day_pkts  = ("pkt_len", "count"),
        day_bytes = ("pkt_len", "sum"),
    )

    if len(daily) < 3:
        # Not enough days to compute meaningful statistics
        return {
            "burst_days":       0,
            "burst_ratio":      0.0,
            "peak_day_bytes":   int(daily["day_bytes"].max()) if not daily.empty else 0,
            "days_sampled":     len(daily),
        }

    mean_pkts  = daily["day_pkts"].mean()
    std_pkts   = daily["day_pkts"].std(ddof=1)
    threshold  = mean_pkts + 2 * std_pkts

    burst_days = int((daily["day_pkts"] > threshold).sum())

    return {
        "burst_days":       burst_days,
        "burst_ratio":      round(burst_days / len(daily), 4),
        "peak_day_bytes":   int(daily["day_bytes"].max()),
        "median_day_pkts":  int(daily["day_pkts"].median()),
        "days_sampled":     len(daily),
    }


# ── Cross-year Z-score ──────────────────────────────────────────────────────────

def _rolling_zscore(values: np.ndarray, window: int) -> np.ndarray:
    """
    Compute Z-score for each value relative to a symmetric rolling window
    (excluding the value itself), clamped to available data at edges.

    Parameters
    ----------
    values : 1-D array of floats (ordered by year)
    window : number of neighbours on each side

    Returns
    -------
    z_scores : array, same shape as values
    """
    n = len(values)
    z = np.zeros(n, dtype=float)
    for i in range(n):
        lo = max(0, i - window)
        hi = min(n, i + window + 1)
        # Exclude point i from baseline
        baseline = np.concatenate([values[lo:i], values[i+1:hi]])
        if len(baseline) < 2:
            z[i] = 0.0
            continue
        mu  = baseline.mean()
        sig = baseline.std(ddof=1)
        z[i] = (values[i] - mu) / sig if sig > 0 else 0.0
    return z


def add_anomaly_scores(
    summary_df: pd.DataFrame,
    metric: str = "total_packets",
    window: int = ANOMALY_WINDOW,
    threshold: float = ANOMALY_THRESHOLD,
) -> pd.DataFrame:
    """
    Add anomaly Z-score and flag columns to the cross-year summary DataFrame.

    Parameters
    ----------
    summary_df : DataFrame with one row per year, sorted by 'year'.
    metric     : Column to compute anomaly score on (default: total_packets).
    window     : Symmetric rolling window half-width in years.
    threshold  : Z-score above which a year is flagged as anomalous.

    Returns
    -------
    summary_df with new columns:
        anomaly_zscore   — rolling Z-score for 'metric'
        anomaly_flag     — True if |z| > threshold
        anomaly_metric   — which metric was scored
    """
    if summary_df.empty or metric not in summary_df.columns:
        return summary_df

    df = summary_df.sort_values("year").copy()
    values = df[metric].astype(float).values
    z = _rolling_zscore(values, window)

    df["anomaly_zscore"]  = np.round(z, 3)
    df["anomaly_flag"]    = np.abs(z) > threshold
    df["anomaly_metric"]  = metric

    return df


# ── Port-scan / DDoS signature detection ───────────────────────────────────────

def scan_signatures(df: pd.DataFrame) -> dict:
    """
    Look for statistical signatures of scanning or DDoS traffic within
    a single year's packet DataFrame.

    Heuristics:
      - SYN-only ratio: TCP packets with SYN=1, ACK=0 → scanners
        (requires tcp.flags parsing; here we use a port diversity proxy)
      - DNS amplification: UDP/53 source traffic volume spike
      - ICMP flood: ICMP packet rate relative to total

    Returns a dict with scan/flood indicators.
    """
    if df.empty:
        return {}

    stats: dict = {}

    tcp_mask  = df["ip_proto"] == 6
    udp_mask  = df["ip_proto"] == 17
    icmp_mask = df["ip_proto"] == 1

    total = len(df)

    # ICMP flood indicator
    icmp_pct = float(icmp_mask.mean() * 100)
    stats["icmp_flood_indicator"] = icmp_pct > 5.0  # >5% ICMP is suspicious
    stats["icmp_pct"]             = round(icmp_pct, 2)

    # DNS amplification indicator: large volume on UDP dst=53
    udp_53 = udp_mask & (df["src_port"] == 53)   # responses FROM dns
    stats["dns_amp_pkt_pct"] = round(float(udp_53.mean() * 100), 2)
    stats["dns_amp_indicator"] = float(udp_53.mean()) > 0.05  # >5% from dns src

    # Port diversity heuristic (scanning proxy):
    # If top-1 dst port accounts for < 5% of TCP traffic but there are
    # thousands of unique dst ports → likely horizontal scan.
    if tcp_mask.any():
        tcp_df = df[tcp_mask]
        unique_dst = tcp_df["dst_port"].nunique()
        top1_pct   = float(tcp_df["dst_port"].value_counts(normalize=True).iloc[0]) * 100
        stats["tcp_dst_port_diversity"] = int(unique_dst)
        stats["tcp_top1_dst_port_pct"]  = round(top1_pct, 2)
        # High diversity + low top-1 concentration → scanning heuristic
        stats["scan_heuristic"] = (unique_dst > 10_000 and top1_pct < 5.0)
    else:
        stats["tcp_dst_port_diversity"] = 0
        stats["tcp_top1_dst_port_pct"]  = 0.0
        stats["scan_heuristic"]         = False

    return stats

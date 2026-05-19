"""
analyzers/summary.py

Cross-year trend computations applied to the assembled summary DataFrame
(one row per year). Computes derived ratios, YoY growth rates, and
protocol transition milestones (e.g. "HTTPS > HTTP crossover year").
"""

from __future__ import annotations

import pandas as pd
import numpy as np


def compute_derived_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add derived ratio and trend columns to the cross-year summary DataFrame.

    Input columns expected (all optional — computed only if source cols exist):
        total_bytes, tcp_bytes, udp_bytes, http_bytes, https_bytes,
        quic_payload_bytes, encrypted_bytes_pct, bittorrent_bytes,
        dns_pkts, total_packets
    """
    if df.empty:
        return df

    df = df.copy().sort_values("year").reset_index(drop=True)

    def safe_div(num_col: str, den_col: str, scale: float = 100.0) -> pd.Series:
        if num_col not in df or den_col not in df:
            return pd.Series(dtype=float)
        den = df[den_col].replace(0, np.nan)
        return (df[num_col] / den * scale).round(2)

    # ── Protocol share ratios ────────────────────────────────────────────────────
    if "tcp_bytes" in df and "total_bytes" in df:
        df["tcp_bytes_pct"]  = safe_div("tcp_bytes",  "total_bytes")
        df["udp_bytes_pct"]  = safe_div("udp_bytes",  "total_bytes")

    if "http_bytes" in df and "total_bytes" in df:
        df["http_bytes_pct"]  = safe_div("http_bytes",  "total_bytes")
        df["https_bytes_pct"] = safe_div("https_bytes", "total_bytes")

    if "quic_payload_bytes" in df and "total_bytes" in df:
        df["quic_bytes_pct"] = safe_div("quic_payload_bytes", "total_bytes")

    # Web (HTTP + HTTPS + QUIC) share of total bytes
    web_cols = [c for c in ["http_bytes", "https_bytes", "quic_payload_bytes"] if c in df]
    if web_cols and "total_bytes" in df:
        df["web_total_bytes"] = df[web_cols].sum(axis=1)
        df["web_bytes_pct"]   = safe_div("web_total_bytes", "total_bytes")

    # HTTPS share of web traffic
    if "https_bytes" in df and "web_total_bytes" in df:
        df["https_of_web_pct"] = safe_div("https_bytes", "web_total_bytes")

    # ── Year-over-year growth ────────────────────────────────────────────────────
    if "total_bytes" in df:
        df["yoy_bytes_growth_pct"] = (
            df["total_bytes"].pct_change() * 100
        ).round(1)

    if "total_packets" in df:
        df["yoy_pkts_growth_pct"] = (
            df["total_packets"].pct_change() * 100
        ).round(1)

    # ── Bytes per packet (average packet size, all protocols) ────────────────────
    if "total_bytes" in df and "total_packets" in df:
        df["avg_pkt_size_all"] = (
            df["total_bytes"] / df["total_packets"].replace(0, np.nan)
        ).round(1)

    # ── Encryption momentum ──────────────────────────────────────────────────────
    if "encrypted_bytes_pct" in df:
        df["enc_yoy_delta"] = df["encrypted_bytes_pct"].diff().round(2)

    # ── Normalised growth index (base = first year = 100) ────────────────────────
    for col in ["total_bytes", "total_packets", "https_bytes", "dns_pkts"]:
        if col in df:
            base = df[col].iloc[0]
            if base and base > 0:
                df[f"{col}_index"] = (df[col] / base * 100).round(1)

    return df


def milestone_report(df: pd.DataFrame) -> list[dict]:
    """
    Identify notable protocol transition years from the summary DataFrame.

    Returns a list of dicts: {year, event, detail}
    """
    if df.empty:
        return []

    milestones: list[dict] = []
    df = df.sort_values("year").reset_index(drop=True)

    def _crossover(col_a: str, col_b: str, label_a: str, label_b: str) -> int | None:
        """Return first year where col_b >= col_a (crossover point)."""
        if col_a not in df or col_b not in df:
            return None
        cross = df[df[col_b] >= df[col_a]]
        return int(cross["year"].iloc[0]) if not cross.empty else None

    # HTTPS > HTTP crossover
    y = _crossover("http_bytes", "https_bytes", "HTTP", "HTTPS")
    if y:
        milestones.append({
            "year": y,
            "event": "HTTPS > HTTP crossover",
            "detail": f"HTTPS bytes first exceeded HTTP bytes in {y}",
        })

    # QUIC first visible (>1% of total)
    if "quic_bytes_pct" in df:
        q = df[df["quic_bytes_pct"] >= 1.0]
        if not q.empty:
            milestones.append({
                "year": int(q["year"].iloc[0]),
                "event": "QUIC reaches 1% of traffic",
                "detail": f"QUIC/UDP-443 first exceeded 1% of total bytes",
            })

    # Encryption > 50%
    if "encrypted_bytes_pct" in df:
        e = df[df["encrypted_bytes_pct"] >= 50.0]
        if not e.empty:
            milestones.append({
                "year": int(e["year"].iloc[0]),
                "event": "Encrypted traffic > 50%",
                "detail": "More than half of all bytes now encrypted",
            })

    # P2P collapse (<1%)
    if "bittorrent_bytes_pct" in df:
        p = df[df["bittorrent_bytes_pct"] < 1.0]
        if not p.empty:
            milestones.append({
                "year": int(p["year"].iloc[0]),
                "event": "BitTorrent share drops below 1%",
                "detail": "P2P era ends as streaming services dominate",
            })

    # Anomaly years
    if "anomaly_flag" in df:
        for _, row in df[df["anomaly_flag"]].iterrows():
            milestones.append({
                "year": int(row["year"]),
                "event": f"Traffic anomaly (Z={row.get('anomaly_zscore', '?'):.2f})",
                "detail": f"Unusual {row.get('anomaly_metric','traffic')} volume vs. rolling baseline",
            })

    milestones.sort(key=lambda m: m["year"])
    return milestones


def print_summary_table(df: pd.DataFrame) -> None:
    """Print a concise year-by-year comparison table to stdout."""
    cols = [
        "year",
        "total_packets", "total_bytes",
        "tcp_pct_pkts", "udp_pct_pkts",
        "http_bytes_pct", "https_bytes_pct",
        "encrypted_bytes_pct",
        "anomaly_zscore",
    ]
    display_cols = [c for c in cols if c in df.columns]
    display_df = df[display_cols].copy()

    # Human-readable formatting
    if "total_bytes" in display_df:
        display_df["total_bytes"] = display_df["total_bytes"].apply(
            lambda b: f"{b/1e9:.1f} GB" if b >= 1e9 else f"{b/1e6:.1f} MB"
        )
    if "total_packets" in display_df:
        display_df["total_packets"] = display_df["total_packets"].apply(
            lambda p: f"{p/1e6:.1f}M" if p >= 1e6 else f"{p/1e3:.1f}K"
        )

    print("\n" + "="*80)
    print("  MAWI Traffic Research — Cross-Year Summary")
    print("="*80)
    print(display_df.to_string(index=False))
    print("="*80 + "\n")

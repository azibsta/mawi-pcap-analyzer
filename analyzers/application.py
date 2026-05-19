"""
analyzers/application.py

Port-based application classification on top of the transport DataFrame.
Classifies flows/packets into: http, https, quic, dns, smtp, ssh,
bittorrent, ntp, and 'other'.

Input : DataFrame produced by analyzers/transport.py
Output: dict of app-layer stats ready for the annual summary row.
"""

from __future__ import annotations

import pandas as pd

from config import (
    PROTO_TCP, PROTO_UDP,
    TCP_PORT_APP, UDP_PORT_APP, P2P_PORTS,
)

# ── Application label assignment ────────────────────────────────────────────────

def _classify_packet(row_proto: int, row_sport: int, row_dport: int) -> str:
    """
    Return an app-layer label for a single packet based on protocol + ports.
    Checks destination port first, then source port (handles reverse flows).
    """
    if row_proto == PROTO_TCP:
        label = (TCP_PORT_APP.get(row_dport)
                 or TCP_PORT_APP.get(row_sport))
        if label:
            return label
        if row_dport in P2P_PORTS or row_sport in P2P_PORTS:
            return "bittorrent"
    elif row_proto == PROTO_UDP:
        label = (UDP_PORT_APP.get(row_dport)
                 or UDP_PORT_APP.get(row_sport))
        if label:
            return label
        if row_dport in P2P_PORTS or row_sport in P2P_PORTS:
            return "bittorrent"
    return "other"


def classify_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Vectorised port classification. Adds an 'app' column to df.
    ~5× faster than row-wise apply for DataFrames > 1M rows.

    Strategy:
      1. Map dst_port → label via lookup Series (TCP and UDP separately).
      2. Where dst_port misses, try src_port.
      3. Flag P2P ports.
      4. Everything else → 'other'.
    """
    if df.empty:
        return df

    tcp_map = pd.Series(TCP_PORT_APP, dtype="object")
    udp_map = pd.Series(UDP_PORT_APP, dtype="object")

    tcp_mask = df["ip_proto"] == PROTO_TCP
    udp_mask = df["ip_proto"] == PROTO_UDP

    app = pd.Series("other", index=df.index, dtype="object")

    # TCP: dst_port lookup
    tcp_dst = df.loc[tcp_mask, "dst_port"].map(tcp_map)
    app.loc[tcp_mask] = tcp_dst.fillna("other")

    # TCP: where dst didn't match, try src_port
    tcp_miss = tcp_mask & (app == "other")
    tcp_src  = df.loc[tcp_miss, "src_port"].map(tcp_map)
    app.loc[tcp_miss] = tcp_src.fillna("other")

    # UDP: dst_port lookup
    udp_dst = df.loc[udp_mask, "dst_port"].map(udp_map)
    app.loc[udp_mask] = udp_dst.fillna("other")

    # UDP: where dst didn't match, try src_port
    udp_miss = udp_mask & (app == "other")
    udp_src  = df.loc[udp_miss, "src_port"].map(udp_map)
    app.loc[udp_miss] = udp_src.fillna("other")

    # P2P override (any protocol)
    p2p_ports = pd.array(list(P2P_PORTS))
    p2p_hit = df["dst_port"].isin(P2P_PORTS) | df["src_port"].isin(P2P_PORTS)
    app.loc[p2p_hit] = "bittorrent"

    df = df.copy()
    df["app"] = app.astype("category")
    return df


# ── Aggregate stats ─────────────────────────────────────────────────────────────

def application_stats(df: pd.DataFrame) -> dict:
    """
    Compute application-layer aggregate stats from a classified DataFrame.

    Expects df to already have an 'app' column (call classify_dataframe first).
    Returns a flat dict for merging into the annual summary row.
    """
    if df.empty or "app" not in df.columns:
        return {}

    total_bytes = int(df["pkt_len"].sum()) if "pkt_len" in df.columns else 1

    app_pkts  = df.groupby("app", observed=True)["pkt_len"].count()
    app_bytes = df.groupby("app", observed=True)["pkt_len"].sum()

    def _pkts(label: str) -> int:
        return int(app_pkts.get(label, 0))

    def _bytes(label: str) -> int:
        return int(app_bytes.get(label, 0))

    def _pct(label: str) -> float:
        b = _bytes(label)
        return round(b / total_bytes * 100, 2) if total_bytes else 0.0

    # Flow counts (unique 4-tuple per app label)
    flow_cols = ["src_ip", "dst_ip", "src_port", "dst_port"]
    flow_counts: dict[str, int] = {}
    for label, grp in df.groupby("app", observed=True):
        flow_counts[str(label)] = int(grp[flow_cols].drop_duplicates().shape[0])

    stats: dict = {
        # HTTP
        "http_pkts":         _pkts("http"),
        "http_bytes":        _bytes("http"),
        "http_bytes_pct":    _pct("http"),
        "http_flows":        flow_counts.get("http", 0),
        # HTTPS
        "https_pkts":        _pkts("https"),
        "https_bytes":       _bytes("https"),
        "https_bytes_pct":   _pct("https"),
        "https_flows":       flow_counts.get("https", 0),
        # QUIC (UDP/443)
        "quic_pkts":         _pkts("quic"),
        "quic_bytes":        _bytes("quic"),
        "quic_bytes_pct":    _pct("quic"),
        "quic_flows":        flow_counts.get("quic", 0),
        # DNS
        "dns_pkts":          _pkts("dns"),
        "dns_bytes":         _bytes("dns"),
        "dns_bytes_pct":     _pct("dns"),
        # SMTP (all variants)
        "smtp_pkts":         _pkts("smtp"),
        "smtp_bytes":        _bytes("smtp"),
        # SSH
        "ssh_pkts":          _pkts("ssh"),
        "ssh_bytes":         _bytes("ssh"),
        # BitTorrent / P2P
        "bittorrent_pkts":   _pkts("bittorrent"),
        "bittorrent_bytes":  _bytes("bittorrent"),
        "bittorrent_bytes_pct": _pct("bittorrent"),
        # NTP
        "ntp_pkts":          _pkts("ntp"),
        # SNMP (often abused for DDoS amplification)
        "snmp_pkts":         _pkts("snmp"),
        # Other (unclassified)
        "other_app_bytes_pct": _pct("other"),
    }

    # Web traffic combined (HTTP + HTTPS + QUIC)
    web_bytes = _bytes("http") + _bytes("https") + _bytes("quic")
    stats["web_bytes_pct"] = round(web_bytes / total_bytes * 100, 2) if total_bytes else 0.0

    return stats

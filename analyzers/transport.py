"""
analyzers/transport.py

Parses raw PCAP records at the IP layer and produces per-packet rows
containing: timestamp, ip_proto, src_ip, dst_ip, src_port, dst_port,
pkt_len, payload_len, and first-payload byte.

Returns a pandas DataFrame — one row per packet. Downstream analyzers
read this DataFrame; nothing touches the PCAP file again after this step.
"""

from __future__ import annotations
import socket
import struct
from pathlib import Path
from typing import Iterator

import dpkt
import pandas as pd

from config import (
    PROTO_TCP, PROTO_UDP, PROTO_ICMP,
    MAX_PACKETS_PER_FILE,
)


# ── Internal helpers ────────────────────────────────────────────────────────────

def _safe_inet(packed: bytes) -> str:
    """Convert 4-byte packed IP to dotted string, return '' on error."""
    try:
        return socket.inet_ntoa(packed)
    except Exception:
        return ""


def _iter_pcap(path: Path) -> Iterator[tuple[float, dpkt.ethernet.Ethernet]]:
    """Yield (timestamp, eth_frame) from a PCAP, handling pcap-ng too."""
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        # pcapng magic: 0x0A0D0D0A
        if magic == b"\x0a\x0d\x0d\x0a":
            reader = dpkt.pcapng.Reader(f)
        else:
            reader = dpkt.pcap.Reader(f)
        for ts, buf in reader:
            yield ts, buf


def _parse_transport(ip: dpkt.ip.IP) -> dict | None:
    """
    Extract transport-layer fields from an IP packet.
    Returns None for non-TCP/UDP/ICMP or malformed packets.
    """
    proto = ip.p
    src = ip.src
    dst = ip.dst
    pkt_len = ip.len

    src_port = dst_port = 0
    payload_len = 0
    first_byte = -1

    try:
        if proto == PROTO_TCP:
            tcp: dpkt.tcp.TCP = ip.data
            src_port  = tcp.sport
            dst_port  = tcp.dport
            payload_len = len(tcp.data) if tcp.data else 0
            if payload_len > 0:
                first_byte = tcp.data[0] if isinstance(tcp.data, (bytes, bytearray)) else -1
        elif proto == PROTO_UDP:
            udp: dpkt.udp.UDP = ip.data
            src_port  = udp.sport
            dst_port  = udp.dport
            payload_len = len(udp.data) if udp.data else 0
            if payload_len > 0:
                first_byte = udp.data[0] if isinstance(udp.data, (bytes, bytearray)) else -1
        elif proto == PROTO_ICMP:
            pass  # no ports for ICMP
        else:
            return None
    except Exception:
        return None

    return {
        "ip_proto":    proto,
        "src_ip":      _safe_inet(src),
        "dst_ip":      _safe_inet(dst),
        "src_port":    src_port,
        "dst_port":    dst_port,
        "pkt_len":     pkt_len,
        "payload_len": payload_len,
        "first_byte":  first_byte,
    }


# ── Public API ──────────────────────────────────────────────────────────────────

def parse_pcap(path: Path, max_packets: int | None = MAX_PACKETS_PER_FILE) -> pd.DataFrame:
    """
    Parse a single PCAP file into a flat DataFrame.

    Parameters
    ----------
    path        : Path to the .pcap / .pcapng file
    max_packets : Stop after this many packets (None = parse all)

    Returns
    -------
    pd.DataFrame with columns:
        ts, ip_proto, src_ip, dst_ip, src_port, dst_port,
        pkt_len, payload_len, first_byte
    """
    rows: list[dict] = []
    count = 0

    for ts, buf in _iter_pcap(path):
        if max_packets and count >= max_packets:
            break
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            row = _parse_transport(ip)
            if row is None:
                continue
            row["ts"] = ts
            rows.append(row)
            count += 1
        except Exception:
            continue

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    # Downcast types to reduce memory
    df["ip_proto"]  = df["ip_proto"].astype("uint8")
    df["src_port"]  = df["src_port"].astype("uint16")
    df["dst_port"]  = df["dst_port"].astype("uint16")
    df["pkt_len"]   = df["pkt_len"].astype("uint32")
    df["payload_len"] = df["payload_len"].astype("uint32")
    df["first_byte"] = df["first_byte"].astype("int16")   # -1 = no payload

    return df


def parse_year(year_dir: Path, max_packets: int | None = MAX_PACKETS_PER_FILE) -> pd.DataFrame:
    """
    Parse all PCAP files under a year directory and concatenate them.
    Files are sorted by filename (MAWI files are date-prefixed so this
    gives chronological order).
    """
    pcap_files = sorted(
        list(year_dir.glob("*.pcap")) + list(year_dir.glob("*.pcapng"))
    )
    if not pcap_files:
        raise FileNotFoundError(f"No PCAP files found in {year_dir}")

    frames: list[pd.DataFrame] = []
    for f in pcap_files:
        print(f"    Parsing {f.name} …")
        df = parse_pcap(f, max_packets=max_packets)
        if not df.empty:
            frames.append(df)

    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def transport_stats(df: pd.DataFrame) -> dict:
    """
    Compute transport-layer aggregate statistics from a packet DataFrame.

    Returns a flat dict ready for merging into the annual summary row.
    """
    if df.empty:
        return {}

    total_pkts  = len(df)
    total_bytes = int(df["pkt_len"].sum())

    tcp_mask  = df["ip_proto"] == PROTO_TCP
    udp_mask  = df["ip_proto"] == PROTO_UDP
    icmp_mask = df["ip_proto"] == PROTO_ICMP

    tcp_df  = df[tcp_mask]
    udp_df  = df[udp_mask]
    icmp_df = df[icmp_mask]

    # Flow approximation: unique (src_ip, dst_ip, src_port, dst_port) tuples
    flow_cols = ["src_ip", "dst_ip", "src_port", "dst_port"]
    tcp_flows  = int(tcp_df[flow_cols].drop_duplicates().shape[0])  if not tcp_df.empty  else 0
    udp_flows  = int(udp_df[flow_cols].drop_duplicates().shape[0])  if not udp_df.empty  else 0

    stats = {
        # Volume
        "total_packets":      total_pkts,
        "total_bytes":        total_bytes,
        # TCP
        "tcp_pkts":           int(tcp_mask.sum()),
        "tcp_bytes":          int(tcp_df["pkt_len"].sum()) if not tcp_df.empty else 0,
        "tcp_pct_pkts":       round(tcp_mask.mean() * 100, 2),
        "tcp_flows_approx":   tcp_flows,
        "avg_tcp_pkt_size":   round(tcp_df["pkt_len"].mean(), 1) if not tcp_df.empty else 0,
        # UDP
        "udp_pkts":           int(udp_mask.sum()),
        "udp_bytes":          int(udp_df["pkt_len"].sum()) if not udp_df.empty else 0,
        "udp_pct_pkts":       round(udp_mask.mean() * 100, 2),
        "udp_flows_approx":   udp_flows,
        "avg_udp_pkt_size":   round(udp_df["pkt_len"].mean(), 1) if not udp_df.empty else 0,
        # ICMP
        "icmp_pkts":          int(icmp_mask.sum()),
        "icmp_bytes":         int(icmp_df["pkt_len"].sum()) if not icmp_df.empty else 0,
        "icmp_pct_pkts":      round(icmp_mask.mean() * 100, 2),
        # Other
        "other_pkts":         int((~tcp_mask & ~udp_mask & ~icmp_mask).sum()),
        # IP diversity
        "unique_src_ips":     int(df["src_ip"].nunique()),
        "unique_dst_ips":     int(df["dst_ip"].nunique()),
    }

    # Top-N destination ports (TCP + UDP combined)
    port_mask = tcp_mask | udp_mask
    top_ports = (
        df[port_mask]["dst_port"]
        .value_counts()
        .head(5)
    )
    for rank, (port, cnt) in enumerate(top_ports.items(), 1):
        stats[f"top_dst_port_{rank}"]       = int(port)
        stats[f"top_dst_port_{rank}_pkts"]  = int(cnt)

    return stats

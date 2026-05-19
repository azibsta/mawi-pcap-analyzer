"""
analyzers/encryption.py

Estimates the fraction of traffic that is encrypted using two methods:

Method A — Port heuristic (fast, low FP for well-known ports):
    Count bytes on known TLS ports (443, 993, 995, 465 …) as encrypted.

Method B — Payload byte heuristic (more accurate, requires payload data):
    TCP: first payload byte == 0x16 → TLS record (ClientHello/AppData)
    UDP/443: first byte in range 0xC0–0xFF → IETF QUIC long header
             first byte in range 0x40–0x7F → QUIC short header (Google QUIC)

Both results are reported. Use Method B if payload data was captured;
fall back to Method A for MAWI traces that strip payload beyond N bytes.

Input : classified DataFrame (with 'app' column from application.py)
Output: dict of encryption stats for the annual summary row.
"""

from __future__ import annotations

import pandas as pd

from config import (
    PROTO_TCP, PROTO_UDP,
    TLS_TCP_PORTS, TLS_FIRST_BYTE,
    QUIC_FIRST_BYTE_MIN,
)


def encryption_stats(df: pd.DataFrame) -> dict:
    """
    Compute encryption coverage statistics.

    Parameters
    ----------
    df : DataFrame from transport.parse_year(), optionally with 'app' column.

    Returns
    -------
    dict with keys:
        enc_port_bytes, enc_port_bytes_pct  — port-heuristic encryption
        enc_payload_bytes, enc_payload_bytes_pct — payload-heuristic
        tls_pkts, quic_pkts
        quic_udp_bytes_pct  — QUIC share of UDP bytes
        plaintext_http_bytes_pct  — unencrypted HTTP share of total
    """
    if df.empty:
        return {}

    total_bytes = int(df["pkt_len"].sum())
    if total_bytes == 0:
        return {}

    tcp_mask = df["ip_proto"] == PROTO_TCP
    udp_mask = df["ip_proto"] == PROTO_UDP

    # ── Method A: port heuristic ────────────────────────────────────────────────
    tls_port_mask = tcp_mask & (
        df["dst_port"].isin(TLS_TCP_PORTS) | df["src_port"].isin(TLS_TCP_PORTS)
    )
    # QUIC: UDP dst or src port 443
    quic_port_mask = udp_mask & (
        (df["dst_port"] == 443) | (df["src_port"] == 443)
    )

    enc_port_bytes = int(df.loc[tls_port_mask | quic_port_mask, "pkt_len"].sum())
    enc_port_pct   = round(enc_port_bytes / total_bytes * 100, 2)

    # ── Method B: payload heuristic ─────────────────────────────────────────────
    has_payload = df["first_byte"] >= 0

    # TLS: TCP packets whose first payload byte is 0x16 (TLS record header)
    tls_payload_mask = (
        tcp_mask
        & has_payload
        & (df["first_byte"] == TLS_FIRST_BYTE)
    )

    # QUIC long header: UDP, first byte >= 0xC0
    quic_long_mask = (
        udp_mask
        & has_payload
        & (df["first_byte"] >= QUIC_FIRST_BYTE_MIN)
        & ((df["dst_port"] == 443) | (df["src_port"] == 443))
    )

    # Google QUIC / IETF QUIC short header: first byte 0x40–0x7F on UDP/443
    quic_short_mask = (
        udp_mask
        & has_payload
        & (df["first_byte"] >= 0x40)
        & (df["first_byte"] < 0x80)
        & ((df["dst_port"] == 443) | (df["src_port"] == 443))
    )

    enc_payload_mask  = tls_payload_mask | quic_long_mask | quic_short_mask
    enc_payload_bytes = int(df.loc[enc_payload_mask, "pkt_len"].sum())
    enc_payload_pct   = round(enc_payload_bytes / total_bytes * 100, 2)

    # ── QUIC detail ──────────────────────────────────────────────────────────────
    quic_pkts  = int((quic_long_mask | quic_short_mask).sum())
    quic_bytes = int(df.loc[quic_long_mask | quic_short_mask, "pkt_len"].sum())
    udp_bytes  = int(df.loc[udp_mask, "pkt_len"].sum())
    quic_udp_pct = round(quic_bytes / udp_bytes * 100, 2) if udp_bytes else 0.0

    # ── Plaintext HTTP ────────────────────────────────────────────────────────────
    http_mask = (
        tcp_mask
        & (
            (df["dst_port"] == 80) | (df["src_port"] == 80)
            | (df["dst_port"] == 8080) | (df["src_port"] == 8080)
        )
    )
    http_bytes     = int(df.loc[http_mask, "pkt_len"].sum())
    http_bytes_pct = round(http_bytes / total_bytes * 100, 2)

    # ── Entropy-based check (optional if payload present) ────────────────────────
    # High Shannon entropy in payload suggests encryption / compression.
    # Only computed if we have at least 10k packets with payloads (can be slow).
    entropy_enc_pct: float | None = None
    payload_df = df[has_payload & (df["payload_len"] >= 8)]
    if len(payload_df) >= 10_000:
        # Proxy: if first_byte is in the high-entropy zone (e.g. >=0x20 and not
        # a common ASCII printable starter), flag as likely encrypted.
        # This is a rough heuristic, not a full byte-entropy calculation.
        high_entropy = payload_df["first_byte"].apply(
            lambda b: b >= 128 or (b < 32 and b not in (0, 10, 13))
        )
        entropy_enc_pct = round(high_entropy.mean() * 100, 2)

    stats: dict = {
        # Port-based
        "enc_port_bytes":         enc_port_bytes,
        "enc_port_bytes_pct":     enc_port_pct,
        # Payload-based (more accurate)
        "enc_payload_bytes":      enc_payload_bytes,
        "enc_payload_bytes_pct":  enc_payload_pct,
        # TLS detail
        "tls_pkts":               int(tls_payload_mask.sum()),
        "tls_bytes":              int(df.loc[tls_payload_mask, "pkt_len"].sum()),
        # QUIC detail
        "quic_payload_pkts":      quic_pkts,
        "quic_payload_bytes":     quic_bytes,
        "quic_udp_bytes_pct":     quic_udp_pct,
        # Plaintext
        "plaintext_http_bytes":   http_bytes,
        "plaintext_http_pct":     http_bytes_pct,
        # Best-effort encrypted share (prefers payload method if data available)
        "encrypted_bytes_pct":    enc_payload_pct if enc_payload_bytes > 0 else enc_port_pct,
    }

    if entropy_enc_pct is not None:
        stats["entropy_enc_est_pct"] = entropy_enc_pct

    return stats

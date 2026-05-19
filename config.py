"""
config.py — Central configuration for MAWI PCAP analyzer.
Edit paths and mappings here; nothing else needs changing for most use cases.
"""

import os
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR / "data"       # data/2006/*.pcap, data/2007/*.pcap, ...
CACHE_DIR  = BASE_DIR / "cache"      # auto-created Parquet files
REPORT_DIR = BASE_DIR / "reports"    # CSV / JSON output

for _d in (DATA_DIR, CACHE_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ── Year range supported ───────────────────────────────────────────────────────
YEAR_MIN = 2006
YEAR_MAX = 2025

# ── IP protocol numbers ────────────────────────────────────────────────────────
PROTO_TCP  = 6
PROTO_UDP  = 17
PROTO_ICMP = 1

# ── Well-known port → application label ───────────────────────────────────────
# TCP ports
TCP_PORT_APP = {
    80:   "http",
    8080: "http",
    443:  "https",
    8443: "https",
    25:   "smtp",
    587:  "smtp",
    465:  "smtp",
    110:  "pop3",
    143:  "imap",
    993:  "imap",
    995:  "pop3",
    22:   "ssh",
    23:   "telnet",
    21:   "ftp",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017:"mongodb",
    # P2P era (BitTorrent)
    6881: "bittorrent",
    6882: "bittorrent",
    6883: "bittorrent",
    6884: "bittorrent",
    6885: "bittorrent",
    6886: "bittorrent",
    6887: "bittorrent",
    6888: "bittorrent",
    6889: "bittorrent",
    6890: "bittorrent",
}

# UDP ports
UDP_PORT_APP = {
    53:   "dns",
    5353: "mdns",
    123:  "ntp",
    161:  "snmp",
    443:  "quic",   # QUIC runs over UDP/443
    3478: "stun",
    4500: "ipsec",
    500:  "ipsec",
    1194: "openvpn",
    51820:"wireguard",
    # Streaming / gaming
    9000: "video_stream",
    5004: "rtp",
    5005: "rtcp",
}

# Ports to flag as likely P2P (union of TCP+UDP)
P2P_PORTS = set(range(6881, 6890)) | {4662, 4672, 51413, 6969}

# ── TLS/encryption heuristics ─────────────────────────────────────────────────
# TCP ports almost certainly carrying TLS
TLS_TCP_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990, 5061}

# First-byte values that indicate a TLS ClientHello (record type 0x16 = 22)
TLS_FIRST_BYTE = 0x16

# QUIC magic bytes (IETF QUIC long-header first byte has top 2 bits set: 0xC0–0xFF)
QUIC_FIRST_BYTE_MIN = 0xC0

# ── Anomaly detection ─────────────────────────────────────────────────────────
ANOMALY_WINDOW = 3          # years on each side for rolling Z-score baseline
ANOMALY_THRESHOLD = 2.5     # Z-score above this is flagged

# ── Parsing performance ───────────────────────────────────────────────────────
# Max packets to parse per PCAP file (None = unlimited).
# Set e.g. 5_000_000 for a quick exploratory run on large files.
MAX_PACKETS_PER_FILE = None

# Chunk size for pandas operations (rows)
PANDAS_CHUNK = 500_000

# ── Report settings ───────────────────────────────────────────────────────────
TOP_PORTS_N = 5             # How many top dst ports to include in report

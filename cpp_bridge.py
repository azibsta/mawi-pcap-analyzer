"""
cpp_bridge.py

Calls the compiled mawi_engine binary (built from mawi_engine.cpp) via
subprocess, parses its newline-delimited JSON output, and returns a
pandas DataFrame that slots directly into the existing pipeline.

The C++ engine handles raw PCAP parsing at native speed.
Python handles everything above: encryption heuristics, cross-year
anomaly scoring, derived metrics, and export.

Architecture:
    Python (analyze.py / pipeline.py)
        └── cpp_bridge.py
                └── subprocess → mawi_engine [--year-dir / --dir] --json
                        └── stdout: one JSON object per year, newline-delimited

Fallback:
    If the binary is not found or compilation fails, the bridge raises
    CppEngineNotFound and the pipeline falls back to the pure-Python
    dpkt parser (analyzers/transport.py).
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator

import pandas as pd

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE         = Path(__file__).parent
_SRC          = _HERE / "mawi_engine.cpp"
_BIN_NAME     = "mawi_engine.exe" if platform.system() == "Windows" else "mawi_engine"
_BIN_PATH     = _HERE / _BIN_NAME


class CppEngineNotFound(RuntimeError):
    pass


# ── Build helpers ───────────────────────────────────────────────────────────────

def _compiler() -> str | None:
    """Return first available C++ compiler, or None."""
    for cxx in ("g++", "c++", "clang++"):
        if shutil.which(cxx):
            return cxx
    return None


def build_engine(force: bool = False) -> Path:
    """
    Compile mawi_engine.cpp if the binary is missing or force=True.

    Returns the path to the compiled binary.
    Raises CppEngineNotFound if compilation fails or no compiler is available.
    """
    if _BIN_PATH.exists() and not force:
        return _BIN_PATH

    cxx = _compiler()
    if cxx is None:
        raise CppEngineNotFound(
            "No C++ compiler found (tried g++, c++, clang++). "
            "Please compile mawi_engine.cpp manually:\n"
            f"  g++ -std=c++17 -O2 -pthread {_SRC} -o {_BIN_PATH}"
        )

    print(f"[build] Compiling mawi_engine.cpp with {cxx} …")
    cmd = [cxx, "-std=c++17", "-O2", "-pthread",
           str(_SRC), "-o", str(_BIN_PATH)]

    # Windows / MinGW needs ws2_32
    if platform.system() == "Windows":
        cmd.append("-lws2_32")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise CppEngineNotFound(
            f"Compilation failed:\n{result.stderr}"
        )

    print(f"[build] Binary ready: {_BIN_PATH}")
    return _BIN_PATH


# ── JSON stream parsing ─────────────────────────────────────────────────────────

def _stream_json(proc: subprocess.Popen) -> Iterator[dict]:
    """
    Yield parsed JSON objects from the engine's stdout line by line.
    Stderr (info/timing messages) is printed to the console.
    """
    assert proc.stdout is not None
    assert proc.stderr is not None

    import threading

    def _drain_stderr():
        for line in proc.stderr:
            sys.stderr.write(line)
        
    t = threading.Thread(target=_drain_stderr, daemon=True)
    t.start()

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"[bridge] JSON parse error: {e} — line: {line[:120]}\n")

    proc.wait()
    t.join()

    if proc.returncode not in (0, None):
        raise RuntimeError(f"mawi_engine exited with code {proc.returncode}")


# ── Column mapping: C++ JSON keys → Python pipeline column names ───────────────
# The Python analyzers use these names in transport_stats(), application_stats()
# etc. We rename C++ output to match so the rest of the pipeline is unchanged.
_RENAME = {
    # C++ key              : Python column
    "total_packets"        : "total_packets",
    "total_bytes"          : "total_bytes",
    "ipv4_pkts"            : "ipv4_pkts",
    "ipv6_pkts"            : "ipv6_pkts",
    "tcp_pkts"             : "tcp_pkts",
    "udp_pkts"             : "udp_pkts",
    "icmp_pkts"            : "icmp_pkts",
    "other_proto_pkts"     : "other_pkts",
    "http_pkts"            : "http_pkts",
    "https_pkts"           : "https_pkts",
    "quic_pkts"            : "quic_payload_pkts",
    "tcp_syn"              : "tcp_syn",
    "tcp_ack"              : "tcp_ack",
    "tcp_fin"              : "tcp_fin",
    "tcp_rst"              : "tcp_rst",
    "anomaly_pkts"         : "anomaly_pkts",
    "checksum_errors"      : "checksum_errors",
    "distinct_flows"       : "tcp_flows_approx",  # combined flow count
    "tcp_pct"              : "tcp_pct_pkts",
    "udp_pct"              : "udp_pct_pkts",
    "icmp_pct"             : "icmp_pct_pkts",
    "http_pct"             : "http_bytes_pct",     # port-based, close enough
    "https_pct"            : "https_bytes_pct",
    "quic_pct"             : "quic_bytes_pct",
    "syn_flood_flag"       : "syn_flood_flag",
    "rst_flood_flag"       : "rst_flood_flag",
    "first_ts"             : "first_ts",
    "last_ts"              : "last_ts",
}


def _flatten_row(raw: dict) -> dict:
    """
    Convert one JSON object from the engine into a flat dict with
    Python pipeline column names. Also expands top_dst_ports array.
    """
    row: dict = {"year": int(raw.get("year", 0))}

    for cpp_key, py_key in _RENAME.items():
        if cpp_key in raw:
            val = raw[cpp_key]
            # Boolean flags arrive as strings from JSON ("true"/"false")
            if isinstance(val, str) and val in ("true", "false"):
                val = val == "true"
            row[py_key] = val

    # Expand top_dst_ports list
    for i, entry in enumerate(raw.get("top_dst_ports", []), 1):
        row[f"top_dst_port_{i}"]      = entry.get("port", 0)
        row[f"top_dst_port_{i}_pkts"] = entry.get("pkts", 0)

    # Derived: approximate bytes per protocol using pkt-level ratios
    # (C++ doesn't split bytes per protocol; we approximate)
    total_bytes = row.get("total_bytes", 0)
    tcp_pct     = row.get("tcp_pct_pkts", 0) / 100.0
    udp_pct     = row.get("udp_pct_pkts", 0) / 100.0
    row["tcp_bytes"]  = int(total_bytes * tcp_pct)
    row["udp_bytes"]  = int(total_bytes * udp_pct)

    # Encryption: port-heuristic from https_pkts as fraction of total_packets
    total_pkts = row.get("total_packets", 1) or 1
    https_pkts = row.get("https_pkts", 0)
    quic_pkts  = row.get("quic_payload_pkts", 0)
    row["enc_port_bytes_pct"]  = round((https_pkts + quic_pkts) / total_pkts * 100, 2)
    row["encrypted_bytes_pct"] = row["enc_port_bytes_pct"]

    # Duration in seconds (for burst analysis)
    dur = row.get("last_ts", 0) - row.get("first_ts", 0)
    row["capture_duration_sec"] = dur if dur > 0 else 0

    return row


# ── Public API ──────────────────────────────────────────────────────────────────

def run_engine_year(year_dir: Path, max_packets: int | None = None) -> dict | None:
    """
    Run the C++ engine on a single year directory.
    Returns a flat dict (one summary row) or None on failure.

    Called by pipeline.py instead of analyzers/transport.parse_year()
    when the binary is available.
    """
    binary = _BIN_PATH
    if not binary.exists():
        try:
            binary = build_engine()
        except CppEngineNotFound as e:
            print(f"[bridge] {e}")
            return None

    cmd = [str(binary), "--year-dir", str(year_dir), "--json"]
    if max_packets:
        cmd += ["--max-packets", str(max_packets)]

    t0 = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print(f"[bridge] Binary not found at {binary}. Run build_engine() first.")
        return None

    row = None
    for obj in _stream_json(proc):
        row = _flatten_row(obj)

    elapsed = time.time() - t0
    if row:
        print(f"  [C++ engine] {year_dir.name}: "
              f"{row.get('total_packets', 0):,} packets in {elapsed:.1f}s")
    return row


def run_engine_all(data_dir: Path, max_packets: int | None = None) -> pd.DataFrame:
    """
    Run the C++ engine on the entire data directory (all years at once).
    Returns a DataFrame with one row per year.

    Use this when you want maximum throughput — the engine parallelises
    within each year via std::async.
    """
    binary = _BIN_PATH
    if not binary.exists():
        binary = build_engine()

    cmd = [str(binary), "--dir", str(data_dir), "--json"]
    if max_packets:
        cmd += ["--max-packets", str(max_packets)]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    rows = [_flatten_row(obj) for obj in _stream_json(proc)]
    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows).sort_values("year").reset_index(drop=True)


def engine_available() -> bool:
    """True if the binary exists OR can be compiled right now."""
    if _BIN_PATH.exists():
        return True
    return _compiler() is not None


def print_engine_status() -> None:
    """Print a one-line status about the C++ engine."""
    if _BIN_PATH.exists():
        print(f"[bridge] C++ engine ready: {_BIN_PATH}")
    elif _compiler():
        print(f"[bridge] C++ engine not compiled — run build_engine() or: "
              f"g++ -std=c++17 -O2 -pthread {_SRC} -o {_BIN_PATH}")
    else:
        print("[bridge] No C++ compiler found — falling back to Python dpkt parser")

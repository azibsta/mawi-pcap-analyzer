# MAWI PCAP Analyzer

A high-performance hybrid (C++ / Python) longitudinal network traffic analyzer designed to process 20 years of MAWI PCAP datasets (2006-2025).

## Overview

This Final Year Project processes hundreds of gigabytes of raw PCAP data to identify long-term macroscopic trends in internet traffic. Because standard Python libraries are too slow for datasets of this magnitude, this project implements a custom multi-threaded C++ engine for raw packet parsing, orchestrated by a Python pipeline that aggregates data, detects statistical anomalies (like massive DDoS attacks), and serves an interactive web dashboard.

## Key Features

- **High-Performance C++ Parsing**: Bypasses slow Python execution by natively reading `.pcap` files in memory at millions of packets per second.
- **Statistical Anomaly Detection**: Uses symmetric rolling window Z-scores to automatically identify massive historical DDoS attacks.
- **TCP vs UDP Shifting**: Tracks the erosion of TCP's monopoly and the rapid rise of QUIC (HTTP/3) over UDP.
- **Legacy Protocol Lifecycles**: Tracks the birth, peak, and death of early 2000s protocols including Gnutella, eMule, MSN Messenger, CU-SeeMe, Telnet, and SSH.
- **Interactive Glassmorphic Dashboard**: A fully responsive vanilla JS / Chart.js frontend visualizing the 20-year data pipeline.

## Analysis Methods & Heuristics

The pipeline employs several specific analytical methods to extract insights from raw traffic:

### 1. Macroscopic Anomaly Detection (Cross-Year Z-Score)
To identify massive traffic spikes (like historical DDoS attacks) without triggering false positives due to natural internet growth, the system calculates a **Symmetric Rolling Window Z-Score**. 
- **Method:** It compares a specific year's total packet volume against a local baseline (the 2 years prior and 2 years after). 
- **Trigger:** A Z-score > `3.0` mathematically confirms a massive anomaly relative to that specific era of the internet.

### 2. Microscopic Intra-Day Attack Signatures
Within the 15-minute PCAP window of a single day, the system looks for specific attack vectors:
- **SYN Floods (`syn_ack_ratio`)**: The engine counts raw TCP flags. A massive ratio of `SYN` (connection requests) to `ACK` (acknowledgments) indicates a half-open connection spam attack.
- **Port Scanning (`rst_fin_ratio` & Port Diversity)**: A high ratio of TCP Reset (`RST`) packets to graceful `FIN` packets indicates aggressive probing of closed ports. If over 10,000 unique destination ports are hit, but no single port receives >5% of traffic, the system flags a horizontal subnet scan.
- **DNS Amplification (`dns_amp_indicator`)**: If sudden UDP traffic originating *from* Port 53 (DNS) exceeds 5% of the total network volume, it flags a DNS amplification attack.
- **ICMP Floods**: If ICMP traffic spikes above 5% of total packets, it flags a ping flood.

### 3. Protocol Shifting & Legacy Tracking
The C++ engine maps destination ports to specific application protocols. 
- **Method:** It tracks Port 80 (HTTP), 443 (HTTPS), and specific UDP payloads for QUIC to chart the rise of encrypted mobile traffic. 
- **Legacy Decay:** It specifically targets obsolete ports (e.g., 6346 for Gnutella, 1863 for MSN Messenger) and maps their percentage of total traffic volume across the 20-year span to visualize their exact lifecycle curves from birth to death.

### 4. Encryption Tracking (`encrypted_bytes_pct`)
The system quantifies the historical adoption of secure internet protocols (which spiked dramatically post-2014) using two possible methods:
- **Port-Based Heuristic (C++ Engine):** For high-speed parsing, it aggregates all packets flowing over known secure protocols (HTTPS/Port 443 and QUIC/UDP Port 443) and divides by total network packets.
- **Shannon Entropy (Python Fallback):** When running in deep-packet inspection mode, it calculates the mathematical Shannon Entropy of the raw payload bytes. Highly randomized (high entropy) payloads are flagged as encrypted, whereas structured plain-text (HTTP/low entropy) are flagged as unencrypted.

### 5. Data Dictionary (Summary Table Columns)
The following columns are output by the pipeline, derived via the methods below:
- **`total_packets` & `total_bytes`**: Extracted directly by iterating the PCAP binary structure and summing Layer 3 headers.
- **`tcp_pct_pkts` & `udp_pct_pkts`**: Calculated by counting packets with IPv4/IPv6 Protocol IDs `6` and `17` respectively, divided by `total_packets`.
- **`http_bytes_pct` & `https_bytes_pct`**: Port-based heuristic tracking the volume of bytes flowing over TCP Ports `80` and `443`.
- **Legacy Application Metrics** (`gnutella_pct`, `emule_pct`, `msn_pct`, `cuseeme_pct`, `telnet_pct`, `ssh_pct`): Port-based heuristics identifying the percentage of total traffic using obsolete application-layer ports (e.g., TCP 1863 for MSN, UDP 7648 for CU-SeeMe).

## System Architecture

1. **`mawi_engine.cpp`**: The C++ core. Reads PCAPs, dissects Layer 3/4 headers, and counts protocols, bandwidth, and ports.
2. **`pipeline.py`**: The Python orchestrator. Retrieves C++ JSON output, calculates derived metrics (like Z-scores), caches data to Parquet files to prevent re-parsing, and exports final trends.
3. **`frontend/`**: The visual layer. A local web server that ingests the JSON exports and renders interactive charts.

## Quick Start

### 1. Requirements
- Python 3.10+
- `g++` compiler (for the C++ engine)
- Python packages: `pandas`, `pyarrow`

### 2. Build the Engine
The pipeline will attempt to build the C++ engine automatically, but you can force a manual build:
```bash
python build.py
```

### 3. Run the CLI Pipeline
Get a summary of a single year directly in the terminal:
```bash
python analyze.py --year 2010 --summary
```

Run the full dataset analysis and export to JSON:
```bash
python analyze.py --from 2006 --to 2025 --export json
```

### 4. Launch the Dashboard
Start the local server to view the interactive dashboard:
```bash
python frontend/serve.py
```
Then navigate to `http://localhost:8000/frontend/index.html` in your browser.

## Documentation
For a complete guide to all CLI commands and system operations, see the `USER_MANUAL.md`.

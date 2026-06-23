# MAWI PCAP Analyzer

A high-performance hybrid (C++ / Python) longitudinal network traffic analyzer designed to process 20 years of MAWI PCAP datasets (2006-2025).

## Overview

This Final Year Project processes hundreds of gigabytes of raw PCAP data to identify long-term macroscopic trends in internet traffic. Because standard Python libraries are too slow for datasets of this magnitude, this project implements a custom multi-threaded C++ engine for raw packet parsing, orchestrated by a Python pipeline that aggregates data, detects statistical anomalies (like massive DDoS attacks), and serves an interactive web dashboard.

## Key Features

- **High-Performance C++ Parsing**: Bypasses slow Python execution by natively reading .pcap files in memory at millions of packets per second.
- **Statistical Anomaly Detection**: Uses symmetric rolling window Z-scores to automatically identify massive historical DDoS attacks.
- **TCP vs UDP Shifting**: Tracks the erosion of TCP's monopoly and the rapid rise of QUIC (HTTP/3) over UDP.
- **Legacy Protocol Lifecycles**: Tracks the birth, peak, and death of early 2000s protocols including Gnutella, eMule, MSN Messenger, CU-SeeMe, Telnet, and SSH.
- **Interactive Glassmorphic Dashboard**: A fully responsive vanilla JS / Chart.js frontend visualizing the 20-year data pipeline.

## System Architecture

1. **mawi_engine.cpp**: The C++ core. Reads PCAPs, dissects Layer 3/4 headers, and counts protocols, bandwidth, and ports.
2. **pipeline.py**: The Python orchestrator. Retrieves C++ JSON output, calculates derived metrics (like Z-scores), caches data to Parquet files to prevent re-parsing, and exports final trends.
3. **rontend/**: The visual layer. A local web server that ingests the JSON exports and renders interactive charts.

## Quick Start

### 1. Requirements
- Python 3.10+
- g++ compiler (for the C++ engine)
- Python packages: pandas, pyarrow`n
### 2. Build the Engine
The pipeline will attempt to build the C++ engine automatically, but you can force a manual build:
`ash
python build.py
``n
### 3. Run the CLI Pipeline
Get a summary of a single year directly in the terminal:
`ash
python analyze.py --year 2010 --summary
``n
Run the full dataset analysis and export to JSON:
`ash
python analyze.py --from 2006 --to 2025 --export json
``n
### 4. Launch the Dashboard
Start the local server to view the interactive dashboard:
`ash
python frontend/serve.py
``nThen navigate to http://localhost:8000/frontend/index.html in your browser.

## Documentation
For a complete guide to all CLI commands and system operations, see the USER_MANUAL.md.

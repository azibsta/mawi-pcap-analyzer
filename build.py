#!/usr/bin/env python3
"""
build.py — Compile mawi_engine.cpp into a native binary.

Run this once before using the pipeline:
    python build.py

Or force a rebuild:
    python build.py --force

The binary (mawi_engine / mawi_engine.exe) lands in the same directory
as this script and is automatically picked up by cpp_bridge.py.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from cpp_bridge import build_engine, print_engine_status, CppEngineNotFound

def main():
    parser = argparse.ArgumentParser(description="Build the MAWI C++ engine")
    parser.add_argument("--force", action="store_true",
                        help="Recompile even if binary already exists")
    args = parser.parse_args()

    try:
        path = build_engine(force=args.force)
        print(f"\n✓  Build successful: {path}")
        print_engine_status()
    except CppEngineNotFound as e:
        print(f"\n✗  Build failed:\n{e}")
        print("\nManual build commands:")
        print("  Linux/macOS:  g++ -std=c++17 -O2 -pthread mawi_engine.cpp -o mawi_engine")
        print("  Windows MSVC: cl /std:c++17 /O2 mawi_engine.cpp ws2_32.lib /Fe:mawi_engine.exe")
        print("  Windows MinGW:g++ -std=c++17 -O2 mawi_engine.cpp -lws2_32 -o mawi_engine.exe")
        sys.exit(1)

if __name__ == "__main__":
    main()

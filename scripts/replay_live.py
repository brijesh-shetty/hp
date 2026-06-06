#!/usr/bin/env python3
"""Replay the dataset as live Zeek traffic.

This script reads the Zeek conn.log generated from the dataset and writes it
line-by-line to a watched output file at a controlled rate, simulating live
network traffic coming out of Zeek.  Filebeat (in tail mode) picks up each
new line as it appears and ships it to Elasticsearch, which then gets bridged
to Kafka via es_to_kafka.py.

Pipeline:
    replay_live.py  ──writes──▶  dataset/zeek-live/conn.log
                                        │
                                   Filebeat (tail)
                                        │
                                   Elasticsearch
                                        │
                                   es_to_kafka.py
                                        │
                                      Kafka  ──▶  AI Backend

Usage:
    # Default: 50 events/sec, loop once
    python replay_live.py

    # Custom rate, infinite loop
    python replay_live.py --rate 100 --loop

    # Burst mode (as fast as possible), 3 loops
    python replay_live.py --rate 0 --repeat 3

    # Use inside Docker
    docker compose --profile live-replay up -d
"""

import argparse
import os
import shutil
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "dataset"
SOURCE_CONN_LOG = DATA_DIR / "zeek" / "conn.log"
FALLBACK_CONN_LOG = DATA_DIR / "conn.log"
ROOT_CONN_LOG = BASE_DIR / "conn.log"

LIVE_OUTPUT_DIR = DATA_DIR / "zeek-live"
LIVE_OUTPUT_FILE = LIVE_OUTPUT_DIR / "conn.log"

# Graceful shutdown
_running = True


def _handle_signal(sig, frame):
    global _running
    _running = False
    print("\n[replay] Shutting down gracefully...")


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


def find_source_log() -> Path:
    """Find the best available source conn.log."""
    for candidate in [SOURCE_CONN_LOG, FALLBACK_CONN_LOG, ROOT_CONN_LOG]:
        if candidate.exists() and candidate.stat().st_size > 0:
            return candidate
    raise FileNotFoundError(
        f"No conn.log found. Tried:\n"
        f"  - {SOURCE_CONN_LOG}\n"
        f"  - {FALLBACK_CONN_LOG}\n"
        f"  - {ROOT_CONN_LOG}\n\n"
        f"Run one of these first:\n"
        f"  python generate_conn_log.py\n"
        f"  python generate_zeek_pcap.py --run-zeek\n"
        f"  docker compose up zeek"
    )


def load_conn_log(path: Path) -> tuple:
    """Load conn.log, separating header lines from data lines."""
    headers = []
    data_lines = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                headers.append(line)
            else:
                stripped = line.strip()
                if stripped:
                    data_lines.append(stripped)
    return headers, data_lines


def write_header(output: Path, headers: List[str]) -> None:
    """Write the Zeek header block to the output file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as f:
        for h in headers:
            f.write(h if h.endswith("\n") else h + "\n")


def replay(
    source: Path,
    output: Path,
    rate: float,
    repeat: int,
    loop_forever: bool,
) -> int:
    """Replay conn.log data lines to the output file at the specified rate."""
    headers, data_lines = load_conn_log(source)

    if not data_lines:
        print("[replay] ERROR: No data lines found in conn.log", file=sys.stderr)
        return 1

    print(f"[replay] Source:      {source}")
    print(f"[replay] Output:      {output}")
    print(f"[replay] Data lines:  {len(data_lines):,}")
    print(f"[replay] Rate:        {'burst (max speed)' if rate <= 0 else f'{rate:.1f} events/sec'}")
    print(f"[replay] Repeat:      {'infinite' if loop_forever else repeat}")
    print()

    # Write header to fresh file
    write_header(output, headers)

    interval = 1.0 / rate if rate > 0 else 0.0
    total_sent = 0
    loop_count = 0

    while _running and (loop_forever or loop_count < repeat):
        loop_count += 1
        start_time = time.time()

        with output.open("a", encoding="utf-8", newline="") as f:
            for i, line in enumerate(data_lines):
                if not _running:
                    break
                f.write(line + "\n")
                f.flush()  # Flush immediately so Filebeat sees it
                total_sent += 1

                if interval > 0:
                    time.sleep(interval)

                # Progress every 1000 lines
                if total_sent % 1000 == 0:
                    elapsed = time.time() - start_time
                    actual_rate = total_sent / elapsed if elapsed > 0 else 0
                    print(
                        f"[replay] Sent {total_sent:,} events "
                        f"(loop {loop_count}, line {i + 1}/{len(data_lines)}, "
                        f"{actual_rate:.1f} evt/s)"
                    )

        elapsed = time.time() - start_time
        actual_rate = len(data_lines) / elapsed if elapsed > 0 else 0
        print(
            f"[replay] Loop {loop_count} complete: "
            f"{len(data_lines):,} lines in {elapsed:.1f}s "
            f"({actual_rate:.1f} evt/s)"
        )

        # If looping, re-write the header for a clean restart
        if _running and (loop_forever or loop_count < repeat):
            print(f"[replay] Starting loop {loop_count + 1}...")
            write_header(output, headers)

    print(f"\n[replay] Done. Total events sent: {total_sent:,}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay dataset conn.log as live Zeek traffic for the pipeline."
    )
    parser.add_argument(
        "--source", type=Path, default=None,
        help="Path to source conn.log (auto-detected if not set)"
    )
    parser.add_argument(
        "--output", type=Path, default=LIVE_OUTPUT_FILE,
        help=f"Output file for live replay (default: {LIVE_OUTPUT_FILE})"
    )
    parser.add_argument(
        "--rate", type=float, default=1.0,
        help="Events per second (0 = burst/max speed). Default: 1"
    )
    parser.add_argument(
        "--repeat", type=int, default=1,
        help="Number of times to replay the dataset (default: 1)"
    )
    parser.add_argument(
        "--loop", action="store_true",
        help="Loop the replay infinitely (Ctrl+C to stop)"
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Remove existing live output before starting"
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Find source
    if args.source:
        source = args.source
        if not source.exists():
            print(f"[replay] ERROR: Source file not found: {source}", file=sys.stderr)
            return 1
    else:
        try:
            source = find_source_log()
        except FileNotFoundError as exc:
            print(f"[replay] ERROR: {exc}", file=sys.stderr)
            return 1

    # Clean if requested
    if args.clean and args.output.exists():
        args.output.unlink()
        print(f"[replay] Cleaned {args.output}")

    return replay(
        source=source,
        output=args.output,
        rate=args.rate,
        repeat=args.repeat,
        loop_forever=args.loop,
    )


if __name__ == "__main__":
    raise SystemExit(main())

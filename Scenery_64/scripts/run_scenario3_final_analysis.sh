#!/usr/bin/env bash
set -euo pipefail

TRIALS="${1:-100}"
SEED="${2:-0x5343454E45525933}"

mkdir -p results
bash scripts/run_scenario3_repeated_chunked.sh "$TRIALS" "$SEED"
python3 scripts/scenario3_analysis.py

#!/usr/bin/env bash
set -euo pipefail

TRIALS="${1:-100}"
MASTER_SEED="${2:-0x5343454E45525932}"

mkdir -p results
make all
make scenario2-step2
./build/scenario2_repeated_experiments \
  "$TRIALS" \
  "$MASTER_SEED" \
  results/scenario2_repeated_trials.csv \
  results/scenario2_repeated_roles.csv
python3 scripts/scenario2_analysis.py

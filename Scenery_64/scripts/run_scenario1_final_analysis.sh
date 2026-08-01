#!/usr/bin/env bash
set -euo pipefail
TRIALS="${1:-100}"
MASTER_SEED="${2:-0x5343454E45525931}"
mkdir -p results paper_artifacts/figures paper_artifacts/tables reports
make all
./build/scenario1_repeated_experiments "$TRIALS" "$MASTER_SEED" \
  results/scenario1_repeated_trials.csv \
  results/scenario1_repeated_words.csv | tee reports/scenario1_repeated_experiments.log
python3 scripts/scenario1_analysis.py | tee reports/scenario1_analysis.log

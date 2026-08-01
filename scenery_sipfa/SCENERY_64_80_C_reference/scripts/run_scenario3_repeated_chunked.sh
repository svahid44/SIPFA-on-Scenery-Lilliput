#!/usr/bin/env bash
set -euo pipefail

TRIALS="${1:-100}"
MASTER_SEED="${2:-0x5343454E45525933}"
CHUNKS="${SCENARIO3_CHUNKS:-10}"

if (( TRIALS < 1 )); then
  echo "trials must be positive" >&2
  exit 2
fi
if (( CHUNKS < 1 )); then
  CHUNKS=1
fi
if (( CHUNKS > TRIALS )); then
  CHUNKS="$TRIALS"
fi

mkdir -p results
TMPDIR_SCENARIO3="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SCENARIO3"' EXIT

base=$((TRIALS / CHUNKS))
remainder=$((TRIALS % CHUNKS))
offset=0

for ((i=0; i<CHUNKS; ++i)); do
  count="$base"
  if (( i < remainder )); then
    count=$((count + 1))
  fi
  seed=$((MASTER_SEED + i * 0x10001))
  printf '%d,%d\n' "$i" "$offset" >> "$TMPDIR_SCENARIO3/offsets.csv"
  ./build/scenario3_repeated_experiments \
    "$count" \
    "$seed" \
    "$TMPDIR_SCENARIO3/chunk_${i}_trials.csv" \
    "$TMPDIR_SCENARIO3/chunk_${i}_words.csv" \
    > "$TMPDIR_SCENARIO3/chunk_${i}.log" &
  offset=$((offset + count))
done
wait

python3 - "$TMPDIR_SCENARIO3" "$CHUNKS" <<'PY'
import csv
import sys
from pathlib import Path

tmp = Path(sys.argv[1])
chunks = int(sys.argv[2])
offsets = {}
with (tmp / "offsets.csv").open() as handle:
    for line in handle:
        chunk, offset = map(int, line.strip().split(","))
        offsets[chunk] = offset

root = Path("results")
for kind in ("trials", "words"):
    destination = root / f"scenario3_repeated_{kind}.csv"
    writer = None
    with destination.open("w", newline="", encoding="utf-8") as output:
        for chunk in range(chunks):
            source = tmp / f"chunk_{chunk}_{kind}.csv"
            with source.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                if writer is None:
                    writer = csv.DictWriter(output, fieldnames=reader.fieldnames)
                    writer.writeheader()
                for row in reader:
                    row["trial"] = str(offsets[chunk] + int(row["trial"]))
                    writer.writerow(row)
PY

cat "$TMPDIR_SCENARIO3"/chunk_*.log
printf 'merged repeated trials: %s\n' "$TRIALS"
printf 'raw trial CSV: results/scenario3_repeated_trials.csv\n'
printf 'raw word CSV:  results/scenario3_repeated_words.csv\n'
printf 'PASS: chunked repeated known-fault infection experiments completed.\n'

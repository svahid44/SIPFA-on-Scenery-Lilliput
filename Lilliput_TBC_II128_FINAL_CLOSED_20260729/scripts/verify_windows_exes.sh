#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EXPECTED_BINARIES=(
  bin/windows/test_tbc.exe
  bin/windows/test_persistent_fault.exe
  bin/windows/test_attack_round.exe
  bin/windows/test_attack_api.exe
  bin/windows/test_phase2_article_mapping.exe
  bin/windows/test_phase3_scenario1_rtk30.exe
  bin/windows/test_master_key_recovery.exe
  bin/windows/test_phase5_scenario4_full_key.exe
  bin/windows/test_scenario1_known_detection.exe
  bin/windows/test_scenario2_unknown_detection.exe
  bin/windows/test_scenario3_known_infection.exe
  bin/windows/test_scenario4_unknown_infection.exe
  bin/windows/scenario1_known_detection.exe
  bin/windows/scenario1_rtk30_known_detection.exe
  bin/windows/scenario1_full_key_known_detection.exe
  bin/windows/scenario2_unknown_detection.exe
  bin/windows/scenario3_known_infection.exe
  bin/windows/scenario4_unknown_infection.exe
  bin/windows/scenario4_full_key_unknown_infection.exe
  PROJECT_OVERVIEW.exe
  RUN_ALL_TESTS.exe
  RUN_ALL_SCENARIOS.exe
  RUN_FULL_PRESENTATION.exe
)

failures=0
for exe in "${EXPECTED_BINARIES[@]}"; do
  if [[ ! -s "$exe" ]]; then
    printf '[MISSING] %s\n' "$exe" >&2
    failures=$((failures + 1))
  else
    printf '[OK] %s (%s bytes)\n' "$exe" "$(stat -c '%s' "$exe")"
  fi
done

actual="$(find bin/windows -maxdepth 1 -type f -name '*.exe' | wc -l)"
printf 'bin/windows EXE count: %s\n' "$actual"
printf 'root launcher count : %s\n' "$(find . -maxdepth 1 -type f -name '*.exe' | wc -l)"

if [[ -f build_reports/WINDOWS_EXE_SHA256SUMS.txt ]]; then
  sha256sum -c build_reports/WINDOWS_EXE_SHA256SUMS.txt
else
  printf '[MISSING] build_reports/WINDOWS_EXE_SHA256SUMS.txt\n' >&2
  failures=$((failures + 1))
fi

if (( failures != 0 )); then
  printf '[FAIL] Windows executable verification failed: %d problem(s).\n' "$failures" >&2
  exit 1
fi
printf '[PASS] All 23 Windows executables are present and checksum-valid.\n'

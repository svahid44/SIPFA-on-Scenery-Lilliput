#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
rm -rf bin/windows
rm -f PROJECT_OVERVIEW.exe RUN_ALL_TESTS.exe RUN_ALL_SCENARIOS.exe RUN_FULL_PRESENTATION.exe
rm -f build_reports/WINDOWS_EXECUTABLE_MANIFEST.csv
rm -f build_reports/WINDOWS_EXE_SHA256SUMS.txt
rm -f build_reports/windows_build_from_wsl.log
rm -f build_reports/windows_pe_validation.log
printf '[OK] Generated Windows executables and reports were removed.\n'

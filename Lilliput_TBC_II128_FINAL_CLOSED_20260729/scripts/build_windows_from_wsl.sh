#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WINDOWS_CC="${WINDOWS_CC:-x86_64-w64-mingw32-gcc}"
OUT_DIR="${WINDOWS_OUT_DIR:-bin/windows}"
REPORT_DIR="build_reports"
LOG_DIR="logs/windows"

if ! command -v "$WINDOWS_CC" >/dev/null 2>&1; then
    cat >&2 <<MSG
[ERROR] Windows cross-compiler not found: $WINDOWS_CC
Install it inside WSL with:

  sudo apt update
  sudo apt install -y mingw-w64 make file

Then run:

  make windows-exes
MSG
    exit 127
fi

mkdir -p "$OUT_DIR" "$REPORT_DIR" "$LOG_DIR" results

COMMON_SOURCES=(
    src/cipher.c
    src/round.c
    src/tweakey.c
    src/persistent_fault.c
    src/attack_common.c
    src/attack_round.c
    src/reference_validation.c
    src/reference_trace.c
    src/detection_dataset.c
    src/known_detection_iterative.c
    src/master_key_recovery.c
    src/unknown_detection_attack.c
    src/infection_dataset.c
    src/known_infection_attack.c
    src/unknown_infection_attack.c
    src/unknown_infection_full_recovery.c
)

TEST_TARGETS=(
    test_tbc
    test_persistent_fault
    test_attack_round
    test_attack_api
    test_phase2_article_mapping
    test_phase3_scenario1_rtk30
    test_master_key_recovery
    test_phase5_scenario4_full_key
    test_scenario1_known_detection
    test_scenario2_unknown_detection
    test_scenario3_known_infection
    test_scenario4_unknown_infection
)

SCENARIO_TARGETS=(
    scenario1_known_detection
    scenario1_rtk30_known_detection
    scenario1_full_key_known_detection
    scenario2_unknown_detection
    scenario3_known_infection
    scenario4_unknown_infection
    scenario4_full_key_unknown_infection
)

LAUNCHERS=(
    "PROJECT_OVERVIEW:presentation/project_overview.c"
    "RUN_ALL_TESTS:presentation/run_all_tests.c"
    "RUN_ALL_SCENARIOS:presentation/run_all_scenarios.c"
    "RUN_FULL_PRESENTATION:presentation/run_full_presentation.c"
)

CFLAGS=(
    -std=c99 -O2
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror
    -Iinclude
    -static -static-libgcc
)

LDFLAGS=()

BUILD_LOG="$REPORT_DIR/windows_build_from_wsl.log"
: > "$BUILD_LOG"

log() {
    printf '%s\n' "$*" | tee -a "$BUILD_LOG"
}

compile_program() {
    local source_file="$1"
    local output_file="$2"
    log "[BUILD] $output_file"
    "$WINDOWS_CC" "${CFLAGS[@]}" "${COMMON_SOURCES[@]}" "$source_file" \
        "${LDFLAGS[@]}" -o "$output_file" 2>&1 | tee -a "$BUILD_LOG"
}

compile_launcher() {
    local source_file="$1"
    local output_file="$2"
    log "[BUILD] $output_file"
    "$WINDOWS_CC" -std=c99 -O2 -Wall -Wextra -Wpedantic -Werror \
        -Ipresentation -static -static-libgcc "$source_file" -o "$output_file" \
        2>&1 | tee -a "$BUILD_LOG"
}

log "==============================================================================="
log "Lilliput-TBC-II-128 / SIPFA Windows build from WSL"
log "Project : $ROOT_DIR"
log "Compiler: $($WINDOWS_CC --version | head -n 1)"
log "Output  : $OUT_DIR"
log "==============================================================================="

for target in "${TEST_TARGETS[@]}"; do
    compile_program "tests/${target}.c" "$OUT_DIR/${target}.exe"
done

for target in "${SCENARIO_TARGETS[@]}"; do
    compile_program "tools/${target}.c" "$OUT_DIR/${target}.exe"
done

for entry in "${LAUNCHERS[@]}"; do
    name="${entry%%:*}"
    source="${entry#*:}"
    compile_launcher "$source" "${name}.exe"
done

# Build a deterministic manifest from the binaries that were just generated.
MANIFEST="$REPORT_DIR/WINDOWS_EXECUTABLE_MANIFEST.csv"
printf 'category,name,path,size_bytes,sha256\n' > "$MANIFEST"
for target in "${TEST_TARGETS[@]}"; do
    path="$OUT_DIR/${target}.exe"
    printf 'test,%s,%s,%s,%s\n' "$target" "$path" "$(stat -c '%s' "$path")" "$(sha256sum "$path" | awk '{print $1}')" >> "$MANIFEST"
done
for target in "${SCENARIO_TARGETS[@]}"; do
    path="$OUT_DIR/${target}.exe"
    printf 'scenario,%s,%s,%s,%s\n' "$target" "$path" "$(stat -c '%s' "$path")" "$(sha256sum "$path" | awk '{print $1}')" >> "$MANIFEST"
done
for entry in "${LAUNCHERS[@]}"; do
    name="${entry%%:*}"
    path="${name}.exe"
    printf 'launcher,%s,%s,%s,%s\n' "$name" "$path" "$(stat -c '%s' "$path")" "$(sha256sum "$path" | awk '{print $1}')" >> "$MANIFEST"
done

# A checksum file limited to generated Windows artifacts.
{
    find "$OUT_DIR" -maxdepth 1 -type f -name '*.exe' -print0
    printf '%s\0' PROJECT_OVERVIEW.exe RUN_ALL_TESTS.exe RUN_ALL_SCENARIOS.exe RUN_FULL_PRESENTATION.exe
} | sort -z | xargs -0 sha256sum > "$REPORT_DIR/WINDOWS_EXE_SHA256SUMS.txt"

# Verify PE format when the `file` utility is available.
PE_REPORT="$REPORT_DIR/windows_pe_validation.log"
: > "$PE_REPORT"
if command -v file >/dev/null 2>&1; then
    while IFS= read -r -d '' exe; do
        description="$(file -b "$exe")"
        printf '%s: %s\n' "$exe" "$description" | tee -a "$PE_REPORT"
        if [[ "$description" != *"PE32+"* && "$description" != *"PE32 executable"* ]]; then
            printf '[ERROR] Not a Windows PE executable: %s\n' "$exe" | tee -a "$PE_REPORT" >&2
            exit 1
        fi
    done < <(find "$OUT_DIR" -maxdepth 1 -type f -name '*.exe' -print0 | sort -z)
    for exe in PROJECT_OVERVIEW.exe RUN_ALL_TESTS.exe RUN_ALL_SCENARIOS.exe RUN_FULL_PRESENTATION.exe; do
        description="$(file -b "$exe")"
        printf '%s: %s\n' "$exe" "$description" | tee -a "$PE_REPORT"
        if [[ "$description" != *"PE32+"* && "$description" != *"PE32 executable"* ]]; then
            printf '[ERROR] Not a Windows PE executable: %s\n' "$exe" | tee -a "$PE_REPORT" >&2
            exit 1
        fi
    done
else
    log "[WARN] 'file' utility is unavailable; PE-format inspection was skipped."
fi

TEST_COUNT="${#TEST_TARGETS[@]}"
SCENARIO_COUNT="${#SCENARIO_TARGETS[@]}"
LAUNCHER_COUNT="${#LAUNCHERS[@]}"
TOTAL_COUNT=$((TEST_COUNT + SCENARIO_COUNT + LAUNCHER_COUNT))

log "==============================================================================="
log "[PASS] Windows build completed inside the current project."
log "Tests     : $TEST_COUNT EXE files"
log "Scenarios : $SCENARIO_COUNT EXE files"
log "Launchers : $LAUNCHER_COUNT EXE files"
log "Total     : $TOTAL_COUNT EXE files"
log "Manifest  : $MANIFEST"
log "Checksums : $REPORT_DIR/WINDOWS_EXE_SHA256SUMS.txt"
log "==============================================================================="

#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(pwd)"
PROJECT_NAME="Lilliput_TBC_II128_FINAL_PACKAGE"
PARENT_DIR="$(dirname "$PROJECT_ROOT")"
PACKAGE_DIR="$PARENT_DIR/$PROJECT_NAME"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ZIP_NAME="${PROJECT_NAME}_${TIMESTAMP}.zip"
ZIP_PATH="$PARENT_DIR/$ZIP_NAME"

WINDOWS_CC="x86_64-w64-mingw32-gcc"

echo
echo "============================================================"
echo " Lilliput-TBC-II-128 Final Package Builder"
echo "============================================================"
echo

required_files=(
    "src/cipher.c"
    "src/tweakey.c"
    "src/persistent_fault.c"
    "src/detection_dataset.c"
    "src/unknown_detection_attack.c"
    "src/infection_dataset.c"
    "src/known_infection_attack.c"
    "src/unknown_infection_attack.c"

    "tools/scenario1_known_detection.c"
    "tools/scenario2_unknown_detection.c"
    "tools/scenario3_known_infection.c"
    "tools/scenario4_unknown_infection.c"

    "tests/test_tbc.c"
    "tests/test_persistent_fault.c"
    "tests/test_scenario1_known_detection.c"
    "tests/test_scenario2_unknown_detection.c"
    "tests/test_scenario3_known_infection.c"
    "tests/test_scenario4_unknown_infection.c"
)

echo "[1/10] Checking project files..."

for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing file:"
        echo "  $file"
        echo
        echo "Make sure Scenario 4 patch has been applied."
        exit 1
    fi
done

if ! command -v "$WINDOWS_CC" >/dev/null 2>&1; then
    echo "ERROR: MinGW cross compiler is not installed."
    echo
    echo "Install it with:"
    echo "sudo apt install -y mingw-w64"
    exit 1
fi

echo "PASS: Required source files found."

echo
echo "[2/10] Cleaning previous builds..."

make clean || true

mkdir -p results

echo
echo "[3/10] Building and running all Linux tests..."

make test 2>&1 | tee results/final_all_tests.log

echo
echo "[4/10] Running all four scenarios..."

make scenario1 2>&1 | tee results/final_scenario1.log
make scenario2 2>&1 | tee results/final_scenario2.log
make scenario3 2>&1 | tee results/final_scenario3.log
make scenario4 2>&1 | tee results/final_scenario4.log

echo
echo "[5/10] Creating organized package directory..."

rm -rf "$PACKAGE_DIR"

mkdir -p "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR/bin/linux"
mkdir -p "$PACKAGE_DIR/bin/windows"
mkdir -p "$PACKAGE_DIR/logs/linux"
mkdir -p "$PACKAGE_DIR/logs/windows"
mkdir -p "$PACKAGE_DIR/results"
mkdir -p "$PACKAGE_DIR/scripts"

echo
echo "[6/10] Copying project sources, documents and results..."

tar \
    --exclude='./build' \
    --exclude='./.git' \
    --exclude='*.zip' \
    --exclude='*.tar.gz' \
    -cf - . | tar -xf - -C "$PACKAGE_DIR"

cp -f results/*.log "$PACKAGE_DIR/logs/linux/" 2>/dev/null || true

echo
echo "[7/10] Copying Linux executables..."

if [[ -d build ]]; then
    while IFS= read -r -d '' executable; do
        cp -f "$executable" "$PACKAGE_DIR/bin/linux/"
    done < <(
        find build \
            -maxdepth 1 \
            -type f \
            -perm -111 \
            -print0
    )
fi

echo
echo "[8/10] Cross-compiling Windows EXE files..."

mapfile -t COMMON_SOURCES < <(
    find src \
        -maxdepth 1 \
        -type f \
        -name '*.c' \
        | sort
)

WINDOWS_FLAGS=(
    -Iinclude
    -std=c99
    -O2
    -Wall
    -Wextra
    -Wpedantic
    -D_WIN32_WINNT=0x0601
    -static
    -static-libgcc
)

build_windows_exe() {
    local input_file="$1"
    local output_name="$2"

    echo "  Building $output_name"

    "$WINDOWS_CC" \
        "${WINDOWS_FLAGS[@]}" \
        "${COMMON_SOURCES[@]}" \
        "$input_file" \
        -o "$PACKAGE_DIR/bin/windows/$output_name" \
        -lm
}

build_windows_exe \
    tests/test_tbc.c \
    test_tbc.exe

build_windows_exe \
    tests/test_persistent_fault.c \
    test_persistent_fault.exe

build_windows_exe \
    tests/test_scenario1_known_detection.c \
    test_scenario1_known_detection.exe

build_windows_exe \
    tests/test_scenario2_unknown_detection.c \
    test_scenario2_unknown_detection.exe

build_windows_exe \
    tests/test_scenario3_known_infection.c \
    test_scenario3_known_infection.exe

build_windows_exe \
    tests/test_scenario4_unknown_infection.c \
    test_scenario4_unknown_infection.exe

build_windows_exe \
    tools/scenario1_known_detection.c \
    scenario1_known_detection.exe

build_windows_exe \
    tools/scenario2_unknown_detection.c \
    scenario2_unknown_detection.exe

build_windows_exe \
    tools/scenario3_known_infection.c \
    scenario3_known_infection.exe

build_windows_exe \
    tools/scenario4_unknown_infection.c \
    scenario4_unknown_infection.exe

echo
echo "[9/10] Creating Windows batch launchers..."

cat > "$PACKAGE_DIR/RUN_ALL_TESTS_WINDOWS.bat" <<'EOF'
@echo off
setlocal

cd /d "%~dp0"

echo ============================================================
echo Lilliput-TBC-II-128 - All Tests
echo ============================================================
echo.

if not exist results mkdir results
if not exist logs mkdir logs
if not exist logs\windows mkdir logs\windows

echo [1/6] Baseline cipher test
bin\windows\test_tbc.exe
if errorlevel 1 goto failed

echo.
echo [2/6] Persistent fault test
bin\windows\test_persistent_fault.exe
if errorlevel 1 goto failed

echo.
echo [3/6] Scenario 1 test
bin\windows\test_scenario1_known_detection.exe
if errorlevel 1 goto failed

echo.
echo [4/6] Scenario 2 test
bin\windows\test_scenario2_unknown_detection.exe
if errorlevel 1 goto failed

echo.
echo [5/6] Scenario 3 test
bin\windows\test_scenario3_known_infection.exe
if errorlevel 1 goto failed

echo.
echo [6/6] Scenario 4 test
bin\windows\test_scenario4_unknown_infection.exe
if errorlevel 1 goto failed

echo.
echo ============================================================
echo ALL TESTS PASSED
echo ============================================================
pause
exit /b 0

:failed
echo.
echo ============================================================
echo A TEST FAILED
echo ============================================================
pause
exit /b 1
EOF

cat > "$PACKAGE_DIR/RUN_ALL_SCENARIOS_WINDOWS.bat" <<'EOF'
@echo off
setlocal

cd /d "%~dp0"

echo ============================================================
echo Lilliput-TBC-II-128 - SIPFA Scenarios
echo ============================================================
echo.

if not exist results mkdir results
if not exist logs mkdir logs
if not exist logs\windows mkdir logs\windows

echo [1/4] Scenario 1
echo Known fault + Detection-based countermeasure
bin\windows\scenario1_known_detection.exe
if errorlevel 1 goto failed

echo.
echo [2/4] Scenario 2
echo Unknown fault + Detection-based countermeasure
bin\windows\scenario2_unknown_detection.exe
if errorlevel 1 goto failed

echo.
echo [3/4] Scenario 3
echo Known fault + Infection-based countermeasure
bin\windows\scenario3_known_infection.exe
if errorlevel 1 goto failed

echo.
echo [4/4] Scenario 4
echo Unknown fault + Infection-based countermeasure
bin\windows\scenario4_unknown_infection.exe
if errorlevel 1 goto failed

echo.
echo ============================================================
echo ALL FOUR SCENARIOS COMPLETED SUCCESSFULLY
echo ============================================================
echo.
echo Results are available in:
echo   results\
echo.
pause
exit /b 0

:failed
echo.
echo ============================================================
echo A SCENARIO FAILED
echo ============================================================
pause
exit /b 1
EOF

cat > "$PACKAGE_DIR/RUN_SCENARIO1_WINDOWS.bat" <<'EOF'
@echo off
cd /d "%~dp0"
if not exist results mkdir results
bin\windows\scenario1_known_detection.exe
pause
EOF

cat > "$PACKAGE_DIR/RUN_SCENARIO2_WINDOWS.bat" <<'EOF'
@echo off
cd /d "%~dp0"
if not exist results mkdir results
bin\windows\scenario2_unknown_detection.exe
pause
EOF

cat > "$PACKAGE_DIR/RUN_SCENARIO3_WINDOWS.bat" <<'EOF'
@echo off
cd /d "%~dp0"
if not exist results mkdir results
bin\windows\scenario3_known_infection.exe
pause
EOF

cat > "$PACKAGE_DIR/RUN_SCENARIO4_WINDOWS.bat" <<'EOF'
@echo off
cd /d "%~dp0"
if not exist results mkdir results
bin\windows\scenario4_unknown_infection.exe
pause
EOF

cat > "$PACKAGE_DIR/README_WINDOWS.txt" <<'EOF'
Lilliput-TBC-II-128 SIPFA Final Package
========================================

This package contains:

1. Complete C source code
2. Linux executables
3. Windows 64-bit EXE executables
4. All result CSV files
5. All test and scenario logs
6. Documentation for all four SIPFA scenarios

Windows execution
-----------------

Run all tests:

    RUN_ALL_TESTS_WINDOWS.bat

Run all scenarios:

    RUN_ALL_SCENARIOS_WINDOWS.bat

Run individual scenarios:

    RUN_SCENARIO1_WINDOWS.bat
    RUN_SCENARIO2_WINDOWS.bat
    RUN_SCENARIO3_WINDOWS.bat
    RUN_SCENARIO4_WINDOWS.bat

Windows executables are located in:

    bin\windows\

Linux executables are located in:

    bin\linux\

Results are located in:

    results\

Scenarios
---------

Scenario 1:
Known persistent fault + detection-based countermeasure

Scenario 2:
Unknown persistent fault + detection-based countermeasure

Scenario 3:
Known persistent fault + infection-based countermeasure

Scenario 4:
Unknown persistent fault + infection-based countermeasure

Expected recovered values
-------------------------

Fault input:

    0x5a

Final-round tweakey:

    b3ed58adabab101d
EOF

cat > "$PACKAGE_DIR/PROJECT_SUMMARY.txt" <<'EOF'
Lilliput-TBC-II-128 SIPFA Project Summary
=========================================

Cipher:
    Lilliput-TBC-II-128

Block size:
    128 bits

Key size:
    128 bits

Tweak size:
    128 bits

Rounds:
    32

Final round tweakey:
    RTK[31]

Recovered RTK[31]:
    b3ed58adabab101d

Persistent fault input:
    0x5a

Implemented scenarios:
    Scenario 1 - Known fault, detection-based
    Scenario 2 - Unknown fault, detection-based
    Scenario 3 - Known fault, infection-based
    Scenario 4 - Unknown fault, infection-based

All scenarios:
    PASS
EOF

echo
echo "[10/10] Creating manifest, checksums and final ZIP..."

{
    echo "Build date:"
    date
    echo
    echo "Linux GCC:"
    gcc --version | head -1
    echo
    echo "Windows cross compiler:"
    "$WINDOWS_CC" --version | head -1
    echo
    echo "Make:"
    make --version | head -1
} > "$PACKAGE_DIR/BUILD_INFORMATION.txt"

(
    cd "$PACKAGE_DIR"

    find . \
        -type f \
        ! -name "MANIFEST.txt" \
        ! -name "checksums.sha256" \
        | sort \
        > MANIFEST.txt

    find . \
        -type f \
        ! -name "checksums.sha256" \
        -print0 \
        | sort -z \
        | xargs -0 sha256sum \
        > checksums.sha256
)

rm -f "$ZIP_PATH"

(
    cd "$PARENT_DIR"
    zip -r -9 "$ZIP_NAME" "$PROJECT_NAME"
)

ZIP_SHA256="$(sha256sum "$ZIP_PATH" | awk '{print $1}')"

echo
echo "============================================================"
echo " FINAL PACKAGE CREATED SUCCESSFULLY"
echo "============================================================"
echo
echo "Package directory:"
echo "  $PACKAGE_DIR"
echo
echo "ZIP file:"
echo "  $ZIP_PATH"
echo
echo "ZIP SHA-256:"
echo "  $ZIP_SHA256"
echo
echo "Windows executables:"
ls -1 "$PACKAGE_DIR/bin/windows"
echo
echo "Linux executables:"
ls -1 "$PACKAGE_DIR/bin/linux"
echo

WINDOWS_DESKTOP="/mnt/c/Users/SADRA/Desktop"

if [[ -d "$WINDOWS_DESKTOP" ]]; then
    cp -f "$ZIP_PATH" "$WINDOWS_DESKTOP/"
    echo "A copy was also placed on the Windows Desktop:"
    echo "  C:\\Users\\SADRA\\Desktop\\$ZIP_NAME"
fi

echo
echo "Done."

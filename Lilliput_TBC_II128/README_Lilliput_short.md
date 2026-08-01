# SIPFA on Lilliput-TBC-II-128

This directory contains the C implementation, tests, experimental tools, and result artifacts used to evaluate four Statistical Ineffective Persistent Fault Analysis (SIPFA) scenarios on Lilliput-TBC-II-128.

## Directory structure

```text
Lilliput_TBC_II128/
├── include/          Public headers and attack interfaces
├── src/              Cipher, fault model, datasets, and recovery algorithms
├── tests/            Cipher, fault-model, scenario, and key-recovery tests
├── tools/            Standalone programs for the four SIPFA scenarios
├── scripts/          Windows cross-build and verification scripts
├── bin/windows/      Compiled Windows executables
├── results/          Generated experimental outputs
├── paper_artifacts/  Figures, tables, and summarized results
└── presentation/     Source code for the presentation launchers
```

## Main source files

| File | Purpose |
|---|---|
| `src/cipher.c` | Lilliput-TBC-II-128 encryption implementation |
| `src/tweakey.c` | Tweakey schedule |
| `src/persistent_fault.c` | Persistent S-box fault model |
| `src/detection_dataset.c` | Detection-based dataset generation |
| `src/infection_dataset.c` | Infection-based dataset generation |
| `src/known_detection_iterative.c` | Known-fault detection attack |
| `src/unknown_detection_attack.c` | Unknown-fault detection attack |
| `src/known_infection_attack.c` | Known-fault infection attack |
| `src/unknown_infection_attack.c` | Unknown-fault infection attack |
| `src/master_key_recovery.c` | Master-key recovery from recovered round material |

## Recommended execution order

### 1. Build the Windows executables from WSL

```bash
sudo apt update
sudo apt install -y mingw-w64
cd Lilliput_TBC_II128
bash scripts/build_windows_from_wsl.sh
```

### 2. Verify the generated executables

```bash
bash scripts/verify_windows_exes.sh
```

### 3. Run the complete test suite

From Windows:

```text
RUN_ALL_TESTS.exe
```

From WSL:

```bash
cmd.exe /c RUN_ALL_TESTS.exe
```

### 4. Run all four SIPFA scenarios

From Windows:

```text
RUN_ALL_SCENARIOS.exe
```

From WSL:

```bash
cmd.exe /c RUN_ALL_SCENARIOS.exe
```

### 5. Run individual experiments

```text
bin/windows/scenario1_full_key_known_detection.exe
bin/windows/scenario2_unknown_detection.exe
bin/windows/scenario3_known_infection.exe
bin/windows/scenario4_full_key_unknown_infection.exe
```

## Scenario map

| Scenario | Fault knowledge | Countermeasure | Main executable |
|---:|---|---|---|
| 1 | Known fault | Detection | `scenario1_full_key_known_detection.exe` |
| 2 | Unknown fault | Detection | `scenario2_unknown_detection.exe` |
| 3 | Known fault | Infection | `scenario3_known_infection.exe` |
| 4 | Unknown fault | Infection | `scenario4_full_key_unknown_infection.exe` |

Generated figures and summarized experimental results are available in `paper_artifacts/`.

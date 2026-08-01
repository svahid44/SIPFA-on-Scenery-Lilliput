# SIPFA on SCENERY-64/80

This directory contains the C implementation, tests, experimental tools, and result artifacts used to evaluate four Statistical Ineffective Persistent Fault Analysis (SIPFA) scenarios on SCENERY-64/80.

## Directory structure

```text
Scenery_64/
├── include/          Public headers and attack interfaces
├── src/              Cipher, fault model, datasets, and recovery algorithms
├── tests/            Cipher, fault-model, scenario, and regression tests
├── tools/            Standalone programs for the four SIPFA scenarios
├── scripts/          Experiment, analysis, and convenience scripts
├── results/          Generated CSV outputs and experiment summaries
├── paper_artifacts/  Figures, tables, and publication material
├── docs/             Technical documentation
├── reports/          Build, test, and validation reports
├── Makefile
└── CMakeLists.txt
```

## Main source files

| File | Purpose |
|---|---|
| `src/scenery.c` | SCENERY-64/80 encryption, decryption, key schedule, and round trace |
| `src/persistent_fault.c` | Persistent single-entry logical S-box fault model |
| `src/detection_dataset.c` | Detection-based ineffective ciphertext collection |
| `src/infection_dataset.c` | Infection-based public output generation |
| `src/known_detection_attack.c` | Scenario 1 missing-value recovery |
| `src/unknown_detection_attack.c` | Scenario 2 fault localization and active-key filtering |
| `src/known_infection_attack.c` | Scenario 3 minimum-frequency recovery |
| `src/unknown_infection_attack.c` | Scenario 4 SEI localization, ranking, and structural audit |

## Recommended execution order

### 1. Build and test the implementation

```bash
cd Scenery_64
make clean
make all
make test
```

### 2. Run the four reference scenarios

```bash
make scenario1-step4
make scenario2-step2
make scenario3-step2
make scenario4-step3
```

### 3. Run all final experiments

```bash
make scenario1-final
make scenario2-final
make scenario3-final
make scenario4-final
```

The `final` targets include repeated experiments and may require more execution time than the fixed reference campaigns.

### 4. Optional CMake build

```bash
cmake -S . -B build-cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build-cmake --parallel
ctest --test-dir build-cmake --output-on-failure
```

## Scenario map

| Scenario | Fault knowledge | Countermeasure | Main result |
|---:|---|---|---|
| 1 | Known S-box and known `delta` | Detection | Complete 32-bit final-round subkey `SK28` |
| 2 | Unknown S-box and unknown `delta` | Detection | Fault location, unique `delta`, and 18 of 20 active `SK28` bits |
| 3 | Known S-box and known `delta` | Infection | Complete 32-bit final-round subkey `SK28` |
| 4 | Unknown S-box and unknown `delta` | Infection | Fault location, unique `delta`, and an 18-bit consensus within a four-candidate structural class |

Generated datasets are written to `results/`, and figures and summarized tables are stored in `paper_artifacts/`.

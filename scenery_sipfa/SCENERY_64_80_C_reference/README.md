# SIPFA on SCENERY-64/80

[![C99 build and tests](https://github.com/svahid44/SCENERY-64-80-SIPFA/actions/workflows/ci.yml/badge.svg)](https://github.com/svahid44/SCENERY-64-80-SIPFA/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/svahid44/SCENERY-64-80-SIPFA?include_prereleases)](https://github.com/svahid44/SCENERY-64-80-SIPFA/releases)
[![Language](https://img.shields.io/badge/language-C99-blue.svg)](#build-and-test)
[![Research software](https://img.shields.io/badge/status-research%20software-orange.svg)](#scope-and-limitations)

A reproducible C99 implementation of **Statistical Ineffective Persistent Fault Analysis (SIPFA)** on the lightweight Feistel block cipher **SCENERY-64/80**.

The repository includes a validated implementation of the cipher, a persistent single-entry logical S-box fault model, detection- and infection-based countermeasure simulators, all four SIPFA scenarios, deterministic tests, repeated experiments, CSV datasets, figures, Excel workbooks, and technical reports.

> **Research software only.** This implementation is intended for academic evaluation and reproducibility. It is not guaranteed to be constant-time and must not be used as production cryptographic software.

[Persian README](README_FA.md) · [Reproducibility guide](docs/REPRODUCIBILITY.md) · [Results summary](docs/RESULTS_SUMMARY.md) · [Comprehensive Persian report](docs/reports/SIPFA_SCENERY_64_80_Comprehensive_Report_FA.docx)

---

## Project overview

This project adapts the four attack settings introduced in the SIPFA framework to SCENERY-64/80:

1. known persistent fault with a detection-based countermeasure;
2. unknown persistent fault with a detection-based countermeasure;
3. known persistent fault with an infection-based countermeasure;
4. unknown persistent fault with an infection-based countermeasure.

The implementation deliberately separates the **public attack inputs** from the **simulation ground truth**. Attack routines do not receive the master key or the true final-round key. In the unknown-fault scenarios, they also do not receive the actual fault location, the real fault input `delta`, plaintexts, or effective/ineffective event labels.

The deterministic reference key produces:

```text
Final-round key SK28     = A3B7389D
Unknown-fault location   = logical S-box 5
Unknown-fault delta      = 0xB
Actual active candidate  = 0x3BB7E
```

---

## Target cipher

| Property | Value |
|---|---|
| Cipher | SCENERY-64/80 |
| Block size | 64 bits |
| Master-key size | 80 bits |
| Structure | Balanced Feistel network |
| Number of rounds | 28 |
| Round-key size | 32 bits |
| Logical S-boxes | Eight bitsliced 4-bit lanes |
| Round function | AddRoundKey → SubColumns → MixColumns |
| Reference final-round key | `SK28 = A3B7389D` |

The baseline C implementation is validated against:

- all four official appendix test vectors;
- the complete 28-round trace of test vector 1;
- all 28 round keys of the reference key-schedule trace;
- 200 deterministic Python-generated cross-validation vectors;
- 10,000 encryption/decryption round trips;
- GCC and Clang builds;
- CMake/CTest;
- AddressSanitizer and UndefinedBehaviorSanitizer checks.

---

## Persistent-fault model

A persistent fault modifies exactly one input entry of one logical 4-bit S-box lane:

```text
S_faulty[sbox][delta] = (S_correct[delta] + 1) mod 16
```

The modified entry remains active across all rounds and encryptions until the fault state is reset. For a single logical S-box used once per round, the approximate ineffective-event probability is:

```text
P_ineffective = (15/16)^28 ≈ 0.164132936375
```

Two countermeasure models are implemented:

- **Detection-based:** an output is released only when the correct and faulty computations are equal. The public dataset therefore contains only verified ineffective ciphertexts.
- **Infection-based:** every query releases one output. Ineffective events release the correct ciphertext, while effective events release an independent random 64-bit block. Event labels remain hidden from the attack.

---

## Implemented attack scenarios

| Scenario | Fault knowledge | Countermeasure | Supported final result |
|---:|---|---|---|
| 1 | Known S-box and known `delta` | Detection | Complete 32-bit `SK28` recovery |
| 2 | Unknown S-box and unknown `delta` | Detection | Fault location, unique `delta`, and 18 of 20 active `SK28` bits; four structural candidates remain |
| 3 | Known S-box and known `delta` | Infection | Complete 32-bit `SK28` recovery |
| 4 | Unknown S-box and unknown `delta` | Infection | Fault location, unique `delta`, and 18 of 20 active `SK28` bits; four structurally indistinguishable rank-one candidates remain |

### Scenario 1 — known fault, detection-based

For each logical S-box, the detection oracle collects only ineffective ciphertexts. A 16-bin histogram is built from the public last-round word. The unique missing value satisfies:

```text
missing[j] = delta XOR SK28[j]
SK28[j]    = missing[j] XOR delta
```

Eight independent campaigns recover the eight 4-bit words and reconstruct the complete 32-bit final-round key.

```bash
make scenario1-step4
```

Reference result:

```text
Recovered SK28 = A3B7389D
Actual SK28    = A3B7389D
Status         = PASS
```

### Scenario 2 — unknown fault, detection-based

The final-round supports are inspected across all eight logical S-box lanes. The unique persistent missing value identifies the faulty lane and its public missing word. Exact partial decryption then evaluates the complete active-key space:

```text
2^20 = 1,048,576 candidates
```

The fixed experiment leaves the following four structural candidates:

```text
0x3B37E
0x3B77E
0x3BB7E  <-- actual
0x3BF7E
```

Their consensus determines 18 of the 20 active key bits, and the unknown fault input is uniquely recovered as `delta = 0xB`.

```bash
make scenario2-step2
```

Supported result:

```text
Detected S-box           = 5
Recovered delta          = 0xB
Recovered active bits    = 18/20
Actual candidate rank    = 1, tied among four candidates
Status                   = PASS
```

### Scenario 3 — known fault, infection-based

Because infected outputs fill the target bin with random values, the target is no longer absent. Instead, it becomes the unique minimum-frequency value. The known `delta` converts each lane minimum into the corresponding 4-bit word of `SK28`.

```bash
make scenario3-step2
```

Reference result:

```text
Recovered SK28 = A3B7389D
Actual SK28    = A3B7389D
Status         = PASS
```

### Scenario 4 — unknown fault, infection-based

Scenario 4 is implemented in three stages.

#### Step 1: fault localization

All public outputs are unlabeled. The attack ranks the eight logical S-box distributions using squared Euclidean imbalance, identifies the faulty lane, and produces the 16 coupled `(delta, SK28-word)` hypotheses implied by the public minimum.

```bash
make scenario4-step1
```

#### Step 2: exact active-key ranking

The attack ranks all `2^20` active last-round key candidates. Exact partial-decryption SEI scores are computed using a 20-dimensional XOR Walsh-Hadamard convolution. The attack routine receives no master key, true `delta`, or event labels.

```bash
make scenario4-step2
```

The correct structural class is ranked first, the unknown `delta` is recovered uniquely, and 18 of 20 active key bits are determined.

#### Step 3: structural-equivalence audit

The four rank-one candidates are compared sample by sample. Each candidate sequence is either identical to another sequence or differs from it by a constant XOR. Therefore their histograms are permutations of one another and their SEI scores remain equal for every tested dataset prefix.

```bash
make scenario4-step3
```

Final supported result:

```text
Detected S-box                       = 5
Recovered delta                      = 0xB
Actual active candidate              = 0x3BB7E
Actual candidate present             = YES
Actual candidate uniquely identified = NO
Honest recovery                      = 18/20 active bits + unique delta
More samples break the current tie   = NO
Status                               = PASS
```

The remaining two bits are structurally unidentifiable under the current one-word SEI observation. This is a property of the observation model, not a failure caused by insufficient sample size.

![Scenario 4 analysis preview](docs/assets/scenario4_analysis_preview.png)

---

## Repeated-experiment results

The repository includes randomized repeated experiments and success-rate curves for all four scenarios.

| Scenario | Representative sample size | Observed result |
|---:|---:|---|
| 1 | 128 ineffective ciphertexts per S-box | 99/100 complete `SK28` recoveries |
| 1 | 160 ineffective ciphertexts per S-box | 100/100 complete `SK28` recoveries |
| 2 | 512 ineffective ciphertexts | 100/100 recoveries of the supported 18/20-bit class and unique `delta` |
| 3 | 16,384 public outputs per S-box | 99/100 complete `SK28` recoveries |
| 3 | 24,576 public outputs per S-box | 100/100 complete `SK28` recoveries |
| 4 | 65,536 public outputs | 99/100 recoveries of the correct structural class, 18-bit consensus, and unique `delta` |
| 4 | 65,536 public outputs | 0/100 unique 20-bit recoveries, as predicted by the structural audit |

An observed `100/100` result is an empirical outcome, not a mathematical guarantee. The generated reports include Wilson confidence intervals.

Selected figures:

![Scenario 1 success curve](docs/assets/scenario1_success_vs_samples.png)

![Scenario 3 success curve](docs/assets/scenario3_success_vs_samples.png)

---

## Build and test

### Requirements

For the core C project:

- a C99 compiler, such as GCC or Clang;
- GNU Make or CMake;
- a POSIX-like environment for the shell scripts.

For plots and Excel workbooks:

- Python 3;
- packages listed in `requirements-analysis.txt`.

### GNU Make

```bash
make clean
make all
make test
```

### CMake and CTest

```bash
cmake -S . -B build-cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build-cmake --parallel
ctest --test-dir build-cmake --output-on-failure
```

### Windows

From a compiler-enabled Windows terminal:

```bat
BUILD_AND_TEST_WINDOWS.bat
```

The fixed attack campaigns can be run with:

```bat
RUN_ALL_REFERENCE_CAMPAIGNS_WINDOWS.bat
```

---

## Run the reference campaigns

Run the final deterministic stage of each scenario:

```bash
make scenario1-step4
make scenario2-step2
make scenario3-step2
make scenario4-step3
```

Run all four in sequence:

```bash
bash scripts/run_all_reference_campaigns.sh
```

The generated CSV files are written to `results/`.

Useful individual targets include:

```bash
# Scenario 1
make scenario1-dataset
make scenario1-recover-word
make scenario1-recover-full

# Scenario 2
make scenario2-dataset
make scenario2-identify
make scenario2-filter
make scenario2-verify

# Scenario 3
make scenario3-dataset
make scenario3-recover-word
make scenario3-recover-full

# Scenario 4
make scenario4-dataset
make scenario4-identify
make scenario4-rank
make scenario4-audit-tie
```

---

## Regenerate publication artifacts

Install the Python dependencies:

```bash
python3 -m pip install -r requirements-analysis.txt
```

Then run one or more complete evaluation targets:

```bash
make scenario1-final
make scenario2-final
make scenario3-final
make scenario4-final
```

The `final` targets include repeated experiments and may require substantially more CPU time than the fixed deterministic campaigns.

Generated artifacts include:

- raw and summarized CSV files;
- success-rate curves;
- per-S-box heatmaps;
- SEI candidate-ranking plots;
- query-complexity plots;
- PNG, PDF, and SVG figures;
- Excel analysis workbooks;
- Persian and English result reports.

These files are stored in `results/` and `paper_artifacts/`.

---

## Repository layout

```text
.
├── .github/                CI workflow and contribution templates
├── include/                Public C headers
├── src/                    Cipher, fault model, datasets, and attack cores
├── tests/                  Baseline, regression, and attack tests
├── tools/                  Standalone scenario executables
├── examples/               Encryption and round-trace examples
├── scripts/                Analysis and convenience scripts
├── results/                Deterministic and repeated-experiment CSV outputs
├── paper_artifacts/        Figures, tables, and Excel workbooks
├── docs/                   Technical documentation and reports
├── Makefile
├── CMakeLists.txt
├── CITATION.cff
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── NOTICE.md
└── requirements-analysis.txt
```

### Main implementation files

| File | Purpose |
|---|---|
| `src/scenery.c` | SCENERY encryption, decryption, key schedule, and trace support |
| `src/persistent_fault.c` | Persistent single-entry logical S-box fault model |
| `src/detection_dataset.c` | Detection-based ineffective-output collection |
| `src/infection_dataset.c` | Unlabeled infection-output generation |
| `src/known_detection_attack.c` | Scenario 1 missing-value recovery |
| `src/unknown_detection_attack.c` | Scenario 2 localization and active-key filtering |
| `src/known_infection_attack.c` | Scenario 3 minimum-frequency recovery |
| `src/unknown_infection_attack.c` | Scenario 4 localization, exact ranking, and structural audit |

---

## Reproducibility and validation

The repository provides:

- deterministic seeds for fixed campaigns;
- generated public datasets and summaries;
- regression tests for every attack stage;
- Make and CMake build paths;
- GCC and Clang CI jobs;
- checksums in `SHA256SUMS.txt`;
- a complete file listing in `MANIFEST.txt`;
- detailed Persian phase reports;
- a comprehensive Persian Word report.

See:

- [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md)
- [`docs/RESULTS_SUMMARY.md`](docs/RESULTS_SUMMARY.md)
- [`docs/reports/SIPFA_SCENERY_64_80_Comprehensive_Report_FA.docx`](docs/reports/SIPFA_SCENERY_64_80_Comprehensive_Report_FA.docx)

---

## Attack and ground-truth boundary

The project maintains a strict separation between attack inputs and validation data:

- the master key is never supplied to an attack routine;
- the true `SK28` is never supplied to an attack routine;
- unknown-fault routines do not receive the actual S-box index or `delta`;
- infection-based routines do not receive event labels;
- plaintexts are not required by the public recovery routines;
- ground truth is used only after recovery to verify success.

This separation is enforced in the APIs and regression tests.

---

## Scope and limitations

The project supports the following claims:

- all four SIPFA scenarios are implemented on SCENERY-64/80;
- Scenarios 1 and 3 recover the complete 32-bit final-round key `SK28`;
- Scenarios 2 and 4 identify the unknown faulty logical S-box and recover a unique `delta`;
- Scenarios 2 and 4 recover an 18-bit consensus within a four-member active-key equivalence class;
- Scenario 4 includes a sample-by-sample proof that the final two active bits cannot be distinguished under the current one-word SEI observation.

The project does **not** currently claim:

- recovery of the complete 80-bit SCENERY master key;
- a physical persistent-fault injection experiment on hardware;
- robustness against arbitrary multi-entry, transient, or noisy fault models;
- unique recovery of all 20 active bits in Scenarios 2 and 4;
- constant-time or side-channel-resistant software;
- suitability for production cryptographic use.

---

## Citation

GitHub can render the software citation directly from [`CITATION.cff`](CITATION.cff).

If this repository or its experimental artifacts are used in academic work, cite both the repository and the original SIPFA paper:

> N. Bagheri, S. Sadeghi, P. Ravi, S. Bhasin, and H. Soleimany, “SIPFA: Statistical Ineffective Persistent Faults Analysis on Feistel Ciphers,” *IACR Transactions on Cryptographic Hardware and Embedded Systems*, 2022(3), pp. 367–390, 2022.

Project author:

- **Vahid Soleimani** — [GitHub](https://github.com/svahid44) · [ORCID](https://orcid.org/0009-0002-7821-3607)

---

## Contributing and security

Contributions that improve correctness, portability, reproducibility, documentation, or experimental coverage are welcome. Before opening a pull request, read [`CONTRIBUTING.md`](CONTRIBUTING.md).

For implementation or reproducibility issues, use the GitHub issue template. For sensitive security concerns, follow [`SECURITY.md`](SECURITY.md).

Do not submit real secret keys, confidential hardware traces, or proprietary fault-injection data to public issues.

---

## Attribution and license status

This repository combines a SCENERY implementation, research adaptations, attack code, datasets, and generated experimental artifacts. No new open-source license is imposed on upstream material by this package.

Review [`NOTICE.md`](NOTICE.md) and the terms of the original sources before redistribution, modification, or reuse.

---

## Version

Current research release: **v1.0.0**

See [`CHANGELOG.md`](CHANGELOG.md) and [`RELEASE_NOTES_v1.0.0.md`](RELEASE_NOTES_v1.0.0.md) for release details.

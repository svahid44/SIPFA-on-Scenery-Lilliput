# SIPFA Evaluation and Full-Key Recovery on Lilliput-TBC-II-128

**Authors:** [AUTHOR 1], [AUTHOR 2], [ADDITIONAL AUTHORS]  
**Affiliations:** [AFFILIATION 1], [AFFILIATION 2]  
**Emails:** [EMAIL 1], [EMAIL 2]  
**Associated paper:** [PAPER TITLE, VENUE, YEAR, DOI]  
**Repository URL:** `https://github.com/[GITHUB-USERNAME]/[REPOSITORY-NAME]`

> Replace all bracketed fields in this file, `AUTHORS.md`, and `CITATION.cff` before publication.

## Overview

This repository provides a reproducible C implementation and experimental evaluation of Statistical Ineffective Persistent Fault Analysis (SIPFA) on **Lilliput-TBC-II-128**. It contains the validated cipher implementation, a persistent shared-S-box fault model, four attack scenarios, two complete master-key recovery chains, unit and end-to-end tests, reference CSV results, paper-ready figures and LaTeX tables, continuous integration, and WSL-based Windows cross-compilation.

The central result is an end-to-end recovery of the 128-bit master key under two simulated settings:

1. a known persistent S-box fault with a detection-based countermeasure; and
2. an unknown persistent S-box fault with an infection-based countermeasure.

Both chains first recover the last two 64-bit round tweakeys and then invert the official Lilliput tweakey schedule by solving a full-rank 128-by-128 system over GF(2).

## Target parameters

| Parameter | Value |
|---|---:|
| Primitive | Lilliput-TBC-II-128 |
| Block size | 128 bits |
| Key size | 128 bits |
| Tweak size | 128 bits |
| Number of rounds | 32 |
| Round tweakey size | 64 bits |
| Nonlinear layer | Shared 8-bit S-box |

## Research scope

The implemented fault changes exactly one entry of the shared S-box lookup table and keeps that modification active across every round and subsequent faulty encryption until reset. The cipher and tweakey schedule otherwise remain correct.

The repository evaluates four SIPFA scenarios:

| Scenario | Fault value | Countermeasure | Attack mechanism | Main output |
|---|---|---|---|---|
| 1 | Known | Detection-based | Missing-value analysis | `RTK[31]` |
| 2 | Unknown | Detection-based | Candidate enumeration and penultimate-round filtering | `delta`, `RTK[31]` |
| 3 | Known | Infection-based | Minimum-frequency analysis | `RTK[31]` |
| 4 | Unknown | Infection-based | SEI ranking after partial inversion | `delta`, `RTK[31]` |

The complete chains additionally recover `RTK[30]` and invert the tweakey schedule to obtain the master key.

## Main reference result

For the default deterministic experiment configuration:

```text
recovered fault input delta = 0x5a
recovered RTK[31]           = b3ed58adabab101d
recovered RTK[30]           = 8ae2660cd1ea6cc0
GF(2) system rank           = 128
recovered master key        = 000102030405060708090a0b0c0d0e0f
validation ciphertext       = fdb0d1a0b68a8e3c9579e9aa7a5704b9
```

The Scenario 4 reference experiment uses 100,000 unlabeled published ciphertexts and produces a positive SEI winner gap. All expected values are recorded in `results/scenario4_full_key_summary.csv`.

## Repository contents

```text
include/           Public interfaces and cipher parameters
src/               Cipher, fault model, datasets, attacks, and key inversion
tests/             Unit, mapping, boundary, and full-chain tests
tools/             Standalone executables for Scenarios 1--4
results/           Reference datasets, histograms, candidates, and summaries
validation/        Machine-readable validation records and concise reports
paper_artifacts/   Figures, tables, and LaTeX integration files
presentation/      Console launchers for Windows presentation builds
scripts/           Reproduction, boundary-check, and cross-build scripts
docs/              Detailed technical report and reproducibility documentation
.github/workflows/ Continuous-integration and Windows cross-build workflows
```

A file-by-file explanation is provided in [`docs/REPOSITORY_STRUCTURE.md`](docs/REPOSITORY_STRUCTURE.md).

## Quick start

### Linux or WSL

```bash
sudo apt update
sudo apt install -y build-essential make
make test
```

Run all four scenarios and both full-key chains:

```bash
make scenarios
```

Run only the two end-to-end key-recovery experiments:

```bash
make scenario1-full-key
make scenario4-full-key
```

### Strict validation

```bash
make check-gcc
make check-clang
make check-sanitize
```

The tests cover the official cipher vector, encryption/decryption round trips, persistent fault behavior, exact final-round inversion, paper-to-implementation mapping, attacker-input boundaries, all four attack scenarios, iterative `RTK[30]` recovery, GF(2) master-key inversion, and both end-to-end chains.

## Attack methodology

### Detection-based model

The simulator computes correct and faulty encryptions. Only outputs satisfying `C_correct == C_faulty` are released. These accepted ciphertexts represent ineffective events. In the known-fault setting, the persistent fault excludes one last-round S-box input in each lane, yielding

```text
missing[j] = delta XOR RTK[31][j].
```

After recovering `RTK[31]`, the implementation removes the final round and applies the same argument to recover `RTK[30]`.

### Infection-based model

The published dataset is unlabeled. Ineffective events retain correct ciphertexts, whereas effective events are replaced by randomized outputs. The correct candidate remains statistically biased. Scenario 3 uses the least frequent byte value per lane. Scenario 4 enumerates every `delta` candidate, partially inverts the final round, and ranks the resulting distributions with Squared Euclidean Imbalance.

### Master-key recovery

For a fixed public tweak, a round tweakey is an affine function of the master key:

```text
RTK[r] = A_r K XOR b_r(T).
```

Combining rounds 30 and 31 gives 128 equations in 128 unknown key bits. The matrix is generated from basis keys using the official Lilliput transformations and solved with Gaussian elimination over GF(2). The reference matrix has rank 128 and therefore a unique solution.

## Reproducibility and paper use

The detailed reproduction procedure is in [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md). The methodological report is in [`docs/TECHNICAL_REPORT.md`](docs/TECHNICAL_REPORT.md), and the compact result table is in [`docs/RESULTS.md`](docs/RESULTS.md).

Paper-ready artifacts are stored in `paper_artifacts/`:

- vector PDF and 300-DPI PNG figures;
- LaTeX tables suitable for `\input{...}`;
- a scenario summary CSV;
- example LaTeX integration commands.

The repository is intended to be cited through `CITATION.cff`. Replace its author, repository, release-date, and paper placeholders before creating the GitHub release used by the manuscript.

## Building Windows executables from WSL

```bash
sudo apt install -y mingw-w64 file
make windows-rebuild
```

This creates experiment and test executables under `bin/windows/` and the following launchers in the repository root:

```text
PROJECT_OVERVIEW.exe
RUN_ALL_TESTS.exe
RUN_ALL_SCENARIOS.exe
RUN_FULL_PRESENTATION.exe
```

See [`docs/WINDOWS_WSL.md`](docs/WINDOWS_WSL.md).

## Assumptions and limitations

The reported results are simulation results for a single persistent corruption of one shared S-box entry. The experiments do not model missed injections, multiple corrupted entries, timing or spatial uncertainty, device resets during acquisition, additional measurement noise, alternate infection distributions, masked implementations, or a new physical fault-injection campaign. The code is a research prototype and must not be used as a production cryptographic library.

The SIPFA algorithms were published for Feistel ciphers such as DES, 3DES, and Camellia. Their statistical principles are adapted here to Lilliput-TBC-II-128 and its shared S-box structure. The final conversion from two recovered round tweakeys to the master key is specific to the official Lilliput tweakey schedule.

## Upstream software and references

The Lilliput cipher and tweakey source files are derived from the public Lilliput-AE reference implementation by Kévin Le Gouguec and retain their CC0 notices.

Primary references:

1. N. Bagheri, S. Sadeghi, P. Ravi, S. Bhasin, and H. Soleimany, “SIPFA: Statistical Ineffective Persistent Faults Analysis on Feistel Ciphers,” *IACR Transactions on Cryptographic Hardware and Embedded Systems*, 2022(3), pp. 367–390, 2022. DOI: `10.46586/tches.v2022.i3.367-390`.
2. T. P. Berger, J. Francq, M. Minier, and G. Thomas, “Extended Generalized Feistel Networks Using Matrix Representation to Propose a New Lightweight Block Cipher: Lilliput,” *IEEE Transactions on Computers*, 65(7), pp. 2074–2089, 2016. DOI: `10.1109/TC.2015.2468218`.
3. Lilliput-AE submission and reference implementation, version 1.1, NIST Lightweight Cryptography process, 2019.

## License

The repository currently uses CC0-1.0 to match the upstream reference source. Confirm the intended license for the authors’ original additions before publication.

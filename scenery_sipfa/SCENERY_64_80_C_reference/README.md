# SCENERY-64/80 C Reference

Portable C99 implementation of the 64-bit block / 80-bit key / 28-round SCENERY cipher.

```sh
make clean && make all && make test
```

Validated against all four appendix vectors, the complete 28-round TV1 trace, 200 deterministic Python-generated vectors, 10,000 round trips, GCC, Clang, CMake/CTest, ASan, and UBSan.

See `README_FA.md`, `docs/PORTING_NOTES_FA.md`, and `reports/TEST_REPORT.md`.

## Scenario 4, Step 1: unknown fault with infection

The Algorithm-4 localization stage is available through:

```bash
make scenario4-step1
```

It consumes unlabeled public infection outputs, ranks all eight logical S-box lanes by squared Euclidean imbalance, identifies the faulty lane, and emits the sixteen coupled `(delta, SK28-word)` hypotheses implied by the public minimum. See `docs/PHASE12_SCENARIO4_STEP1_FA.md` for the exact attack boundary and deterministic results.

## Phase 13 — Scenario 4, Step 2

The unknown-fault infection attack now exhaustively ranks all `2^20` active
last-round key candidates. Exact partial-decryption SEI scores are computed by
a 20-dimensional XOR Walsh-Hadamard convolution; no master key, actual delta,
or event labels are inputs to the attack routine.

```bash
make scenario4-step2
```

Reference result: the correct structural class is ranked first, the unknown
delta is uniquely recovered, and 18 of the 20 active key bits are determined.
Four MixColumns-equivalent candidates remain.


## Phase 14 — Scenario 4, Step 3

The four rank-1 candidates from Step 2 are audited for structural
indistinguishability under the same one-word partial-decryption SEI
observation.

```bash
make scenario4-step3
```

The audit proves sample by sample that every candidate sequence is either
identical to another sequence or differs by one constant XOR. Therefore all
histograms are permutations and all SEI scores remain equal for every dataset
prefix. Additional samples cannot resolve the two remaining bits without
changing the observation or the attack assumptions. The honest final Step-3
claim is `18/20 active bits + unique delta`.

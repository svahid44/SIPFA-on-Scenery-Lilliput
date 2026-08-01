# SIPFA on SCENERY-64/80 — v1.0.0

This is the first GitHub-ready research release.

## Included

- Portable C99 implementation of SCENERY-64/80.
- Official-vector, round-trace, key-schedule, cross-validation, and structural tests.
- Persistent single-entry logical S-box fault infrastructure.
- Four SIPFA scenarios under detection-based and infection-based countermeasures.
- Exhaustive `2^20` active-key analysis for unknown-fault scenarios.
- Structural-equivalence proof for the unresolved Scenario-4 bits.
- Repeated-experiment CSV files and publication-ready analysis artifacts.
- Persian and English documentation, including the comprehensive Persian Word report.
- GitHub Actions CI for GCC, Clang, and CMake/CTest.

## Validated release status

```text
Make build/test:      PASS
CMake/CTest:          17/17 PASS
Official vectors:     4/4 PASS
Reference SK28:       A3B7389D
Scenario 1 result:    complete SK28
Scenario 2 result:    18/20 active bits + unique delta
Scenario 3 result:    complete SK28
Scenario 4 result:    18/20 active bits + unique delta
```

## Important limitation

The release does not claim recovery of the full 80-bit master key or physical fault-injection validation. In Scenarios 2 and 4, four structural candidates remain under the current observation.

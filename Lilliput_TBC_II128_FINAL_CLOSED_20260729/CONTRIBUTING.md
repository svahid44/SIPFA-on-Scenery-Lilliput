# Contributing

Contributions should preserve reproducibility and the separation between attacker-visible data and simulation-only ground truth.

1. Build with both GCC and Clang using warnings as errors.
2. Run `make test` before submitting changes.
3. Do not pass secret keys, injected fault values, plaintexts, internal traces, or event labels into attack APIs unless the scenario explicitly assumes that information.
4. Add a deterministic test for every new attack or fault model.
5. Document any deviation from the single persistent shared-S-box fault model.
6. Keep generated datasets and figures traceable to a command and source CSV.

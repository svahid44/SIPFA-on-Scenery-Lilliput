# Contributing

Contributions that improve correctness, reproducibility, portability, documentation, or statistical evaluation are welcome.

## Development checks

Before submitting a change, run:

```bash
make clean
make all
make test
```

Also verify the CMake path:

```bash
cmake -S . -B build-cmake
cmake --build build-cmake
ctest --test-dir build-cmake --output-on-failure
```

## Scientific integrity requirements

- Keep simulation ground truth separate from attack inputs.
- Do not pass the master key, actual `SK28`, actual unknown `delta`, or hidden event labels into unknown-fault attack routines.
- Distinguish observed success rates from mathematical guarantees.
- Preserve the structural-equivalence limitation in Scenarios 2 and 4 unless a new observation demonstrably breaks it.
- Add deterministic regression tests for algorithmic changes.
- Document changed experiment parameters and random seeds.

## Code style

The project targets portable C99 and builds with strict warnings:

```text
-Wall -Wextra -Wpedantic -Wshadow -Wconversion
```

Avoid compiler-specific extensions unless they are isolated and documented.

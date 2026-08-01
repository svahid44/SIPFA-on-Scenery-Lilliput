# Security policy

## Intended use

This repository is designed for cryptographic research, reproducibility, and education. It intentionally contains fault-injection and cryptanalysis code.

## Not suitable for production

The implementation is table-based and does not claim constant-time behavior, side-channel resistance, secure key storage, hardened randomness, or production-quality fault countermeasures. Do not deploy it to protect real secrets.

## Reporting a problem

For implementation defects, incorrect scientific claims, accidental ground-truth leakage into an attack routine, or reproducibility failures, open a GitHub issue with:

- compiler and operating-system details;
- the exact command used;
- the smallest reproducible input or dataset;
- expected and observed behavior.

Do not include real secret keys or confidential hardware information in public issues.

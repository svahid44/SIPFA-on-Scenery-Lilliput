# Source map

Target: Lilliput-TBC-II-128, reference implementation version 1.1.

| Local file | Official source path |
|---|---|
| include/parameters.h | src/ii-128/parameters.h |
| include/constants.h | src/ref/constants.h |
| include/cipher.h | src/ref/cipher.h |
| include/tweakey.h | src/ref/tweakey.h |
| include/multiplications.h | src/ref/multiplications.h |
| src/cipher.c | src/ref/cipher.c |
| src/tweakey.c | src/ref/tweakey.c |

Local additions:

- Makefile
- tests/test_tbc.c
- README_FA.md

The local test uses the public ascending-byte trace input and verifies encryption/decryption round-trip.

Validation vector: official `src/add_vhdltbc/ii/ii-128/tb/top_tb.vhd`; the local byte-array representation is `0e00dd58ba4110fca88da6edca38d95d`.


Additional local fault-analysis files:

- include/persistent_fault.h
- include/detection_dataset.h
- include/unknown_detection_attack.h
- include/infection_dataset.h
- include/known_infection_attack.h
- include/unknown_infection_attack.h
- src/persistent_fault.c
- src/detection_dataset.c
- src/unknown_detection_attack.c
- src/infection_dataset.c
- src/known_infection_attack.c
- src/unknown_infection_attack.c
- tests/test_persistent_fault.c
- tests/test_scenario1_known_detection.c
- tests/test_scenario2_unknown_detection.c
- tests/test_scenario3_known_infection.c
- tests/test_scenario4_unknown_infection.c
- tools/scenario1_known_detection.c
- tools/scenario2_unknown_detection.c
- tools/scenario3_known_infection.c
- tools/scenario4_unknown_infection.c

These are local research additions; they are not part of the official reference implementation.

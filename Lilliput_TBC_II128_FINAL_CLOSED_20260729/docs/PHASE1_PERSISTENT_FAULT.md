# Phase 1 — Persistent S-box fault infrastructure

This phase preserves the validated Lilliput-TBC-II-128 reference encryption and
adds a second encryption path using a persistent faulty lookup table.

Fault model:

- shared 8-bit S-box;
- exactly one modified table entry at a time;
- fault persists across all rounds and subsequent faulty encryptions;
- tweakey schedule remains correct;
- reset restores the original table.

New API:

- `lilliput_fault_reset()`
- `lilliput_fault_inject(delta, faulty_output)`
- `lilliput_tbc_encrypt_faulty(...)`

Validation:

- official reference vector still passes;
- correct and faulty paths agree before injection;
- effective and ineffective encryptions are both observed;
- repeated faulty encryption is deterministic;
- reset restores correct behavior.

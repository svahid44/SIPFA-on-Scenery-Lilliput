# Phase 2 — SIPFA Scenario 1 on Lilliput-TBC-II-128

## Attack assumptions

- persistent corruption of one shared 8-bit S-box entry;
- fault input `delta` and its location/model are known;
- detection-based countermeasure returns output only for ineffective events;
- key and public tweak remain fixed while random 128-bit plaintexts are queried.

## Dataset generation

For every plaintext, the program computes both the correct and faulty encryption.
Only samples satisfying

```text
C_correct == C_faulty
```

are retained.  These emulate outputs accepted by a detection-based redundant
implementation.  The generator stores plaintext/ciphertext pairs and builds one
256-bin histogram for each of ciphertext bytes 0..7.

## Last-round relation

The final Lilliput-TBC round does not apply the branch permutation.  Therefore,
for lane `j`, ciphertext byte `C[j]` is the state byte entering the final S-box
before the round-tweakey XOR.  For a known faulty S-box input `delta`, ineffective
samples exclude

```text
M[j] = delta XOR RTK[31][j].
```

After enough samples, each lane must contain exactly one missing byte value.
The final round tweakey is recovered as

```text
RTK[31][j] = M[j] XOR delta.
```

## Outputs

Running `make scenario1` writes:

- `results/scenario1_ineffective_samples.csv`
- `results/scenario1_histogram.csv`

and verifies the recovered eight-byte round tweakey against the reference
schedule.  This comparison is a simulation-side correctness check; the attack
itself uses only the missing values and the known `delta`.

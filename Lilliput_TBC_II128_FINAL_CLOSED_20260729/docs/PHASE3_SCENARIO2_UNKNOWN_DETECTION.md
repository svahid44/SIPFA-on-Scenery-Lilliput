# Phase 3 — SIPFA Scenario 2 on Lilliput-TBC-II-128

## Scope and correspondence with the paper

This phase adapts the paper's **Algorithm 2**:

- detection-based countermeasure;
- persistent fault;
- unknown faulty S-box input value `delta`;
- accepted outputs are ineffective ciphertexts only;
- final-round missing-value detection;
- candidate filtering by partially undoing the last round and testing whether
  the penultimate-round support still contains an impossible value.

The target cipher differs from DES/Camellia in the paper. Lilliput-TBC-II-128
uses one shared 8-bit S-box table in all eight round calls. Therefore, the
paper's "unknown S-box location" does not become an eight-way search over
distinct S-box tables: there is one physical shared table. The shared-table
adaptation uses all eight calls as repeated observations of the same unknown
fault, consistent with the repeated-S-box relation discussed around Eq. (12).

## Attack boundary

The dataset generator knows the simulation secrets:

- 128-bit key;
- public 128-bit tweak;
- injected persistent fault;
- correct implementation used by the redundancy checker.

The attack function receives only:

```text
accepted ciphertexts + sample count
```

It is deliberately not passed:

```text
key, tweak, delta, faulty output, actual RTK[31]
```

The reference key schedule and true fault input are used only after the attack
to verify the result.

## Step 1 — accepted ineffective ciphertexts

A single table entry is changed persistently:

```text
S_faulty[delta] != S_correct[delta]
```

For each random plaintext, the simulator computes correct and faulty
encryptions. A detection-based implementation returns an output only when both
results agree. Those accepted ciphertexts are the ineffective-event dataset.

For 32 rounds, eight shared-S-box calls per round, and an 8-bit S-box input, the
paper's ineffective-event model gives

```text
Pi_c = (1 - 2^-8)^(8*32) ~= 0.36716.
```

## Step 2 — final-round missing values

The final Lilliput round has no branch permutation. For each lane `j`, the first
eight ciphertext bytes expose the value before the last-round S-box input XOR.
Among ineffective samples, one byte value is absent:

```text
M[j] = delta XOR RTK[31][j].
```

Because `delta` is unknown, the final-round histogram alone yields only relative
round-tweakey bytes:

```text
M[j] XOR M[0] = RTK[31][j] XOR RTK[31][0].
```

The attack enumerates all 256 possible values of `delta` and forms

```text
RTK_candidate[31][j] = M[j] XOR delta_candidate.
```

## Step 3 — Algorithm-2 penultimate-round filter

For each candidate:

1. remove the final no-permutation round using the candidate `RTK[31]`;
2. undo round 30's permutation only far enough to recover its left input bytes;
3. build one 256-bin support table per repeated S-box call;
4. keep the candidate only if every repeated call still has at least one
   impossible value.

The correct candidate preserves the ineffective-event exclusion in round 30.
A wrong candidate generally produces complete support and is rejected.

The filter does not need `RTK[30]`: XOR by an unknown fixed byte only translates
the support, so it does not change whether a missing value exists.

## Files

```text
include/unknown_detection_attack.h
src/unknown_detection_attack.c
tests/test_scenario2_unknown_detection.c
tools/scenario2_unknown_detection.c
```

## Commands

```bash
make clean
make test
make scenario2
```

To save the run:

```bash
make scenario2 2>&1 | tee results/scenario2_run.log
```

Generated files:

```text
results/scenario2_ineffective_samples.csv
results/scenario2_final_histogram.csv
results/scenario2_candidates.csv
results/scenario2_run.log
```

The default simulation uses a hidden nonzero fault input `0x5a`. The attack API
does not receive this value. It should reduce 256 candidates to one and recover
the complete final-round tweakey.

# Phase 4 — SIPFA Scenario 3 on Lilliput-TBC-II-128

## Scope and correspondence with the paper

This phase adapts the paper's **Algorithm 3**:

- infection-based countermeasure;
- one persistent fault in the shared 8-bit S-box table;
- known faulty S-box input value `delta`;
- all public outputs are used;
- ineffective outputs remain correct;
- effective outputs are replaced by fresh random 128-bit strings;
- the complete final-round tweakey `RTK[31]` is recovered from the
  least-frequent final-round byte in each lane.

This is the known-fault infection-based scenario.  No effective/ineffective
label is given to the attack.

## Lilliput-specific adaptation

Lilliput-TBC-II-128 has:

```text
32 rounds
8 shared-S-box calls per round
8-bit S-box input
8-byte round tweakey
```

The last round has no permutation.  Therefore, for each lane `j`, the first
eight public ciphertext bytes expose a translated version of the last-round
S-box input.  If the persistent fault is located at input `delta`, ineffective
encryptions exclude

```text
target[j] = delta XOR RTK[31][j].
```

Unlike the detection-based scenarios, the target is not completely missing
from the public histogram.  Random infected outputs still hit every byte value,
including the target.  It nevertheless appears less often than the other 255
values.

## Infection model

For every random plaintext, the simulator computes both the correct and faulty
encryptions.

```text
if correct_ciphertext == faulty_ciphertext:
    published_ciphertext = correct_ciphertext
else:
    published_ciphertext = fresh uniform random 128-bit string
```

The public callback receives only:

```text
sample_index + published_ciphertext
```

It does not receive:

```text
plaintext
effective/ineffective label
key
tweak
faulty S-box output
true RTK[31]
```

Internal event counters are retained only for simulation validation and the
final report.

## Expected distribution

For an 8-bit S-box, 8 calls per round, and 32 rounds, the paper's model gives

```text
Pi_c = (1 - 2^-8)^(8*32) ~= 0.36716.
```

For the target bin in a public final-round lane:

```text
p_target = (1 - Pi_c) / 256.
```

For every other bin:

```text
p_other = Pi_c / 255 + (1 - Pi_c) / 256.
```

Hence:

```text
p_target < p_other.
```

With enough public ciphertexts, the unique least-frequent value in lane `j`
is expected to be

```text
minimum[j] = delta XOR RTK[31][j].
```

The known-fault recovery is therefore

```text
RTK[31][j] = minimum[j] XOR delta.
```

This is the direct Lilliput adaptation of Algorithm 3.

## Attack boundary

The recovery function is:

```c
int lilliput_known_infection_recover(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t known_delta,
    lilliput_known_infection_result *result
);
```

It receives all public ciphertexts, the sample count, and the known fault input.
It does not receive any internal event labels or secret verification material.

The result stores, for each of the eight lanes:

- complete 256-bin histogram;
- least-frequent value;
- least-frequent count;
- second-least-frequent count;
- minimum multiplicity;
- recovered final-round tweakey byte.

## Default experiment

The standalone tool uses:

```text
known delta:       0x5a
published samples: 100000
key:               000102030405060708090a0b0c0d0e0f
tweak:             000102030405060708090a0b0c0d0e0f
```

The expected final-round tweakey is:

```text
b3ed58adabab101d
```

The default deterministic run recovers all eight bytes and reports a positive
gap between the minimum and second minimum in every lane.

## Files

```text
include/infection_dataset.h
include/known_infection_attack.h
src/infection_dataset.c
src/known_infection_attack.c
tests/test_scenario3_known_infection.c
tools/scenario3_known_infection.c
```

## Commands

```bash
make clean
make test
make scenario3
```

To save the run:

```bash
make scenario3 2>&1 | tee results/scenario3_run.log
```

Optional arguments:

```bash
./build/scenario3_known_infection \
  [published_samples] \
  [known_fault_input] \
  [seed] \
  [samples.csv] \
  [histogram.csv] \
  [lane_summary.csv]
```

Example:

```bash
./build/scenario3_known_infection \
  100000 0x5a 0xA54FF53A5F1D36F1 \
  results/scenario3_published_ciphertexts.csv \
  results/scenario3_final_histogram.csv \
  results/scenario3_lane_minima.csv
```

## Generated files

```text
results/scenario3_published_ciphertexts.csv
results/scenario3_final_histogram.csv
results/scenario3_lane_minima.csv
results/scenario3_run.log
```

The published-ciphertext CSV intentionally contains no event label.

# Phase 5 — SIPFA Scenario 4 on Lilliput-TBC-II-128

## Scope and correspondence with the paper

This phase adapts the paper's **Algorithm 4** to Lilliput-TBC-II-128:

- infection-based countermeasure;
- one persistent fault in the shared 8-bit S-box table;
- unknown faulty S-box input value `delta`;
- every public output is used;
- ineffective outputs remain correct;
- effective outputs are replaced by fresh random 128-bit strings;
- candidates are ranked with squared Euclidean imbalance (SEI);
- the unknown fault input and the complete final-round tweakey `RTK[31]`
  are recovered.

No effective/ineffective label is given to the recovery function.

## Lilliput-specific adaptation

The paper first identifies which distinct S-box is faulty.  Lilliput-TBC-II-128
has one shared 8-bit S-box table used by all eight nonlinear calls, so the
faulty-table location is structurally unique and all eight lanes are biased.
The unknown fault parameter is the table input byte `delta`.

The last round has no permutation.  For lane `j`, the least-frequent public
ciphertext byte is expected to be

```text
minimum[j] = delta XOR RTK[31][j].
```

Therefore the final histograms determine the relative final-round tweakey:

```text
RTK[31][j] XOR RTK[31][0] = minimum[j] XOR minimum[0].
```

There are still 256 possible absolute translations.  For each candidate `d`,

```text
candidate_RTK31[j] = minimum[j] XOR d.
```

The attack peels the final round with this candidate and histograms the eight
penultimate-round left bytes.

## SEI ranking

For delta candidate `d`, penultimate lane `j`, byte value `x`, and `N` public
ciphertexts, define

```text
p[d][j][x] = count[d][j][x] / N.
```

The lane score is

```text
SEI[d][j] = sum_x (p[d][j][x] - 1/256)^2.
```

Because the shared persistent fault affects all eight lanes, the implementation
uses the aggregate score

```text
aggregate_SEI[d] = sum_j SEI[d][j].
```

An unknown `RTK[30][j]` only XOR-translates the penultimate distribution and
does not change its SEI.  The correct candidate preserves the persistent-fault
bias after final-round inversion, while wrong candidates are closer to uniform.
The unique largest aggregate SEI is selected.

Finally,

```text
recovered_delta = argmax_d aggregate_SEI[d]
recovered_RTK31[j] = minimum[j] XOR recovered_delta.
```

## Attack boundary

The recovery interface is:

```c
int lilliput_unknown_infection_recover(
    const uint8_t *ciphertexts,
    size_t sample_count,
    lilliput_unknown_infection_result *result
);
```

It receives only:

```text
all unlabeled public ciphertexts
number of public ciphertexts
```

It does not receive:

```text
key
tweak
fault input
fault output
effective/ineffective labels
actual RTK[31]
```

The secret fault input and the actual round tweakey are used only by the
standalone simulator after the attack for ground-truth validation.

## Default deterministic experiment

```text
secret fault input: 0x5a
published samples:  100000
key:                000102030405060708090a0b0c0d0e0f
tweak:              000102030405060708090a0b0c0d0e0f
```

Expected result:

```text
recovered delta:   0x5a
recovered RTK[31]: b3ed58adabab101d
```

The reference deterministic run ranks `0x5a` first with a positive gap between
the best and second-best aggregate SEI values.

## Files

```text
include/unknown_infection_attack.h
src/unknown_infection_attack.c
tests/test_scenario4_unknown_infection.c
tools/scenario4_unknown_infection.c
```

The existing infection-based generator is reused:

```text
include/infection_dataset.h
src/infection_dataset.c
```

## Commands

```bash
make clean
make test
make scenario4
```

To save the run:

```bash
make scenario4 2>&1 | tee results/scenario4_run.log
```

Optional arguments:

```bash
./build/scenario4_unknown_infection \
  [published_samples] \
  [secret_fault_input] \
  [seed] \
  [samples.csv] \
  [histogram.csv] \
  [candidates.csv]
```

Example:

```bash
./build/scenario4_unknown_infection \
  100000 0x5a 0x9B05688C2B3E6C1F \
  results/scenario4_published_ciphertexts.csv \
  results/scenario4_final_histogram.csv \
  results/scenario4_candidates.csv
```

## Generated files

```text
results/scenario4_published_ciphertexts.csv
results/scenario4_final_histogram.csv
results/scenario4_candidates.csv
results/scenario4_run.log
```

The public-ciphertext CSV intentionally contains no event label.

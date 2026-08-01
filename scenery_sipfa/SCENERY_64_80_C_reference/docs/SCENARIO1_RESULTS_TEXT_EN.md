# Manuscript-ready Scenario 1 results text

## Experimental setup

Scenario 1 implements the known-fault, detection-based SIPFA setting. A single known input of one logical 4-bit S-box is persistently modified, and the redundant detector releases a ciphertext only when the correct and faulted executions coincide. Eight independent campaigns target the eight logical bitsliced S-boxes of SCENERY. For each campaign, the unique missing public last-round value reveals one four-bit word of the final round key through `SK28[j] = missing[j] XOR delta`.

To evaluate data complexity, we conducted 100 independent experiments. Each experiment used a fresh random 80-bit key, a fresh random known fault input, and independent deterministic campaign seeds. The number of released ineffective ciphertexts per S-box was varied from 16 to 256.

## Main result

The attack recovered the complete 32-bit final-round key in all eight fixed 4096-sample campaigns. For the reference experiment, the recovered and actual values were both `A3B7389D`.

The repeated experiments show a sharp success transition. The complete-key success rate was 59% at 80 ineffective ciphertexts per S-box, 83% at 96 samples, 94% at 112 samples, and 99% at 128 samples. All 100 experiments succeeded at 160 samples and above; the 95% Wilson interval at 160 samples is approximately [96.3%, 100%].

At 128 ineffective ciphertexts per S-box, the mean total oracle cost over the eight campaigns was 6254.28 queries with a standard deviation of 167.60. The mean empirical ineffective-event rate remained close to the theoretical value `(15/16)^28 = 0.164132936` over the complete sample grid.

## Claim boundary

These results demonstrate complete recovery of `SK28`, the 32-bit final-round key. They do not by themselves constitute recovery of the 80-bit master key. The evaluation is currently software-based and does not include a physical fault-injection experiment.

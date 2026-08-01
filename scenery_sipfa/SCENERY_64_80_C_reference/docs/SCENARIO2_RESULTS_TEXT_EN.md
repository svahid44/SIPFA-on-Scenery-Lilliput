# Scenario 2 — Paper-ready results text

## Experimental setup

We instantiated Algorithm 2 of SIPFA on SCENERY-64/80 under an unknown persistent S-box fault and a detection-based countermeasure. The public attack input contains only ineffective ciphertexts. The faulty logical S-box, the persistent-fault input, the 80-bit master key, and the last-round subkey are hidden from the attack. The SCENERY MixColumns dependency graph yields a 20-bit active `SK28` space composed of five 4-bit logical words.

We performed 100 independent experiments. Each experiment used a random 80-bit master key, a random faulty logical S-box, a random 4-bit persistent-fault input, and an independent plaintext-generation seed. We evaluated public ineffective datasets of 64, 96, 128, 160, 192, 256, 320, 384, and 512 ciphertexts.

## Fixed-campaign result

The exhaustive `2^20` partial-decryption filter retained four candidates. Their consensus recovered 18 of the 20 active `SK28` bits. The true active-key candidate was present in the set, and the unknown persistent-fault input was uniquely recovered. The four candidates differ only in two bits of one active word, which are structurally unobservable through the targeted MixColumns output.

## Repeated-experiment results

Fault localization reached 95% at 128 ineffective ciphertexts and 100/100 observed successes at 160 ciphertexts. The complete Scenario-2 outcome—correct localization, retention of the true candidate, recovery of 18/20 active bits, and unique recovery of the fault input—was observed in 68% of trials at 256 ciphertexts, 96% at 320 ciphertexts, 97% at 384 ciphertexts, and 100/100 trials at 512 ciphertexts. The 95% Wilson interval for 100 successes in 100 trials is approximately [96.3%, 100%].

At 512 ciphertexts, every tested fault location and every tested fault input reached the same structural result: four candidates, 18 known active-key bits, and a uniquely recovered fault input. The mean number of oracle queries was 3115.36, while the mean empirical ineffective-event rate was 0.1646105, close to the theoretical `(15/16)^28 = 0.1641329`.

## Honest claim

The experiment does not establish unique recovery of all 20 active subkey bits, the complete 32-bit `SK28`, or the 80-bit master key. The supported claim is:

> Scenario 2 recovers 18 of the 20 active last-round subkey bits and the unknown persistent-fault input uniquely, leaving four structurally equivalent active-key candidates.

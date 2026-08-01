# Scenario 3 — Paper-ready Results Text

## Known persistent fault under infection

We instantiated SIPFA Algorithm 3 on SCENERY-64/80. The attacker knows the targeted logical S-box and the four-bit persistent-fault input `delta`. For an ineffective event, the oracle publishes the correct ciphertext; for an effective event, it replaces the output with an independent uniformly generated 64-bit block. Every query therefore produces one public ciphertext, and no effective/ineffective label is disclosed.

For logical S-box `j`, the correct ineffective component suppresses the public last-round value `delta XOR SK28[j]`, whereas the random infected component fills all sixteen values approximately uniformly. Consequently, the target is generally not absent but appears as the least-frequent histogram value. The recovered word is computed as `SK28[j] = minimum[j] XOR delta`. Eight independent campaigns recover the eight four-bit bitsliced words of the complete 32-bit last-round subkey.

In the fixed reference experiment, each campaign published 32,768 ciphertexts. Across all eight campaigns, 43,547 of 262,144 internal events were ineffective, giving an empirical rate of 0.166118622, close to the theoretical `(15/16)^28 = 0.164132936`. Every histogram had a unique minimum, with minimum-to-second-minimum gaps ranging from 221 to 382 counts. The recovered words `[B,3,A,C,E,7,0,B]` composed to `SK28 = A3B7389D`, equal to the reference last-round subkey.

We additionally performed 100 independent experiments with randomized 80-bit master keys, randomized four-bit fault inputs, and independent plaintext/infection seeds. Complete-subkey success increased from 26% at 4,096 published ciphertexts per S-box to 59% at 6,144, 90% at 8,192, 94% at 12,288, and 99% at 16,384. We observed 100 successes out of 100 trials at both 24,576 and 32,768 ciphertexts per S-box. The corresponding 95% Wilson interval for 100/100 observations is approximately 96.3% to 100%, so the observed rate is not interpreted as a mathematical guarantee.

Word-level recovery reached 85.625% at 4,096 samples, 94.250% at 6,144, 98.750% at 8,192, and 99.875% at 16,384. The average minimum-frequency gap grew from approximately 2.99 counts at 512 samples to 278.57 counts at 32,768 samples, quantitatively demonstrating the statistical separation introduced by additional data.

The attack implementation receives only public ciphertexts, the known S-box index, and the known `delta`; master-key and internal-event information is used solely after recovery for simulation verification. The reported result is limited to recovery of the 32-bit `SK28` subkey and does not claim recovery of the 80-bit master key or earlier round subkeys.

#ifndef ATTACK_ROUND_H
#define ATTACK_ROUND_H

#include <stdint.h>

#include "constants.h"

/*
 * One-round partial decryption used by SIPFA Algorithms 1--4.
 *
 * In the paper's notation this removes round n after sk_n is known or
 * hypothesized.  Lilliput's final round has no permutation and its
 * nonlinear-plus-linear map is an involution because the active half is not
 * modified by the round function.
 */
void lilliput_attack_peel_final_round(
    const uint8_t ciphertext[BLOCK_BYTES],
    const uint8_t final_round_tweakey[ROUND_TWEAKEY_BYTES],
    uint8_t state_after_penultimate_round[BLOCK_BYTES]
);

/*
 * Recover paper x_{n-1}: the eight pre-key bytes entering F_{n-1,I}.
 * Lilliput's F_{r,I} is the identity on these bytes; XOR with RTK[r] forms
 * the S-box inputs y_r.
 */
void lilliput_attack_extract_penultimate_inputs(
    const uint8_t state_after_penultimate_round[BLOCK_BYTES],
    uint8_t penultimate_inputs[ROUND_TWEAKEY_BYTES]
);

#endif /* ATTACK_ROUND_H */

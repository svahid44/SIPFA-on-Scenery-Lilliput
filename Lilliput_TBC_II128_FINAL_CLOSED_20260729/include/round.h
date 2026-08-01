#ifndef LILLIPUT_ROUND_H
#define LILLIPUT_ROUND_H

#include <stdint.h>

#include "constants.h"

typedef uint8_t (*lilliput_sbox_lookup)(uint8_t input);

typedef enum lilliput_round_permutation {
    LILLIPUT_PERMUTATION_ENCRYPTION = 0,
    LILLIPUT_PERMUTATION_DECRYPTION = 1,
    LILLIPUT_PERMUTATION_NONE = 2
} lilliput_round_permutation;

void lilliput_round_apply(
    uint8_t state[BLOCK_BYTES],
    const uint8_t round_tweakey[ROUND_TWEAKEY_BYTES],
    lilliput_round_permutation permutation,
    lilliput_sbox_lookup lookup
);

void lilliput_round_permute(
    uint8_t state[BLOCK_BYTES],
    lilliput_round_permutation permutation
);

/*
 * For a state after the encryption permutation, recover the eight left bytes
 * before that permutation.  These bytes are the round-function inputs because
 * the Lilliput nonlinear and linear layers modify only the opposite half.
 */
void lilliput_round_extract_pre_permutation_left(
    const uint8_t state_after_permutation[BLOCK_BYTES],
    uint8_t left_before_permutation[ROUND_TWEAKEY_BYTES]
);

#endif /* LILLIPUT_ROUND_H */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "round.h"

static const uint8_t PERMUTATIONS[2][BLOCK_BYTES] = {
    [LILLIPUT_PERMUTATION_ENCRYPTION] = {
        13, 9, 14, 8, 10, 11, 12, 15, 4, 5, 3, 1, 2, 6, 0, 7
    },
    [LILLIPUT_PERMUTATION_DECRYPTION] = {
        14, 11, 12, 10, 8, 9, 13, 15, 3, 1, 4, 5, 6, 0, 2, 7
    }
};

static uint8_t round_function_byte(
    uint8_t state_byte,
    uint8_t tweakey_byte,
    lilliput_sbox_lookup lookup
)
{
    return lookup((uint8_t)(state_byte ^ tweakey_byte));
}

static void nonlinear_layer(
    uint8_t state[BLOCK_BYTES],
    const uint8_t round_tweakey[ROUND_TWEAKEY_BYTES],
    lilliput_sbox_lookup lookup
)
{
    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        state[15U - lane] ^=
            round_function_byte(state[lane], round_tweakey[lane], lookup);
    }
}

static void linear_layer(uint8_t state[BLOCK_BYTES])
{
    for (size_t lane = 1U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        state[15] ^= state[lane];
    }

    for (size_t lane = 14U; lane > 8U; --lane) {
        state[lane] ^= state[7];
    }
}

void lilliput_round_permute(
    uint8_t state[BLOCK_BYTES],
    lilliput_round_permutation permutation
)
{
    uint8_t old_state[BLOCK_BYTES];

    if ((state == NULL) || (permutation == LILLIPUT_PERMUTATION_NONE)) {
        return;
    }
    if ((permutation != LILLIPUT_PERMUTATION_ENCRYPTION) &&
        (permutation != LILLIPUT_PERMUTATION_DECRYPTION)) {
        return;
    }

    memcpy(old_state, state, BLOCK_BYTES);
    for (size_t index = 0U; index < BLOCK_BYTES; ++index) {
        state[PERMUTATIONS[permutation][index]] = old_state[index];
    }
}

void lilliput_round_apply(
    uint8_t state[BLOCK_BYTES],
    const uint8_t round_tweakey[ROUND_TWEAKEY_BYTES],
    lilliput_round_permutation permutation,
    lilliput_sbox_lookup lookup
)
{
    if ((state == NULL) || (round_tweakey == NULL) || (lookup == NULL)) {
        return;
    }
    if ((permutation != LILLIPUT_PERMUTATION_ENCRYPTION) &&
        (permutation != LILLIPUT_PERMUTATION_DECRYPTION) &&
        (permutation != LILLIPUT_PERMUTATION_NONE)) {
        return;
    }

    nonlinear_layer(state, round_tweakey, lookup);
    linear_layer(state);
    lilliput_round_permute(state, permutation);
}

void lilliput_round_extract_pre_permutation_left(
    const uint8_t state_after_permutation[BLOCK_BYTES],
    uint8_t left_before_permutation[ROUND_TWEAKEY_BYTES]
)
{
    if ((state_after_permutation == NULL) ||
        (left_before_permutation == NULL)) {
        return;
    }

    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        left_before_permutation[lane] =
            state_after_permutation
                [PERMUTATIONS[LILLIPUT_PERMUTATION_ENCRYPTION][lane]];
    }
}

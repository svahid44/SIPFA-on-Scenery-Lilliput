#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "persistent_fault.h"
#include "reference_trace.h"
#include "round.h"
#include "tweakey.h"

int lilliput_reference_encrypt_trace(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t plaintext[BLOCK_BYTES],
    uint8_t ciphertext[BLOCK_BYTES],
    lilliput_reference_trace *trace
)
{
    uint8_t state[BLOCK_BYTES];
    uint8_t tweakey_state[TWEAKEY_BYTES];

    if ((key == NULL) || (tweak == NULL) || (plaintext == NULL) ||
        (ciphertext == NULL) || (trace == NULL)) {
        return -1;
    }

    memset(trace, 0, sizeof(*trace));
    memcpy(state, plaintext, BLOCK_BYTES);
    tweakey_state_init(tweakey_state, key, tweak);

    for (size_t round = 0U; round < ROUNDS; ++round) {
        const lilliput_round_permutation permutation =
            (round + 1U == ROUNDS)
                ? LILLIPUT_PERMUTATION_NONE
                : LILLIPUT_PERMUTATION_ENCRYPTION;

        if (round > 0U) {
            tweakey_state_update(tweakey_state);
        }

        tweakey_state_extract(
            tweakey_state,
            (uint8_t)round,
            trace->round_tweakey[round]
        );
        memcpy(trace->state_before_round[round], state, BLOCK_BYTES);

        for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
            trace->sbox_input[round][lane] =
                (uint8_t)(state[lane] ^ trace->round_tweakey[round][lane]);
        }

        lilliput_round_apply(
            state,
            trace->round_tweakey[round],
            permutation,
            lilliput_sbox_correct
        );
        memcpy(trace->state_after_round[round], state, BLOCK_BYTES);
    }

    memcpy(ciphertext, state, BLOCK_BYTES);
    return 0;
}

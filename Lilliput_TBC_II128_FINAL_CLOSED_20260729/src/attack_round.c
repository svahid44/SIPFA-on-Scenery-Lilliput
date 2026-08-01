#include <stdint.h>
#include <string.h>

#include "attack_round.h"
#include "persistent_fault.h"
#include "round.h"

void lilliput_attack_peel_final_round(
    const uint8_t ciphertext[BLOCK_BYTES],
    const uint8_t final_round_tweakey[ROUND_TWEAKEY_BYTES],
    uint8_t state_after_penultimate_round[BLOCK_BYTES]
)
{
    if ((ciphertext == NULL) || (final_round_tweakey == NULL) ||
        (state_after_penultimate_round == NULL)) {
        return;
    }

    memcpy(state_after_penultimate_round, ciphertext, BLOCK_BYTES);
    lilliput_round_apply(
        state_after_penultimate_round,
        final_round_tweakey,
        LILLIPUT_PERMUTATION_NONE,
        lilliput_sbox_correct
    );
}

void lilliput_attack_extract_penultimate_inputs(
    const uint8_t state_after_penultimate_round[BLOCK_BYTES],
    uint8_t penultimate_inputs[ROUND_TWEAKEY_BYTES]
)
{
    lilliput_round_extract_pre_permutation_left(
        state_after_penultimate_round,
        penultimate_inputs
    );
}

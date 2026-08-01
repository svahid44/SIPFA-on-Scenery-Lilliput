#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "attack_round.h"
#include "cipher.h"
#include "persistent_fault.h"
#include "reference_validation.h"
#include "round.h"

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

int main(void)
{
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t plaintext[BLOCK_BYTES];
    uint8_t ciphertext[BLOCK_BYTES];
    uint8_t rtk31[ROUND_TWEAKEY_BYTES];
    uint8_t peeled[BLOCK_BYTES];
    uint8_t reapplied[BLOCK_BYTES];

    for (size_t i = 0U; i < KEY_BYTES; ++i) {
        key[i] = (uint8_t)i;
        tweak[i] = (uint8_t)(0xf0U ^ (uint8_t)i);
        plaintext[i] = (uint8_t)(0xa5U ^ (uint8_t)(17U * i));
    }

    lilliput_fault_reset();
    lilliput_tbc_encrypt(key, tweak, plaintext, ciphertext);
    if (lilliput_reference_round_tweakey(
            key, tweak, ROUNDS - 1U, rtk31) != 0) {
        return fail("could not derive validation RTK[31]");
    }

    lilliput_attack_peel_final_round(ciphertext, rtk31, peeled);
    memcpy(reapplied, peeled, BLOCK_BYTES);
    lilliput_round_apply(
        reapplied,
        rtk31,
        LILLIPUT_PERMUTATION_NONE,
        lilliput_sbox_correct
    );
    if (memcmp(reapplied, ciphertext, BLOCK_BYTES) != 0) {
        return fail("final-round peeling is not the inverse of the final round");
    }

    for (size_t trial = 0U; trial < 256U; ++trial) {
        uint8_t state[BLOCK_BYTES];
        uint8_t original[BLOCK_BYTES];
        uint8_t rtk[ROUND_TWEAKEY_BYTES];
        uint8_t recovered[BLOCK_BYTES];

        for (size_t i = 0U; i < BLOCK_BYTES; ++i) {
            state[i] = (uint8_t)(trial + 29U * i);
        }
        for (size_t i = 0U; i < ROUND_TWEAKEY_BYTES; ++i) {
            rtk[i] = (uint8_t)(3U * trial + 11U * i);
        }
        memcpy(original, state, BLOCK_BYTES);
        lilliput_round_apply(
            state, rtk, LILLIPUT_PERMUTATION_NONE, lilliput_sbox_correct
        );
        lilliput_attack_peel_final_round(state, rtk, recovered);
        if (memcmp(recovered, original, BLOCK_BYTES) != 0) {
            return fail("unpermuted round involution failed");
        }
    }

    {
        uint8_t before[BLOCK_BYTES];
        uint8_t after[BLOCK_BYTES];
        uint8_t extracted[ROUND_TWEAKEY_BYTES];

        for (size_t i = 0U; i < BLOCK_BYTES; ++i) {
            before[i] = (uint8_t)(0x40U + i);
        }
        memcpy(after, before, BLOCK_BYTES);
        lilliput_round_permute(after, LILLIPUT_PERMUTATION_ENCRYPTION);
        lilliput_attack_extract_penultimate_inputs(after, extracted);
        if (memcmp(extracted, before, ROUND_TWEAKEY_BYTES) != 0) {
            return fail("penultimate input extraction uses an incorrect permutation map");
        }
    }

    puts("PASS: shared final-round peeling and penultimate-input extraction verified.");
    return 0;
}

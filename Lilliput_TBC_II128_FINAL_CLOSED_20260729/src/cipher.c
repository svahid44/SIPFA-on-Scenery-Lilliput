/*
Implementation of the Lilliput-AE tweakable block cipher.

Authors, hereby denoted as "the implementer":
    Kévin Le Gouguec,
    2019.

For more information, feedback or questions, refer to our website:
https://paclido.fr/lilliput-ae

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file provides the implementation for Lilliput-TBC.
*/
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "persistent_fault.h"
#include "round.h"
#include "tweakey.h"

static void state_init(
    uint8_t state[BLOCK_BYTES],
    const uint8_t message[BLOCK_BYTES]
)
{
    memcpy(state, message, BLOCK_BYTES);
}

static void compute_round_tweakeys(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    uint8_t round_tweakeys[ROUNDS][ROUND_TWEAKEY_BYTES]
)
{
    uint8_t tweakey_state[TWEAKEY_BYTES];

    tweakey_state_init(tweakey_state, key, tweak);
    tweakey_state_extract(tweakey_state, 0U, round_tweakeys[0]);

    for (size_t round = 1U; round < ROUNDS; ++round) {
        tweakey_state_update(tweakey_state);
        tweakey_state_extract(
            tweakey_state,
            (uint8_t)round,
            round_tweakeys[round]
        );
    }
}

static void encrypt_with_sbox(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t message[BLOCK_BYTES],
    uint8_t ciphertext[BLOCK_BYTES],
    lilliput_sbox_lookup lookup
)
{
    uint8_t state[BLOCK_BYTES];
    uint8_t round_tweakeys[ROUNDS][ROUND_TWEAKEY_BYTES];

    state_init(state, message);
    compute_round_tweakeys(key, tweak, round_tweakeys);

    for (size_t round = 0U; round < ROUNDS - 1U; ++round) {
        lilliput_round_apply(
            state,
            round_tweakeys[round],
            LILLIPUT_PERMUTATION_ENCRYPTION,
            lookup
        );
    }

    lilliput_round_apply(
        state,
        round_tweakeys[ROUNDS - 1U],
        LILLIPUT_PERMUTATION_NONE,
        lookup
    );
    memcpy(ciphertext, state, BLOCK_BYTES);
}

void lilliput_tbc_encrypt(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t message[BLOCK_BYTES],
    uint8_t ciphertext[BLOCK_BYTES]
)
{
    encrypt_with_sbox(
        key,
        tweak,
        message,
        ciphertext,
        lilliput_sbox_correct
    );
}

void lilliput_tbc_encrypt_faulty(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t message[BLOCK_BYTES],
    uint8_t ciphertext[BLOCK_BYTES]
)
{
    encrypt_with_sbox(
        key,
        tweak,
        message,
        ciphertext,
        lilliput_sbox_faulty
    );
}

void lilliput_tbc_decrypt(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t ciphertext[BLOCK_BYTES],
    uint8_t message[BLOCK_BYTES]
)
{
    uint8_t state[BLOCK_BYTES];
    uint8_t round_tweakeys[ROUNDS][ROUND_TWEAKEY_BYTES];

    state_init(state, ciphertext);
    compute_round_tweakeys(key, tweak, round_tweakeys);

    for (size_t offset = 0U; offset < ROUNDS - 1U; ++offset) {
        lilliput_round_apply(
            state,
            round_tweakeys[ROUNDS - 1U - offset],
            LILLIPUT_PERMUTATION_DECRYPTION,
            lilliput_sbox_correct
        );
    }

    lilliput_round_apply(
        state,
        round_tweakeys[0],
        LILLIPUT_PERMUTATION_NONE,
        lilliput_sbox_correct
    );
    memcpy(message, state, BLOCK_BYTES);
}

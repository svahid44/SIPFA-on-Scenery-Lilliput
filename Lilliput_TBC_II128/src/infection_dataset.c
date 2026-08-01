#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "infection_dataset.h"
#include "persistent_fault.h"

static uint64_t splitmix64_next(uint64_t *state)
{
    uint64_t z;

    *state += UINT64_C(0x9E3779B97F4A7C15);
    z = *state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static void random_block(uint64_t *state, uint8_t block[BLOCK_BYTES])
{
    for (size_t offset = 0; offset < BLOCK_BYTES; offset += 8U) {
        const uint64_t word = splitmix64_next(state);
        for (size_t byte = 0; byte < 8U; ++byte) {
            block[offset + byte] = (uint8_t)(word >> (8U * byte));
        }
    }
}

void lilliput_infection_stats_init(lilliput_infection_stats *stats)
{
    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
    }
}

int lilliput_infection_collect(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    uint64_t total_samples,
    uint64_t seed,
    lilliput_infection_stats *stats,
    lilliput_published_callback callback,
    void *user_data
)
{
    uint64_t plaintext_state = seed;
    uint64_t infection_state =
        seed ^ UINT64_C(0xD1B54A32D192ED03);

    if ((key == NULL) || (tweak == NULL) || (stats == NULL) ||
        (total_samples == 0U)) {
        return -1;
    }

    if (!lilliput_fault_is_active()) {
        return -2;
    }

    lilliput_infection_stats_init(stats);

    for (uint64_t sample = 0; sample < total_samples; ++sample) {
        uint8_t plaintext[BLOCK_BYTES];
        uint8_t correct_ciphertext[BLOCK_BYTES];
        uint8_t faulty_ciphertext[BLOCK_BYTES];
        uint8_t published_ciphertext[BLOCK_BYTES];

        random_block(&plaintext_state, plaintext);
        lilliput_tbc_encrypt(key, tweak, plaintext, correct_ciphertext);
        lilliput_tbc_encrypt_faulty(key, tweak, plaintext, faulty_ciphertext);

        if (memcmp(correct_ciphertext, faulty_ciphertext, BLOCK_BYTES) == 0) {
            memcpy(published_ciphertext, correct_ciphertext, BLOCK_BYTES);
            ++stats->internal_ineffective_count;
        } else {
            /*
             * Infection model used in the paper: an effective fault produces
             * a random output phi.  A fresh independent random block makes
             * the public output statistically uniform for those events.
             */
            random_block(&infection_state, published_ciphertext);
            ++stats->internal_effective_count;
        }

        ++stats->published_count;
        for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
            ++stats->histogram[lane][published_ciphertext[lane]];
        }

        if ((callback != NULL) &&
            (callback(sample + 1U, published_ciphertext, user_data) != 0)) {
            return -3;
        }
    }

    return 0;
}

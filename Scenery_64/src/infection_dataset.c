#include "infection_dataset.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

static void random_block(
    uint64_t *state,
    uint8_t block[SCENERY_BLOCK_SIZE]
)
{
    const uint64_t word = splitmix64_next(state);
    size_t byte;

    for (byte = 0u; byte < SCENERY_BLOCK_SIZE; ++byte) {
        block[byte] = (uint8_t)(word >> (8u * byte));
    }
}

void scenery_infection_stats_init(scenery_infection_stats *stats)
{
    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
    }
}

int scenery_infection_collect(
    const scenery_ctx *ctx,
    uint64_t total_samples,
    uint64_t seed,
    scenery_infection_stats *stats,
    scenery_published_callback callback,
    void *user_data
)
{
    uint64_t plaintext_state = seed;
    uint64_t infection_state = seed ^ UINT64_C(0xD1B54A32D192ED03);
    uint64_t sample;

    if (ctx == NULL || stats == NULL || total_samples == 0u) {
        return -1;
    }
    if (!scenery_fault_is_active()) {
        return -2;
    }

    scenery_infection_stats_init(stats);

    for (sample = 0u; sample < total_samples; ++sample) {
        uint8_t plaintext[SCENERY_BLOCK_SIZE];
        uint8_t correct_ciphertext[SCENERY_BLOCK_SIZE];
        uint8_t faulty_ciphertext[SCENERY_BLOCK_SIZE];
        uint8_t published_ciphertext[SCENERY_BLOCK_SIZE];

        random_block(&plaintext_state, plaintext);
        if (scenery_encrypt_block(ctx, plaintext, correct_ciphertext) != 0 ||
            scenery_encrypt_block_faulty(ctx, plaintext, faulty_ciphertext) != 0) {
            return -3;
        }

        if (memcmp(correct_ciphertext,
                   faulty_ciphertext,
                   SCENERY_BLOCK_SIZE) == 0) {
            memcpy(published_ciphertext,
                   correct_ciphertext,
                   SCENERY_BLOCK_SIZE);
            ++stats->internal_ineffective_count;
        } else {
            random_block(&infection_state, published_ciphertext);
            ++stats->internal_effective_count;
        }

        ++stats->published_count;
        if (callback != NULL &&
            callback(sample + 1u, published_ciphertext, user_data) != 0) {
            return -4;
        }
    }

    return 0;
}

#include "detection_dataset.h"

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

void scenery_detection_stats_init(scenery_detection_stats *stats)
{
    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
    }
}

double scenery_detection_theoretical_ineffective_rate(void)
{
    double probability = 1.0;
    size_t round;

    for (round = 0u; round < SCENERY_ROUNDS; ++round) {
        probability *= 15.0 / 16.0;
    }
    return probability;
}

int scenery_detection_collect(
    const scenery_ctx *ctx,
    uint64_t target_ineffective,
    uint64_t max_queries,
    uint64_t seed,
    scenery_detection_stats *stats,
    scenery_ineffective_callback callback,
    void *user_data
)
{
    uint64_t prng_state = seed;

    if (ctx == NULL || stats == NULL || target_ineffective == 0u ||
        max_queries < target_ineffective) {
        return -1;
    }
    if (!scenery_fault_is_active()) {
        return -2;
    }

    scenery_detection_stats_init(stats);

    while (stats->ineffective_count < target_ineffective &&
           stats->total_queries < max_queries) {
        uint8_t plaintext[SCENERY_BLOCK_SIZE];
        uint8_t correct_ciphertext[SCENERY_BLOCK_SIZE];
        uint8_t faulty_ciphertext[SCENERY_BLOCK_SIZE];

        random_block(&prng_state, plaintext);
        if (scenery_encrypt_block(ctx, plaintext, correct_ciphertext) != 0 ||
            scenery_encrypt_block_faulty(
                ctx,
                plaintext,
                faulty_ciphertext
            ) != 0) {
            return -4;
        }

        ++stats->total_queries;
        if (memcmp(
                correct_ciphertext,
                faulty_ciphertext,
                SCENERY_BLOCK_SIZE
            ) == 0) {
            ++stats->ineffective_count;

            if (callback != NULL &&
                callback(
                    stats->total_queries,
                    stats->ineffective_count,
                    plaintext,
                    correct_ciphertext,
                    user_data
                ) != 0) {
                return -5;
            }
        } else {
            ++stats->effective_count;
        }
    }

    if (stats->ineffective_count != target_ineffective) {
        return -3;
    }
    return 0;
}

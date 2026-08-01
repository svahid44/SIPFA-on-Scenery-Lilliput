#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "detection_dataset.h"
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
    for (size_t offset = 0U; offset < BLOCK_BYTES; offset += 8U) {
        const uint64_t word = splitmix64_next(state);
        for (size_t byte = 0U; byte < 8U; ++byte) {
            block[offset + byte] = (uint8_t)(word >> (8U * byte));
        }
    }
}

void lilliput_detection_stats_init(lilliput_detection_stats *stats)
{
    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
    }
}

int lilliput_detection_collect(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    uint64_t target_ineffective,
    uint64_t max_queries,
    uint64_t seed,
    lilliput_detection_stats *stats,
    lilliput_ineffective_callback callback,
    void *user_data
)
{
    uint64_t prng_state = seed;

    if ((key == NULL) || (tweak == NULL) || (stats == NULL) ||
        (target_ineffective == 0U) || (max_queries < target_ineffective)) {
        return -1;
    }

    if (!lilliput_fault_is_active()) {
        return -2;
    }

    lilliput_detection_stats_init(stats);

    while ((stats->ineffective_count < target_ineffective) &&
           (stats->total_queries < max_queries)) {
        uint8_t plaintext[BLOCK_BYTES];
        uint8_t correct_ciphertext[BLOCK_BYTES];
        uint8_t faulty_ciphertext[BLOCK_BYTES];

        random_block(&prng_state, plaintext);
        lilliput_tbc_encrypt(key, tweak, plaintext, correct_ciphertext);
        lilliput_tbc_encrypt_faulty(key, tweak, plaintext, faulty_ciphertext);
        ++stats->total_queries;

        if (memcmp(correct_ciphertext, faulty_ciphertext, BLOCK_BYTES) == 0) {
            ++stats->ineffective_count;

            for (size_t lane = 0U;
                 lane < LILLIPUT_LAST_ROUND_LANES;
                 ++lane) {
                ++stats->histogram[lane][correct_ciphertext[lane]];
            }

            if ((callback != NULL) &&
                (callback(stats->total_queries,
                          stats->ineffective_count,
                          correct_ciphertext,
                          user_data) != 0)) {
                return -4;
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

#ifndef DETECTION_DATASET_H
#define DETECTION_DATASET_H

#include <stddef.h>
#include <stdint.h>

#include "attack_common.h"
#include "constants.h"

typedef struct lilliput_detection_stats {
    uint64_t total_queries;
    uint64_t ineffective_count;
    uint64_t effective_count;
    uint64_t histogram[LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];
} lilliput_detection_stats;

/*
 * Attacker-visible callback for a detection-based countermeasure.  In the
 * ciphertext-only model of SIPFA, plaintexts and internal event metadata are
 * deliberately not exposed.
 */
typedef int (*lilliput_ineffective_callback)(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
);

void lilliput_detection_stats_init(lilliput_detection_stats *stats);

/*
 * Generate random plaintexts internally and retain only outputs accepted by a
 * detection countermeasure, i.e., encrypt_correct(P) == encrypt_faulty(P).
 * The callback receives only the accepted ciphertext.
 *
 * Return values:
 *   0  target number of ineffective ciphertexts collected
 *  -1  invalid argument
 *  -2  no persistent fault is active
 *  -3  max_queries reached before target_ineffective
 *  -4  callback reported an error
 */
int lilliput_detection_collect(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    uint64_t target_ineffective,
    uint64_t max_queries,
    uint64_t seed,
    lilliput_detection_stats *stats,
    lilliput_ineffective_callback callback,
    void *user_data
);

#endif /* DETECTION_DATASET_H */

#ifndef INFECTION_DATASET_H
#define INFECTION_DATASET_H

#include <stddef.h>
#include <stdint.h>

#include "constants.h"
#include "attack_common.h"

typedef struct lilliput_infection_stats {
    uint64_t published_count;
    uint64_t internal_ineffective_count;
    uint64_t internal_effective_count;
    uint64_t histogram[LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];
} lilliput_infection_stats;

/*
 * The callback models the attacker-visible interface.  It receives only the
 * published ciphertext and its public sample index.  It is deliberately not
 * told whether the internal redundant computation was effective or
 * ineffective.
 */
typedef int (*lilliput_published_callback)(
    uint64_t sample_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
);

void lilliput_infection_stats_init(lilliput_infection_stats *stats);

/*
 * Generate exactly total_samples public outputs under an infection-based
 * redundancy countermeasure:
 *
 *   - ineffective event: publish the correct ciphertext;
 *   - effective event:   publish a fresh uniform random 128-bit string.
 *
 * The persistent S-box fault must already be active.  The generator keeps
 * internal event counters only for validation/reporting; the callback never
 * receives the event label.
 *
 * Return values:
 *   0  success
 *  -1  invalid argument
 *  -2  no persistent fault is active
 *  -3  callback reported an error
 */
int lilliput_infection_collect(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    uint64_t total_samples,
    uint64_t seed,
    lilliput_infection_stats *stats,
    lilliput_published_callback callback,
    void *user_data
);

#endif /* INFECTION_DATASET_H */

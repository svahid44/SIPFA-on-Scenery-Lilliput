#ifndef INFECTION_DATASET_H
#define INFECTION_DATASET_H

#include <stdint.h>

#include "scenery.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct scenery_infection_stats {
    uint64_t published_count;
    uint64_t internal_ineffective_count;
    uint64_t internal_effective_count;
} scenery_infection_stats;

/*
 * Attacker-visible callback.  It receives only the published ciphertext and
 * its public index.  The internal effective/ineffective event label is never
 * disclosed.
 */
typedef int (*scenery_published_callback)(
    uint64_t sample_index,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
);

void scenery_infection_stats_init(scenery_infection_stats *stats);

/*
 * Algorithm-3 infection-based oracle:
 *
 *   ineffective event: publish the correct ciphertext;
 *   effective event:   publish a fresh uniform random 64-bit block.
 *
 * Exactly total_samples public outputs are produced.  A persistent fault must
 * already be active.  Internal counters are retained only for simulation
 * validation and are not passed to the attacker callback.
 *
 * Return values:
 *   0  success
 *  -1  invalid argument
 *  -2  no persistent fault is active
 *  -3  encryption failed
 *  -4  callback returned an error
 */
int scenery_infection_collect(
    const scenery_ctx *ctx,
    uint64_t total_samples,
    uint64_t seed,
    scenery_infection_stats *stats,
    scenery_published_callback callback,
    void *user_data
);

#ifdef __cplusplus
}
#endif

#endif /* INFECTION_DATASET_H */

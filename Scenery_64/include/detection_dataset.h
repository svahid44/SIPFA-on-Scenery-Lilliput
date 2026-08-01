#ifndef DETECTION_DATASET_H
#define DETECTION_DATASET_H

#include <stddef.h>
#include <stdint.h>

#include "scenery.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct scenery_detection_stats {
    uint64_t total_queries;
    uint64_t ineffective_count;
    uint64_t effective_count;
} scenery_detection_stats;

typedef int (*scenery_ineffective_callback)(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
);

void scenery_detection_stats_init(scenery_detection_stats *stats);

/*
 * Standard SIPFA detection-based oracle model.
 *
 * For every chosen plaintext, the simulator evaluates both the validated
 * reference encryption and the persistent-fault encryption.  Only samples
 * satisfying
 *
 *     C_correct == C_faulty
 *
 * are released through callback.  Effective events are suppressed exactly as
 * a redundant detection countermeasure would suppress them.
 *
 * Return values:
 *   0  requested ineffective dataset was collected
 *  -1  invalid argument
 *  -2  no persistent fault is active
 *  -3  max_queries was reached before target_ineffective
 *  -4  encryption failed
 *  -5  callback returned an error
 */
int scenery_detection_collect(
    const scenery_ctx *ctx,
    uint64_t target_ineffective,
    uint64_t max_queries,
    uint64_t seed,
    scenery_detection_stats *stats,
    scenery_ineffective_callback callback,
    void *user_data
);

/*
 * Under the uniform and independent S-box-input assumption used in SIPFA,
 * one faulty 4-bit S-box input is avoided in all 28 rounds with probability
 * (15/16)^28.
 */
double scenery_detection_theoretical_ineffective_rate(void);

#ifdef __cplusplus
}
#endif

#endif /* DETECTION_DATASET_H */

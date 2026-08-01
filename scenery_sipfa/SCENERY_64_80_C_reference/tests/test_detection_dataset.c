#include "detection_dataset.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TARGET_INEFFECTIVE UINT64_C(4096)
#define MAX_QUERIES        UINT64_C(50000)
#define DATASET_SEED       UINT64_C(0x6A09E667F3BCC909)

static const scenery_ctx *callback_ctx = NULL;
static uint64_t callback_count = 0u;
static uint64_t previous_query_index = 0u;

static int verify_ineffective_sample(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    uint8_t correct[SCENERY_BLOCK_SIZE];
    uint8_t faulty[SCENERY_BLOCK_SIZE];

    (void)user_data;

    if (callback_ctx == NULL ||
        query_index <= previous_query_index ||
        ineffective_index != callback_count + 1u) {
        return -1;
    }
    if (scenery_encrypt_block(callback_ctx, plaintext, correct) != 0 ||
        scenery_encrypt_block_faulty(callback_ctx, plaintext, faulty) != 0) {
        return -1;
    }
    if (memcmp(correct, faulty, SCENERY_BLOCK_SIZE) != 0 ||
        memcmp(correct, ciphertext, SCENERY_BLOCK_SIZE) != 0) {
        return -1;
    }

    previous_query_index = query_index;
    callback_count = ineffective_index;
    return 0;
}

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const uint8_t target_sbox = 3u;
    const uint8_t delta = 0x5u;
    const uint8_t correct_output = scenery_sbox_correct(delta);
    const uint8_t faulty_output =
        (uint8_t)((correct_output + 1u) & 0x0Fu);
    scenery_ctx ctx;
    scenery_detection_stats stats;
    double empirical_rate;
    double theoretical_rate;
    double absolute_error;
    int status;

    if (scenery_init(&ctx, key) != 0) {
        return fail("scenery_init failed");
    }

    scenery_fault_reset();
    if (scenery_fault_inject(
            target_sbox,
            delta,
            faulty_output
        ) != 0) {
        return fail("persistent fault injection failed");
    }

    callback_ctx = &ctx;
    callback_count = 0u;
    previous_query_index = 0u;
    status = scenery_detection_collect(
        &ctx,
        TARGET_INEFFECTIVE,
        MAX_QUERIES,
        DATASET_SEED,
        &stats,
        verify_ineffective_sample,
        NULL
    );
    if (status != 0) {
        fprintf(stderr, "FAIL: dataset collector returned %d\n", status);
        return 1;
    }

    if (stats.total_queries !=
            stats.ineffective_count + stats.effective_count ||
        stats.ineffective_count != TARGET_INEFFECTIVE ||
        callback_count != TARGET_INEFFECTIVE ||
        stats.effective_count == 0u) {
        return fail("dataset counters are inconsistent");
    }

    empirical_rate =
        (double)stats.ineffective_count / (double)stats.total_queries;
    theoretical_rate = scenery_detection_theoretical_ineffective_rate();
    absolute_error = empirical_rate >= theoretical_rate
        ? empirical_rate - theoretical_rate
        : theoretical_rate - empirical_rate;

    /* A broad reproducibility guard; the deterministic run is much closer. */
    if (absolute_error > 0.015) {
        return fail("empirical rate is too far from the SIPFA model");
    }

    printf("target logical S-box:     %u\n", target_sbox);
    printf("known fault input delta:  0x%X\n", delta);
    printf("target ineffective:       %" PRIu64 "\n",
           TARGET_INEFFECTIVE);
    printf("total oracle queries:     %" PRIu64 "\n",
           stats.total_queries);
    printf("effective events blocked: %" PRIu64 "\n",
           stats.effective_count);
    printf("ineffective outputs kept: %" PRIu64 "\n",
           stats.ineffective_count);
    printf("theoretical rate:         %.9f\n", theoretical_rate);
    printf("empirical rate:           %.9f\n", empirical_rate);
    printf("absolute error:           %.9f\n", absolute_error);

    scenery_fault_reset();
    puts("PASS: detection-based oracle retained only verified ineffective ciphertexts.");
    return 0;
}
